"""Router log ingestion over email (IMAP).

PNMA is host-based: it sees the network from one machine's vantage point, which
means NAT'd outbound connections, DHCP lease churn and anything the router does
on the WAN side are invisible to it. The router sees all of that -- but this
TP-Link Archer (and most consumer routers) has no remote syslog. What it does
have is a "Mail Log" feature: it emails its system log to an address on a
schedule.

This collector closes the gap the only way the hardware allows: it logs into a
mailbox over IMAP, reads the router's log emails, parses the lines it
recognises, and raises alerts for the events worth surfacing -- a new DHCP lease,
an admin login, a firewall/DoS event, a config change. The router becomes a
sensor like any other.

Boundaries, in keeping with the rest of PNMA:

* **Opt-in.** Off unless a mailbox is configured. Reading a mailbox is a
  standing capability a stranger reading this repo should not find switched on.
* **Read-only.** It fetches and parses; it never sends, deletes or moves mail.
  (It marks messages Seen so the same log is not re-ingested, and only that.)
* **Credentials in the OS store.** The IMAP password is the secret
  ``maillog_imap_password``; the host/user/folder are config. Use an
  app-specific password, never your main one.
* **Parser is best-effort and format-tolerant.** TP-Link's log line format
  varies by model and firmware; unrecognised lines are counted and skipped, not
  fatal. The recognised patterns below are the common Archer format and are
  easy to extend once you see your own emails (``pnma maillog --dry-run`` prints
  what it parsed).
"""

from __future__ import annotations

import email
import imaplib
import logging
import re
import time
from dataclasses import dataclass

from ..db import Database

log = logging.getLogger(__name__)

# TP-Link Archer syslog lines look roughly like:
#   "Jan  1 12:00:00 ... [DHCP] ... assigned 192.168.0.42 to AA:BB:CC:DD:EE:FF"
#   "... [LOGIN] ... admin login from 192.168.0.5"
#   "... [Firewall] ... DoS attack ... from 203.0.113.9"
# Match on the event keyword and pull the obvious fields; keep the whole line as
# evidence so nothing is lost to an over-eager regex.
_MAC = r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})"
_IP = r"(\d{1,3}(?:\.\d{1,3}){3})"

_PATTERNS = [
    ("dhcp_lease", "low",
     re.compile(r"DHCP.*?(?:assign|lease).*?" + _IP + r".*?" + _MAC, re.IGNORECASE),
     "New DHCP lease issued by the router"),
    ("admin_login", "medium",
     re.compile(r"(?:LOGIN|log ?in|authenticat).*?" + _IP, re.IGNORECASE),
     "Admin login to the router"),
    ("firewall_event", "high",
     re.compile(r"(?:DoS|attack|flood|intrusion|blocked).*?" + _IP, re.IGNORECASE),
     "Router firewall flagged an attack"),
    ("config_change", "medium",
     re.compile(r"(?:config|setting|firmware|reboot|upgrade).*?chang|reboot|upgrade",
                re.IGNORECASE),
     "Router configuration or firmware changed"),
    ("wan_event", "low",
     re.compile(r"(?:WAN|PPPoE|internet).*?(?:up|down|connect|disconnect)", re.IGNORECASE),
     "Router WAN link state changed"),
]


@dataclass
class ParsedEvent:
    kind: str
    severity: str
    title: str
    ip: str | None
    mac: str | None
    line: str


def parse_log_line(line: str) -> ParsedEvent | None:
    """Classify one router syslog line, or None if unrecognised."""
    line = line.strip()
    if not line:
        return None
    for kind, severity, pattern, title in _PATTERNS:
        m = pattern.search(line)
        if m:
            ip = next((g for g in m.groups() if g and re.fullmatch(_IP, g)), None)
            mac = next((g for g in m.groups() if g and re.fullmatch(_MAC, g)), None)
            return ParsedEvent(kind, severity, title, ip, mac, line[:400])
    return None


def parse_log_body(body: str) -> list[ParsedEvent]:
    events = []
    for line in body.splitlines():
        ev = parse_log_line(line)
        if ev:
            events.append(ev)
    return events


class MailLogCollector:
    """Reads router log emails over IMAP and raises alerts from them."""

    def __init__(self, db: Database, sensor_id: str, *, host: str, user: str,
                 password: str, folder: str = "INBOX", from_filter: str = "",
                 port: int = 993):
        self.db = db
        self.sensor_id = sensor_id
        self.host = host
        self.user = user
        self.password = password
        self.folder = folder
        self.from_filter = from_filter
        self.port = port

    def run_once(self, *, dry_run: bool = False) -> dict:
        """Fetch unseen router mails, parse, and raise alerts. Best-effort."""
        try:
            conn = imaplib.IMAP4_SSL(self.host, self.port)
            conn.login(self.user, self.password)
        except (imaplib.IMAP4.error, OSError) as exc:
            log.warning("maillog IMAP connect failed: %s", exc)
            return {"ok": False, "reason": str(exc)}

        self.db.register_sensor(self.sensor_id, "router_maillog", hostname=self.host,
                                version="imap")
        parsed_total = 0
        raised = 0
        try:
            conn.select(self.folder)
            criteria = ["UNSEEN"]
            if self.from_filter:
                criteria = ["UNSEEN", "FROM", self.from_filter]
            typ, data = conn.search(None, *criteria)
            if typ != "OK":
                return {"ok": False, "reason": "IMAP search failed"}
            ids = data[0].split()
            for mid in ids:
                fetch_flag = "(BODY.PEEK[])" if dry_run else "(RFC822)"
                typ, msg_data = conn.fetch(mid, fetch_flag)
                if typ != "OK" or not msg_data or not msg_data[0]:
                    continue
                body = _extract_text(msg_data[0][1])
                events = parse_log_body(body)
                parsed_total += len(events)
                if not dry_run:
                    for ev in events:
                        if self._raise(ev):
                            raised += 1
        finally:
            try:
                conn.close()
            except imaplib.IMAP4.error:
                pass
            conn.logout()

        self.db.log_scan("maillog_ingest", self.host,
                         result=f"{parsed_total} events parsed, {raised} alerts")
        return {"ok": True, "parsed": parsed_total, "raised": raised, "messages": len(ids)}

    def _raise(self, ev: ParsedEvent) -> bool:
        where = ev.ip or ev.mac or "the router"
        return self.db.raise_alert(
            dedup_key=f"maillog:{ev.kind}:{ev.ip or ev.mac or 'router'}",
            rule_id="router_maillog",
            severity=ev.severity,
            title=f"Router log: {ev.title}"
                  + (f" ({ev.ip})" if ev.ip else ""),
            description=(
                f"The router emailed a log line PNMA recognised as: {ev.title}.\n\n"
                f"WHY THIS MATTERS: this is the router's own view of the network -- "
                f"the WAN side, DHCP and admin activity PNMA cannot see from a "
                f"single host.\n\n"
                f"NEXT STEP: confirm you recognise {where}. An admin login or a "
                f"config change you did not make, or a firewall event from an "
                f"external IP, is worth investigating on the router directly.\n\n"
                f"ROUTER LOG LINE: {ev.line}"
            ),
            evidence={"kind": ev.kind, "ip": ev.ip, "mac": ev.mac, "line": ev.line},
        )


def _extract_text(raw: bytes) -> str:
    """Pull the text body out of an email message (plain preferred)."""
    try:
        msg = email.message_from_bytes(raw)
    except Exception:  # noqa: BLE001
        return raw.decode("latin-1", "replace")
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    return payload.decode(part.get_content_charset() or "utf-8", "replace")
    payload = msg.get_payload(decode=True)
    if payload:
        return payload.decode(msg.get_content_charset() or "utf-8", "replace")
    return str(msg.get_payload())
