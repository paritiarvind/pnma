"""Honeypot ingestion: turn a Cowrie log into first-class PNMA alerts.

A honeypot is the safest way to study live attack traffic, because nothing real
sits behind it -- every connection to it is, by definition, unwanted. This
collector reads the JSON event log that **Cowrie** (the standard SSH/Telnet
honeypot) writes and turns it into the same alerts and sensor heartbeat as every
other PNMA source, so "something is knocking on the decoy" becomes a line on the
Alerts tab instead of a log nobody reads.

It is deliberately *ingestion only*. PNMA does not run the honeypot, and the
honeypot must not run on the production LAN -- its whole job is to attract
attackers, which is the last thing you want with a route to the laptops. Stand
Cowrie up on an isolated VM/VLAN (see docs/PENTEST_LAB.md), point
``[honeypot].cowrie_log_path`` at its ``cowrie.json``, and this reads it.

Design notes:

* **Passive.** It reads a file. No egress, no probing, so the scope guard has
  no opinion on it -- the guard is about not touching networks we are not
  authorised for, and a local log is neither.
* **Incremental.** The read offset is stored in ``meta`` so a restart resumes
  where it left off rather than re-alerting on the whole history. A log that
  shrank (rotated) resets the offset.
* **Aggregated by source.** One attacker makes hundreds of login attempts; that
  is one alert with a climbing count, not hundreds of rows. Dedup is by source
  IP, exactly like every other rule, so ``raise_alert`` does the counting.
* **Tolerant.** A malformed JSON line is skipped, not fatal -- a honeypot under
  active attack is the worst possible time for the reader to crash on one bad
  line.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from ..db import Database

log = logging.getLogger(__name__)

_OFFSET_KEY = "honeypot_cowrie_offset"

# Cowrie eventids we act on. The rest (session.closed, client.version, ...) are
# read past silently.
_LOGIN_FAILED = "cowrie.login.failed"
_LOGIN_SUCCESS = "cowrie.login.success"
_COMMAND = "cowrie.command.input"
_SESSION = "cowrie.session.connect"


class HoneypotCollector:
    """Reads a Cowrie JSON log and raises alerts for what hit the decoy."""

    def __init__(self, db: Database, sensor_id: str, log_path: str):
        self.db = db
        self.sensor_id = sensor_id
        self.log_path = Path(log_path)

    def _get_offset(self) -> int:
        row = self.db.query_one("SELECT value FROM meta WHERE key = ?", (_OFFSET_KEY,))
        try:
            return int(row["value"]) if row else 0
        except (TypeError, ValueError):
            return 0

    def _set_offset(self, offset: int) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)",
            (_OFFSET_KEY, str(offset)),
        )

    def available(self) -> bool:
        return self.log_path.exists()

    def run_once(self) -> dict:
        """Read new events since the last run and raise alerts. Returns a summary."""
        if not self.log_path.exists():
            log.warning("honeypot log not found: %s", self.log_path)
            return {"ok": False, "reason": "log not found"}

        self.db.register_sensor(
            self.sensor_id, "honeypot", hostname=self.log_path.name, version="cowrie"
        )

        size = self.log_path.stat().st_size
        offset = self._get_offset()
        if offset > size:
            # The log rotated/truncated under us; start from the top.
            offset = 0

        # Aggregate this batch by source IP so one busy attacker is one alert.
        by_src: dict[str, dict] = {}
        read = 0
        try:
            with self.log_path.open("r", encoding="utf-8", errors="replace") as fh:
                fh.seek(offset)
                for line in fh:
                    read += 1
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except ValueError:
                        continue
                    self._accumulate(by_src, ev)
                new_offset = fh.tell()
        except OSError as exc:
            log.warning("honeypot read failed: %s", exc)
            return {"ok": False, "reason": str(exc)}

        for src, agg in by_src.items():
            self._raise_for_source(src, agg)

        self._set_offset(new_offset)
        summary = {
            "ok": True,
            "sources": len(by_src),
            "logins": sum(a["logins"] for a in by_src.values()),
            "commands": sum(len(a["commands"]) for a in by_src.values()),
        }
        self.db.log_scan(
            "honeypot_ingest", str(self.log_path),
            result=f"{summary['sources']} sources, {summary['logins']} login attempts",
        )
        return summary

    @staticmethod
    def _accumulate(by_src: dict, ev: dict) -> None:
        src = ev.get("src_ip")
        if not src:
            return
        eid = ev.get("eventid")
        agg = by_src.setdefault(src, {
            "logins": 0, "success": 0, "commands": [], "creds": set(), "sessions": 0,
        })
        if eid == _LOGIN_FAILED:
            agg["logins"] += 1
            agg["creds"].add(f"{ev.get('username', '?')}:{ev.get('password', '?')}")
        elif eid == _LOGIN_SUCCESS:
            agg["logins"] += 1
            agg["success"] += 1
            agg["creds"].add(f"{ev.get('username', '?')}:{ev.get('password', '?')}")
        elif eid == _COMMAND:
            cmd = ev.get("input")
            if cmd:
                agg["commands"].append(cmd)
        elif eid == _SESSION:
            agg["sessions"] += 1

    def _raise_for_source(self, src: str, agg: dict) -> None:
        # A successful login or a command run is a materially worse event than
        # knocking, so it drives severity up.
        if agg["commands"] or agg["success"]:
            severity = "high"
        elif agg["logins"] >= 10:
            severity = "medium"
        else:
            severity = "low"

        creds = sorted(agg["creds"])[:12]
        cmds = agg["commands"][:12]
        parts = [
            f"A source hitting the honeypot decoy made {agg['logins']} login "
            f"attempt{'s' if agg['logins'] != 1 else ''}"
            + (f", {agg['success']} of them accepted" if agg["success"] else "")
            + (f", then ran {len(agg['commands'])} command(s)" if agg["commands"] else "")
            + ".",
            "",
            "WHY THIS MATTERS: everything that reaches a honeypot is unwanted by "
            "definition -- there is no legitimate reason to connect to it. This "
            "is what a real attacker's first moves look like, captured safely.",
            "",
            "NEXT STEP: confirm the honeypot is on an isolated segment with no "
            "route to your real devices (it should be). Note the source and the "
            "credentials tried -- if any match a password you actually use, "
            "rotate it now. This is intelligence, not an incident on your LAN, "
            "unless the source IP is one of your own devices.",
        ]
        if creds:
            parts += ["", "CREDENTIALS TRIED: " + ", ".join(creds)]
        if cmds:
            parts += ["", "COMMANDS RUN: " + " ; ".join(cmds)]

        self.db.raise_alert(
            dedup_key=f"honeypot:{src}",
            rule_id="honeypot_hit",
            severity=severity,
            title=f"Honeypot: attack traffic from {src}",
            description="\n".join(parts),
            mitre_id="T1110",
            mitre_name="Brute Force",
            evidence={
                "src_ip": src,
                "login_attempts": agg["logins"],
                "successful_logins": agg["success"],
                "credentials_tried": creds,
                "commands": cmds,
                "sessions": agg["sessions"],
            },
        )
