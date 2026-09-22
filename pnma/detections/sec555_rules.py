"""Detections adapted from the SANS SEC555 (SIEM / tactical analytics, the
GCDA course) techniques, restricted to what Hearth already collects so they
need no new configuration from the operator.

Each maps a standard, non-proprietary detection idea onto our own telemetry:
the *concept* (flag cleartext protocols; flag a machine-generated service
name) is ordinary security knowledge; the implementation here is our own,
over our own tables, with the same honesty contract as every other rule --
a stated data source (`requires`) and a stated blind spot.
"""

from __future__ import annotations

import json
import re

from .base import Detection, DetectionContext, Finding
from .. import activity

WINDOW_S = 30 * 24 * 3600
DAY = 86400


# --------------------------------------------------------------- cleartext

# Port -> (protocol, what an eavesdropper on the LAN gets). Legacy protocols
# that carry credentials or data with no transport encryption.
CLEARTEXT_PORTS = {
    21: ("FTP", "file transfers and the login, in the clear"),
    23: ("Telnet", "the whole session including the password, in the clear"),
    25: ("SMTP", "mail contents in the clear (unless STARTTLS is enforced)"),
    69: ("TFTP", "file transfers with no authentication at all"),
    110: ("POP3", "the mailbox login and messages, in the clear"),
    143: ("IMAP", "the mailbox login and messages, in the clear"),
    512: ("rexec", "remote command execution with the password in the clear"),
    513: ("rlogin", "a remote login with the password in the clear"),
    514: ("rsh", "remote shell with host-based trust, no real authentication"),
    5900: ("VNC", "the screen and, on old servers, keystrokes without encryption"),
}


class CleartextProtocolDetection(Detection):
    """A device on the LAN is offering a protocol that carries credentials or
    data with no encryption -- anyone on the same Wi-Fi can read it."""

    rule_id = "cleartext_protocol"
    name = "Cleartext / legacy protocol in use"
    severity = "medium"
    mitre_id = "T1040"
    mitre_name = "Network Sniffing"
    requires = "the open-ports inventory (port scan): a listening port in the legacy-protocol set"
    blind_spots = (
        "Port-based: it sees that, say, 23/tcp is open, not whether anything ever "
        "authenticates over it. A service can also run a modern protocol on a "
        "legacy port. Confirm by connecting once and reading the banner. It "
        "cannot see cleartext auth carried over an ordinary HTTP port (80), "
        "which needs payload inspection Hearth does not do."
    )

    def evaluate(self, ctx: DetectionContext) -> list[Finding]:
        rows = ctx.db.query(
            "SELECT p.device_id, p.port, p.proto, d.label, d.hostname, d.ip, d.device_class, d.trusted "
            "FROM ports p JOIN devices d ON d.device_id = p.device_id "
            "WHERE p.closed_at IS NULL AND p.port IN (%s)"
            % ",".join(str(k) for k in CLEARTEXT_PORTS),
        )
        out: list[Finding] = []
        for r in rows:
            if r["device_id"] in ctx.self_device_ids:
                continue
            proto, what = CLEARTEXT_PORTS[r["port"]]
            name = r["label"] or r["hostname"] or r["ip"] or r["device_id"]
            out.append(Finding(
                dedup_key=f"cleartext:{r['device_id']}:{r['port']}",
                severity=self.severity,
                title=f"{name}: {proto} in use on {r['port']}/{r['proto']}",
                description=(
                    f"{name} ({r['ip']}) is offering {proto} on {r['port']}/{r['proto']}.\n\n"
                    f"WHY THIS MATTERS: {proto} sends {what}. On a shared Wi-Fi network "
                    "anyone who can capture packets -- a guest, a compromised device, "
                    "a neighbour on the same access point -- can read it. This is the "
                    "'use of cleartext protocols' case: the exposure is not a bug in "
                    "the device, it is the protocol.\n\n"
                    "BENIGN EXPLANATION: an old printer, NAS, camera or IoT device that "
                    "only speaks the legacy protocol on the local network, and you "
                    "accept that within your own home.\n\n"
                    "MALICIOUS EXPLANATION: a device you did not knowingly enable this "
                    "on, or one that also faces the internet.\n\n"
                    "NEXT STEP: in the device's settings, switch to the encrypted "
                    "equivalent (SFTP/FTPS for FTP, SSH for Telnet/rsh, IMAPS/POP3S for "
                    "mail, a VNC with TLS or a tunnel). If it cannot, keep it on a "
                    "trusted network only and never expose the port to the internet."
                ),
                device_id=r["device_id"],
                evidence={"port": r["port"], "proto": r["proto"], "protocol": proto, "ip": r["ip"]},
                correlation_key=f"port:{r['device_id']}:{r['port']}",
            ))
        return out


# ---------------------------------------------------- randomly-named service

_VOWELS = set("aeiouAEIOU")
_GUID = re.compile(r"^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}", re.A)


def looks_random(name: str) -> bool:
    """True if a service/task name looks machine-generated rather than named.

    Malware that installs a service often uses a random or GUID-like name so
    it does not stand out in a list read by a human; a legitimate service is
    almost always a pronounceable word or a vendor string. Conservative on
    purpose -- a false 'random' on a real service is worse than a miss."""
    n = (name or "").strip()
    if len(n) < 8 or " " in n:
        return False
    if _GUID.match(n):
        return True
    core = re.sub(r"[^A-Za-z0-9]", "", n)
    if len(core) < 8:
        return False
    # An all-hex name of any length is machine-generated: a GUID fragment, a
    # hash, a random token. Real service names are words, not hex blobs.
    if re.fullmatch(r"[0-9a-fA-F]+", core) and sum(c.isdigit() for c in core) >= 3:
        return True
    letters = [c for c in core if c.isalpha()]
    if not letters:
        return False
    vowel_ratio = sum(c in _VOWELS for c in letters) / len(letters)
    digits = sum(c.isdigit() for c in core)
    case_flips = sum(1 for a, b in zip(core, core[1:]) if a.isalpha() and b.isalpha() and a.islower() != b.islower())
    # random-looking: very few vowels (unpronounceable) AND some digits, OR a
    # lot of case changes with digits mixed through (aB3xK9zQ).
    return (vowel_ratio < 0.26 and digits >= 1) or (case_flips >= 4 and digits >= 2)


class RandomServiceNameDetection(Detection):
    """A service or scheduled task installed under a machine-generated name."""

    rule_id = "random_service_name"
    name = "Randomly-named service or task installed"
    severity = "high"
    mitre_id = "T1543.003"
    mitre_name = "Create or Modify System Process: Windows Service"
    requires = "host events: a service_installed row (System 7045, or Security 4698 when elevated)"
    blind_spots = (
        "A name heuristic, not a signature: it flags names that look random and "
        "misses malware that deliberately names itself after a Windows service "
        "(the opposite trick). It reads only the name, not the binary -- pair it "
        "with the service's path and SHA-256 in the same alert. A legitimate "
        "service with a hashed or GUID name will be flagged and should be "
        "acknowledged."
    )

    def evaluate(self, ctx: DetectionContext) -> list[Finding]:
        rows = ctx.db.query(
            "SELECT id, ts, summary, detail FROM host_events "
            "WHERE kind = 'service_installed' AND agent_generated = 0 AND ts >= ? "
            "ORDER BY ts DESC LIMIT 200",
            (ctx.now - WINDOW_S,),
        )
        out: list[Finding] = []
        for r in rows:
            try:
                d = json.loads(r["detail"] or "{}")
            except ValueError:
                d = {}
            svc = d.get("name") or ""
            if not looks_random(svc):
                continue
            out.append(Finding(
                dedup_key=f"random_service:{r['id']}",
                severity=self.severity,
                title=f"Service installed under a random-looking name: {svc}",
                description=(
                    f"A service or task named '{svc}' was installed.\n\n"
                    f"  Path     {d.get('path') or '-'}\n"
                    f"  SHA-256  {d.get('sha256') or 'not hashed'}\n\n"
                    "WHY THIS MATTERS: legitimate software names its service after "
                    "itself so a person can recognise it. A random or GUID-like name "
                    "is what malware uses to blend into a service list -- there is "
                    "nothing to look up and nothing to recognise.\n\n"
                    "BENIGN EXPLANATION: some installers and per-user services do use "
                    "hashed or GUID names (a few Windows and browser components do). "
                    "Check the path and publisher.\n\n"
                    "MALICIOUS EXPLANATION: the path is under AppData/Temp/ProgramData/"
                    "Public, the binary is unsigned, or you installed nothing at that "
                    "time.\n\n"
                    "NEXT STEP: `Get-Service -Name '" + svc + "' | Format-List *` and "
                    "look up the SHA-256 by hand before deciding. If it is not yours, "
                    "`sc.exe stop`/`delete` it and quarantine the binary "
                    "(`pnma quarantine`)."
                ),
                evidence={"host_event_id": r["id"], "service": svc,
                          "path": d.get("path"), "sha256": d.get("sha256")},
                mitre_id=self.mitre_id, mitre_name=self.mitre_name,
            ))
        return out




class OffHoursActivityDetection(Detection):
    """A device active at an hour it is never normally active.

    SEC555's baselining idea: learn a thing's rhythm, then flag the departure.
    A phone or laptop that only ever appears 07:00-23:00 suddenly chattering at
    03:00 is worth one look -- it woke for an update, or something is using it
    while you sleep."""

    rule_id = "off_hours_activity"
    name = "Device active outside its normal hours"
    severity = "low"
    mitre_id = "T1071"
    mitre_name = "Application Layer Protocol"
    requires = "passive observations: a device's learned active-hour envelope (needs 14+ days of history)"
    blind_spots = (
        "Needs a fortnight of history before it will judge a device at all, and "
        "never fires on an always-on device (a TV, a hub, the gateway) -- those "
        "have no 'off hours'. It sees that a device was present at an unusual "
        "hour, not what it did; a scheduled update and an intruder look the same "
        "here, so it is deliberately low severity and a prompt to look, not a "
        "verdict."
    )
    RECENT_S = 3600

    def evaluate(self, ctx: DetectionContext) -> list[Finding]:
        if ctx.in_learning_mode:
            return []
        out: list[Finding] = []
        recent = ctx.db.query(
            "SELECT DISTINCT device_id FROM observations "
            "WHERE agent_generated = 0 AND ts >= ? AND device_id IS NOT NULL",
            (ctx.now - self.RECENT_S,))
        for r in recent:
            did = r["device_id"]
            if did in ctx.self_device_ids:
                continue
            env = activity.active_hour_envelope(ctx.db, did, now=ctx.now)
            if not activity.is_off_hours(env, ctx.now):
                continue
            dev = ctx.db.query_one("SELECT label, hostname, ip FROM devices WHERE device_id = ?", (did,))
            name = (dev["label"] or dev["hostname"] or dev["ip"] or did) if dev else did
            hour = int(activity._local_hour(ctx.now))
            out.append(Finding(
                dedup_key="off_hours:" + did + ":" + str(int(ctx.now // DAY)),
                severity=self.severity,
                title=name + " is active at " + ("%02d:00" % hour) + ", outside its usual hours",
                description=(
                    name + " was seen on the network around " + ("%02d:00" % hour) + ". Over the last "
                    + str(int(env["history_days"])) + " days it has only ever been active during: "
                    + _hours_phrase(env["active_hours"]) + "." + REST),
                device_id=did,
                evidence={"hour": hour, "active_hours": env["active_hours"],
                          "history_days": round(env["history_days"], 1)},
                triggers_triage_scan=True,
            ))
        return out


REST = ("\n\nWHY THIS MATTERS: a device keeping to a daily rhythm that "
                    "suddenly breaks it is a small but real signal -- something "
                    "woke it, or something is using it, at a time you are usually "
                    "not.\n\n"
                    "BENIGN EXPLANATION: a scheduled OS or app update, a backup, "
                    "a family member up late, or the device simply staying on "
                    "longer than usual.\n\n"
                    "MALICIOUS EXPLANATION: the device is compromised and active "
                    "on someone else's schedule, or it is not the device you "
                    "think it is.\n\n"
                    "NEXT STEP: open its Investigation log for this window and see "
                    "what it did -- a scan, a new port, an outbound connection. If "
                    "nothing explains it and it is not yours, untrust it.")


def _hours_phrase(hours):
    if not hours:
        return "no established hours"
    runs, start, prev = [], hours[0], hours[0]
    for h in hours[1:]:
        if h == prev + 1:
            prev = h
        else:
            runs.append((start, prev)); start = prev = h
    runs.append((start, prev))
    return ", ".join(("%02d:00-%02d:00" % (a, b)) if a != b else ("%02d:00" % a) for a, b in runs)


def sec555_rules() -> list[Detection]:
    return [
        CleartextProtocolDetection(),
        RandomServiceNameDetection(),
        OffHoursActivityDetection(),
    ]
