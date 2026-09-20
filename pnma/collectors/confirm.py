"""Active confirmation of a flagged exposure -- a banner grab, nothing more.

The CVE advisory rule (``cve_exposure``) matches on the exposure *class*: it
says "port 23 is open on a camera, and open telnet is the Mirai vector." That
is a strong signal but not a confirmed one -- the match is on the port, not on
what is actually answering. This module closes that gap in the mildest way
possible: for a device that already has an open advisory, it makes a single,
scope-guarded, timeout-bounded TCP connection to the flagged port, reads
whatever banner the service volunteers, and records it. "Port 23 open" becomes
"port 23 open, and it answered `BusyBox telnetd`."

Why this and not more. PNMA's whole identity is a *polite* agent: nmap at -T2,
no version probes, never the aggressive timing that crashes cheap IoT. An
active confirmation that fits that identity is a passive read -- open a socket,
read what is offered, close. It sends no exploit, no credentials, no crafted
payload; it is strictly less invasive than the port scan PNMA already runs. So
it is gated behind its own flag (``[scan].confirm_exposures``), off by default,
and it refuses any target the scope guard has not cleared -- the same gate every
other probe passes.

What this is NOT. It does not test credentials, fuzz, or exploit. Turning "this
service is here" into "this service is compromised" is done by hand, in a lab,
against a target built to be attacked -- see docs/PENTEST_LAB.md. Firing an
actual exploit at a live household device is exactly the crash-the-IoT outcome
the rest of this codebase is built to avoid.
"""

from __future__ import annotations

import logging
import socket
import time

from ..db import Database
from ..guard import ScopeGuard, ScopeViolation

log = logging.getLogger(__name__)

# Ports we will read a banner from, and how to coax one. Most services speak
# first (telnet, ssh, smtp); HTTP needs a minimal, well-formed request before
# it will answer, so we send the smallest legal one. Nothing here is a probe
# for a vulnerability -- it is the same request a browser's first byte would be.
_HTTP_PORTS = {80, 8080, 8443, 443}
_HTTP_NUDGE = b"HEAD / HTTP/1.0\r\n\r\n"

# Ports worth confirming, drawn from the advisory catalogue's own set.
CONFIRMABLE_PORTS = {23, 2323, 5555, 445, 139, 3389, 80, 8080, 1900, 22}


class ConfirmationProbe:
    """Reads service banners for devices that already have an open advisory."""

    def __init__(self, db: Database, guard: ScopeGuard, *, timeout_s: float = 3.0,
                 max_bytes: int = 256):
        self.db = db
        self.guard = guard
        self.timeout_s = timeout_s
        self.max_bytes = max_bytes

    def run_once(self) -> dict:
        """Confirm every flagged port on every device with an open cve alert."""
        rows = self.db.query(
            """SELECT DISTINCT a.device_id, d.ip
               FROM alerts a JOIN devices d ON d.device_id = a.device_id
               WHERE a.rule_id = 'cve_exposure' AND a.status = 'open'
                 AND d.ip IS NOT NULL"""
        )
        confirmed = 0
        attempted = 0
        for row in rows:
            ip = row["ip"]
            try:
                self.guard.assert_target_allowed(ip)
            except ScopeViolation as exc:
                log.debug("confirm: skipping out-of-scope %s (%s)", ip, exc)
                continue
            ports = self.db.query(
                "SELECT port, proto FROM ports WHERE device_id = ? AND closed_at IS NULL",
                (row["device_id"],),
            )
            for p in ports:
                if p["port"] not in CONFIRMABLE_PORTS or (p["proto"] or "tcp") != "tcp":
                    continue
                attempted += 1
                banner = self._grab(ip, p["port"])
                if banner is not None:
                    self._store(row["device_id"], p["port"], banner)
                    confirmed += 1
        self.db.log_scan(
            "confirm_exposure", "flagged devices",
            result=f"{confirmed}/{attempted} banners read",
        )
        return {"attempted": attempted, "confirmed": confirmed}

    def _grab(self, ip: str, port: int) -> str | None:
        """One connection, read a banner, close. Returns text or None."""
        try:
            with socket.create_connection((ip, port), timeout=self.timeout_s) as sock:
                sock.settimeout(self.timeout_s)
                if port in _HTTP_PORTS:
                    try:
                        sock.sendall(_HTTP_NUDGE)
                    except OSError:
                        return None
                data = sock.recv(self.max_bytes)
        except (OSError, socket.timeout):
            return None
        if not data:
            return ""  # answered but silent -- still a confirmation of listening
        text = data.decode("latin-1", "replace").strip()
        # Collapse to a single tidy line; a banner with control chars is noise.
        text = " ".join(text.split())
        return text[:200]

    def _store(self, device_id: str, port: int, banner: str) -> None:
        self.db.execute(
            """INSERT INTO exposure_banners(device_id, port, banner, confirmed_at)
               VALUES(?,?,?,?)
               ON CONFLICT(device_id, port) DO UPDATE SET
                   banner = excluded.banner, confirmed_at = excluded.confirmed_at""",
            (device_id, port, banner, time.time()),
        )


def confirmed_banners(db: Database, device_id: str) -> dict[int, str]:
    """{port: banner} confirmed for a device, for the advisory rule to cite."""
    rows = db.query(
        "SELECT port, banner FROM exposure_banners WHERE device_id = ?",
        (device_id,),
    )
    return {r["port"]: r["banner"] for r in rows}
