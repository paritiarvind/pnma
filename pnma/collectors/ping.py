"""ICMP availability and latency.

Feeds the availability/SLO panels. Uses the system ``ping`` binary rather than
raw sockets so this collector needs no elevation -- keeping the privileged
surface as small as possible is the whole point of the process split.

Every probe is gated by the scope guard. Discovery output is untrusted input:
an ARP reply can claim any address it likes, so a target that came from the
network never reaches the wire without being re-checked.
"""

from __future__ import annotations

import concurrent.futures
import logging
import platform
import re
import subprocess
import time

from ..db import Database
from ..guard import ScopeGuard, ScopeViolation

log = logging.getLogger(__name__)

IS_WINDOWS = platform.system() == "Windows"

# Windows: "Average = 12ms" / Unix: "rtt min/avg/max/mdev = 1.2/3.4/5.6/0.1 ms"
_WIN_RTT = re.compile(r"Average\s*=\s*(\d+)ms", re.IGNORECASE)
_UNIX_RTT = re.compile(r"=\s*[\d.]+/([\d.]+)/")


def ping_host(ip: str, timeout_s: int = 2) -> tuple[bool, float | None]:
    """Send a single echo request. Returns (reachable, rtt_ms)."""
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_s * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s + 3, check=False
        )
    except (subprocess.SubprocessError, OSError):
        return False, None

    if proc.returncode != 0:
        return False, None

    out = proc.stdout
    # Windows ping exits 0 even for "Destination host unreachable".
    if IS_WINDOWS and "unreachable" in out.lower():
        return False, None

    match = (_WIN_RTT if IS_WINDOWS else _UNIX_RTT).search(out)
    return True, float(match.group(1)) if match else None


class PingCollector:
    source = "icmp"

    # Devices not seen for this long stop being pinged. Without this the target
    # list only ever grows, and every guest phone that ever joined is probed
    # forever -- which is both wasteful and, cumulatively, noisy.
    STALE_AFTER_S = 86400 * 7

    def __init__(
        self,
        db: Database,
        guard: ScopeGuard,
        sensor_id: str,
        workers: int = 8,
        auditor=None,  # pnma.audit.Auditor
    ):
        self.db = db
        self.guard = guard
        self.sensor_id = sensor_id
        self.workers = workers
        self.auditor = auditor

    def _targets(self) -> list[str]:
        """Recently-seen device IPs, plus the gateway. Not a sweep of the range.

        Pinging only what we already know about keeps the traffic proportionate
        and avoids looking like a horizontal sweep to anything else watching.
        """
        rows = self.db.query(
            "SELECT DISTINCT ip FROM devices "
            "WHERE ip IS NOT NULL AND ip != '' AND last_seen >= ?",
            (time.time() - self.STALE_AFTER_S,),
        )
        ips = {r["ip"] for r in rows}
        ips.add(self.guard.config.network.gateway_ip)
        return self.guard.filter_targets(sorted(ips))

    def run_once(self) -> int:
        targets = self._targets()
        if not targets:
            return 0
        if self.auditor is None:
            return self._probe(targets)
        # One ICMP echo per target.
        return self.auditor.active_operation(
            "ping", f"{len(targets)} hosts", len(targets),
            lambda: self._probe(targets), target_ips=targets,
        ) or 0

    def _probe(self, targets: list[str]) -> int:
        started = time.time()

        results: list[tuple[str, bool, float | None]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(ping_host, ip): ip for ip in targets}
            for future in concurrent.futures.as_completed(futures):
                ip = futures[future]
                try:
                    reachable, rtt = future.result()
                except Exception:  # noqa: BLE001
                    reachable, rtt = False, None
                results.append((ip, reachable, rtt))

        now = time.time()
        recorded = 0
        for ip, reachable, rtt in results:
            row = self.db.query_one(
                "SELECT device_id FROM devices WHERE ip = ? "
                "ORDER BY last_seen DESC LIMIT 1",
                (ip,),
            )
            if row is None:
                continue
            self.db.execute(
                "INSERT INTO availability(ts, device_id, reachable, rtt_ms) "
                "VALUES(?,?,?,?)",
                (now, row["device_id"], int(reachable), rtt),
            )
            # Deliberately NOT updating devices.last_seen here. A device is not
            # "seen" because we poked it -- that would make presence a function
            # of our own probing and contaminate every absence-based detection
            # with agent activity. Presence comes from passive observation only.
            recorded += 1

        up = sum(1 for _, r, _ in results if r)
        self.db.log_scan(
            "ping",
            f"{len(targets)} hosts",
            duration_s=time.time() - started,
            result=f"{up}/{len(targets)} reachable",
        )
        return recorded


def gateway_latency(guard: ScopeGuard) -> tuple[bool, float | None]:
    """Convenience probe used by the dashboard header for WAN-ish health."""
    gw = guard.config.network.gateway_ip
    try:
        guard.assert_target_allowed(gw)
    except ScopeViolation:
        return False, None
    return ping_host(gw)
