"""ARP cache collector -- the zero-privilege, zero-packet baseline.

Reads what the OS already knows. Sends nothing, needs no elevation, works on
every platform, and cannot crash a fragile device. It is the floor that PNMA
falls back to when passive capture is unavailable, and it runs alongside
capture the rest of the time as a cheap cross-check.

Its weakness is that the cache only holds hosts this machine has recently
talked to, so it under-reports. Passive capture (:mod:`pnma.collectors.passive`)
is what fills that gap.
"""

from __future__ import annotations

import logging
import time

from ..db import Database
from ..guard import ScopeGuard, ScopeViolation
from ..inventory import observe
from ..netutil import read_arp_table

log = logging.getLogger(__name__)


class ArpTableCollector:
    source = "arp_table"

    def __init__(self, db: Database, guard: ScopeGuard, sensor_id: str):
        self.db = db
        self.guard = guard
        self.sensor_id = sensor_id

    def run_once(self) -> int:
        """Ingest the current ARP cache. Returns the number of devices seen."""
        started = time.time()
        seen = 0
        try:
            for entry in read_arp_table():
                try:
                    self.guard.assert_target_allowed(entry.ip)
                except ScopeViolation:
                    # VMware host-only nets and anything else off-scope. Not an
                    # error -- this is the filter doing its job.
                    continue
                device_id = observe(
                    self.db,
                    mac=entry.mac,
                    ip=entry.ip,
                    source=self.source,
                    sensor_id=self.sensor_id,
                    detail={"arp_type": entry.kind},
                )
                if device_id:
                    seen += 1
        except Exception as exc:  # noqa: BLE001 - a collector must not kill the loop
            log.exception("ARP table collection failed")
            self.db.log_scan(
                "arp_table_read",
                self.guard.config.network.cidr,
                duration_s=time.time() - started,
                error=str(exc),
            )
            return 0

        self.db.log_scan(
            "arp_table_read",
            self.guard.config.network.cidr,
            duration_s=time.time() - started,
            result=f"{seen} devices",
        )
        log.debug("ARP cache: %d in-scope devices", seen)
        return seen
