"""Active host discovery.

This exists because the two discovery paths that came before it both have a
hole, and on an unprivileged Windows host the hole is the whole feature.

:mod:`pnma.collectors.arp_table` reads the operating system's ARP cache. That
is genuinely passive and costs nothing, but it only ever contains devices this
host has recently exchanged traffic with -- and on Windows, entries age out in
well under a minute when unused. Measured on this network: an ``nmap -sn``
sweep found six live hosts, and by the time the sweep finished the OS cache was
back down to three. A monitoring agent whose inventory depends on what Windows
happens to still be caching is not an inventory.

:mod:`pnma.collectors.passive` sees everything, because it watches ARP
broadcasts directly -- but it needs Administrator and a packet-capture driver.
That is a supported mode, not a required one, and the unprivileged mode is the
one most people will actually run.

So: an explicit sweep. ``nmap -sn`` performs host discovery and **touches no
ports** -- on the local segment it resolves hosts by ARP, which also means the
reply carries the MAC address directly. That matters more than it sounds. The
MAC arrives from nmap's own output rather than from the OS cache, so identity
no longer depends on the cache still holding the entry when we get around to
reading it.

**Every discovered address is re-authorised before it is recorded.** Discovery
output is untrusted input: a host can claim any address it likes in a reply,
and the fact that this agent asked the question does not make the answer
authoritative. The sweep target is checked against the scope guard, and so is
every address that comes back.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET

from ..db import Database
from ..guard import ScopeGuard, ScopeViolation
from ..inventory import observe

log = logging.getLogger(__name__)


class DiscoveryCollector:
    """Sweeps the authorised network for live hosts. No ports are scanned."""

    source = "discovery_sweep"

    def __init__(self, db: Database, guard: ScopeGuard, sensor_id: str, auditor=None):
        self.db = db
        self.guard = guard
        self.sensor_id = sensor_id
        self.auditor = auditor
        self.cfg = guard.config.scan

    def available(self) -> bool:
        return shutil.which(self.cfg.nmap_path) is not None

    def _build_command(self, target: str) -> list[str]:
        return [
            self.cfg.nmap_path,
            "-oX", "-",              # XML to stdout; never parse the human output
            "-sn",                   # host discovery ONLY -- no port scan
            f"-T{self.cfg.timing}",  # the project's politeness setting, shared
            "-n",                    # no reverse DNS: it is slow and leaks queries
            target,
        ]

    def run_once(self) -> int:
        """Sweep the configured CIDR. Returns the number of in-scope devices."""
        target = self.guard.config.network.cidr
        if not self.available():
            log.warning("nmap not found at %r -- discovery sweep skipped", self.cfg.nmap_path)
            return 0

        started = time.time()
        cmd = self._build_command(target)
        log.info("discovery sweep: %s (host discovery only, no ports)", target)

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=900, check=False
            )
        except (subprocess.SubprocessError, OSError) as exc:
            self.db.log_scan(
                self.source, target, duration_s=time.time() - started, error=str(exc)
            )
            log.exception("discovery sweep failed to run")
            return 0

        seen, refused, macless = self._ingest(proc.stdout)
        elapsed = time.time() - started

        # A sweep that found hosts but no MACs has not partially worked -- it has
        # run in a mode that cannot do the job, and saying "0 devices" would read
        # as an empty network. Report the degradation as the result, the same way
        # an unmeasured host control reports `unknown` rather than `ok`.
        degraded = macless > 1 and seen == 0
        if degraded:
            note = (
                f"DEGRADED: {macless} hosts responded but none returned a MAC "
                "address -- nmap has no raw socket access and fell back to "
                "TCP-connect discovery, which cannot see layer 2. Device "
                "identity requires a MAC, so nothing was recorded."
            )
            log.error("discovery sweep %s", note)
            log.error(
                "  Fix: install or repair Npcap with non-administrator access, "
                "or run the collector elevated. Until then device discovery is "
                "limited to the OS ARP cache."
            )
            self.db.log_scan(self.source, target, duration_s=elapsed, error=note)
            return 0

        self.db.log_scan(
            self.source,
            target,
            duration_s=elapsed,
            result=f"{seen} devices"
            + (f" ({refused} out of scope, refused)" if refused else "")
            + (f" ({macless} without a MAC, skipped)" if macless else ""),
        )
        log.info("discovery sweep: %d in-scope devices in %.0fs", seen, elapsed)
        return seen

    def _ingest(self, xml_text: str) -> tuple[int, int, int]:
        """Record live hosts. Returns (recorded, out-of-scope, seen-without-a-MAC)."""
        if not xml_text.strip():
            return 0, 0, 0
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            log.warning("discovery sweep produced unparseable XML")
            return 0, 0, 0

        seen = 0
        refused = 0
        macless = 0
        for host in root.iter("host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue

            ip = None
            mac = None
            vendor = None
            for addr in host.iter("address"):
                kind = addr.get("addrtype")
                if kind == "ipv4":
                    ip = addr.get("addr")
                elif kind == "mac":
                    mac = addr.get("addr")
                    vendor = addr.get("vendor")

            if not ip:
                continue

            try:
                self.guard.assert_target_allowed(ip)
            except ScopeViolation:
                # An address outside the authorised range came back from a sweep
                # of that range. Worth counting rather than silently dropping --
                # it means either the config or the reply is wrong.
                refused += 1
                continue

            # No MAC. Two very different causes, and the difference decides
            # whether this sweep is trustworthy:
            #
            #   * this machine itself -- nmap reports the local host up without
            #     an ARP exchange, and there is nothing to record;
            #   * raw socket access is unavailable, so nmap fell back to
            #     unprivileged TCP-connect discovery for EVERY host. That mode
            #     cannot see layer 2 at all, so no host returns a MAC.
            #
            # The second case is the dangerous one. Device identity in this
            # project is the MAC; an IP alone cannot be tracked across a DHCP
            # lease. Recording IP-only devices would quietly build an inventory
            # that fragments every time the router reassigns an address, and it
            # would look like a working inventory while doing it. So they are
            # counted, not stored, and `run_once` reports the count.
            if not mac:
                macless += 1
                continue

            # `vendor` is nmap's own OUI lookup. It is deliberately passed as
            # detail rather than used as the device vendor: `pnma.oui` is the
            # single source of truth for that, and two lookups disagreeing on
            # the dashboard would be worse than one being occasionally coarse.
            device_id = observe(
                self.db,
                mac=mac,
                ip=ip,
                source=self.source,
                sensor_id=self.sensor_id,
                detail={"nmap_vendor": vendor} if vendor else None,
            )
            if device_id:
                seen += 1

        return seen, refused, macless
