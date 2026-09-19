"""Service inventory via nmap, with a deliberately conservative profile.

Two things this module does differently from the nmap invocation in every
tutorial:

**It is polite.** ``-T2``, no ``-sV`` by default, top-100 ports. Aggressive
timing and version probes are well documented to crash embedded devices, reboot
smart plugs, and make network printers emit pages of garbage. This is your
house, not a CTF box, and the printer does not consent to ``-T4 -A``.

**Every target is re-authorised.** The target list comes from discovery, and
discovery output is untrusted -- an ARP reply can claim any address. The guard
re-checks each address immediately before the scan, so a hostile reply cannot
steer a scan off-network.

Port risk classification is where the "is this device doing something it
shouldn't" question gets answered. We cannot see a device's outbound traffic
from a switched network (see THREAT_MODEL.md, "Visibility limits"), but we can
see what it is *listening* on, and a host offering 4444/tcp or an open ADB
port is telling you something important.
"""

from __future__ import annotations

import concurrent.futures
import logging
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET

from ..db import Database
from ..guard import ScopeGuard, ScopeViolation
from ..inventory import reclassify
from ..oui import is_iot_vendor
from .ping import ping_host

log = logging.getLogger(__name__)


# Ports that mean something on a home network, and why. The `note` is what gets
# surfaced in the alert -- a severity with no reasoning attached is just a
# colour, and the operator still has to go and look it up.
PORT_RISK: dict[int, tuple[str, str]] = {
    23:    ("high",   "Telnet: credentials cross the network in cleartext. On IoT gear this is usually an unchanged factory default and a favourite of Mirai-class worms."),
    2323:  ("high",   "Alternate Telnet: almost exclusively seen on compromised or badly-shipped IoT devices."),
    21:    ("medium", "FTP: cleartext credentials. Check whether anonymous login is enabled."),
    445:   ("high",   "SMB exposed on the LAN. The vector for EternalBlue and most ransomware lateral movement."),
    139:   ("medium", "NetBIOS session service: legacy Windows file sharing, rarely needed today."),
    3389:  ("high",   "RDP exposed. Brute-force magnet; catastrophic if this device is also port-forwarded."),
    5900:  ("high",   "VNC: frequently deployed with no password at all."),
    5555:  ("high",   "Android Debug Bridge exposed over the network. Grants full shell access with no authentication. Actively worm-scanned."),
    4444:  ("high",   "Metasploit/meterpreter default listener. On a home network there is no legitimate reason for this."),
    1337:  ("high",   "Conventional backdoor port. Treat as compromise until proven otherwise."),
    31337: ("high",   "Back Orifice heritage backdoor port."),
    6667:  ("medium", "IRC: the classic botnet command-and-control channel. Unusual on a home LAN in 2026."),
    1080:  ("medium", "SOCKS proxy: can indicate a device being used to relay someone else's traffic."),
    3128:  ("medium", "Squid proxy: as above, check whether this is deliberate."),
    9001:  ("medium", "Tor ORPort. Legitimate if you run a relay on purpose; notable if you do not."),
    22:    ("low",    "SSH. Fine if intentional -- confirm it uses keys rather than a password."),
    80:    ("low",    "Unencrypted HTTP admin interface. Common on routers, cameras and printers; check for default credentials."),
    8080:  ("low",    "Alternate HTTP admin interface."),
    161:   ("low",    "SNMP. Check it is not still answering to the 'public' community string."),
    1900:  ("low",    "UPnP/SSDP. Can allow devices to open firewall holes without asking you."),
}

# A listening service on these ports is strong enough to warrant escalation on
# its own -- the escalation playbook raises severity and triggers a re-scan.
C2_INDICATOR_PORTS = {4444, 1337, 31337, 5555, 6667, 2323}


def classify_port(port: int) -> tuple[str | None, str]:
    """Return (risk, explanation) for a port number."""
    if port in PORT_RISK:
        return PORT_RISK[port]
    return None, ""


class PortScanCollector:
    source = "nmap"

    def __init__(self, db: Database, guard: ScopeGuard, sensor_id: str, auditor=None):
        self.db = db
        self.guard = guard
        self.sensor_id = sensor_id
        self.auditor = auditor
        self.cfg = guard.config.scan

    def available(self) -> bool:
        return shutil.which(self.cfg.nmap_path) is not None

    def _build_command(self, targets: list[str], *, deep: bool = False) -> list[str]:
        cmd = [
            self.cfg.nmap_path,
            "-oX", "-",              # XML to stdout; do not parse human output
            f"-T{self.cfg.timing}",
            "--top-ports", str(self.cfg.top_ports),
            "-Pn",                   # discovery already told us these are up
            "--host-timeout", "90s",
        ]
        if self.cfg.service_detection or deep:
            # Version intensity capped low: full -sV throws a lot of malformed
            # payloads at services, which is exactly what breaks IoT devices.
            cmd += ["-sV", "--version-intensity", "2"]
        cmd += targets
        return cmd

    # Hosts per nmap invocation. Batching bounds the blast radius of a subprocess
    # timeout: without it, one slow host past the 600s wall clock discards the
    # results for every other host in the run, and the whole scan repeats next
    # cycle having produced nothing but traffic.
    BATCH_SIZE = 16

    def scan(self, targets: list[str], *, deep: bool = False) -> int:
        """Scan a list of addresses. Returns the number of open ports recorded."""
        if not self.available():
            log.warning("nmap not found at %r -- skipping port scan", self.cfg.nmap_path)
            return 0

        allowed = self.guard.filter_targets(targets)
        if not allowed:
            return 0

        total = 0
        for i in range(0, len(allowed), self.BATCH_SIZE):
            batch = allowed[i : i + self.BATCH_SIZE]
            total += self._scan_batch(batch, deep=deep)
        return total

    # ---------------------------------------------------------------- liveness
    #
    # Every batch is bracketed by an ICMP sample of its own targets, taken
    # immediately before the scan starts and immediately after it finishes.
    #
    # Why this exists. On 2026-08-24 the first live port scan was followed by a
    # printer that answered nothing -- no ICMP, no 80/tcp, no 9100/tcp -- while
    # still replying to ARP. Had the scan knocked it over, or had it simply gone
    # to sleep? Unanswerable, because the last availability sample predated the
    # scan by thirty minutes. A monitoring agent that cannot say whether its own
    # probing caused an outage is not in a position to report on anyone else's
    # network, so the gap is closed here rather than argued about later.
    #
    # ICMP silence is not proof a device is down: plenty of hosts ignore echo
    # requests while answering ARP perfectly well, and the printer in that
    # incident did exactly that. What the bracket establishes is a *change*
    # across the scan, which is the part attribution actually needs -- a host
    # that was ICMP-silent before the scan cannot have been silenced by it.
    LIVENESS_WORKERS = 8
    LIVENESS_TIMEOUT_S = 2

    def _sample_liveness(self, batch: list[str]) -> dict[str, tuple[bool, float | None]]:
        """One echo request per target, in parallel. Never raises."""
        results: dict[str, tuple[bool, float | None]] = {}
        workers = max(1, min(self.LIVENESS_WORKERS, len(batch)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(ping_host, ip, self.LIVENESS_TIMEOUT_S): ip for ip in batch
            }
            for fut in concurrent.futures.as_completed(futures):
                ip = futures[fut]
                try:
                    results[ip] = fut.result()
                except Exception:  # noqa: BLE001 - a probe must not abort the scan
                    log.exception("liveness probe failed for %s", ip)
                    results[ip] = (False, None)
        return results

    def _write_availability(
        self, ip: str, reachable: bool, rtt_ms: float | None, ts: float
    ) -> None:
        row = self.db.query_one(
            "SELECT device_id FROM devices WHERE ip = ? ORDER BY last_seen DESC LIMIT 1",
            (ip,),
        )
        if row is None:
            # An address with no device row cannot be charted, and inventing an
            # identity for it here would key availability on IP -- the exact
            # fragmentation DiscoveryCollector refuses to introduce.
            return
        self.db.execute(
            "INSERT INTO availability(ts, device_id, reachable, rtt_ms) VALUES(?,?,?,?)",
            (ts, row["device_id"], int(reachable), rtt_ms),
        )

    def _record_liveness(
        self,
        before: dict[str, tuple[bool, float | None]],
        after: dict[str, tuple[bool, float | None]],
        *,
        before_ts: float,
        after_ts: float,
    ) -> list[str]:
        """Persist both samples. Returns targets that answered before, not after.

        Both samples go into `availability` so the existing charts and the
        availability rule see them, which also means the history now contains a
        point immediately adjacent to every scan instead of whatever happened to
        be sampled last.
        """
        for ip, (up, rtt) in before.items():
            self._write_availability(ip, up, rtt, before_ts)

        lost: list[str] = []
        for ip, (up, rtt) in after.items():
            self._write_availability(ip, up, rtt, after_ts)
            was_up = before.get(ip, (False, None))[0]
            if was_up and not up:
                lost.append(ip)
        return sorted(lost)

    @staticmethod
    def _liveness_summary(
        before: dict[str, tuple[bool, float | None]],
        after: dict[str, tuple[bool, float | None]],
        lost: list[str],
    ) -> str:
        up_before = sum(1 for up, _ in before.values() if up)
        up_after = sum(1 for up, _ in after.values() if up)
        summary = (
            f"icmp {up_before}/{len(before)} before, {up_after}/{len(after)} after"
        )
        if lost:
            # Named rather than counted: the whole point is that a specific
            # address can be looked at, and "1 host stopped answering" sends the
            # reader back to the database to find out which.
            summary += "; stopped answering across the scan: " + ", ".join(lost)
        return summary

    @staticmethod
    def _nmap_error(proc) -> str | None:
        """Detect an nmap run that failed while still looking like a result.

        nmap can fail *and* emit well-formed XML. Refused raw socket access is
        the case seen in practice: nmap decides it is privileged, selects a SYN
        scan, cannot open the device, and quits -- emitting a complete document
        with `<scaninfo>`, zero `<host>` elements, and the failure recorded only
        in `<runstats><finished exit="error" errormsg="...">`.

        Parsed naively that is a scan which found nothing, and "no open ports"
        is the most reassuring sentence this tool can write. It would be a clean
        bill of health for a scan that never sent a packet -- the same shape as
        `Get-WinEvent` answering "No events were found" when the real answer was
        an access denial, and as `Get-MpPreference` returning the string "N/A:
        Must be an administrator" instead of erroring. Both of those were found
        the hard way; this is the third, so assume there will be a fourth and
        check for the refusal explicitly rather than trusting an empty result.
        """
        # nmap's own errormsg is preferred over stderr, and checked first even
        # when the exit code already tells us something is wrong. stderr ends
        # with "QUITTING!" -- true, and useless. The XML carries the sentence
        # that says what to fix ("Couldn't open a raw socket or eth handle"),
        # and an error nobody can act on wastes the alert it occupies.
        try:
            root = ET.fromstring(proc.stdout)
        except ET.ParseError:
            # Unparseable output is a different failure from a documented one;
            # _ingest already warns about it. Fall through to the exit code.
            root = None

        if root is not None:
            finished = root.find("runstats/finished")
            if finished is not None and finished.get("exit") == "error":
                return "nmap reported failure: " + (
                    finished.get("errormsg") or "no message given"
                )

        if proc.returncode != 0:
            # Last two non-empty stderr lines: enough to carry the diagnostic
            # that precedes nmap's closing "QUITTING!", without pasting a wall
            # of output into a database column.
            detail = [ln.strip() for ln in (proc.stderr or "").splitlines() if ln.strip()]
            return (
                f"nmap exited {proc.returncode}"
                + (f": {' / '.join(detail[-2:])}" if detail else " with no diagnostic output")
            )
        return None

    def _scan_batch(self, batch: list[str], *, deep: bool) -> int:
        started = time.time()
        cmd = self._build_command(batch, deep=deep)
        # Scale the wall clock to the batch: --host-timeout is 90s, so allow
        # that per host plus headroom for nmap's own startup and reporting.
        timeout = 90 * len(batch) + 120
        log.info("port scan: %d target(s)%s", len(batch), " [deep]" if deep else "")

        before_ts = time.time()
        before = self._sample_liveness(batch)

        proc = None
        error: str | None = None
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, check=False
            )
        except (subprocess.SubprocessError, OSError) as exc:
            error = str(exc)
            log.exception("nmap invocation failed")

        # Sampled on the failure path too. A scan that timed out still sent
        # packets, so it is exactly the run whose effect most needs accounting
        # for -- recording liveness only on success would leave the noisiest
        # case unmeasured.
        after_ts = time.time()
        after = self._sample_liveness(batch)
        lost = self._record_liveness(
            before, after, before_ts=before_ts, after_ts=after_ts
        )
        liveness = self._liveness_summary(before, after, lost)

        if lost:
            log.warning(
                "port scan: %s answered ICMP before the scan and not after -- "
                "attribution is open, see scan_runs", ", ".join(lost),
            )

        # `proc` is None only when the subprocess raised, in which case `error`
        # is already set. Stated as a precondition rather than left implicit in
        # the ordering, because _nmap_error dereferences proc.
        if proc is not None and error is None:
            error = self._nmap_error(proc)

        if error is not None:
            # The liveness summary stays on the row: it is still true, and a
            # failed scan is exactly the run whose effect on the network someone
            # may later need to check. It is recorded beside the error rather
            # than as a result, so the row cannot be read as a completed scan.
            self.db.log_scan(
                "port_scan", ",".join(batch),
                duration_s=time.time() - started,
                result=liveness,
                error=error,
            )
            return 0

        found = self._ingest(proc.stdout)
        self.db.log_scan(
            "port_scan",
            ",".join(batch),
            duration_s=time.time() - started,
            result=f"{found} open ports across {len(batch)} hosts"
            + (" [deep]" if deep else "")
            + f"; {liveness}",
        )
        return found

    def _ingest(self, xml_text: str) -> int:
        if not xml_text.strip():
            return 0
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            log.warning("could not parse nmap XML output")
            return 0

        now = time.time()
        total = 0

        for host in root.iter("host"):
            addr_el = host.find("address[@addrtype='ipv4']")
            if addr_el is None:
                continue
            ip = addr_el.get("addr", "")

            row = self.db.query_one(
                "SELECT device_id FROM devices WHERE ip = ? "
                "ORDER BY last_seen DESC LIMIT 1",
                (ip,),
            )
            if row is None:
                continue
            device_id = row["device_id"]

            open_ports: set[tuple[int, str]] = set()
            for port_el in host.iter("port"):
                state = port_el.find("state")
                if state is None or state.get("state") != "open":
                    continue
                port = int(port_el.get("portid", "0"))
                proto = port_el.get("protocol", "tcp")
                svc_el = port_el.find("service")
                service = svc_el.get("name") if svc_el is not None else None
                product = None
                if svc_el is not None:
                    product = " ".join(
                        p for p in (svc_el.get("product"), svc_el.get("version")) if p
                    ) or None

                risk, _ = classify_port(port)
                open_ports.add((port, proto))
                total += 1

                self.db.execute(
                    """INSERT INTO ports(device_id, port, proto, service, product,
                                         first_seen, last_seen, risk)
                       VALUES(?,?,?,?,?,?,?,?)
                       ON CONFLICT(device_id, port, proto) DO UPDATE SET
                           last_seen = excluded.last_seen,
                           service   = COALESCE(excluded.service, ports.service),
                           product   = COALESCE(excluded.product, ports.product),
                           risk      = excluded.risk,
                           closed_at = NULL""",
                    (device_id, port, proto, service, product, now, now, risk),
                )

            # Mark previously-open ports that have stopped answering. A service
            # disappearing is drift worth keeping, not a row worth deleting.
            for prev in self.db.query(
                "SELECT port, proto FROM ports "
                "WHERE device_id = ? AND closed_at IS NULL",
                (device_id,),
            ):
                if (prev["port"], prev["proto"]) not in open_ports:
                    self.db.execute(
                        "UPDATE ports SET closed_at = ? "
                        "WHERE device_id = ? AND port = ? AND proto = ?",
                        (now, device_id, prev["port"], prev["proto"]),
                    )

            self.db.record_observation(
                source=self.source,
                agent_generated=True,
                sensor_id=self.sensor_id,
                device_id=device_id,
                ip=ip,
                detail={"open_ports": sorted(p for p, _ in open_ports)},
            )

            # Observed services are the strongest classification signal we ever
            # get -- behaviour, rather than what the device claims about itself.
            # Reclassifying here means the profile rules judge this device
            # against the right baseline on the very next detection cycle.
            gw = self.db.query_one("SELECT value FROM meta WHERE key = 'gateway_ip'")
            reclassify(self.db, device_id, gw["value"] if gw else None)

        return total

    def run_once(self) -> int:
        rows = self.db.query(
            "SELECT DISTINCT ip FROM devices "
            "WHERE ip IS NOT NULL AND ip != '' AND last_seen >= ?",
            (time.time() - 86400 * 7,),
        )
        targets = [r["ip"] for r in rows]
        if not targets:
            return 0
        if self.auditor is None:
            return self.scan(targets)
        return self.auditor.active_operation(
            "port_scan", f"{len(targets)} hosts",
            len(targets) * self.cfg.top_ports // 100,  # budget in probe-units
            lambda: self.scan(targets), target_ips=targets,
        ) or 0

    def triage_scan(self, device_id: str) -> int:
        """Targeted re-scan of one device, triggered by the escalation playbook.

        This is the "suspicious device gets scanned" path. It is deliberately a
        separate entry point from the scheduled sweep so that escalation shows
        up in scan_runs as its own kind of event.

        Note the inversion: escalation would normally mean probing harder, but
        the devices most likely to be flagged (IoT gear with a telnet port or an
        exposed ADB) are exactly the devices most likely to fall over under
        version probing. Escalating into a crash is not a detection, it is an
        outage you caused. So IoT vendors get the gentle profile, and the alert
        says why.
        """
        row = self.db.query_one(
            "SELECT ip, mac FROM devices WHERE device_id = ?", (device_id,)
        )
        if row is None or not row["ip"]:
            return 0
        try:
            self.guard.assert_target_allowed(row["ip"])
        except ScopeViolation:
            log.warning("triage scan refused: %s out of scope", row["ip"])
            return 0

        fragile = bool(row["mac"]) and is_iot_vendor(row["mac"])
        if fragile:
            log.info(
                "escalation: triage scan of %s (%s) -- IoT vendor, suppressing "
                "version probes to avoid crashing the device",
                device_id, row["ip"],
            )
        else:
            log.info("escalation: triage scan of %s (%s)", device_id, row["ip"])

        run = lambda: self.scan([row["ip"]], deep=not fragile)  # noqa: E731
        if self.auditor is None:
            return run()
        return self.auditor.active_operation(
            "triage_scan", row["ip"], self.cfg.top_ports // 10,
            run, target_ips=[row["ip"]],
        ) or 0
