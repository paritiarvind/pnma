"""The collector orchestrator -- where the safety controls become real.

This module exists because a control that is written but never called is
documentation, not a control. The scope guard, the noise budget, the auditor
and the retention policy are all defined elsewhere; this is the only place that
actually invokes them, and it does so on every packet-emitting path.

Structure:

* **One privileged process** (this one) holds capture rights and does all
  probing.
* **One unprivileged process** (:mod:`pnma.api`) serves the dashboard.

They share only the SQLite file. That split is deliberate: merging them would
mean the web surface inherits raw-capture privilege, so a bug in request
handling becomes a bug with SYSTEM behind it. Splitting later is painful;
starting split costs nothing.

**Privilege modes.** PNMA runs in either of two modes, and says which one it is
in rather than silently degrading:

``full``
    Elevated. Passive ARP/DHCP capture is active, so device identity survives
    MAC randomisation and ARP spoofing is detected from the frames themselves.

``unprivileged``
    No elevation required and none requested. Everything works except passive
    capture: discovery falls back to the OS ARP cache, device identity relies on
    burned-in MACs, and randomised-MAC devices are reported with low confidence
    rather than guessed at. This is a genuinely supported mode, not a broken
    one -- but the dashboard states the reduced coverage plainly, because a
    monitoring tool that hides its blind spots is worse than no tool.
"""

from __future__ import annotations

import logging
import platform
import random
import signal
import socket
import threading
import time
import uuid

from .audit import Auditor, NoiseBudget
from .collectors.arp_table import ArpTableCollector
from .collectors.discovery import DiscoveryCollector
from .collectors.host_windows import (
    HostCollectorUnavailable,
    HostPostureCollector,
)
from .collectors.passive import PassiveCollector, ScapyUnavailable, capture_available
from .collectors.ping import PingCollector
from .collectors.portscan import PortScanCollector
from .config import Config
from .db import Database
from .detections.base import DetectionEngine
from .detections.rules import default_rules
from .guard import ScopeGuard

log = logging.getLogger(__name__)

VERSION = "0.1.0"

# The guard is re-checked on this interval, not just at startup. Laptops
# suspend at home and resume somewhere else; a startup-only check would happily
# keep scanning after the network underneath it changed.
GUARD_RECHECK_S = 300
PRUNE_INTERVAL_S = 86400


class Scheduler:
    """Fixed-interval task runner with jitter.

    Jitter matters more than it looks. Without it, every collector started at
    the same moment fires on the same tick forever, and after a suspend/resume
    all overdue timers fire simultaneously -- a thundering herd of probes at the
    exact moment the network state is least certain.
    """

    def __init__(self):
        self._tasks: list[dict] = []

    def every(self, interval_s: int, fn, name: str, jitter: float = 0.1) -> None:
        self._tasks.append(
            {
                "interval": interval_s,
                "fn": fn,
                "name": name,
                "jitter": jitter,
                # Stagger first runs so startup is not a burst either.
                "next": time.monotonic() + random.uniform(0, min(interval_s, 10)),
            }
        )

    def run_due(self) -> None:
        now = time.monotonic()
        for task in self._tasks:
            if now < task["next"]:
                continue
            try:
                task["fn"]()
            except Exception:  # noqa: BLE001 - one bad task must not stop the loop
                log.exception("scheduled task %s failed", task["name"])
            spread = task["interval"] * task["jitter"]
            task["next"] = now + task["interval"] + random.uniform(-spread, spread)


class Collector:
    """The privileged half of PNMA."""

    def __init__(self, config: Config):
        self.config = config
        self.db = Database(config.database)
        self.guard = ScopeGuard(config)
        self.auditor = Auditor(
            self.db,
            self.guard,
            NoiseBudget(capacity=120, refill_per_minute=60),
        )
        self.sensor_id = self._stable_sensor_id()
        self.mode = "unknown"
        self.capture_status = "not started"
        self._stop = threading.Event()
        self._scheduler = Scheduler()
        self.started_at = time.time()

        # Persist network identity so detection rules can read it without
        # holding a reference to the config object.
        self.db.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('gateway_ip', ?)",
            (config.network.gateway_ip,),
        )
        self.db.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('gateway_mac', ?)",
            (config.network.gateway_mac,),
        )
        self.db.register_sensor(
            self.sensor_id, "network", hostname=socket.gethostname(), version=VERSION
        )

        self.arp = ArpTableCollector(self.db, self.guard, self.sensor_id)
        self.ping = PingCollector(
            self.db, self.guard, self.sensor_id, auditor=self.auditor
        )
        # Active discovery. The ARP-cache collector above stays -- it is free
        # and catches devices between sweeps -- but it cannot be the only source
        # of inventory on a host whose ARP entries expire in seconds.
        self.discovery = DiscoveryCollector(
            self.db, self.guard, self.sensor_id, auditor=self.auditor
        )
        self.portscan = PortScanCollector(
            self.db, self.guard, self.sensor_id, auditor=self.auditor
        )
        self.passive: PassiveCollector | None = None

        # Host posture: the machine this agent runs on, as opposed to the
        # devices it watches. Platform-gated at construction so an unsupported
        # OS is reported once here rather than raising on every interval.
        #
        # It reads local configuration and sends nothing, so the scope guard
        # has no opinion on it. Note though that `run()` returns before
        # scheduling anything when the guard denies the network, so moving to
        # an unrecognised network stops host collection too. That is a
        # defensible reading of a safety gate rather than an oversight, but it
        # is a choice: the alternative is a daemon that keeps reading its own
        # host while refusing to touch the network.
        self.host: HostPostureCollector | None = None
        if not config.collector.host_posture:
            self.host_status = "disabled in config (collector.host_posture = false)"
        else:
            ok, reason = HostPostureCollector.available()
            if ok:
                self.host = HostPostureCollector(
                    self.db, self.sensor_id, auditor=self.auditor
                )
                self.host_status = "enabled"
            else:
                self.host_status = reason

        # `default_rules()` includes the three host posture rules. They are
        # inert until something populates `host_facts`, so a non-Windows host
        # runs them harmlessly rather than needing a second rule set.
        self.engine = DetectionEngine(
            self.db, default_rules(), learning_window_h=1
        )

    @staticmethod
    def _stable_sensor_id() -> str:
        """A per-host id that survives restarts but identifies nothing publicly."""
        return "net-" + uuid.uuid5(
            uuid.NAMESPACE_DNS, socket.gethostname()
        ).hex[:12]

    # -- privilege / capability ---------------------------------------------

    def _init_capture(self) -> None:
        """Start passive capture, or explain clearly why we are not.

        Unprivileged operation is a supported mode. What is not acceptable is
        claiming coverage we do not have, so the reason is recorded and shown.
        """
        if not self.config.collector.passive_capture:
            self.mode = "unprivileged"
            self.capture_status = (
                "disabled in config (collector.passive_capture = false)"
            )
            log.info("running in UNPRIVILEGED mode by configuration")
            self._log_degradation()
            return

        ok, reason = capture_available(self.config.collector.interface)
        if not ok:
            self.mode = "unprivileged"
            self.capture_status = reason
            log.warning("passive capture unavailable: %s", reason)
            log.warning("falling back to UNPRIVILEGED mode")
            self._log_degradation()
            return

        try:
            self.passive = PassiveCollector(
                self.db,
                self.guard,
                self.sensor_id,
                interface=self.config.collector.interface,
                auditor=self.auditor,
            )
            self.passive.start()
            self.mode = "full"
            self.capture_status = "active (ARP + DHCP headers only)"
            log.info("running in FULL mode -- passive capture active")
        except ScapyUnavailable as exc:
            self.mode = "unprivileged"
            self.capture_status = str(exc)
            log.warning("passive capture failed to start: %s", exc)
            self._log_degradation()

    @staticmethod
    def _log_degradation() -> None:
        log.warning(
            "UNPRIVILEGED MODE -- reduced coverage:\n"
            "  * Device discovery uses the OS ARP cache only, so devices this\n"
            "    host has not exchanged traffic with may not be seen.\n"
            "  * No DHCP fingerprinting, so devices using randomised MACs\n"
            "    cannot be tracked across address rotation. They are reported\n"
            "    at low confidence rather than guessed at.\n"
            "  * ARP spoofing is detected from cache state rather than from the\n"
            "    forged replies themselves -- slower, and it misses attacks\n"
            "    that do not alter this host's cache.\n"
            "  Everything else -- inventory, port scanning, service drift, C2\n"
            "  indicators, availability and SLOs -- works normally."
        )

    def capabilities(self) -> dict:
        """What this instance can and cannot currently see."""
        full = self.mode == "full"
        return {
            "mode": self.mode,
            "capture_status": self.capture_status,
            "elevated": full,
            "features": {
                "device_inventory": True,
                "active_discovery": bool(
                    self.config.collector.discovery_sweep and self.discovery.available()
                ),
                "port_scanning": self.portscan.available(),
                "service_drift": self.portscan.available(),
                "c2_port_indicators": self.portscan.available(),
                "availability_slo": True,
                "passive_arp_capture": full,
                "dhcp_fingerprinting": full,
                "mac_randomisation_tracking": full,
                "arp_spoof_frame_detection": full,
                "host_posture": self.host is not None,
            },
            "host_posture_status": self.host_status,
            "blind_spots": [
                "Per-device traffic volume and destinations. A host on a "
                "switched network does not receive other devices' traffic; "
                "this needs a local DNS resolver, router NetFlow, or inline "
                "placement.",
                "Outbound C2 beaconing and data exfiltration, for the same "
                "reason. PNMA sees what a device LISTENS on, not what it sends.",
                "UDP services -- only TCP ports are scanned.",
            ]
            + (
                []
                if self.host is not None
                else [
                    f"This host's own security posture: {self.host_status}. "
                    "The agent is reporting on other devices from a machine it "
                    "has not examined."
                ]
            )
            + (
                []
                if full
                else [
                    "Devices this host never exchanges traffic with.",
                    "Devices using randomised MACs cannot be correlated across "
                    "address rotation without DHCP fingerprinting.",
                ]
            ),
        }

    # -- detection + escalation ---------------------------------------------

    def _run_detections(self) -> None:
        findings = self.engine.run_all()
        for finding in findings:
            # The escalation playbook: a device that looks suspicious gets a
            # targeted service inventory, so the next alert has evidence behind
            # it rather than just a name.
            if finding.triggers_triage_scan and finding.device_id:
                if self.config.scan.enabled and self.portscan.available():
                    self.portscan.triage_scan(finding.device_id)

    def _collect_host(self) -> None:
        """Read this machine's posture into `host_facts`, and record that we did.

        The `log_scan` calls are the point of this wrapper. Host collection
        sends no packets, but `pnma audit` answers "what did the agent do",
        not "what did it transmit" -- and seven PowerShell processes appearing
        on a half-hourly schedule is something an operator is entitled to find
        in the agent's own record rather than in Task Manager.
        """
        # The scheduler has no unregister, so a task that disables itself below
        # is still called every interval. Without this guard the next tick would
        # raise AttributeError on `None.collect()` and be caught by the generic
        # handler -- a traceback and a scan_runs error row every half hour,
        # forever, reporting the wrong cause.
        if self.host is None:
            return

        started = time.time()
        try:
            summary = self.host.collect()
        except HostCollectorUnavailable as exc:
            # The platform gate tripped after construction. Stop scheduling it
            # rather than logging the same refusal every half hour.
            self.host_status = str(exc)
            self.host = None
            log.warning("host posture collection stopped: %s", exc)
            self.db.log_scan("host_posture", "localhost", error=str(exc))
            return
        except Exception as exc:  # noqa: BLE001 - a failed read must not stop the loop
            log.exception("host posture collection failed")
            self.db.log_scan(
                "host_posture", "localhost",
                duration_s=time.time() - started,
                error=f"{type(exc).__name__}: {exc}",
            )
            return

        self.db.log_scan(
            "host_posture", "localhost",
            duration_s=time.time() - started,
            result=(
                f"{summary['total']} facts: {summary['ok']} ok, "
                f"{summary['finding']} finding, {summary['unknown']} unknown "
                f"(elevated={summary['elevated']})"
            ),
        )

    def _recheck_guard(self) -> None:
        previous = self.guard.last_verdict
        verdict = self.guard.check_network()
        if previous and previous.allowed and not verdict.allowed:
            log.error(
                "NETWORK CHANGED -- scope guard now DENIES activity: %s",
                verdict.reason,
            )
            self.db.raise_alert(
                dedup_key=f"scope_change:{int(time.time() // 3600)}",
                rule_id="scope_guard",
                severity="high",
                title="Agent moved to an unrecognised network -- scanning halted",
                description=(
                    f"{verdict.reason}\n\n"
                    "All active probing has stopped. Passive observation "
                    "continues, but nothing is transmitted.\n\n"
                    "This is the guard working as designed: it prevents the "
                    "agent from scanning a network it has no authorisation for."
                ),
                evidence={
                    "observed_gateway_ip": verdict.observed_gateway_ip,
                    "observed_gateway_mac": verdict.observed_gateway_mac,
                    "expected_gateway_mac": verdict.expected_gateway_mac,
                },
            )

    def _prune(self) -> None:
        deleted = self.db.prune(self.config.retention_days)
        if any(deleted.values()):
            log.info("retention: pruned %s", deleted)

    # -- lifecycle ----------------------------------------------------------

    def run(self) -> int:
        log.info("PNMA collector %s starting on %s", VERSION, platform.system())

        # Authorisation first, before anything is allowed to transmit.
        verdict = self.guard.check_network()
        if not verdict.allowed:
            log.error("REFUSING TO START: %s", verdict.reason)
            log.error(
                "PNMA will not probe a network it is not configured for. "
                "If you have changed router or network, update "
                "config/pnma.toml (see: pnma init)."
            )
            return 2
        log.info("scope guard: %s", verdict.reason)

        self._init_capture()

        cc = self.config.collector
        self._scheduler.every(cc.arp_table_interval_s, self.arp.run_once, "arp_table")
        if cc.discovery_sweep and self.discovery.available():
            self._scheduler.every(
                cc.discovery_interval_s, self.discovery.run_once, "discovery"
            )
        elif cc.discovery_sweep:
            log.warning(
                "discovery sweep enabled but nmap was not found -- device "
                "discovery falls back to the OS ARP cache, which on Windows "
                "expires entries in seconds and will under-report."
            )
        self._scheduler.every(cc.ping_interval_s, self.ping.run_once, "ping")
        if self.host is not None:
            # Scheduled before detections are registered so the first host
            # collection lands before the first rule pass looks for its facts.
            self._scheduler.every(
                cc.host_posture_interval_s, self._collect_host, "host_posture"
            )
        else:
            log.info("host posture not scheduled: %s", self.host_status)
        self._scheduler.every(cc.detection_interval_s, self._run_detections, "detect")
        self._scheduler.every(GUARD_RECHECK_S, self._recheck_guard, "guard_recheck")
        self._scheduler.every(PRUNE_INTERVAL_S, self._prune, "prune")
        if self.config.scan.enabled:
            self._scheduler.every(
                cc.port_scan_interval_s, self.portscan.run_once, "port_scan"
            )

        self._install_signal_handlers()
        log.info(
            "collector running in %s mode -- press Ctrl-C to stop", self.mode.upper()
        )

        while not self._stop.is_set():
            self._scheduler.run_due()
            self._stop.wait(1.0)

        self.shutdown()
        return 0

    def _install_signal_handlers(self) -> None:
        def handler(_signum, _frame):
            log.info("shutdown requested")
            self._stop.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass  # not always available off the main thread

    def shutdown(self) -> None:
        if self.passive:
            self.passive.stop()
        self.db.close()
        log.info("collector stopped")

    def status(self) -> dict:
        return {
            "version": VERSION,
            "sensor_id": self.sensor_id,
            "uptime_s": round(time.time() - self.started_at, 1),
            "mode": self.mode,
            "capabilities": self.capabilities(),
            "guard": {
                "allowed": bool(
                    self.guard.last_verdict and self.guard.last_verdict.allowed
                ),
                "reason": (
                    self.guard.last_verdict.reason
                    if self.guard.last_verdict
                    else "not checked"
                ),
            },
            "passive": self.passive.stats() if self.passive else None,
            "noise_budget": self.auditor.budget.snapshot(),
        }
