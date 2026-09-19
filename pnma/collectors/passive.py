"""Passive ARP + DHCP capture.

The only privileged component in PNMA, and the reason the process split in
:mod:`pnma.daemon` exists: this needs raw capture rights, so nothing else does.

**What it captures, exactly.** A BPF filter pinned to ARP frames and DHCP
(UDP 67/68). Nothing else reaches userspace. No payloads, no DNS, no HTTP, no
record of anything anyone in the house browses. The filter is applied in the
kernel, so this is a genuine technical constraint rather than a promise to
discard data after the fact -- which matters, because other people live on this
network and did not ask to be monitored.

**Why it is worth the elevation.** Two things become possible that are simply
not available from the ARP cache:

1. *DHCP option 55 fingerprinting.* The parameter request list a client sends
   is stable per OS build and survives MAC randomisation. Without it, device
   identity collapses every time a phone rotates its MAC and the new-device
   detector becomes noise. See :mod:`pnma.fingerprint`.
2. *Real ARP spoofing detection.* The ARP cache shows you the current state --
   the end result. Capture shows you the gratuitous replies that produced it,
   which is the actual attack signal.

Observations from here are marked ``agent_generated=False``: this is traffic
that happened whether or not PNMA was running, which is what makes it
trustworthy input to the detectors.
"""

from __future__ import annotations

import logging
import threading
import time

from ..db import Database
from ..guard import ScopeGuard, ScopeViolation
from ..inventory import observe

log = logging.getLogger(__name__)

# Kernel-level filter. ARP frames, and DHCP on its two well-known ports.
# Deliberately narrow: anything not matching this is never copied to us.
BPF_FILTER = "arp or (udp and (port 67 or port 68))"

# DHCP options we read. Everything else is ignored.
OPT_HOSTNAME = "hostname"          # option 12
OPT_PARAM_REQ = "param_req_list"   # option 55
OPT_VENDOR_CLASS = "vendor_class_id"  # option 60


class ScapyUnavailable(RuntimeError):
    """scapy or the platform capture driver is not usable."""


def is_elevated() -> bool:
    """Whether this process has the privilege raw capture requires."""
    import os
    import platform

    if platform.system() == "Windows":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # noqa: BLE001
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def capture_available(interface: str = "") -> tuple[bool, str]:
    """Check whether passive capture can run, without starting it.

    Checking elevation here rather than discovering it inside the sniff loop is
    the difference between one clear startup message and an endless retry loop
    filling the log with the same permission error.
    """
    try:
        import scapy.all  # noqa: F401
    except ImportError:
        return False, (
            "scapy is not installed. Run: pip install scapy  "
            "(and install Npcap on Windows, or libpcap on Linux/macOS)"
        )
    try:
        from scapy.arch import get_if_list

        if not get_if_list():
            return False, "no capture interfaces visible -- is Npcap/libpcap installed?"
    except Exception as exc:  # noqa: BLE001
        return False, f"capture layer unavailable: {exc}"

    # Elevation is a *proxy* for "can this process open a capture handle", and
    # on Windows the proxy is wrong whenever Npcap was installed with
    # AdminOnly=0: any local user may capture, and an elevation check would
    # refuse a capability the driver grants. Measured 2026-09-19 -- an
    # unelevated sniff returned 22 ARP frames while this function said no.
    # So ask the driver. A failed open is reported with the driver's own
    # words, and elevation is offered as the fix only when it is one.
    ok, why = _probe_capture(interface)
    if ok:
        return True, "available"
    if not is_elevated():
        return False, (
            f"passive capture cannot open the interface ({why}). Run the "
            "collector as Administrator (Windows) or with sudo (Linux/macOS), "
            "or set collector.passive_capture = false to run unprivileged "
            "with weaker device identity resolution."
        )
    return False, f"passive capture cannot open the interface even elevated: {why}"


def _probe_capture(interface: str = "") -> tuple[bool, str]:
    """Open a capture handle and close it again, without reading anything.

    ``store=False`` and ``count=1`` with a short timeout: the probe returns on
    the first frame or after ``timeout`` seconds, whichever is first, and keeps
    nothing. The BPF filter is the production one, so a driver that accepts
    the open but rejects the filter is caught here rather than in the loop.
    """
    try:
        from scapy.all import sniff

        kwargs = {"filter": BPF_FILTER, "store": False, "count": 1, "timeout": 1}
        if interface:
            kwargs["iface"] = interface
        sniff(**kwargs)
        return True, "ok"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc).strip() or exc.__class__.__name__


class PassiveCollector:
    """Sniffs ARP and DHCP in a background thread."""

    # Per-MAC write throttle. An ARP storm -- which is exactly what the
    # spoofing attack we detect looks like -- would otherwise become a
    # synchronous disk-write storm, three rows per frame. The detector's own
    # trigger condition must not be its amplifier.
    MAX_WRITES_PER_MAC_PER_MIN = 20

    def __init__(
        self,
        db: Database,
        guard: ScopeGuard,
        sensor_id: str,
        interface: str = "",
        auditor=None,  # pnma.audit.Auditor -- for probe-window correlation
    ):
        self.db = db
        self.guard = guard
        self.sensor_id = sensor_id
        self.interface = interface or None
        self.auditor = auditor
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.packets_seen = 0
        self.arp_replies_seen = 0
        self.dhcp_seen = 0
        self.self_attributed = 0
        self.throttled = 0
        self.started_at: float | None = None
        # mac -> (window_start, writes_in_window)
        self._write_counts: dict[str, tuple[float, int]] = {}
        self._flood_alerted: set[str] = set()

    def _may_write(self, mac: str) -> bool:
        """Token-per-minute throttle on database writes for one MAC."""
        now = time.time()
        start, count = self._write_counts.get(mac, (now, 0))
        if now - start >= 60:
            self._write_counts[mac] = (now, 1)
            self._flood_alerted.discard(mac)
            return True
        if count >= self.MAX_WRITES_PER_MAC_PER_MIN:
            self.throttled += 1
            if mac not in self._flood_alerted:
                self._flood_alerted.add(mac)
                # One alert for the flood, rather than a row per frame.
                self.db.raise_alert(
                    dedup_key=f"arp_flood:{mac}:{int(now // 300)}",
                    rule_id="arp_flood",
                    severity="high",
                    title=f"Excessive ARP traffic from {mac}",
                    description=(
                        f"{mac} sent more than {self.MAX_WRITES_PER_MAC_PER_MIN} "
                        "ARP replies in a minute. Further frames from this MAC "
                        "are being counted rather than individually recorded.\n\n"
                        "BENIGN EXPLANATION: a misbehaving or chatty device, or "
                        "a network loop.\n\n"
                        "MALICIOUS EXPLANATION: active ARP cache poisoning, "
                        "which floods the segment with forged replies."
                    ),
                    mitre_id="T1557.002",
                    mitre_name="Adversary-in-the-Middle: ARP Cache Poisoning",
                    evidence={"mac": mac, "threshold_per_min": self.MAX_WRITES_PER_MAC_PER_MIN},
                )
            return False
        self._write_counts[mac] = (start, count + 1)
        return True

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        ok, reason = capture_available(self.interface)
        if not ok:
            raise ScapyUnavailable(reason)
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="pnma-passive", daemon=True
        )
        self.started_at = time.time()
        self._thread.start()
        log.info(
            "passive capture started (filter: %s) on %s",
            BPF_FILTER, self.interface or "default interface",
        )

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _run(self) -> None:
        from scapy.all import sniff

        while not self._stop.is_set():
            try:
                sniff(
                    filter=BPF_FILTER,
                    prn=self._handle,
                    store=False,           # never buffer packets in memory
                    iface=self.interface,
                    timeout=30,            # wake periodically to check the stop flag
                )
            except Exception as exc:  # noqa: BLE001
                log.error("capture error (retrying in 10s): %s", exc)
                # Backoff prevents a permanently-broken interface from becoming
                # a hot loop that pins a core.
                self._stop.wait(10)

    # -- packet handling ----------------------------------------------------

    def _handle(self, pkt) -> None:  # noqa: ANN001 - scapy packet
        self.packets_seen += 1
        try:
            from scapy.layers.dhcp import DHCP
            from scapy.layers.l2 import ARP

            if pkt.haslayer(DHCP):
                self._handle_dhcp(pkt)
            elif pkt.haslayer(ARP):
                self._handle_arp(pkt)
        except Exception:  # noqa: BLE001
            log.debug("failed to parse captured frame", exc_info=True)

    def _handle_arp(self, pkt) -> None:  # noqa: ANN001
        from scapy.layers.l2 import ARP

        arp = pkt[ARP]
        # op 2 = reply. Replies carry the binding claim, which is both the
        # useful inventory signal and the spoofing signal.
        if arp.op != 2:
            return
        self.arp_replies_seen += 1

        mac, ip = arp.hwsrc, arp.psrc
        try:
            self.guard.assert_target_allowed(ip)
        except ScopeViolation:
            return

        if not self._may_write(mac):
            return

        # Did we provoke this reply? Our own ping and nmap probes elicit ARP
        # replies, and recording those as unsolicited evidence would feed the
        # spoofing detector its own footsteps. See pnma.audit.ProbeWindow.
        solicited = bool(self.auditor and self.auditor.probe_window.is_probing(ip))
        if solicited:
            self.self_attributed += 1

        observe(
            self.db,
            mac=mac,
            ip=ip,
            source="passive_arp",
            sensor_id=self.sensor_id,
            agent_generated=solicited,
            detail={
                "op": "reply",
                "hwdst": arp.hwdst,
                "pdst": arp.pdst,
                "solicited_by_agent": solicited,
            },
        )

    def _handle_dhcp(self, pkt) -> None:  # noqa: ANN001
        from scapy.layers.dhcp import BOOTP, DHCP

        bootp = pkt[BOOTP]
        opts = self._parse_options(pkt[DHCP].options)

        msg_type = opts.get("message-type")
        # 1 = DISCOVER, 3 = REQUEST. These are the client-originated messages
        # that carry the fingerprint; server replies do not.
        if msg_type not in (1, 3):
            return
        self.dhcp_seen += 1

        mac = self._chaddr_to_mac(bootp.chaddr)
        if not mac:
            return

        # A DISCOVER has no assigned address yet, so ip may legitimately be None.
        ip = opts.get("requested_addr") or (
            bootp.ciaddr if bootp.ciaddr != "0.0.0.0" else None
        )
        if ip:
            try:
                self.guard.assert_target_allowed(ip)
            except ScopeViolation:
                ip = None

        param_list = opts.get(OPT_PARAM_REQ)
        if isinstance(param_list, (bytes, bytearray)):
            param_list = list(param_list)
        elif isinstance(param_list, int):
            param_list = [param_list]

        observe(
            self.db,
            mac=mac,
            ip=ip,
            source="passive_dhcp",
            sensor_id=self.sensor_id,
            hostname=self._as_text(opts.get(OPT_HOSTNAME)),
            param_request_list=param_list,
            vendor_class=self._as_text(opts.get(OPT_VENDOR_CLASS)),
            detail={"dhcp_message_type": msg_type},
        )

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _parse_options(options) -> dict:  # noqa: ANN001
        parsed: dict = {}
        for opt in options:
            if isinstance(opt, tuple) and len(opt) >= 2:
                parsed[opt[0]] = opt[1] if len(opt) == 2 else list(opt[1:])
            elif opt in ("end", "pad"):
                break
        return parsed

    @staticmethod
    def _as_text(value) -> str | None:  # noqa: ANN001
        if value is None:
            return None
        if isinstance(value, (bytes, bytearray)):
            return value.decode("utf-8", errors="replace").strip("\x00").strip() or None
        return str(value).strip() or None

    @staticmethod
    def _chaddr_to_mac(chaddr) -> str | None:  # noqa: ANN001
        if not chaddr:
            return None
        raw = bytes(chaddr)[:6]
        if len(raw) < 6:
            return None
        return ":".join(f"{b:02x}" for b in raw)

    def stats(self) -> dict:
        uptime = time.time() - self.started_at if self.started_at else 0
        return {
            "running": self.running,
            "interface": self.interface or "default",
            "filter": BPF_FILTER,
            "uptime_s": round(uptime, 1),
            "packets_seen": self.packets_seen,
            "arp_replies": self.arp_replies_seen,
            "dhcp_messages": self.dhcp_seen,
            "self_attributed": self.self_attributed,
            "throttled_writes": self.throttled,
        }
