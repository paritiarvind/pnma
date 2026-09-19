"""Cross-platform reads of local network state, without elevated privilege.

Everything here is passive in the strict sense: it reads state the OS already
has (the ARP cache, the routing table) and sends nothing. That matters because
it is the layer the scope guard runs on, and the scope guard has to be able to
answer "which network am I on?" *before* the agent is allowed to emit a single
packet.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import subprocess
from dataclasses import dataclass

IS_WINDOWS = platform.system() == "Windows"

# 192.168.0.1  98-03-8e-00-11-22  dynamic      (Windows)
_WIN_ARP_RE = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})\s+(\w+)",
    re.IGNORECASE | re.MULTILINE,
)
# ? (192.168.0.1) at 98:03:8e:00:11:22 [ether] on wlan0   (Linux/macOS)
_UNIX_ARP_RE = re.compile(
    r"\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ArpEntry:
    ip: str
    mac: str
    kind: str = "dynamic"


def _run(cmd: list[str], timeout: int = 10) -> str:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.stdout or ""
    except (subprocess.SubprocessError, OSError):
        return ""


def read_arp_table() -> list[ArpEntry]:
    """Read the OS ARP cache. Sends no packets."""
    out = _run(["arp", "-a"])
    entries: list[ArpEntry] = []
    if IS_WINDOWS:
        for ip, mac, kind in _WIN_ARP_RE.findall(out):
            entries.append(ArpEntry(ip, mac.lower().replace("-", ":"), kind.lower()))
    else:
        for ip, mac in _UNIX_ARP_RE.findall(out):
            entries.append(ArpEntry(ip, mac.lower()))
    return entries


def default_gateway() -> str | None:
    """Return the gateway of the *lowest-metric* default route.

    Reading adapter output in enumeration order is wrong and dangerously so.
    Enumeration order is not routing-metric order, so on a multi-homed host --
    home Wi-Fi up alongside a phone tether, a VPN, or a docking Ethernet port --
    it can report the home gateway while traffic actually egresses somewhere
    else. The guard would then confirm "this is your network" while probes
    leaked onto a foreign one. The routing table is the only authority on which
    interface traffic will actually take.
    """
    if IS_WINDOWS:
        # `route print 0.0.0.0` columns: Network Destination, Netmask, Gateway,
        # Interface, Metric
        out = _run(["route", "print", "0.0.0.0"])
        best: tuple[int, str] | None = None
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                gw = parts[2]
                if not _is_ipv4(gw):
                    continue  # "On-link" and similar
                try:
                    metric = int(parts[4])
                except ValueError:
                    continue
                if best is None or metric < best[0]:
                    best = (metric, gw)
        if best:
            return best[1]

        # Fall back to ipconfig only if the routing table told us nothing.
        for line in _run(["ipconfig"]).splitlines():
            if "Default Gateway" in line:
                candidate = line.split(":", 1)[-1].strip()
                if candidate and _is_ipv4(candidate):
                    return candidate
        return None

    out = _run(["ip", "route", "show", "default"])
    m = re.search(r"default via (\d{1,3}(?:\.\d{1,3}){3})", out)
    if m:
        return m.group(1)
    out = _run(["route", "-n", "get", "default"])  # macOS
    m = re.search(r"gateway:\s*(\d{1,3}(?:\.\d{1,3}){3})", out)
    return m.group(1) if m else None


def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def mac_for_ip(ip: str) -> str | None:
    """Look up an IP in the ARP cache. Returns None if not present."""
    for entry in read_arp_table():
        if entry.ip == ip:
            return entry.mac
    return None


def local_ipv4_addresses() -> list[str]:
    """Best-effort list of this host's IPv4 addresses."""
    addrs: list[str] = []
    if IS_WINDOWS:
        out = _run(["ipconfig"])
        for line in out.splitlines():
            if "IPv4 Address" in line:
                # Windows appends "(Preferred)". removesuffix, not rstrip --
                # rstrip strips a character *set*, which happens to work on
                # digits by luck and would silently corrupt anything else.
                candidate = line.split(":", 1)[-1].strip()
                candidate = candidate.removesuffix("(Preferred)").strip()
                if _is_ipv4(candidate):
                    addrs.append(candidate)
    else:
        out = _run(["hostname", "-I"])
        addrs = [a for a in out.split() if _is_ipv4(a)]
    return addrs


def address_in_scope(
    ip: str, cidr: str, exclude_cidrs: list[str] | None = None
) -> bool:
    """Whether an address falls inside the monitored range and outside exclusions.

    Every packet-emitting code path funnels through this. VMware host-only
    adapters in particular will otherwise fill the inventory with phantom
    hosts that are not on the home network at all.
    """
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    if addr not in ipaddress.IPv4Network(cidr, strict=False):
        return False
    for excluded in exclude_cidrs or []:
        if addr in ipaddress.IPv4Network(excluded, strict=False):
            return False
    return True
