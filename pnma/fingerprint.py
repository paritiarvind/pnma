"""Device identity that survives MAC randomisation.

The naive design keys a device on its MAC address. That worked until roughly
2020. iOS 14+ and Android 10+ generate a fresh *locally-administered* MAC per
SSID and rotate it periodically, so a MAC-keyed inventory invents a brand new
device every time a phone reconnects -- and a "new device on the network"
detector built on it becomes unusable within about a day.

The fix is to notice that not all MACs are equal:

* A **globally-administered** MAC is burned in by the manufacturer and is
  stable. Its OUI identifies a real vendor. Key on it directly.
* A **locally-administered** MAC is software-generated and may be gone in an
  hour. Keying on it is meaningless. We instead key on what the device *says*
  about itself over DHCP -- the option 55 parameter request list, the option 60
  vendor class, and the hostname. That triple is remarkably stable per OS build
  and is the basis of how tools like Fingerbank classify devices.

The U/L bit is bit 1 of the first octet (0x02). It is the single cheapest and
most under-used signal in home network monitoring::

    02:xx  ->  0x02 & 0x02 = 2  ->  locally administered  (randomised)
    98:xx  ->  0x98 & 0x02 = 0  ->  globally administered (real vendor OUI)

Confidence is reported alongside identity because a detector should treat
"a device I can positively identify" differently from "a MAC I cannot pin
down". Alerting at full severity on the latter is how you train yourself to
ignore the dashboard.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

MAC_RE = re.compile(r"^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$", re.IGNORECASE)

# Multicast/broadcast and other addresses that are never a real endpoint.
NON_DEVICE_PREFIXES = ("01:00:5e", "33:33", "ff:ff:ff")


def normalise_mac(mac: str) -> str:
    """Canonicalise to lowercase colon-separated form.

    Windows ``arp -a`` emits ``98-03-8e-00-11-22``; scapy emits
    ``98:03:8e:00:11:22``. Downstream code should never have to care.
    """
    cleaned = mac.strip().lower().replace("-", ":")
    if not MAC_RE.match(cleaned):
        raise ValueError(f"not a MAC address: {mac!r}")
    return cleaned


def is_locally_administered(mac: str) -> bool:
    """True if the U/L bit is set, i.e. the MAC is software-generated.

    On modern phones this almost always means "randomised private address".
    """
    first_octet = int(normalise_mac(mac).split(":")[0], 16)
    return bool(first_octet & 0x02)


def is_multicast(mac: str) -> bool:
    """True if the I/G bit is set -- multicast or broadcast, never an endpoint."""
    first_octet = int(normalise_mac(mac).split(":")[0], 16)
    return bool(first_octet & 0x01)


def is_real_endpoint(mac: str) -> bool:
    """Filter out the broadcast/multicast noise that fills every ARP table."""
    try:
        m = normalise_mac(mac)
    except ValueError:
        return False
    if is_multicast(m):
        return False
    return not m.startswith(NON_DEVICE_PREFIXES)


def mac_type(mac: str) -> str:
    return "local" if is_locally_administered(mac) else "global"


def dhcp_fingerprint(
    param_request_list: list[int] | None,
    vendor_class: str | None = None,
) -> str | None:
    """Hash a DHCP option 55 request list (plus option 60) into a stable id.

    The *order* of option 55 is part of the signature -- it is determined by the
    DHCP client implementation, not the user -- so it is deliberately not
    sorted. Two devices running the same OS build produce the same value; the
    same device produces the same value across MAC rotations, which is the
    whole point.
    """
    if not param_request_list:
        return None
    basis = ",".join(str(int(o)) for o in param_request_list)
    if vendor_class:
        basis += "|" + vendor_class.strip()
    return hashlib.sha256(basis.encode()).hexdigest()[:16]


@dataclass
class DeviceIdentity:
    """The resolved identity of an observed device."""

    device_id: str
    mac: str
    mac_type: str
    strategy: str  # mac | dhcp | ephemeral
    confidence: str  # high | medium | low
    hostname: str | None = None
    fingerprint: str | None = None
    vendor_class: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def is_stable(self) -> bool:
        """Whether this identity can be trusted to persist across reconnects."""
        return self.strategy in ("mac", "dhcp")


def resolve_identity(
    mac: str,
    *,
    hostname: str | None = None,
    param_request_list: list[int] | None = None,
    vendor_class: str | None = None,
) -> DeviceIdentity:
    """Derive a stable device_id from whatever signals we actually have.

    Three strategies, in descending order of trustworthiness:

    ``mac``
        Burned-in vendor MAC. Stable indefinitely. High confidence.
    ``dhcp``
        Randomised MAC, but the device told us its DHCP fingerprint and/or
        hostname. Stable across MAC rotation. Medium confidence.
    ``ephemeral``
        Randomised MAC and nothing else to go on. We cannot distinguish "a new
        device" from "the same phone with a new MAC", and we say so rather than
        guessing. Low confidence -- detectors downgrade severity accordingly.
    """
    mac = normalise_mac(mac)
    mtype = mac_type(mac)
    fp = dhcp_fingerprint(param_request_list, vendor_class)
    notes: list[str] = []

    if mtype == "global":
        return DeviceIdentity(
            device_id="m:" + hashlib.sha256(mac.encode()).hexdigest()[:16],
            mac=mac,
            mac_type=mtype,
            strategy="mac",
            confidence="high",
            hostname=hostname,
            fingerprint=fp,
            vendor_class=vendor_class,
            notes=notes,
        )

    notes.append(
        "Locally-administered MAC: this device is using a randomised private "
        "address, so the MAC itself is not a durable identifier."
    )

    if fp or hostname:
        basis = f"{fp or ''}|{(hostname or '').strip().lower()}"
        notes.append(
            "Identity derived from DHCP fingerprint/hostname, which survives "
            "MAC rotation."
        )
        return DeviceIdentity(
            device_id="f:" + hashlib.sha256(basis.encode()).hexdigest()[:16],
            mac=mac,
            mac_type=mtype,
            strategy="dhcp",
            confidence="medium",
            hostname=hostname,
            fingerprint=fp,
            vendor_class=vendor_class,
            notes=notes,
        )

    notes.append(
        "No DHCP fingerprint or hostname observed yet. Identity is provisional "
        "and may merge with an existing device once this host renews its lease."
    )
    return DeviceIdentity(
        device_id="e:" + hashlib.sha256(mac.encode()).hexdigest()[:16],
        mac=mac,
        mac_type=mtype,
        strategy="ephemeral",
        confidence="low",
        hostname=hostname,
        fingerprint=fp,
        vendor_class=vendor_class,
        notes=notes,
    )
