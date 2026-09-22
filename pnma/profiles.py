"""Device classification and expected-behaviour baselines.

Most home network tools evaluate a port the same way regardless of what is
listening on it. That is why they are noisy: 445/tcp on a NAS is the entire
reason the NAS exists, and 445/tcp on a smart bulb means something has gone
very wrong. The port is identical; the meaning is not.

So PNMA classifies each device and holds a baseline per class:

``expected``
    Services that are the normal reason this class of device exists. Present
    and expected -> no alert, and the dashboard says why it is fine.
``tolerated``
    Plausible but worth knowing about. Reported at low severity.
``forbidden``
    Should never be listening on this class of device. A phone running SSH, a
    smart plug offering ADB, a printer speaking telnet -- these are escalated
    *above* their generic port risk, because the context is the signal.

Classification uses four independent signals so that no single one has to be
right: the OUI, the DHCP option 55 fingerprint, the hostname pattern, and the
observed service mix. Each contributes a weighted vote, and the result carries
its own confidence -- because a wrong class silently changes what gets alerted,
so a low-confidence guess must be visible rather than silently authoritative.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from .oui import lookup as oui_lookup


class DeviceClass(str, Enum):
    ROUTER = "router"
    PHONE = "phone"
    TABLET = "tablet"
    LAPTOP = "laptop"
    DESKTOP = "desktop"
    PRINTER = "printer"
    TV = "tv"
    STREAMING = "streaming_stick"
    GAME_CONSOLE = "game_console"
    SMART_SPEAKER = "smart_speaker"
    CAMERA = "camera"
    IOT_SENSOR = "iot_sensor"
    NAS = "nas"
    SMART_HOME_HUB = "smart_home_hub"
    WEARABLE = "wearable"
    UNKNOWN = "unknown"


@dataclass
class Baseline:
    """What normal looks like for one class of device."""

    label: str
    # port -> why this is normal here
    expected: dict[int, str] = field(default_factory=dict)
    tolerated: dict[int, str] = field(default_factory=dict)
    # port -> why this is alarming on THIS class specifically
    forbidden: dict[int, str] = field(default_factory=dict)
    # True if the device should essentially never accept inbound connections.
    should_not_listen: bool = False
    notes: str = ""
    # Multiplier applied to generic port risk for this class.
    fragility: str = "normal"  # fragile | normal | robust


BASELINES: dict[DeviceClass, Baseline] = {
    DeviceClass.ROUTER: Baseline(
        label="Router / Gateway",
        expected={
            53: "DNS forwarder for the LAN",
            80: "Local admin interface",
            443: "Local admin interface over TLS",
            67: "DHCP server",
        },
        tolerated={
            22: "SSH admin -- fine if you enabled it and use keys",
            1900: "UPnP/SSDP -- convenient, but lets devices open firewall holes",
        },
        forbidden={
            23: "Telnet on a gateway is a remote-root risk and a Mirai target",
            2323: "Alternate telnet -- almost always a compromised device",
            21: "FTP on a gateway has no legitimate modern purpose",
        },
        notes=(
            "The gateway is the highest-value device on the network: it sees "
            "all traffic and controls DNS. Any unexpected service here matters "
            "more than the same service anywhere else."
        ),
        fragility="normal",
    ),
    DeviceClass.PHONE: Baseline(
        label="Phone",
        should_not_listen=True,
        tolerated={
            5353: "mDNS -- normal service discovery chatter",
            62078: "iOS lockdown/sync service, normal on iPhones",
        },
        forbidden={
            22: "SSH on a phone means it is jailbroken/rooted, or something installed a listener",
            23: "Telnet on a phone is not a legitimate configuration",
            5555: "Android Debug Bridge over the network -- full shell access, no authentication",
            80: "A web server on a phone is unusual and worth explaining",
            8080: "A web server on a phone is unusual and worth explaining",
            445: "SMB on a phone is not a normal configuration",
        },
        notes=(
            "A phone is a client, not a server. It should initiate connections "
            "and accept almost none. Any listening service on a phone deserves "
            "an explanation, which is why the bar here is deliberately low. "
            "Phones also rotate their MAC address, so identity relies on DHCP "
            "fingerprinting rather than the MAC."
        ),
        fragility="normal",
    ),
    DeviceClass.TABLET: Baseline(
        label="Tablet",
        should_not_listen=True,
        tolerated={5353: "mDNS service discovery", 62078: "iOS lockdown/sync"},
        forbidden={
            22: "SSH on a tablet indicates jailbreak or an installed listener",
            5555: "ADB over network -- unauthenticated shell access",
            23: "Telnet has no legitimate purpose here",
        },
        notes="As with phones: a client device that should rarely listen.",
    ),
    DeviceClass.LAPTOP: Baseline(
        label="Laptop",
        expected={},
        tolerated={
            22: "SSH -- fine if deliberate; confirm key-only authentication",
            445: "SMB file sharing -- common on Windows, but a lateral-movement path",
            139: "NetBIOS -- legacy Windows sharing",
            5353: "mDNS service discovery",
            3389: "RDP -- verify Network Level Authentication is on",
            631: "CUPS printing service (macOS/Linux)",
        },
        forbidden={
            23: "Telnet",
            4444: "Metasploit default listener -- no legitimate reason on a laptop",
            1337: "Conventional backdoor port",
            31337: "Backdoor port",
            5555: "ADB -- unexpected on a laptop",
        },
        notes=(
            "General-purpose machines legitimately run many services, so the "
            "baseline is permissive. The forbidden set is narrow and specific: "
            "these ports have no benign explanation on a personal laptop."
        ),
    ),
    DeviceClass.DESKTOP: Baseline(
        label="Desktop / Workstation",
        tolerated={
            22: "SSH", 445: "SMB sharing", 139: "NetBIOS", 3389: "RDP",
            5353: "mDNS", 5900: "VNC -- verify it has a password",
        },
        forbidden={
            23: "Telnet",
            4444: "Metasploit default listener",
            1337: "Backdoor port",
            31337: "Backdoor port",
        },
        notes="As laptop, but more likely to legitimately host services.",
    ),
    DeviceClass.PRINTER: Baseline(
        label="Network Printer",
        expected={
            9100: "Raw JetDirect printing -- the normal print path",
            631: "IPP (Internet Printing Protocol)",
            515: "LPD line printer daemon",
            80: "Printer admin web interface",
            443: "Printer admin over TLS",
            5353: "mDNS/Bonjour printer discovery",
        },
        tolerated={161: "SNMP for toner/status monitoring -- check it is not 'public'"},
        forbidden={
            23: "Telnet on a printer is a classic unchanged factory default",
            21: "FTP on a printer is often used to stage files for exfiltration",
            22: "SSH is unusual on consumer printers and worth explaining",
        },
        notes=(
            "Printers are a favourite pivot: they are rarely patched, often "
            "hold cached documents, and almost nobody looks at them. They are "
            "also fragile -- aggressive scanning makes many models print pages "
            "of garbage, so PNMA never version-probes them by default."
        ),
        fragility="fragile",
    ),
    DeviceClass.TV: Baseline(
        label="Smart TV",
        expected={
            8008: "DIAL/Chromecast discovery",
            8009: "Cast protocol",
            1900: "UPnP/DLNA media discovery",
            7676: "Samsung remote control",
            8080: "Vendor control API",
        },
        tolerated={9080: "Vendor remote/control service", 3000: "Vendor app service", 8443: "Cast v2 over TLS"},
        forbidden={
            5555: "ADB over network on an Android TV -- unauthenticated shell access",
            23: "Telnet",
            22: "SSH is not a normal smart TV service",
        },
        notes=(
            "Smart TVs run full operating systems, phone home constantly, and "
            "receive firmware updates you do not control. Android TV models in "
            "particular ship ADB, which is remotely exploitable when exposed."
        ),
        fragility="fragile",
    ),
    DeviceClass.STREAMING: Baseline(
        label="Streaming Device",
        expected={
            8060: "Roku External Control Protocol",
            8008: "DIAL/Chromecast discovery",
            8009: "Cast protocol",
            1900: "UPnP/SSDP discovery",
        },
        tolerated={8443: "Cast v2 over TLS", 9000: "vendor app service"},
        forbidden={
            5555: "ADB over network -- unauthenticated shell access",
            23: "Telnet",
            22: "SSH",
        },
        notes="Fire TV and Android-based sticks are the usual ADB exposure risk.",
        fragility="fragile",
    ),
    DeviceClass.GAME_CONSOLE: Baseline(
        label="Games Console",
        expected={
            3074: "Xbox Live / Game services",
            3075: "Games services",
            3076: "Games services",
            1935: "RTMP streaming",
            9295: "PlayStation Remote Play",
            9296: "PlayStation Remote Play",
            9297: "PlayStation Remote Play",
            1900: "UPnP -- consoles use it to open NAT ports",
        },
        tolerated={
            80: "Console web service",
            443: "Console web service",
            10243: "Xbox media streaming",
        },
        forbidden={
            23: "Telnet",
            22: "SSH on a stock console indicates modification",
            5555: "ADB",
            445: "SMB on a console is not a stock configuration",
        },
        notes=(
            "Consoles aggressively use UPnP to open inbound NAT holes, which is "
            "normal for them and worth understanding rather than alerting on. "
            "A console offering SSH or SMB has almost certainly been modified."
        ),
        fragility="normal",
    ),
    DeviceClass.SMART_SPEAKER: Baseline(
        label="Smart Speaker",
        expected={
            8009: "Cast protocol (Google Home/Nest)",
            8008: "DIAL discovery",
            4070: "Amazon Alexa control service",
            1900: "UPnP/SSDP",
            5353: "mDNS",
        },
        forbidden={
            22: "SSH", 23: "Telnet", 5555: "ADB", 80: "An open web server on a smart speaker is unexpected",
        },
        notes=(
            "Always-on devices with a microphone. They should offer only their "
            "vendor control protocol; anything else is a meaningful deviation."
        ),
        fragility="fragile",
    ),
    DeviceClass.CAMERA: Baseline(
        label="Security Camera",
        expected={
            554: "RTSP video stream",
            80: "Camera admin interface -- check for default credentials",
            443: "Camera admin over TLS",
            8000: "Vendor control API",
            34567: "Vendor (Dahua/XiongMai-family) control port",
        },
        tolerated={1935: "RTMP streaming", 8554: "Alternate RTSP"},
        forbidden={
            23: "Telnet on a camera is the single most exploited IoT exposure -- this is the Mirai vector",
            2323: "Alternate telnet -- strongly associated with IoT botnets",
            21: "FTP is often used by cameras to push footage off-device; verify the destination",
            22: "SSH is unusual on consumer cameras",
        },
        notes=(
            "IP cameras are the most-compromised device class on home networks. "
            "They combine unchanged default credentials, unpatched firmware, and "
            "a video feed worth stealing. Telnet on a camera should be treated "
            "as compromise until proven otherwise."
        ),
        fragility="fragile",
    ),
    DeviceClass.IOT_SENSOR: Baseline(
        label="IoT Device / Sensor",
        expected={},
        tolerated={
            80: "Local configuration page -- common on ESP-based devices",
            1900: "UPnP/SSDP discovery",
            5353: "mDNS",
        },
        forbidden={
            23: "Telnet -- the Mirai vector",
            2323: "Alternate telnet",
            22: "SSH on a smart plug or bulb is not a stock configuration",
            5555: "ADB",
            4444: "Metasploit default listener",
        },
        should_not_listen=False,
        notes=(
            "Small IoT devices should expose almost nothing. They are built to "
            "cheap price points, rarely receive firmware updates, and are the "
            "usual foothold on a home network. They are also the most fragile "
            "under scanning, so PNMA suppresses version probes for them."
        ),
        fragility="fragile",
    ),
    DeviceClass.NAS: Baseline(
        label="NAS / Home Server",
        expected={
            445: "SMB file sharing -- the reason a NAS exists",
            139: "NetBIOS session service",
            2049: "NFS",
            5000: "Vendor admin UI (Synology DSM)",
            5001: "Vendor admin UI over TLS",
            80: "Admin web interface",
            443: "Admin web interface over TLS",
        },
        tolerated={
            22: "SSH -- common and useful; confirm key-only authentication",
            548: "AFP (legacy Apple file sharing)",
            3306: "MySQL -- fine if a hosted app needs it, alarming if exposed beyond the LAN",
            8080: "Hosted application",
        },
        forbidden={
            23: "Telnet",
            21: "FTP -- cleartext credentials to your entire file store",
            4444: "Metasploit default listener",
            1337: "Backdoor port",
        },
        notes=(
            "A NAS legitimately runs many services, so the baseline is broad. "
            "It is also where the household's data actually lives, which makes "
            "it the highest-consequence device after the gateway."
        ),
        fragility="robust",
    ),
    DeviceClass.SMART_HOME_HUB: Baseline(
        label="Smart Home Hub",
        expected={
            80: "Local hub UI", 443: "Local hub UI over TLS",
            8123: "Home Assistant", 1883: "MQTT broker",
            8883: "MQTT over TLS", 5353: "mDNS",
        },
        tolerated={22: "SSH -- common on self-hosted hubs", 1900: "UPnP/SSDP"},
        forbidden={23: "Telnet", 2323: "Alternate telnet"},
        notes=(
            "A hub controls other devices, so compromising it grants control of "
            "everything attached. An unauthenticated MQTT broker in particular "
            "hands over the whole smart-home estate."
        ),
    ),
    DeviceClass.WEARABLE: Baseline(
        label="Wearable",
        should_not_listen=True,
        forbidden={22: "SSH", 23: "Telnet", 80: "Web server on a wearable is unexpected"},
        notes="Should behave purely as a client.",
    ),
    DeviceClass.UNKNOWN: Baseline(
        label="Unclassified Device",
        tolerated={},
        forbidden={
            23: "Telnet", 2323: "Alternate telnet", 4444: "Metasploit default listener",
            1337: "Backdoor port", 31337: "Backdoor port", 5555: "ADB over network",
        },
        notes=(
            "PNMA could not confidently classify this device, so only the "
            "universally-alarming ports are treated as forbidden. Naming the "
            "device in the dashboard improves classification."
        ),
    ),
}


# -- classification signals -------------------------------------------------

# Vendor substring -> class. Checked against the OUI lookup result.
_VENDOR_HINTS: list[tuple[str, DeviceClass]] = [
    ("arris", DeviceClass.ROUTER), ("commscope", DeviceClass.ROUTER),
    ("netgear", DeviceClass.ROUTER), ("tp-link", DeviceClass.ROUTER),
    ("sagemcom", DeviceClass.ROUTER), ("technicolor", DeviceClass.ROUTER),
    ("ubiquiti", DeviceClass.ROUTER), ("mikrotik", DeviceClass.ROUTER),
    ("brother", DeviceClass.PRINTER), ("hewlett", DeviceClass.PRINTER),
    ("canon", DeviceClass.PRINTER), ("epson", DeviceClass.PRINTER),
    ("lexmark", DeviceClass.PRINTER), ("wistron neweb", DeviceClass.PRINTER),
    ("roku", DeviceClass.STREAMING), ("azurewave", DeviceClass.STREAMING),
    ("gaoshengda", DeviceClass.STREAMING), ("skyworth", DeviceClass.STREAMING),
    ("nest", DeviceClass.SMART_HOME_HUB),
    ("espressif", DeviceClass.IOT_SENSOR), ("tuya", DeviceClass.IOT_SENSOR),
    ("shelly", DeviceClass.IOT_SENSOR), ("sonoff", DeviceClass.IOT_SENSOR),
    ("lifx", DeviceClass.IOT_SENSOR), ("philips hue", DeviceClass.IOT_SENSOR),
    ("eq-3", DeviceClass.IOT_SENSOR), ("texas instruments", DeviceClass.IOT_SENSOR),
    ("wyze", DeviceClass.CAMERA), ("hikvision", DeviceClass.CAMERA),
    ("dahua", DeviceClass.CAMERA), ("amcrest", DeviceClass.CAMERA),
    ("synology", DeviceClass.NAS), ("qnap", DeviceClass.NAS),
    ("western digital", DeviceClass.NAS),
    ("microsoft", DeviceClass.DESKTOP),
    ("sony interactive", DeviceClass.GAME_CONSOLE),
    ("nintendo", DeviceClass.GAME_CONSOLE),
    ("raspberry pi", DeviceClass.SMART_HOME_HUB),
]

# Hostname regex -> class. Hostnames are self-reported and thus a hint only.
_HOSTNAME_HINTS: list[tuple[re.Pattern, DeviceClass]] = [
    (re.compile(r"iphone|android|pixel|galaxy|oneplus|redmi|xiaomi-phone", re.I), DeviceClass.PHONE),
    (re.compile(r"ipad|tablet|tab-", re.I), DeviceClass.TABLET),
    (re.compile(r"macbook|laptop|thinkpad|xps|latitude|inspiron|notebook", re.I), DeviceClass.LAPTOP),
    (re.compile(r"desktop-|imac|workstation|pc-", re.I), DeviceClass.DESKTOP),
    (re.compile(r"printer|prn|brother|hp[-_]?laser|officejet|deskjet|ecotank", re.I), DeviceClass.PRINTER),
    (re.compile(r"\btv\b|bravia|samsungtv|lgtv|webos|aquos", re.I), DeviceClass.TV),
    (re.compile(r"roku|firetv|chromecast|appletv|shield", re.I), DeviceClass.STREAMING),
    (re.compile(r"xbox|playstation|ps[45]|nintendo|switch", re.I), DeviceClass.GAME_CONSOLE),
    (re.compile(r"echo|alexa|googlehome|nest-?mini|homepod", re.I), DeviceClass.SMART_SPEAKER),
    (re.compile(r"cam|camera|doorbell|ipc-", re.I), DeviceClass.CAMERA),
    (re.compile(r"nas|synology|qnap|freenas|truenas", re.I), DeviceClass.NAS),
    (re.compile(r"esp[-_]?\d*|shelly|sonoff|plug|bulb|sensor|thermostat", re.I), DeviceClass.IOT_SENSOR),
    (re.compile(r"hass|homeassistant|hub|bridge|deconz|zigbee", re.I), DeviceClass.SMART_HOME_HUB),
    (re.compile(r"watch|band|fitbit|garmin", re.I), DeviceClass.WEARABLE),
    (re.compile(r"gateway|router|modem|rt-|openwrt", re.I), DeviceClass.ROUTER),
]

# DHCP vendor class (option 60) -> class. More trustworthy than hostname:
# it is set by the OS/firmware rather than by the user.
_VENDOR_CLASS_HINTS: list[tuple[str, DeviceClass]] = [
    ("android-dhcp", DeviceClass.PHONE),
    ("msft", DeviceClass.DESKTOP),
    ("amazonecho", DeviceClass.SMART_SPEAKER),
    ("amazon", DeviceClass.SMART_SPEAKER),
    ("roku", DeviceClass.STREAMING),
    ("esp32", DeviceClass.IOT_SENSOR),
    ("esp8266", DeviceClass.IOT_SENSOR),
    ("xbox", DeviceClass.GAME_CONSOLE),
    ("playstation", DeviceClass.GAME_CONSOLE),
    ("udhcp", DeviceClass.IOT_SENSOR),
]

# A distinctive open port is often the strongest signal of all -- it is
# observed behaviour rather than something the device claims about itself.
_PORT_HINTS: dict[int, DeviceClass] = {
    9100: DeviceClass.PRINTER,
    515: DeviceClass.PRINTER,
    631: DeviceClass.PRINTER,
    8008: DeviceClass.STREAMING,   # Google Cast / DIAL discovery
    8009: DeviceClass.STREAMING,   # Cast protocol
    8060: DeviceClass.STREAMING,
    3074: DeviceClass.GAME_CONSOLE,
    9295: DeviceClass.GAME_CONSOLE,
    4070: DeviceClass.SMART_SPEAKER,
    554: DeviceClass.CAMERA,
    34567: DeviceClass.CAMERA,
    5000: DeviceClass.NAS,
    2049: DeviceClass.NAS,
    8123: DeviceClass.SMART_HOME_HUB,
    1883: DeviceClass.SMART_HOME_HUB,
    62078: DeviceClass.PHONE,
    7676: DeviceClass.TV,
}


@dataclass
class Classification:
    device_class: DeviceClass
    confidence: str          # high | medium | low
    signals: list[str] = field(default_factory=list)
    scores: dict[str, float] = field(default_factory=dict)

    @property
    def baseline(self) -> Baseline:
        return BASELINES[self.device_class]


def classify(
    *,
    mac: str | None = None,
    hostname: str | None = None,
    vendor_class: str | None = None,
    open_ports: list[int] | None = None,
    is_gateway: bool = False,
) -> Classification:
    """Weighted vote across four independent signals.

    Weights reflect trustworthiness. An observed listening port is behaviour and
    weighs most; a hostname is whatever the user typed into a settings screen
    and weighs least.
    """
    if is_gateway:
        return Classification(
            DeviceClass.ROUTER, "high", ["is the configured default gateway"]
        )

    scores: dict[DeviceClass, float] = {}
    signals: list[str] = []

    def vote(cls: DeviceClass, weight: float, why: str) -> None:
        scores[cls] = scores.get(cls, 0.0) + weight
        signals.append(f"{why} (+{weight:g} -> {cls.value})")

    if mac:
        vendor = oui_lookup(mac)
        if vendor:
            lowered = vendor.lower()
            for needle, cls in _VENDOR_HINTS:
                if needle in lowered:
                    vote(cls, 2.0, f"OUI vendor is {vendor}")
                    break

    if vendor_class:
        lowered = vendor_class.lower()
        for needle, cls in _VENDOR_CLASS_HINTS:
            if needle in lowered:
                vote(cls, 2.5, f"DHCP vendor class contains {needle!r}")
                break

    if hostname:
        for pattern, cls in _HOSTNAME_HINTS:
            if pattern.search(hostname):
                vote(cls, 1.5, f"hostname {hostname!r} matches {cls.value}")
                break

    for port in open_ports or []:
        if port in _PORT_HINTS:
            vote(_PORT_HINTS[port], 3.0, f"listening on {port}")

    if not scores:
        return Classification(
            DeviceClass.UNKNOWN, "low",
            ["no vendor, hostname, DHCP or service signal matched"],
        )

    best = max(scores.items(), key=lambda kv: kv[1])
    total = sum(scores.values())
    margin = best[1] / total if total else 0

    if best[1] >= 3.0 and margin >= 0.6:
        confidence = "high"
    elif best[1] >= 2.0:
        confidence = "medium"
    else:
        confidence = "low"

    return Classification(
        device_class=best[0],
        confidence=confidence,
        signals=signals,
        scores={k.value: v for k, v in scores.items()},
    )


def evaluate_port(cls: DeviceClass, port: int) -> tuple[str, str]:
    """Judge one port in the context of a device class.

    Returns (verdict, explanation) where verdict is one of:
    ``expected``, ``tolerated``, ``forbidden``, ``unexpected``.
    """
    baseline = BASELINES[cls]
    if port in baseline.expected:
        return "expected", baseline.expected[port]
    if port in baseline.forbidden:
        return "forbidden", baseline.forbidden[port]
    if port in baseline.tolerated:
        return "tolerated", baseline.tolerated[port]
    if baseline.should_not_listen:
        return "forbidden", (
            f"{baseline.label}s should not accept inbound connections at all. "
            "Any listening service here needs an explanation."
        )
    return "unexpected", (
        f"Not part of the normal service profile for a {baseline.label.lower()}."
    )


def is_fragile(cls: DeviceClass) -> bool:
    """Whether this class should be spared aggressive scanning."""
    return BASELINES[cls].fragility == "fragile"
