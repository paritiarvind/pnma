"""MAC vendor (OUI) lookup, offline.

Deliberately not using a library that fetches the IEEE registry at runtime.
A monitoring agent that phones out to a third party on every device discovery
adds a supply-chain dependency and a network side-effect to what should be a
pure local lookup -- and it breaks the moment you run the agent on an isolated
segment. The table below is vendored, and ``pnma oui-update`` refreshes it from
the IEEE registry as an explicit, auditable act.

Only the OUI (first 3 octets) is meaningful, and only for globally-administered
addresses. A randomised MAC has no vendor -- reporting one would be a lie, so
:func:`lookup` returns None for those.
"""

from __future__ import annotations

import csv
from pathlib import Path

from .fingerprint import is_locally_administered, normalise_mac

_OUI_FILE = Path(__file__).parent / "data" / "oui.csv"

# A small built-in table so the tool is useful with zero setup. This covers the
# vendors that actually turn up on a home network. `pnma oui-update` overlays it
# with the full IEEE registry (~40k MA-L assignments).
#
# Hand-written, and therefore checked: `pnma oui-update --check` compares every
# entry below against the registry and exits non-zero on a disagreement. That
# check exists because on 2026-08-24 the first entry in this table identified
# the author's own gateway as ARRIS when the registry says TP-Link, and a wrong
# vendor propagates into classification, profiling and written advice. Running
# it on 2026-09-02 found twelve more.
_BUILTIN: dict[str, str] = {
    "98:03:8e": "TP-Link Systems Inc.",
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "00:05:69": "VMware",
    "dc:a6:32": "Raspberry Pi Trading",
    "b8:27:eb": "Raspberry Pi Foundation",
    "e4:5f:01": "Raspberry Pi Trading",
    "3c:22:fb": "Apple",
    "a4:83:e7": "Apple",
    "f0:18:98": "Apple",
    "00:1a:11": "Google",
    "f4:f5:d8": "Google",
    "1c:f2:9a": "Google",
    "44:07:0b": "Google",
    "18:b4:30": "Nest Labs",
    "50:dc:e7": "Amazon Technologies",
    "fc:65:de": "Amazon Technologies",
    "68:37:e9": "Amazon Technologies",
    "00:1d:d8": "Microsoft",
    "7c:1e:52": "Microsoft",
    "28:18:78": "Microsoft",
    "00:15:5d": "Microsoft Hyper-V",
    "d8:3a:dd": "Raspberry Pi Trading Ltd",
    "34:23:87": "Hon Hai Precision Ind. Co.,Ltd.",
    "5c:f9:38": "Apple, Inc.",
    "00:1e:c2": "Apple, Inc.",
    "a0:40:a0": "Netgear",
    "c4:04:15": "Netgear",
    "00:1f:33": "Netgear",
    "e8:94:f6": "TP-Link",
    "50:c7:bf": "TP-Link",
    "b0:be:76": "TP-Link",
    "00:31:92": "TP-Link",
    "2c:f0:5d": "Micro-Star / MSI",
    "00:e0:4c": "Realtek",
    "00:09:0f": "Fortinet",
    "00:1b:21": "Intel",
    "94:65:9c": "Intel",
    "10:b6:76": "HP Inc.",
    "68:6c:e6": "Microsoft Corporation",
    "94:b3:f7": "Hui Zhou Gaoshengda Technology Co.,LTD",
    "00:17:88": "Philips Hue",
    "ec:fa:bc": "Espressif (ESP32/ESP8266 IoT)",
    "24:6f:28": "Espressif (ESP32/ESP8266 IoT)",
    "84:f3:eb": "Espressif (ESP32/ESP8266 IoT)",
    "b4:e6:2d": "Espressif (ESP32/ESP8266 IoT)",
    "00:24:e4": "Withings",
    "18:65:90": "Apple",
    "00:1c:b3": "Apple",
    "88:e9:fe": "Apple",
    "d4:6d:6d": "Intel",
    "00:26:bb": "Apple",
    "00:23:6c": "Apple",
    "e0:cb:ee": "Samsung Electronics",
    "00:16:6c": "Samsung Electronics",
    "cc:9e:a2": "Amazon Technologies Inc.",
    "2c:aa:8e": "Wyze Labs",
    "00:12:4b": "Texas Instruments",
    "78:e1:03": "Amazon Technologies",
    "44:65:0d": "Amazon Technologies",
    "0c:47:c9": "Amazon Technologies",
    "40:b4:cd": "Amazon Technologies",
    "ac:63:be": "Amazon Technologies",
    "74:c2:46": "Amazon Technologies",
    "00:04:4b": "NVIDIA",
    "48:b0:2d": "NVIDIA",
    "6c:ad:f8": "AzureWave (IoT/Roku)",
    "b0:a7:37": "Roku",
    "cc:6d:a0": "Roku",
    "d8:31:34": "Roku",
    "00:0d:4b": "Roku",
    "18:1d:ea": "Intel",
    "70:85:c2": "ASRock",
    "1c:69:7a": "Elitegroup / ECS",
    "00:11:32": "Synology",
    "00:1c:c0": "Intel",
    "9c:b6:d0": "Rivet Networks",
}

# Deliberate friendly names. Each of these disagrees with the IEEE registry on
# purpose, and they are kept apart from `_BUILTIN` so that disagreement stays a
# statement rather than a suspected error.
#
# The distinction earns its keep twice. `check_builtins()` can hold the built-in
# table to the registry strictly, because everything that is meant to differ
# lives here -- which is how a wrong entry like the gateway's becomes visible
# instead of hiding among intended overrides. And `_load_table` applies these
# last, so `pnma oui-update` cannot quietly rename "LIFX" to "LIFI LABS
# MANAGEMENT PTY LTD" and take `is_iot_vendor` down with it.
#
# The bar for adding one: the registrant's legal name is not the name the device
# is sold under, and the useful answer is the product. A guess does not qualify
# -- ac:de:48 used to read "Apple" here and the registry says "Private", meaning
# the registrant withheld the name. That is an inference, not an alias, so it
# was dropped rather than moved.
_ALIASES: dict[str, str] = {
    "08:00:27": "Oracle VirtualBox",       # registered to PCS Systemtechnik GmbH
    "d0:73:d5": "LIFX",                    # registered to LiFi Labs Management Pty Ltd
    "00:1a:22": "eQ-3 / Homematic",        # registered to eQ-3 Entwicklung GmbH
}
# Not listed above, and deliberately: 52:54:00 (QEMU/KVM) has the
# locally-administered bit set, so `lookup` returns None for it before any table
# is consulted. An entry here could never be reached. Recognising virtual NICs
# by their locally-administered prefix would need its own lookup path, on the
# other side of the "a randomised MAC has no vendor" rule -- a separate feature,
# not an alias.

_cache: dict[str, str] | None = None


def _load_table() -> dict[str, str]:
    """Built-ins, then the vendored CSV, then aliases -- in that order.

    Aliases go last on purpose: a registry refresh must not be able to overwrite
    a deliberate product name with the registrant's legal one.
    """
    global _cache
    if _cache is not None:
        return _cache
    table = dict(_BUILTIN)
    if _OUI_FILE.exists():
        try:
            with _OUI_FILE.open(newline="", encoding="utf-8") as fh:
                for row in csv.reader(fh):
                    if len(row) >= 2 and row[0]:
                        table[row[0].strip().lower()] = row[1].strip()
        except OSError:
            pass  # a corrupt cache should degrade to built-ins, not crash
    table.update(_ALIASES)
    _cache = table
    return table


def lookup(mac: str) -> str | None:
    """Return the vendor for a MAC, or None if unknown or not applicable.

    Returns None for locally-administered (randomised) MACs. Those have no
    vendor, and inventing one would put a confident-looking lie on the
    dashboard.
    """
    try:
        m = normalise_mac(mac)
    except ValueError:
        return None
    if is_locally_administered(m):
        return None
    return _load_table().get(m[:8])


def describe(mac: str) -> str:
    """Human-facing vendor string, honest about randomised addresses."""
    try:
        m = normalise_mac(mac)
    except ValueError:
        return "invalid"
    if is_locally_administered(m):
        return "randomised MAC (no vendor)"
    return lookup(m) or "unknown vendor"


def is_iot_vendor(mac: str) -> bool:
    """Heuristic: does this OUI belong to a vendor whose kit is usually IoT?

    Used only to raise the risk weighting on scan fragility and on
    default-credential exposure -- IoT gear is both more likely to fall over
    when probed and more likely to ship something nasty listening.
    """
    vendor = lookup(mac)
    if not vendor:
        return False
    needles = (
        "espressif", "wyze", "lifx", "hue", "nest", "roku", "tuya",
        "shelly", "sonoff", "xiaomi", "eq-3", "texas instruments",
    )
    lowered = vendor.lower()
    return any(n in lowered for n in needles)


# ---------------------------------------------------------------- registry --
#
# `pnma oui-update` refreshes the vendored table from the IEEE registry. It is
# an explicit, auditable act rather than something the agent does on its own:
# a lookup that reaches the network turns device discovery into an outbound
# request, and stops working on the isolated segments this tool is most useful
# on. Fetching is therefore something the operator asks for, on a file they can
# inspect, diff and commit.

IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"


def fetch_registry(url: str = IEEE_OUI_URL, timeout: int = 120) -> str:
    """Download the IEEE OUI registry. Raises OSError on failure."""
    import urllib.request

    req = urllib.request.Request(url, headers={"User-Agent": "pnma/oui-update"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        # The registry is not clean UTF-8 throughout; a stray byte in one
        # organisation's address must not cost us the other 40,000 entries.
        return resp.read().decode("utf-8", errors="replace")


def parse_registry(text: str) -> dict[str, str]:
    """Parse IEEE CSV text into {oui: organisation}.

    Only MA-L rows are usable. MA-M and MA-S assignments are 28- and 36-bit
    blocks: several organisations share one 24-bit prefix, so keying them on
    three octets would attribute a device to whichever of them happened to be
    parsed last. The published oui.csv contains only MA-L, but the filter is
    explicit so that a future file which does not cannot corrupt the table.

    `csv.reader` is not optional here -- a quarter of the organisation names
    contain commas inside quotes ("Cisco Systems, Inc"), and splitting by hand
    silently truncates them.
    """
    import io as _io

    table: dict[str, str] = {}
    reader = csv.reader(_io.StringIO(text))
    for row in reader:
        if len(row) < 3 or row[0].strip() != "MA-L":
            continue
        assignment = row[1].strip().lower()
        if len(assignment) != 6:
            continue
        oui = ":".join(assignment[i : i + 2] for i in (0, 2, 4))
        org = row[2].strip()
        # "Private" is not a vendor. It is the registry recording that the
        # assignee asked for their name to be withheld -- 107 blocks at the time
        # of writing. Rendering it on a dashboard would read as a company called
        # Private, which is worse than "unknown vendor": it looks like an answer.
        if org and org.lower() != "private":
            table[oui] = org
    return table


def check_builtins(registry: dict[str, str]) -> list[tuple[str, str, str | None]]:
    """Built-in entries the registry contradicts, as (oui, ours, theirs).

    This is the point of the whole command. The built-in table is hand-written,
    and on 2026-08-24 its very first entry turned out to identify the author's
    own gateway as ARRIS when the registry says TP-Link -- a wrong vendor
    propagates into device classification, into profiling, and from there into
    written advice. Nothing catches that except comparing against the source,
    so the comparison runs every time the table is refreshed.

    `_ALIASES` is excluded by construction: those disagree deliberately.
    """
    mismatches: list[tuple[str, str, str | None]] = []
    for oui, ours in sorted(_BUILTIN.items()):
        key = oui.strip().lower()
        theirs = registry.get(key)
        if theirs is None:
            mismatches.append((key, ours, None))
            continue
        a, b = ours.lower(), theirs.lower()
        # Substring either way, because "Apple" and "Apple, Inc." agree, while
        # "Netgear" and "Apple, Inc." do not.
        if a[:6] not in b and b[:6] not in a:
            mismatches.append((key, ours, theirs))
    return mismatches


def write_table(registry: dict[str, str], path: Path | None = None) -> int:
    """Write {oui: org} to the vendored CSV. Returns the number of rows.

    Written to a temporary file and renamed, so an interrupted or truncated
    download cannot replace a working table with a half-written one.
    """
    target = path or _OUI_FILE
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        for oui, org in sorted(registry.items()):
            writer.writerow([oui, org])
    tmp.replace(target)

    global _cache
    _cache = None  # the next lookup must see the new table
    return len(registry)
