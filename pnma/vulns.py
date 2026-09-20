"""Known-exploited-vulnerability advisories, matched to your own devices.

Two things this module is, and one it is deliberately not.

It **is** an offline catalogue of vulnerability classes that are actively
exploited on home networks -- Mirai-style telnet, exposed ADB, UPnP/SSDP
reflection, BlueKeep-era RDP, EternalBlue-era SMB, and so on -- each keyed to
the fields PNMA already stores per device (open port, service, product string,
vendor, device class). ``match_devices`` walks the live inventory and returns
the advisories that apply, so "port 23 is open on a camera" becomes "this is
the Mirai vector (CVE-2017-..., in CISA's Known Exploited catalogue), here is
what it means and how to close it."

It **also** can, when explicitly enabled, refresh a local cache from CISA's
Known Exploited Vulnerabilities feed, so the catalogue tracks what is actually
being exploited in the wild rather than only what was true when this file was
written. That fetch is the only network egress in this module and is off by
default, for the same reason every other outbound path in PNMA is off by
default (see pnma.audit): an agent that auto-starts, runs elevated, maps the
network and then reaches out to the internet is, accurately, the profile of a
remote-access trojan. Offline, the bundled catalogue still works.

It is **not** an exploitation tool. It identifies exposure and explains it; it
never sends an exploit. Actually attacking a device -- even one you own -- is a
lab activity, and matching a device here produces a `sandbox_note` describing
how to reproduce and study the finding safely, not a payload. See
docs/PENTEST_LAB.md.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

log = logging.getLogger("pnma.vulns")

# CISA Known Exploited Vulnerabilities catalogue, JSON form. Public, no key.
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@dataclass
class Advisory:
    """One class of actively-exploited exposure PNMA can recognise locally."""

    advisory_id: str
    title: str
    severity: str                       # info|low|medium|high|critical
    # What it is, in one or two plain sentences.
    summary: str
    # Why it matters on a home network specifically.
    impact: str
    # What to do about it, concrete.
    remediation: str
    # How to study it safely, for the learning angle. Never an exploit.
    sandbox_note: str
    # CVE ids / references this advisory represents (illustrative, not
    # exhaustive; the class is the point, not one CVE).
    references: list[str] = field(default_factory=list)
    mitre_id: str | None = None
    mitre_name: str | None = None
    # Predicate over a device dict (with an `open_ports` list of dicts). Kept
    # as a function so a match can consider several fields at once -- "telnet
    # on a camera" is a different advisory from "telnet on anything".
    matches: Callable[[dict], bool] = lambda d: False
    # True once a live KEV refresh has confirmed at least one referenced CVE is
    # in CISA's catalogue. None means "not checked" (offline); False means
    # checked and absent. Purely informational -- the class-based match stands
    # on its own.
    kev_confirmed: bool | None = None


def _has_port(device: dict, *ports: int) -> bool:
    open_ports = device.get("open_ports") or []
    live = {p.get("port") for p in open_ports if not p.get("closed_at")}
    return any(p in live for p in ports)


def _service_like(device: dict, *needles: str) -> bool:
    for p in device.get("open_ports") or []:
        if p.get("closed_at"):
            continue
        hay = " ".join(str(p.get(k) or "") for k in ("service", "product")).lower()
        if any(n in hay for n in needles):
            return True
    return False


def _class(device: dict, *classes: str) -> bool:
    return (device.get("device_class") or "") in classes


# The bundled catalogue. Curated for the home-network threat model: every entry
# is a class of exposure that is both detectable from PNMA's telemetry and
# genuinely, currently exploited at scale. References cite the emblematic CVE
# or advisory; the match is on the exposure class, so it holds for the whole
# family, not one firmware version.
CATALOGUE: list[Advisory] = [
    Advisory(
        advisory_id="telnet-mirai",
        title="Telnet exposed -- the Mirai vector",
        severity="critical",
        summary="An open Telnet service (23/tcp) with no transport encryption. "
                "Mirai and its descendants spread by brute-forcing default "
                "credentials over exactly this port.",
        impact="On a camera, DVR or router this is the single most exploited "
               "IoT weakness in existence: worms scan the whole internet for "
               "it continuously, and a match on a device with a default "
               "password is compromised within minutes of being reachable.",
        remediation="Disable Telnet in the device's settings and use its app or "
                    "HTTPS page instead. If it cannot be disabled, the device "
                    "is unsafe to keep on the main network -- move it to the "
                    "IoT/guest network and consider replacing it.",
        sandbox_note="To study safely: stand up an intentionally-vulnerable "
                     "image (e.g. a Mirai-lab container) in an isolated VM "
                     "network, not against your own camera. The learning is in "
                     "the credential-stuffing loop, which you can watch in a "
                     "honeypot like Cowrie.",
        references=["CVE-2016-10401", "CISA-KEV: multiple IoT telnet entries"],
        mitre_id="T1110.001", mitre_name="Brute Force: Password Guessing",
        matches=lambda d: _has_port(d, 23) or _service_like(d, "telnet"),
    ),
    Advisory(
        advisory_id="adb-open",
        title="Android Debug Bridge exposed over TCP",
        severity="critical",
        summary="Port 5555/tcp is Android Debug Bridge in network mode. It "
                "grants a full shell with no authentication whatsoever.",
        impact="ADBMiner and similar worms scan for this constantly. On a Fire "
               "TV, Android TV box or rooted phone it is remote code execution "
               "for anyone on the network, and cryptominers deploy through it "
               "automatically.",
        remediation="Turn off 'ADB debugging' / 'Network debugging' in the "
                    "device's Developer Options. On a TV device this is usually "
                    "Settings -> Device -> Developer options -> Network debugging.",
        sandbox_note="Reproduce in a lab with an Android emulator: `adb tcpip "
                     "5555` then connect from another host on an isolated "
                     "network to see the unauthenticated shell. Never leave it "
                     "on outside the lab.",
        references=["ADB.Miner", "CVE-2020-0458 (context)"],
        mitre_id="T1210", mitre_name="Exploitation of Remote Services",
        matches=lambda d: _has_port(d, 5555) or _service_like(d, "adb"),
    ),
    Advisory(
        advisory_id="smb-eternalblue",
        title="SMB reachable -- EternalBlue family",
        severity="high",
        summary="SMB file sharing (445/tcp, or legacy 139) reachable on the "
                "network. The EternalBlue/EternalRomance exploits and the "
                "WannaCry and NotPetya worms all traversed this service.",
        impact="An unpatched or misconfigured SMB service is a wormable remote "
               "code execution target and, combined with LLMNR/NBT-NS "
               "poisoning, a credential-relay target. It is how ransomware "
               "moves laterally once one machine is compromised.",
        remediation="If this host does not share files, disable SMB (or at "
                    "least SMBv1) and block 445 at the host firewall. If it "
                    "does, require SMB signing and keep the OS patched.",
        sandbox_note="The classic lab is a deliberately-unpatched Windows 7 VM "
                     "on an isolated network with Metasploit's ms17_010 module "
                     "from a Kali VM. Snapshot first; this is destructive.",
        references=["CVE-2017-0144 (EternalBlue)"],
        mitre_id="T1210", mitre_name="Exploitation of Remote Services",
        matches=lambda d: _has_port(d, 445, 139) or _service_like(d, "microsoft-ds", "smb", "netbios"),
    ),
    Advisory(
        advisory_id="rdp-bluekeep",
        title="RDP exposed -- BlueKeep family",
        severity="high",
        summary="Remote Desktop (3389/tcp) is reachable. BlueKeep "
                "(CVE-2019-0708) is a wormable pre-auth RCE in older RDP, and "
                "RDP in general is the top ransomware entry vector.",
        impact="An exposed RDP service is brute-forced continuously and, if the "
               "OS is behind on patches, exploitable without any password at "
               "all. If this device is also port-forwarded at the router it is "
               "reachable from the whole internet.",
        remediation="Disable Remote Desktop if you do not use it (System -> "
                    "Remote Desktop -> off). If you need it, require Network "
                    "Level Authentication, a strong password, and never forward "
                    "3389 through the router -- use a VPN or Tailscale instead.",
        sandbox_note="Study in a lab against an unpatched Windows VM with the "
                     "rdp_scanner and bluekeep modules; the pre-auth crash is "
                     "the lesson. Isolated network, snapshot first.",
        references=["CVE-2019-0708 (BlueKeep)"],
        mitre_id="T1210", mitre_name="Exploitation of Remote Services",
        matches=lambda d: _has_port(d, 3389) or _service_like(d, "ms-wbt-server", "rdp"),
    ),
    Advisory(
        advisory_id="upnp-exposed",
        title="UPnP / SSDP exposed",
        severity="medium",
        summary="A UPnP service (1900/udp SSDP, or an IGD control point) is "
                "reachable. UPnP has a long history of exploited flaws "
                "(CallStranger, the Pinkslipbot family) and is used for DDoS "
                "reflection.",
        impact="On a router, UPnP lets any device on the LAN open holes in the "
               "firewall to the internet without asking you -- malware uses "
               "this to expose itself. On IoT gear it is a reflection/"
               "amplification and information-disclosure surface.",
        remediation="Turn UPnP off on the router (Advanced -> NAT Forwarding -> "
                    "UPnP) unless a specific app needs it, and open any required "
                    "ports manually instead.",
        sandbox_note="Explore with `upnpc` and the SSDP modules against a lab "
                     "router or an emulated IGD -- watch how a client can add a "
                     "port-forward with no authentication.",
        references=["CVE-2020-12695 (CallStranger)"],
        mitre_id="T1190", mitre_name="Exploit Public-Facing Application",
        matches=lambda d: _has_port(d, 1900) or _service_like(d, "upnp", "ssdp"),
    ),
    Advisory(
        advisory_id="iot-http-admin",
        title="IoT device serving an unauthenticated-prone web admin",
        severity="medium",
        summary="A camera, plug, bulb or similar is serving HTTP (80/tcp) "
                "and/or a vendor control API. Consumer IoT web interfaces are a "
                "steady stream of auth-bypass and command-injection CVEs.",
        impact="Many IoT web panels ship with default or no credentials, "
               "command-injection in the setup endpoints, or a debug API on a "
               "high port. A match here means the device has an attack surface "
               "worth checking against its vendor's advisories.",
        remediation="Change the device's default password, update its firmware, "
                    "and keep it on the IoT/guest network so a compromise of it "
                    "cannot reach your laptops. If it exposes a cloud/remote "
                    "feature you do not use, disable it.",
        sandbox_note="For learning, capture the app<->device traffic with a "
                     "proxy (mitmproxy) on a lab network and read the local API. "
                     "Firmware analysis with binwalk/FACT on a downloaded image "
                     "is the safe deep dive -- not live fuzzing of the device.",
        references=["Numerous vendor CVEs; class-level advisory"],
        mitre_id="T1190", mitre_name="Exploit Public-Facing Application",
        matches=lambda d: _class(d, "camera", "iot_sensor", "smart_speaker", "streaming_stick")
        and (_has_port(d, 80) or _service_like(d, "http")),
    ),
]


def match_devices(devices: list[dict]) -> list[dict]:
    """Return {device, advisories:[Advisory]} for each device with a match."""
    out = []
    for d in devices:
        hits = [a for a in CATALOGUE if _safe_match(a, d)]
        if hits:
            out.append({"device": d, "advisories": hits})
    return out


def _safe_match(advisory: Advisory, device: dict) -> bool:
    try:
        return bool(advisory.matches(device))
    except Exception:  # noqa: BLE001 - a bad predicate must not sink the pass
        log.exception("advisory %s match failed", advisory.advisory_id)
        return False


# --------------------------------------------------------------------------
# Optional live refresh from CISA KEV. Off unless the caller opts in.
# --------------------------------------------------------------------------

def _cache_path(database: str) -> Path:
    return Path(database).parent / "kev-cache.json"


def refresh_kev(database: str, *, url: str = KEV_FEED_URL, timeout_s: float = 20.0) -> dict:
    """Download CISA KEV and cache the CVE ids locally.

    Egress. Only call this when the operator has enabled the CVE feed. Returns
    a summary dict; never raises on a network error -- a monitor that crashes
    because a feed was unreachable is worse than one running on last week's
    catalogue.
    """
    import urllib.request

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PNMA/vuln-refresh"})
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310 - fixed https URL
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        log.warning("KEV refresh failed: %s", exc)
        return {"ok": False, "error": str(exc)}

    ids = sorted({v.get("cveID") for v in data.get("vulnerabilities", []) if v.get("cveID")})
    cache = {"fetched_at": time.time(), "count": len(ids), "cve_ids": ids}
    try:
        _cache_path(database).write_text(json.dumps(cache), encoding="utf-8")
    except OSError as exc:
        log.warning("could not write KEV cache: %s", exc)
    log.info("KEV refresh: %d CVEs in catalogue", len(ids))
    return {"ok": True, "count": len(ids), "fetched_at": cache["fetched_at"]}


def load_kev_ids(database: str) -> set[str]:
    """The cached KEV CVE ids, or an empty set if never refreshed."""
    try:
        cache = json.loads(_cache_path(database).read_text(encoding="utf-8"))
        return set(cache.get("cve_ids", []))
    except (OSError, ValueError):
        return set()


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _cve_ids(references: list[str]) -> set[str]:
    """Pull bare CVE ids out of reference strings like 'CVE-2019-0708 (BlueKeep)'."""
    ids: set[str] = set()
    for ref in references:
        ids.update(m.group(0).upper() for m in _CVE_RE.finditer(ref))
    return ids


def annotate_with_kev(database: str) -> None:
    """Mark advisories whose referenced CVEs are in the cached KEV set."""
    kev = load_kev_ids(database)
    if not kev:
        return
    for a in CATALOGUE:
        cves = _cve_ids(a.references)
        a.kev_confirmed = bool(cves & kev) if cves else None
