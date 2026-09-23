"""Network-behaviour detections over the host's own outbound connections
(pnma.collectors.host_events writes them to connection_endpoints). Adapted from
SEC555's C2/beacon analytics, scoped to what a single host can honestly observe
by sampling its own TCP table -- no packet capture, no feed, all local.

* Beaconing: a process re-connecting to one external endpoint at a regular
  cadence -- the rhythm of malware checking in with a controller.
* New external destination: a process (that is not a browser) reaching an
  external address it has never reached before.
"""

from __future__ import annotations

import ipaddress
import json
import re
import statistics

from .base import Detection, DetectionContext, Finding

# Processes that legitimately hold a steady, periodic outbound connection:
# browsers, cloud sync, OS/vendor push, messaging, VPN/mesh clients, updaters,
# security agents, and the AI coding assistant this project is built with. A
# metronome beat from one of these is the norm, not a controller check-in.
# Matched on the exact executable basename (not a substring), so "maps.exe"
# never matches "aps".
_KNOWN_PERIODIC_NAMES = {
    # browsers
    "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "iexplore", "safari",
    # Windows components
    "svchost", "backgroundtaskhost", "searchapp", "widgetservice", "searchindexer",
    # cloud sync
    "onedrive", "dropbox", "googledrivefs", "googledrive", "box",
    # messaging / media
    "msteams", "teams", "slack", "discord", "zoom", "spotify", "steam", "steamwebhelper",
    # VPN / mesh
    "tailscale", "tailscaled", "wireguard", "expressvpn", "expressvpn-service",
    "nordvpn", "openvpn", "openvpn-gui",
    # Apple push / sync
    "apsdaemon", "itunes", "icloudservices", "icloud",
    # AI / dev assistants
    "claude", "code", "cursor",
    # updaters
    "update", "updater", "edgeupdate", "msedgeupdate", "googleupdate", "googleupdatecore",
    # security agents
    "msmpeng", "mssense", "nissrv", "securityhealthservice", "smartscreen",
}

# Trusted vendor families whose components multiply into many executable names
# (icloud*, *copilot, mpdefender*). Prefix-matched to avoid whack-a-mole; the
# throwaway-path guard below still applies, so a spoof cannot ride a prefix in
# from Downloads.
_KNOWN_PERIODIC_PREFIXES = (
    "icloud", "copilot", "mscopilot", "m365copilot", "tailscale",
    "mpdefender", "microsoftedge", "msedge", "microsoftstart", "hpprinter",
    "googleupdate", "onedrive",
)

# A trusted name running from a throwaway location is exactly the spoof this
# rule exists to catch, so it is NOT allowlisted.
_SUSPICIOUS_PATH = re.compile(
    r"[\\/](temp|tmp|downloads|public)[\\/]|[\\/]appdata[\\/]local[\\/]temp[\\/]", re.I)


def _exe_name(process: str | None, path: str | None) -> str:
    base = (process or "") or (path or "")
    base = base.replace("/", "\\").split("\\")[-1].strip().lower()
    return base[:-4] if base.endswith(".exe") else base


def _is_known_good(process: str | None, path: str | None) -> bool:
    name = _exe_name(process, path)
    known = name in _KNOWN_PERIODIC_NAMES or any(name.startswith(p) for p in _KNOWN_PERIODIC_PREFIXES)
    if not known:
        return False
    if path and _SUSPICIOUS_PATH.search(path):
        return False   # trusted name, untrusted path -> still worth a look
    return True


def _samples(row) -> list[float]:
    try:
        return sorted(float(x) for x in json.loads(row["samples"] or "[]"))
    except (TypeError, ValueError):
        return []


def _is_public(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        return False
    # Tailnet CGNAT range 100.64/10 is "yours", not the internet.
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10"):
        return False
    return True


class BeaconingDetection(Detection):
    """A process re-connecting to one external endpoint at a regular cadence."""

    rule_id = "beaconing"
    name = "Regular beaconing to an external host"
    severity = "high"
    mitre_id = "T1071"
    mitre_name = "Application Layer Protocol"
    requires = "connection_endpoints: this host's own outbound-connection samples (host events)"
    blind_spots = (
        "Sampled from the host's own TCP table every few minutes, so it sees "
        "beacons whose interval is minutes or more -- a sub-minute beacon, or one "
        "that only briefly opens a socket between samples, can be missed. It is "
        "the host's own connections only, not other devices'. A legitimate app "
        "that polls a server on a fixed schedule (an updater, a sync client) has "
        "the same rhythm; browsers, cloud sync, VPN/mesh clients, OS push and "
        "security agents are excluded by exact process name, so a beacon flagged "
        "here is one that is NOT one of those. That exclusion is name-based, so "
        "it is bypassed for a trusted name running from a throwaway path (Temp, "
        "Downloads) -- the classic spoof -- and the process path is shown so a "
        "borrowed name still stands out. Real flow data would make this sharper; "
        "Hearth does not capture packets."
    )
    MIN_SAMPLES = 6
    MIN_SPAN_S = 2 * 3600
    MAX_CV = 0.30           # coefficient of variation of the intervals: low = regular

    def evaluate(self, ctx: DetectionContext) -> list[Finding]:
        rows = ctx.db.query(
            "SELECT process, path, raddr, rport, first_seen, last_seen, sample_count, samples "
            "FROM connection_endpoints WHERE sample_count >= ? AND (last_seen - first_seen) >= ?",
            (self.MIN_SAMPLES, self.MIN_SPAN_S))
        out = []
        for r in rows:
            if _is_known_good(r["process"], r["path"]):
                continue
            if not _is_public(r["raddr"] or ""):
                continue
            samples = _samples(r)
            if len(samples) < self.MIN_SAMPLES:
                continue
            intervals = [b - a for a, b in zip(samples, samples[1:]) if b > a]
            if len(intervals) < self.MIN_SAMPLES - 1:
                continue
            mean = statistics.mean(intervals)
            if mean <= 0:
                continue
            cv = statistics.pstdev(intervals) / mean
            if cv > self.MAX_CV:
                continue
            period = int(mean / 60)
            out.append(Finding(
                dedup_key="beacon:%s:%s:%s" % (r["process"], r["raddr"], r["rport"]),
                severity=self.severity,
                title="%s beacons to %s:%s about every %d min" % (
                    r["process"], r["raddr"], r["rport"], max(1, period)),
                description=(
                    "'" + r["process"] + "' has connected to " + r["raddr"] + ":" +
                    str(r["rport"]) + " " + str(r["sample_count"]) + " times at a "
                    "regular interval of roughly " + str(max(1, period)) + " minutes "
                    "(the timing barely varies).\n\n"
                    "  Process  " + r["process"] + "\n"
                    "  Path     " + (r["path"] or "-") + "\n\n"
                    "WHY THIS MATTERS: malware checks in with its controller on a "
                    "timer, and that steady rhythm is its most reliable tell -- far "
                    "more than any single connection. A process keeping a metronome "
                    "to one external address deserves a look.\n\n"
                    "BENIGN EXPLANATION: plenty of good software polls on a schedule "
                    "-- an updater, a cloud sync, a messaging app keeping its "
                    "connection warm. Do you recognise the process and the address?\n\n"
                    "MALICIOUS EXPLANATION: the process is a script host or a binary "
                    "in a user-writable path, or the address is one you cannot place.\n\n"
                    "NEXT STEP: look up " + r["raddr"] + " by hand (a reputation "
                    "service, from your browser -- Hearth will not reach out for you). "
                    "If the process is unfamiliar, find it with `Get-Process` and "
                    "quarantine its binary."
                ),
                evidence={"process": r["process"], "path": r["path"], "raddr": r["raddr"],
                          "rport": r["rport"], "interval_min": max(1, period),
                          "samples": r["sample_count"], "regularity_cv": round(cv, 3)},
                mitre_id=self.mitre_id, mitre_name=self.mitre_name,
            ))
        return out


class NewExternalDestinationDetection(Detection):
    """A non-browser process reached an external address for the first time."""

    rule_id = "new_external_destination"
    name = "New external destination for a process"
    severity = "low"
    mitre_id = "T1071"
    mitre_name = "Application Layer Protocol"
    requires = "connection_endpoints: a first-seen external endpoint (host events)"
    blind_spots = (
        "Browsers and known sync/update processes are excluded -- they reach new "
        "addresses constantly and would drown this in noise -- so it only speaks "
        "up for the processes where a new destination is unusual. Needs a little "
        "history first, or every destination looks new. It sees that a connection "
        "was made, not what crossed it."
    )
    RECENT_S = 3600

    def evaluate(self, ctx: DetectionContext) -> list[Finding]:
        if ctx.in_learning_mode:
            return []
        rows = ctx.db.query(
            "SELECT process, path, raddr, rport, first_seen FROM connection_endpoints "
            "WHERE first_seen >= ?", (ctx.now - self.RECENT_S,))
        out = []
        for r in rows:
            if _is_known_good(r["process"], r["path"]):
                continue
            if not _is_public(r["raddr"] or ""):
                continue
            out.append(Finding(
                dedup_key="newdest:%s:%s:%s" % (r["process"], r["raddr"], r["rport"]),
                severity=self.severity,
                title="%s connected to a new address %s:%s" % (
                    r["process"], r["raddr"], r["rport"]),
                description=(
                    "'" + r["process"] + "' connected to " + r["raddr"] + ":" +
                    str(r["rport"]) + ", an external address it has not used before.\n\n"
                    "  Path     " + (r["path"] or "-") + "\n\n"
                    "WHY THIS MATTERS: a program that normally talks to a fixed set "
                    "of servers suddenly reaching a new one is how a compromise, or "
                    "a newly-installed component, first shows on the network.\n\n"
                    "BENIGN EXPLANATION: the app added a feature, moved to a new "
                    "server, used a CDN node it had not before, or you just started "
                    "using it.\n\n"
                    "MALICIOUS EXPLANATION: the process is a script host or lives in "
                    "a user-writable path, or the address is one you cannot place.\n\n"
                    "NEXT STEP: look the address up by hand. If it repeats on a timer "
                    "the beaconing rule will follow up; if the process is unfamiliar, "
                    "investigate it."
                ),
                evidence={"process": r["process"], "path": r["path"],
                          "raddr": r["raddr"], "rport": r["rport"]},
                mitre_id=self.mitre_id, mitre_name=self.mitre_name,
            ))
        return out


def network_rules() -> list[Detection]:
    return [
        BeaconingDetection(),
        NewExternalDestinationDetection(),
    ]
