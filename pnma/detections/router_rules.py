"""Detections over the router's own logs (pnma.collectors.maillog parses the
router's syslog into ``router_events``). The router is the most important
device on a home network -- everything leaves through it, and whoever controls
it controls the network -- yet its events were being stored and shown in the
log without ever raising an alert. These rules close that gap.

They fire only when the router is configured to forward syslog to the mailbox
PNMA reads (see the router-logs setup); until then the table stays empty and
these rules honestly find nothing.
"""

from __future__ import annotations

from .base import Detection, DetectionContext, Finding

# Per-kind detail: which events are worth an alert, their technique, and the
# plain-language why/benign/malicious/next-step. dhcp_lease is deliberately
# excluded -- every device getting an address is not an incident.
_KINDS = {
    "firewall_event": {
        "mitre": ("T1595", "Active Scanning"),
        "why": "the router's own firewall flagged an attack, scan or flood aimed at your network -- something on the internet is probing or hitting your connection",
        "benign": "a noisy internet scan hitting your public IP (constant background on any connection), or your own heavy traffic tripping a DoS heuristic",
        "malicious": "the source repeats, targets a forwarded port, or coincides with a device on your LAN starting to behave oddly",
        "next": "note the source IP; if a port is forwarded to a device, make sure that device is patched. Repeated targeted hits are worth blocking at the router.",
    },
    "config_change": {
        "mitre": ("T1601", "Modify System Image"),
        "why": "the router's configuration or firmware changed -- a settings change, reboot or firmware update on the device that controls your whole network",
        "benign": "you changed a setting, applied a firmware update, or rebooted it; an ISP-managed router may update on its own",
        "malicious": "you changed nothing, and especially if it pairs with an admin login you do not recognise -- an intruder who owns the router can redirect all your traffic",
        "next": "open the router admin page and check DNS servers, port forwarding / DMZ, remote-management, and the firmware version. Confirm each is what you set.",
    },
    "admin_login": {
        "mitre": ("T1078", "Valid Accounts"),
        "why": "someone logged in to the router's admin interface -- full control of the network's gateway",
        "benign": "you (or a family member) signed in to change a setting",
        "malicious": "you did not, or the source address is not a device on your LAN -- a login from the internet side is especially serious",
        "next": "if it was not you, change the router admin password immediately (a long unique one), disable remote/WAN management, and update the firmware.",
    },
    "wan_event": {
        "mitre": (None, None),
        "why": "the router's internet (WAN) link changed state -- it went up or down",
        "benign": "an ISP blip, a reboot, or a line fault -- almost always operational, not security",
        "malicious": "repeated flaps coinciding with other findings could indicate interference, but on its own this is context, not an incident",
        "next": "if it keeps dropping, it is an ISP/line issue. Nothing to do here unless it lines up with something else.",
    },
}


class RouterEventDetection(Detection):
    rule_id = "router_event"
    name = "Notable event on the router"
    severity = "medium"
    mitre_id = "T1601"
    mitre_name = "Modify System Image"
    requires = ("router_events parsed from the router's syslog -- needs the router configured to "
                "forward syslog to the mailbox PNMA reads (router-logs setup); empty until then")
    blind_spots = (
        "Only as good as what the router logs and how its syslog is worded -- the parser matches "
        "common phrasings, so a router that logs an admin login or a config change in unusual "
        "language can be missed. It cannot see a change made through a cloud/app management channel "
        "that never touches the local syslog. dhcp_lease events are recorded for context but not "
        "alerted (every device getting an address is not an incident)."
    )
    WINDOW_S = 24 * 3600

    def evaluate(self, ctx: DetectionContext) -> list[Finding]:
        rows = ctx.db.query(
            "SELECT id, ts, kind, severity, title, ip, mac, line FROM router_events "
            "WHERE ts >= ? AND severity IS NOT NULL AND kind IN "
            "('firewall_event','config_change','admin_login','wan_event') "
            "ORDER BY ts DESC LIMIT 100",
            (ctx.now - self.WINDOW_S,),
        )
        out: list[Finding] = []
        for r in rows:
            info = _KINDS.get(r["kind"])
            if not info:
                continue
            mitre_id, mitre_name = info["mitre"]
            src = (" from " + r["ip"]) if r["ip"] else ""
            out.append(Finding(
                dedup_key=f"router:{r['kind']}:{r['id']}",
                severity=r["severity"] or self.severity,
                title=r["title"] + src,
                description=(
                    r["title"] + src + ".\n\n"
                    "  Log line  " + (r["line"] or "")[:200] + "\n\n"
                    "WHY THIS MATTERS: " + info["why"] + ".\n\n"
                    "BENIGN EXPLANATION: " + info["benign"] + ".\n\n"
                    "MALICIOUS EXPLANATION: " + info["malicious"] + ".\n\n"
                    "NEXT STEP: " + info["next"]
                ),
                evidence={"kind": r["kind"], "source_ip": r["ip"], "mac": r["mac"], "line": r["line"]},
                mitre_id=mitre_id or self.mitre_id,
                mitre_name=mitre_name or self.mitre_name,
            ))
        return out


def router_rules() -> list[Detection]:
    return [RouterEventDetection()]
