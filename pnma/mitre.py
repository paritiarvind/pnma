"""ATT&CK technique resolution: ID -> name, tactic, and a link to read more.

**Why this ships a table instead of calling an API.**

The authoritative source is MITRE's own STIX bundle at
``github.com/mitre-attack/attack-stix-data`` (``enterprise-attack.json``, and
it is roughly 35 MB). Two reasons PNMA does not simply fetch it at runtime:

1. A security tool that phones out on startup is a security tool you have to
   justify to whoever runs it. Every other network action in this project is
   scoped, logged in ``scan_runs``, and re-authorised by the guard. A silent
   HTTPS fetch to GitHub would be the one exception, and "it's only metadata"
   is exactly the reasoning that puts telemetry in products nobody wanted.
2. The dashboard has to render when the internet is down, which on a home
   network monitoring tool is precisely when you are looking at it.

So the techniques PNMA actually emits are vendored below -- a few dozen rows,
checked by a test against the rule set so the two cannot drift apart. If you
want the full catalogue, :func:`load_stix_bundle` reads a bundle you have
downloaded yourself, and enriches the table in place. Opt-in, offline, and your
copy.

Tactic strings use MITRE's shortnames so they group the way the ATT&CK matrix
does, which is what makes a coverage view possible in the dashboard.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

ATTACK_URL = "https://attack.mitre.org/techniques/{path}/"


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]

    @property
    def url(self) -> str:
        # T1562.001 -> T1562/001 in the public URL scheme.
        return ATTACK_URL.format(path=self.id.replace(".", "/"))

    @property
    def parent_id(self) -> str:
        return self.id.split(".")[0]

    @property
    def is_subtechnique(self) -> bool:
        return "." in self.id


# Every technique referenced by a PNMA rule, network or host. Kept alphabetical
# by ID. tests/test_mitre.py asserts this covers the live rule set.
TECHNIQUES: dict[str, Technique] = {
    t.id: t
    for t in (
        Technique("T1014", "Rootkit", ("defense-evasion",)),
        Technique("T1021.002", "Remote Services: SMB/Windows Admin Shares",
                  ("lateral-movement",)),
        Technique("T1027", "Obfuscated Files or Information", ("defense-evasion",)),
        Technique("T1036", "Masquerading", ("defense-evasion",)),
        Technique("T1046", "Network Service Discovery", ("discovery",)),
        # Identity register (pnma/detections/identity_rules.py). These name the
        # technique an account gap makes cheap, not an observed attack.
        Technique("T1078", "Valid Accounts",
                  ("defense-evasion", "persistence", "privilege-escalation", "initial-access")),
        Technique("T1110.004", "Brute Force: Credential Stuffing", ("credential-access",)),
        Technique("T1556", "Modify Authentication Process",
                  ("credential-access", "defense-evasion", "persistence")),
        Technique("T1053.005", "Scheduled Task/Job: Scheduled Task",
                  ("execution", "persistence", "privilege-escalation")),
        Technique("T1059.003", "Command and Scripting Interpreter: Windows Command Shell",
                  ("execution",)),
        Technique("T1070.001", "Indicator Removal: Clear Windows Event Logs",
                  ("defense-evasion",)),
        Technique("T1136.001", "Create Account: Local Account", ("persistence",)),
        Technique("T1200", "Hardware Additions", ("initial-access",)),
        Technique("T1210", "Exploitation of Remote Services", ("lateral-movement",)),
        Technique("T1219", "Remote Access Software", ("command-and-control",)),
        Technique("T1498", "Network Denial of Service", ("impact",)),
        Technique("T1542.001", "Pre-OS Boot: System Firmware",
                  ("persistence", "defense-evasion")),
        Technique("T1543.003", "Create or Modify System Process: Windows Service",
                  ("persistence", "privilege-escalation")),
        Technique("T1546.003", "Event Triggered Execution: WMI Event Subscription",
                  ("persistence", "privilege-escalation")),
        Technique("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys",
                  ("persistence", "privilege-escalation")),
        Technique("T1547.004", "Boot or Logon Autostart Execution: Winlogon Helper DLL",
                  ("persistence", "privilege-escalation")),
        Technique("T1557.001",
                  "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay",
                  ("credential-access", "collection")),
        Technique("T1557.002", "Adversary-in-the-Middle: ARP Cache Poisoning",
                  ("credential-access", "collection")),
        Technique("T1562", "Impair Defenses", ("defense-evasion",)),
        Technique("T1562.001", "Impair Defenses: Disable or Modify Tools",
                  ("defense-evasion",)),
        Technique("T1562.002", "Impair Defenses: Disable Windows Event Logging",
                  ("defense-evasion",)),
        Technique("T1571", "Non-Standard Port", ("command-and-control",)),
        Technique("T1595", "Active Scanning", ("reconnaissance",)),
    )
}

# Display order matching the ATT&CK enterprise matrix, so a coverage view reads
# left to right the way an analyst expects rather than alphabetically.
TACTIC_ORDER = (
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
)

TACTIC_NAMES = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


def resolve(technique_id: str | None) -> Technique | None:
    """Look up a technique. Unknown IDs return None rather than raising.

    A rule referencing a technique this table does not carry is a gap in the
    table, not a reason to take the dashboard down.
    """
    if not technique_id:
        return None
    hit = TECHNIQUES.get(technique_id)
    if hit is None:
        log.debug("technique %s not in the vendored table", technique_id)
    return hit


def describe(technique_id: str | None) -> dict | None:
    """Resolve to a JSON-friendly dict for the API."""
    t = resolve(technique_id)
    if t is None:
        return {"id": technique_id, "name": None, "tactics": [], "url": None} if technique_id else None
    return {
        "id": t.id,
        "name": t.name,
        "tactics": [
            {"id": tac, "name": TACTIC_NAMES.get(tac, tac)} for tac in t.tactics
        ],
        "url": t.url,
        "is_subtechnique": t.is_subtechnique,
        "parent_id": t.parent_id if t.is_subtechnique else None,
    }


def coverage(technique_ids: list[str]) -> list[dict]:
    """Group observed techniques by tactic, in matrix order.

    Feeds the dashboard's coverage strip: which stages of an intrusion PNMA has
    actually seen evidence for, as opposed to which rules exist. An empty tactic
    is included deliberately -- the gaps are the interesting part.
    """
    by_tactic: dict[str, set[str]] = {t: set() for t in TACTIC_ORDER}
    unmapped: set[str] = set()

    for tid in technique_ids:
        t = resolve(tid)
        if t is None:
            if tid:
                unmapped.add(tid)
            continue
        for tac in t.tactics:
            by_tactic.setdefault(tac, set()).add(t.id)

    out = [
        {
            "tactic": tac,
            "name": TACTIC_NAMES.get(tac, tac),
            "techniques": sorted(by_tactic.get(tac, ())),
            "count": len(by_tactic.get(tac, ())),
        }
        for tac in TACTIC_ORDER
    ]
    if unmapped:
        out.append(
            {
                "tactic": "unmapped",
                "name": "Not in the local table",
                "techniques": sorted(unmapped),
                "count": len(unmapped),
            }
        )
    return out


# Severity -> layer colour. Deliberately not a red/green ramp: the point of a
# Navigator layer is to show *where* evidence sits on the matrix, and a scale
# that shades by confidence reads better than one that shouts.
_SEVERITY_COLOUR = {
    "critical": "#8c2f27",
    "high": "#c0563d",
    "medium": "#d99a3e",
    "low": "#7d92a8",
    "info": "#b8c0cc",
}


def navigator_layer(
    observed: list[tuple[str, str, int]],
    *,
    name: str = "PNMA coverage",
    description: str = "Techniques PNMA has raised open alerts for on this network.",
) -> dict:
    """Build an ATT&CK Navigator layer from ``(technique_id, severity, count)``.

    Navigator (``github.com/mitre-attack/attack-navigator``) renders this JSON
    directly onto the enterprise matrix. This is the honest way to answer "what
    does your tool cover": a layer file an analyst can open next to their own,
    rather than a screenshot of a list that cannot be diffed or challenged.

    Note what this layer means. A coloured cell is a technique PNMA has
    *actually raised an alert for*, not one it theoretically could. Colouring
    the rules rather than the findings would inflate the picture, which is the
    usual way vendor coverage maps mislead.
    """
    # Highest severity wins per technique; counts are summed across severities.
    rank = ["info", "low", "medium", "high", "critical"]
    best: dict[str, tuple[str, int]] = {}
    for tid, severity, count in observed:
        if not tid:
            continue
        prev = best.get(tid)
        sev = severity if severity in rank else "info"
        if prev is None:
            best[tid] = (sev, count)
        else:
            keep = sev if rank.index(sev) > rank.index(prev[0]) else prev[0]
            best[tid] = (keep, prev[1] + count)

    techniques = []
    for tid, (sev, count) in sorted(best.items()):
        t = resolve(tid)
        techniques.append(
            {
                "techniqueID": tid,
                "score": count,
                "color": _SEVERITY_COLOUR.get(sev, "#b8c0cc"),
                "comment": f"{count} open alert(s), highest severity: {sev}",
                "enabled": True,
                "metadata": [{"name": "severity", "value": sev}]
                + ([{"name": "technique", "value": t.name}] if t else []),
            }
        )

    return {
        "name": name,
        "versions": {"attack": "14", "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": description,
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#8c2f27"], "minValue": 0, "maxValue": 10},
        "legendItems": [
            {"label": label, "color": colour}
            for label, colour in _SEVERITY_COLOUR.items()
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "sorting": 3,
    }


def load_stix_bundle(path: str | Path) -> int:
    """Enrich :data:`TECHNIQUES` from a STIX bundle you downloaded yourself.

    Get one from https://github.com/mitre-attack/attack-stix-data --
    ``enterprise-attack/enterprise-attack.json``. Nothing here downloads it;
    that is your call to make, not the tool's.

    Returns the number of techniques added or updated. Existing entries are
    overwritten, so the bundle wins over the vendored table -- it is newer.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"STIX bundle not found: {p}")

    with p.open(encoding="utf-8") as fh:
        bundle = json.load(fh)

    added = 0
    for obj in bundle.get("objects", ()):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        ext = next(
            (
                r
                for r in obj.get("external_references", ())
                if r.get("source_name") == "mitre-attack"
            ),
            None,
        )
        if not ext or not ext.get("external_id"):
            continue

        tactics = tuple(
            ph.get("phase_name")
            for ph in obj.get("kill_chain_phases", ())
            if ph.get("kill_chain_name") == "mitre-attack" and ph.get("phase_name")
        )
        tid = ext["external_id"]
        TECHNIQUES[tid] = Technique(tid, obj.get("name", tid), tactics)
        added += 1

    log.info("loaded %d techniques from %s", added, p)
    return added
