"""Detection rules over host posture, as opposed to network observations.

These read the ``host_facts`` table that :mod:`pnma.collectors.host_windows`
populates. They exist because a monitoring agent that watches every device on
the network except the one it runs on has an obvious blind spot, and because
the machine running the collector is usually the most valuable host on a home
LAN -- it holds the credentials, the source code, and the monitoring data.

**Two rules that most posture tools do not have.**

The first is :class:`UnmeasuredControlDetection`. Every other rule here fires
on a control being *wrong*; that one fires on a control being *unmeasured*. It
exists because of a concrete incident: a Security-log query returned "No events
were found" when the real answer was "access denied", and a review drew a false
negative from it. Silence is not evidence, and a posture dashboard that renders
unmeasured as passing is worse than no dashboard because it manufactures
confidence. So "we could not look" is itself a finding, at low severity,
because the fix is usually just re-running elevated.

The second is :class:`ControlDisabledDetection`. A control that has *always*
been off is technical debt. A control that was on last week and is off now is
an event, and possibly the first move of an intrusion. The ``changed_at``
column in ``host_facts`` is what makes the distinction available, and this rule
is the only thing that reads it.
"""

from __future__ import annotations

from .base import Detection, DetectionContext, Finding

# Facts that map onto a specific ATT&CK technique when they come back as a
# finding. Anything not listed here still surfaces on the dashboard; it just
# does not raise an alert on its own.
#
# (fact_key, severity, mitre_id, mitre_name)
FACT_TECHNIQUES: dict[str, tuple[str, str, str]] = {
    "defender.tamper_protection": (
        "medium",
        "T1562.001",
        "Impair Defenses: Disable or Modify Tools",
    ),
    "defender.realtime": (
        "critical",
        "T1562.001",
        "Impair Defenses: Disable or Modify Tools",
    ),
    "defender.exclusions": (
        "high",
        "T1562.001",
        "Impair Defenses: Disable or Modify Tools",
    ),
    "defender.pua": (
        "low",
        "T1562.001",
        "Impair Defenses: Disable or Modify Tools",
    ),
    "powershell.script_block": (
        "medium",
        "T1562.002",
        "Impair Defenses: Disable Windows Event Logging",
    ),
    "audit.cmdline": (
        "medium",
        "T1562.002",
        "Impair Defenses: Disable Windows Event Logging",
    ),
    "audit.policy": (
        "medium",
        "T1562.002",
        "Impair Defenses: Disable Windows Event Logging",
    ),
    "audit.log_cleared_security": (
        "critical",
        "T1070.001",
        "Indicator Removal: Clear Windows Event Logs",
    ),
    "audit.log_cleared_system": (
        "high",
        "T1070.001",
        "Indicator Removal: Clear Windows Event Logs",
    ),
    "drivers.unsigned": ("high", "T1014", "Rootkit"),
    "persistence.system_tasks": (
        "medium",
        "T1053.005",
        "Scheduled Task/Job: Scheduled Task",
    ),
    "network.smb_signing": (
        "medium",
        "T1557.001",
        "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay",
    ),
    "network.smb1": ("high", "T1210", "Exploitation of Remote Services"),
    "network.smb_reachable": (
        "medium",
        "T1021.002",
        "Remote Services: SMB/Windows Admin Shares",
    ),
}


class HostPostureDetection(Detection):
    """One alert per host control that is measurably in the wrong state."""

    rule_id = "host_posture"
    name = "Host security control misconfigured"
    severity = "medium"
    mitre_id = "T1562"
    mitre_name = "Impair Defenses"
    blind_spots = (
        "Reads only what the collector could measure. A control this rule "
        "reports as fine may simply be one nobody checked -- see the "
        "unmeasured_control rule, which is the other half of this picture. "
        "It also cannot tell a deliberate configuration choice from an "
        "attacker's change; only changed_at hints at that, and only if the "
        "collector was running before the change."
    )

    def evaluate(self, ctx: DetectionContext) -> list[Finding]:
        rows = ctx.db.query(
            "SELECT fact_key, title, state, value, expected, reason, needs_admin "
            "FROM host_facts WHERE state = 'finding'"
        )

        findings: list[Finding] = []
        for row in rows:
            spec = FACT_TECHNIQUES.get(row["fact_key"])
            if spec is None:
                continue
            severity, mitre_id, mitre_name = spec

            findings.append(
                Finding(
                    dedup_key=f"host_posture:{row['fact_key']}",
                    severity=severity,
                    title=f"Host control: {row['title']}",
                    description=(
                        f"{row['reason'] or 'This control is not in the expected state.'}\n\n"
                        f"MEASURED: {row['value']}\n"
                        f"EXPECTED: {row['expected']}\n\n"
                        "This is a finding about the monitoring host itself, not "
                        "about a device on the network. PNMA watches every other "
                        "device on this LAN; this rule exists so it does not "
                        "exempt the machine it runs on."
                    ),
                    evidence={
                        "fact_key": row["fact_key"],
                        "measured": row["value"],
                        "expected": row["expected"],
                        "needs_admin": bool(row["needs_admin"]),
                    },
                    # Per-finding technique. This rule spans several: a cleared
                    # event log is T1070.001, an unsigned driver is T1014, SMB
                    # relay exposure is T1557.001. The class-level T1562 would
                    # flatten all of them into "Impair Defenses", which is true
                    # of almost none of them.
                    mitre_id=mitre_id,
                    mitre_name=mitre_name,
                    # Host facts describe this machine, and several map to the
                    # same underlying weakness (Defender being modifiable covers
                    # tamper protection AND exclusions). Correlate per fact only
                    # -- collapsing across controls would hide remediation steps.
                    correlation_key=f"host:{row['fact_key']}",
                )
            )
        return findings


class UnmeasuredControlDetection(Detection):
    """Fires when checks could not run at all. Silence is not evidence.

    Deliberately low severity: the usual fix is re-running the collector from
    an elevated prompt, not an incident response. But it must be *visible*,
    because the failure mode this guards against is a clean-looking dashboard
    that is clean only because nobody could look.
    """

    rule_id = "unmeasured_control"
    name = "Host security controls could not be measured"
    severity = "low"
    mitre_id = "T1562.002"
    mitre_name = "Impair Defenses: Disable Windows Event Logging"
    blind_spots = (
        "Cannot distinguish 'not elevated' from 'a check is genuinely broken' "
        "beyond the reason string the collector recorded. It also cannot see "
        "checks nobody wrote: a control absent from the collector produces no "
        "row at all, and this rule only counts rows that exist."
    )

    # One alert for the whole set rather than one per unmeasured control. A
    # wall of "could not check X" alerts is precisely the noise this project
    # spends its correlation logic trying to avoid.
    MIN_TO_ALERT = 1

    def evaluate(self, ctx: DetectionContext) -> list[Finding]:
        rows = ctx.db.query(
            "SELECT fact_key, title, reason, needs_admin FROM host_facts "
            "WHERE state = 'unknown'"
        )
        if len(rows) < self.MIN_TO_ALERT:
            return []

        needs_admin = [r for r in rows if r["needs_admin"]]
        listing = "\n".join(f"  - {r['title']}" for r in rows)

        if needs_admin and len(needs_admin) == len(rows):
            headline = (
                f"{len(rows)} host security checks could not run because the "
                "collector is not elevated."
            )
            next_step = (
                "NEXT STEP: re-run the collector from an elevated prompt. Every "
                "one of these becomes a real answer."
            )
        else:
            headline = f"{len(rows)} host security checks could not run."
            next_step = (
                "NEXT STEP: read the recorded reason for each. Some need "
                "elevation; any that do not indicate a broken check."
            )

        return [
            Finding(
                # Stable key: one standing "unmeasured" alert whose count and
                # listing REFRESH as the set changes, not a new alert each time
                # a control moves in or out of the unknown set (that was the
                # churn -- '3 unmeasured', then '4', then '1', all left open).
                dedup_key="unmeasured:host",
                severity="low",
                title=f"{len(rows)} host controls unmeasured",
                description=(
                    f"{headline}\n\n"
                    f"{listing}\n\n"
                    "WHY THIS IS AN ALERT AND NOT A FOOTNOTE: a check that could "
                    "not run looks identical to a check that passed unless "
                    "something insists on the difference. During the host review "
                    "this project was built from, a Security-log query returned "
                    "'No events were found' when the true answer was 'access "
                    "denied' -- and the first draft of that report recorded a "
                    "false negative as a result.\n\n"
                    f"{next_step}"
                ),
                evidence={
                    "unmeasured": [r["fact_key"] for r in rows],
                    "needs_admin": len(needs_admin),
                    "total": len(rows),
                },
            )
        ]


class ControlDisabledDetection(Detection):
    """A control that *changed* to a bad state, as distinct from always being bad.

    Debt is a control that has been off since install. An event is a control
    that was on and is now off. Only the second one might be an intrusion, and
    only ``changed_at`` can tell them apart -- so this rule is deliberately
    separate from :class:`HostPostureDetection` and rated higher.
    """

    rule_id = "control_disabled"
    name = "Host security control was turned off"
    severity = "high"
    mitre_id = "T1562.001"
    mitre_name = "Impair Defenses: Disable or Modify Tools"
    blind_spots = (
        "Only sees changes that happened between two collector runs. A control "
        "disabled and re-enabled between runs is invisible, and a control that "
        "was already off when PNMA was first installed has no changed_at and "
        "will never fire here -- it shows up as debt in host_posture instead."
    )

    # Only a transition into these states is interesting. A control coming back
    # ON is good news and does not warrant an alert.
    WATCHED_STATES = ("finding",)

    def evaluate(self, ctx: DetectionContext) -> list[Finding]:
        rows = ctx.db.query(
            "SELECT fact_key, title, state, value, reason, changed_at "
            "FROM host_facts "
            "WHERE changed_at IS NOT NULL AND state = 'finding' "
            "  AND changed_at > ?",
            (ctx.now - 86400 * 7,),
        )

        findings: list[Finding] = []
        for row in rows:
            spec = FACT_TECHNIQUES.get(row["fact_key"])
            severity = "high"
            mitre_id, mitre_name = self.mitre_id, self.mitre_name
            if spec:
                # Take the technique from the fact, but never lower the severity
                # -- a change is more interesting than the steady state.
                _, mitre_id, mitre_name = spec

            findings.append(
                Finding(
                    dedup_key=f"control_disabled:{row['fact_key']}:{int(row['changed_at'])}",
                    severity=severity,
                    title=f"CHANGED: {row['title']} is no longer in the expected state",
                    description=(
                        f"This control was previously fine and is now not.\n\n"
                        f"NOW: {row['value']}\n"
                        f"{row['reason'] or ''}\n\n"
                        "BENIGN EXPLANATION: someone changed a setting, or a "
                        "software update reset it.\n\n"
                        "MALICIOUS EXPLANATION: disabling defences is an early "
                        "step in most intrusions, and it is done precisely "
                        "because it is rarely noticed. Establish who changed "
                        "this and when before assuming the benign reading."
                    ),
                    evidence={
                        "fact_key": row["fact_key"],
                        "changed_at": row["changed_at"],
                        "current_value": row["value"],
                    },
                    mitre_id=mitre_id,
                    mitre_name=mitre_name,
                    correlation_key=f"host:{row['fact_key']}",
                )
            )
        return findings


def host_rules() -> list[Detection]:
    """Every host posture rule, in the order they should run."""
    return [
        HostPostureDetection(),
        ControlDisabledDetection(),
        UnmeasuredControlDetection(),
    ]
