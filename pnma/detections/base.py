"""Detection rule framework.

Design principles, each one a reaction to a way home-monitoring tools usually
go wrong:

**Rules read only unsolicited evidence.** Detector queries filter
``agent_generated = 0``. The agent's own ARP sweeps and nmap runs churn
MAC/IP bindings, and a detector that treats that churn as signal alerts on its
own footsteps. This is the single most common self-inflicted false positive in
tools of this kind.

**Every alert carries its reasoning.** A severity and a colour tell an operator
nothing. Each rule states what it saw, why that is suspicious, what the benign
explanation would be, and what to do next. If a rule cannot articulate the
benign explanation, it is not ready to ship.

**Confidence modulates severity.** Identity resolved from a randomised MAC with
no DHCP fingerprint is a guess (see :mod:`pnma.fingerprint`). Alerting at full
severity on a guess is how you teach yourself to ignore the dashboard.

**Every rule maps to MITRE ATT&CK.** Not decoration -- it is what lets a
finding be looked up, compared to other tooling, and discussed in the same
vocabulary a SOC uses.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..db import Database

log = logging.getLogger(__name__)

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def downgrade(severity: str, steps: int = 1) -> str:
    """Lower a severity, e.g. when identity confidence is poor."""
    idx = SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 2
    return SEVERITY_ORDER[max(0, idx - steps)]


def upgrade(severity: str, steps: int = 1) -> str:
    idx = SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 2
    return SEVERITY_ORDER[min(len(SEVERITY_ORDER) - 1, idx + steps)]


@dataclass
class Finding:
    """A single detection result, ready to be persisted as an alert."""

    dedup_key: str
    severity: str
    title: str
    description: str
    device_id: str | None = None
    evidence: dict = field(default_factory=dict)
    # Set by the rule class; carried here so the escalation playbook can read it.
    triggers_triage_scan: bool = False
    # Findings sharing a correlation_key describe the SAME underlying fact --
    # typically one open port seen by several rules. Only the most severe is
    # raised; see DetectionEngine._correlate.
    correlation_key: str | None = None
    # Per-finding ATT&CK technique, overriding the rule's class-level one.
    #
    # Most rules map to exactly one technique and set it on the class. Some do
    # not: a single host-posture rule can produce a finding about a cleared
    # event log (T1070.001), an unsigned driver (T1014) and SMB relay exposure
    # (T1557.001). Flattening those to the rule's generic technique throws away
    # the specificity that makes an ATT&CK mapping worth having at all, so a
    # finding may name its own. Falls back to the rule when None.
    mitre_id: str | None = None
    mitre_name: str | None = None


@dataclass
class DetectionContext:
    """Everything a rule needs that is not the database."""

    db: Database
    now: float = field(default_factory=time.time)
    # Suppress alerts for devices seen for the first time during the learning
    # window: on a fresh install every device is "new", and a wall of alerts on
    # day one trains the operator to dismiss them.
    learning_until: float = 0.0

    @property
    def in_learning_mode(self) -> bool:
        return self.now < self.learning_until


class Detection(ABC):
    """Base class for all detection rules."""

    rule_id: str = "abstract"
    name: str = "Abstract rule"
    severity: str = "medium"
    mitre_id: str | None = None
    mitre_name: str | None = None
    # What this rule cannot see. Stated explicitly because an honest account of
    # coverage gaps is more useful than an implied claim of completeness.
    blind_spots: str = ""

    @abstractmethod
    def evaluate(self, ctx: DetectionContext) -> list[Finding]:
        """Return findings. Must not mutate state; the engine persists."""

    def run(self, ctx: DetectionContext) -> list[Finding]:
        try:
            return self.evaluate(ctx)
        except Exception:  # noqa: BLE001 - one broken rule must not stop the rest
            log.exception("detection rule %s failed", self.rule_id)
            return []


class DetectionEngine:
    """Runs every rule and persists findings, with dedup handled by the DB."""

    def __init__(self, db: Database, rules: list[Detection], learning_window_h: int = 0):
        self.db = db
        self.rules = rules
        self.learning_window_h = learning_window_h
        self._started = time.time()
        self.last_run: float | None = None

    def run_all(self) -> list[Finding]:
        ctx = DetectionContext(
            db=self.db,
            learning_until=self._started + self.learning_window_h * 3600,
        )
        new_findings: list[Finding] = []

        collected: list[tuple[Detection, Finding]] = []
        for rule in self.rules:
            for finding in rule.run(ctx):
                collected.append((rule, finding))

        for rule, finding in self._correlate(collected):
                is_new = self.db.raise_alert(
                    dedup_key=finding.dedup_key,
                    rule_id=rule.rule_id,
                    severity=finding.severity,
                    title=finding.title,
                    description=finding.description,
                    device_id=finding.device_id,
                    mitre_id=finding.mitre_id or rule.mitre_id,
                    mitre_name=finding.mitre_name or rule.mitre_name,
                    evidence=finding.evidence,
                    ts=ctx.now,
                )
                if is_new:
                    new_findings.append(finding)
                    log.info(
                        "[%s] %s -- %s", finding.severity.upper(),
                        rule.rule_id, finding.title,
                    )

        self.last_run = ctx.now
        return new_findings

    def _correlate(
        self, collected: list[tuple[Detection, Finding]]
    ) -> list[tuple[Detection, Finding]]:
        """Collapse findings that describe the same underlying fact.

        Several rules legitimately look at the same evidence from different
        angles. One IoT device offering 5555/tcp trips the generic port-risk
        rule, the C2-indicator rule, and the class-baseline rule -- three alerts
        for one fact. Three alerts is not three times the information; it is
        one piece of information and two thirds of the operator's attention
        wasted. That is precisely how a dashboard trains its owner to ignore it.

        So findings that share a correlation_key are reduced to the most severe,
        and the ones that lost are folded into its evidence -- corroboration is
        recorded rather than discarded, because the fact that three independent
        rules agree is itself worth knowing.
        """
        groups: dict[str, list[tuple[Detection, Finding]]] = {}
        passthrough: list[tuple[Detection, Finding]] = []

        for rule, finding in collected:
            key = finding.correlation_key
            if key is None:
                passthrough.append((rule, finding))
            else:
                groups.setdefault(key, []).append((rule, finding))

        result = list(passthrough)
        for key, members in groups.items():
            if len(members) == 1:
                result.append(members[0])
                continue

            members.sort(
                key=lambda rf: SEVERITY_ORDER.index(rf[1].severity)
                if rf[1].severity in SEVERITY_ORDER
                else 0,
                reverse=True,
            )
            winner_rule, winner = members[0]
            others = members[1:]

            winner.evidence = dict(winner.evidence)
            winner.evidence["corroborating_rules"] = [
                {
                    "rule_id": r.rule_id,
                    "severity": f.severity,
                    "title": f.title,
                }
                for r, f in others
            ]
            # Independent agreement is a confidence signal, so say so in the
            # text rather than only in the evidence blob.
            winner.description += (
                "\n\nCORROBORATION: "
                + f"{len(others) + 1} independent detection rules flagged this "
                + "same observation ("
                + ", ".join([winner_rule.rule_id] + [r.rule_id for r, _ in others])
                + "), which raises confidence that it is real rather than an "
                + "artefact of any single rule."
            )
            # Any member wanting escalation escalates the survivor.
            winner.triggers_triage_scan = any(
                f.triggers_triage_scan for _, f in members
            )
            result.append((winner_rule, winner))

            # Retire alerts previously raised by the suppressed rules, so a
            # correlation change does not leave stale rows behind.
            for _, loser in others:
                self.db.execute(
                    "UPDATE alerts SET status = 'resolved' "
                    "WHERE dedup_key = ? AND status = 'open'",
                    (loser.dedup_key,),
                )

        return result

    def catalogue(self) -> list[dict]:
        """Machine-readable description of what this build can and cannot detect."""
        return [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "severity": r.severity,
                "mitre_id": r.mitre_id,
                "mitre_name": r.mitre_name,
                "blind_spots": r.blind_spots,
            }
            for r in self.rules
        ]
