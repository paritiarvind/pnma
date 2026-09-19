"""Detection rules over the identity register.

Two rules, mirroring the host pair. The identity register is attested rather
than measured (see ``pnma.identity`` for why), so these rules never claim
more than the register does: a finding is "you told the agent this control is
wrong and have not fixed it", an unmeasured control is "nobody has looked, or
nobody has looked recently".

Why they produce *alerts* rather than staying a panel. An alert has a
lifecycle -- open, acknowledged, resolved -- and a count of how many runs it
has survived. A gap that has sat open for forty runs reads differently from
one that appeared this morning, and the alerts list is where the operator
already triages. The identity panel shows the state; the alert makes it
nag.

Techniques are the account-takeover pair: T1078 (Valid Accounts) for a
control whose absence makes a stolen credential sufficient, T1110 (Brute
Force) for password hygiene, T1556 (Modify Authentication Process) for
recovery paths an attacker would repoint. They are the *risk* the gap
exposes, not an observed attack -- the description says so.
"""

from __future__ import annotations

from .base import Detection, DetectionContext, Finding

CONTROL_TECHNIQUES: dict[str, tuple[str, str, str]] = {
    # control -> (severity when finding, mitre_id, mitre_name)
    "mfa": ("high", "T1078", "Valid Accounts"),
    "mfa_phishing_resistant": ("medium", "T1078", "Valid Accounts"),
    "password_unique": ("high", "T1110.004", "Brute Force: Credential Stuffing"),
    "recovery_reviewed": ("medium", "T1556", "Modify Authentication Process"),
    "sessions_reviewed": ("low", "T1078", "Valid Accounts"),
    "login_alerts": ("low", "T1078", "Valid Accounts"),
    "breach_exposure": ("high", "T1110.004", "Brute Force: Credential Stuffing"),
}


def _report(ctx: DetectionContext) -> dict:
    from .. import identity

    return identity.report(ctx.db)


class IdentityPostureDetection(Detection):
    """One alert per account control the operator has attested as wrong."""

    rule_id = "identity_posture"
    name = "Account security control not in place"
    severity = "medium"
    mitre_id = "T1078"
    mitre_name = "Valid Accounts"
    blind_spots = (
        "Entirely dependent on what the operator attested. It cannot see a "
        "provider silently disabling a control, a recovery address changed by "
        "an attacker, or an account that was never registered here. The HIBP "
        "check is the only measured control, and only for handles that were "
        "supplied."
    )

    def evaluate(self, ctx: DetectionContext) -> list[Finding]:
        findings: list[Finding] = []
        for acc in _report(ctx)["accounts"]:
            for c in acc["controls"]:
                if c["state"] != "finding":
                    continue
                severity, mitre_id, mitre_name = CONTROL_TECHNIQUES.get(
                    c["control"], ("medium", "T1078", "Valid Accounts")
                )
                findings.append(
                    Finding(
                        dedup_key=f"identity_posture:{acc['account_id']}:{c['control']}",
                        severity=severity,
                        title=f"{acc['label']}: {c['title']}",
                        description=(
                            f"{c['reason'] or 'Attested as not in place.'}\n\n"
                            f"EXPECTED: {c['expected']}\n"
                            f"SOURCE: {c['source']}\n\n"
                            "This is a gap in one of your own accounts, recorded "
                            "by you (or by a breach lookup), not an observed "
                            "attack. The ATT&CK mapping names the technique the "
                            "gap makes cheap."
                        ),
                        evidence={
                            "account_id": acc["account_id"],
                            "provider": acc["provider"],
                            "category": acc["category"],
                            "control": c["control"],
                            "value": c["value"],
                            "attested_at": c["attested_at"],
                            "evidence": c["evidence"],
                        },
                        mitre_id=mitre_id,
                        mitre_name=mitre_name,
                    )
                )
        return findings


class UnreviewedAccountDetection(Detection):
    """One alert per account with controls nobody has attested, or whose
    attestations have aged past the review window. Never per control: an
    account that was never reviewed would otherwise open seven alerts at once,
    and the fix is one sitting, not seven."""

    rule_id = "identity_unreviewed"
    name = "Account has unreviewed security controls"
    severity = "low"
    mitre_id = "T1078"
    mitre_name = "Valid Accounts"
    blind_spots = (
        "Fires only for accounts that were registered. The accounts that most "
        "need reviewing are usually the ones nobody remembered to add."
    )

    def evaluate(self, ctx: DetectionContext) -> list[Finding]:
        findings: list[Finding] = []
        for acc in _report(ctx)["accounts"]:
            unknown = [c for c in acc["controls"] if c["state"] == "unknown"]
            if not unknown:
                continue
            stale = [c for c in unknown if c["stale"]]
            never = [c for c in unknown if c["attested_at"] is None]
            findings.append(
                Finding(
                    dedup_key=f"identity_unreviewed:{acc['account_id']}",
                    # Stale is louder than never: something *was* known and has
                    # been allowed to lapse.
                    severity="medium" if stale else "low",
                    title=f"{acc['label']}: {len(unknown)} of {len(acc['controls'])} controls unreviewed",
                    description=(
                        f"{len(never)} never attested, {len(stale)} attested more than "
                        f"{acc['review_days']} days ago.\n\n"
                        "Unknown is not a pass. Until each control is attested the "
                        "agent reports it as a gap, the same way it reports a host "
                        "check that could not run.\n\n"
                        "Review: " + ", ".join(c["title"] for c in unknown)
                    ),
                    evidence={
                        "account_id": acc["account_id"],
                        "never": [c["control"] for c in never],
                        "stale": [c["control"] for c in stale],
                        "review_days": acc["review_days"],
                    },
                )
            )
        return findings


def identity_rules() -> list[Detection]:
    return [IdentityPostureDetection(), UnreviewedAccountDetection()]
