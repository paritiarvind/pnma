"""Authentication-anomaly detections over the Windows Security log, adapted
from SEC555. These read `auth_events`, which the host-events collector fills
only when it runs elevated (see setup-elevated-collect.ps1); unelevated the
table stays empty and these rules simply find nothing -- honestly, not
falsely quiet, because the "Security event log readable" host fact says so.

The concepts (a wide-but-shallow spread of failed logons is a spray; a narrow-
but-deep one is a brute force; a new member of the Administrators group is
persistence) are standard; the implementation is our own aggregation over our
own rows.
"""

from __future__ import annotations

import json

from .base import Detection, DetectionContext, Finding

# Well-known SID and localised names of the local Administrators group.
_ADMIN_GROUP = {"S-1-5-32-544", "administrators", "administrateurs", "administratoren"}


def _detail(row) -> dict:
    try:
        return json.loads(row["detail"] or "{}")
    except (TypeError, ValueError):
        return {}


class BruteForceDetection(Detection):
    """Many failed logons against ONE account in a short window."""

    rule_id = "auth_brute_force"
    name = "Password brute force against an account"
    severity = "high"
    mitre_id = "T1110.001"
    mitre_name = "Brute Force: Password Guessing"
    requires = "Security log event 4625 (failed logon) -- needs the collector running elevated"
    blind_spots = (
        "Sees failures the local machine logged: attempts against this host's own "
        "accounts, not against a device that does its own auth (a NAS, the router). "
        "Lockout policy can stop the attack before the threshold is reached -- then "
        "the account_lockout rule is what fires instead. Cannot see a slow attack "
        "spread over days."
    )
    WINDOW_S = 600
    THRESHOLD = 8

    def evaluate(self, ctx: DetectionContext) -> list[Finding]:
        rows = ctx.db.query(
            "SELECT account, COUNT(*) n, MIN(ts) first, MAX(ts) last, "
            "       GROUP_CONCAT(DISTINCT source_ip) ips "
            "FROM auth_events WHERE event_id = 4625 AND ts >= ? AND account IS NOT NULL "
            "GROUP BY account HAVING n >= ? AND (MAX(ts) - MIN(ts)) <= ?",
            (ctx.now - self.WINDOW_S, self.THRESHOLD, self.WINDOW_S))
        out = []
        for r in rows:
            out.append(Finding(
                dedup_key="brute:%s:%d" % (r["account"], int(r["first"] // self.WINDOW_S)),
                severity=self.severity,
                title="%d failed logons for '%s' in %d min" % (
                    r["n"], r["account"], max(1, int((r["last"] - r["first"]) / 60))),
                description=(
                    "The account '" + r["account"] + "' had " + str(r["n"]) +
                    " failed logons in a short window" +
                    ((", from " + r["ips"]) if r["ips"] else "") + ".\n\n"
                    "WHY THIS MATTERS: repeated failures against one account is "
                    "password guessing. On a home machine this is unusual -- you "
                    "know your own password.\n\n"
                    "BENIGN EXPLANATION: you (or a family member) mistyped a "
                    "password several times, a saved credential went stale after a "
                    "change, or a mapped drive/service is retrying an old password.\n\n"
                    "MALICIOUS EXPLANATION: something is guessing, especially if the "
                    "source is a network address you do not recognise.\n\n"
                    "NEXT STEP: if it is not you, change that account's password from "
                    "another device, and check the source address in the "
                    "Investigation log. Enable an account lockout policy if none is set."
                ),
                evidence={"account": r["account"], "failures": r["n"],
                          "source_ips": (r["ips"] or "").split(","),
                          "window_min": max(1, int((r["last"] - r["first"]) / 60))},
                mitre_id=self.mitre_id, mitre_name=self.mitre_name,
            ))
        return out


class PasswordSprayDetection(Detection):
    """Failed logons spread ACROSS many accounts in a short window -- the
    inverse shape of brute force: wide and shallow."""

    rule_id = "auth_password_spray"
    name = "Password spray across accounts"
    severity = "high"
    mitre_id = "T1110.003"
    mitre_name = "Brute Force: Password Spraying"
    requires = "Security log event 4625 (failed logon) -- needs the collector running elevated"
    blind_spots = (
        "A single-user home machine usually has one or two accounts, so a spray "
        "(by definition many accounts) is rare here and, when it happens, striking. "
        "Same coverage limit as brute force: only this host's own accounts."
    )
    WINDOW_S = 900
    MIN_ACCOUNTS = 4
    MAX_PER_ACCOUNT = 5

    def evaluate(self, ctx: DetectionContext) -> list[Finding]:
        rows = ctx.db.query(
            "SELECT account, COUNT(*) n FROM auth_events "
            "WHERE event_id = 4625 AND ts >= ? AND account IS NOT NULL "
            "GROUP BY account", (ctx.now - self.WINDOW_S,))
        sprayed = [r for r in rows if r["n"] <= self.MAX_PER_ACCOUNT]
        if len(sprayed) < self.MIN_ACCOUNTS:
            return []
        accounts = sorted(r["account"] for r in sprayed)
        total = sum(r["n"] for r in sprayed)
        return [Finding(
            dedup_key="spray:%d" % int(ctx.now // self.WINDOW_S),
            severity=self.severity,
            title="Password spray: %d accounts with failed logons in %d min" % (
                len(accounts), self.WINDOW_S // 60),
            description=(
                str(len(accounts)) + " different accounts each had a few failed "
                "logons within " + str(self.WINDOW_S // 60) + " minutes (" +
                str(total) + " failures total): " + ", ".join(accounts[:12]) +
                (", ..." if len(accounts) > 12 else "") + ".\n\n"
                "WHY THIS MATTERS: trying one common password against many accounts, "
                "a few tries each, is spraying -- it stays under per-account lockout "
                "thresholds. Many accounts failing at once, few tries each, is its "
                "signature.\n\n"
                "BENIGN EXPLANATION: rare on a home machine. A misconfigured service "
                "or a backup tool cycling through several stored logins could do it.\n\n"
                "MALICIOUS EXPLANATION: an attacker enumerating accounts, or malware "
                "trying to move laterally.\n\n"
                "NEXT STEP: check the source address in the Investigation log, ensure "
                "accounts you do not use are disabled, and change passwords if any "
                "attempt could have succeeded."
            ),
            evidence={"accounts": accounts, "total_failures": total,
                      "window_min": self.WINDOW_S // 60},
            mitre_id=self.mitre_id, mitre_name=self.mitre_name,
        )]


class AccountLockoutDetection(Detection):
    """An account was locked out (4740)."""

    rule_id = "auth_account_lockout"
    name = "Account locked out"
    severity = "medium"
    mitre_id = "T1110"
    mitre_name = "Brute Force"
    requires = "Security log event 4740 (account lockout) -- needs the collector running elevated"
    blind_spots = "Only fires if a lockout policy exists; many home machines have none, in which case brute force runs unimpeded and the brute_force rule is the one to watch."

    def evaluate(self, ctx: DetectionContext) -> list[Finding]:
        rows = ctx.db.query(
            "SELECT id, ts, account, detail FROM auth_events "
            "WHERE event_id = 4740 AND ts >= ? ORDER BY ts DESC LIMIT 50",
            (ctx.now - 30 * 86400,))
        out = []
        for r in rows:
            d = _detail(r)
            caller = d.get("SubjectUserName") or d.get("TargetDomainName") or "?"
            out.append(Finding(
                dedup_key="lockout:%s" % r["id"],
                severity=self.severity,
                title="Account '%s' was locked out" % (r["account"] or "?"),
                description=(
                    "The account '" + (r["account"] or "?") + "' was locked out after "
                    "too many failed logons (the caller was recorded as '" + str(caller) + "').\n\n"
                    "WHY THIS MATTERS: a lockout means the failed-logon threshold was "
                    "reached -- either someone was guessing, or a stale credential is "
                    "retrying fast enough to trip it.\n\n"
                    "BENIGN EXPLANATION: a saved password went stale after a change and "
                    "a service or mapped drive kept retrying it.\n\n"
                    "MALICIOUS EXPLANATION: an active guessing attempt.\n\n"
                    "NEXT STEP: open the Investigation log for the minutes before the "
                    "lockout to see where the attempts came from; if unrecognised, "
                    "change the password from another device."
                ),
                evidence={"account": r["account"], "caller": caller},
                mitre_id=self.mitre_id, mitre_name=self.mitre_name,
            ))
        return out


class NewAdminMemberDetection(Detection):
    """A member was added to the local Administrators group (4732)."""

    rule_id = "auth_new_admin"
    name = "New member added to Administrators"
    severity = "high"
    mitre_id = "T1098"
    mitre_name = "Account Manipulation"
    requires = "Security log event 4732 (member added to a security-enabled local group) -- needs the collector running elevated"
    blind_spots = (
        "Sees the addition, not who really did it (the Subject is whatever process "
        "made the change). It fires on any addition to Administrators, including "
        "ones you make deliberately -- acknowledge those. It does not see a member "
        "added to a domain group (this is a local machine)."
    )

    def evaluate(self, ctx: DetectionContext) -> list[Finding]:
        rows = ctx.db.query(
            "SELECT id, ts, account, detail FROM auth_events "
            "WHERE event_id = 4732 AND ts >= ? ORDER BY ts DESC LIMIT 50",
            (ctx.now - 30 * 86400,))
        out = []
        for r in rows:
            d = _detail(r)
            group = (d.get("TargetUserName") or "").strip()
            group_sid = (d.get("TargetSid") or "").strip()
            if group.lower() not in _ADMIN_GROUP and group_sid not in _ADMIN_GROUP:
                continue
            member = d.get("MemberName") or d.get("MemberSid") or r["account"] or "?"
            who = d.get("SubjectUserName") or "?"
            out.append(Finding(
                dedup_key="newadmin:%s" % r["id"],
                severity=self.severity,
                title="'%s' was added to the Administrators group" % member,
                description=(
                    "'" + str(member) + "' was added to the local Administrators group "
                    "(the change was made by '" + str(who) + "').\n\n"
                    "WHY THIS MATTERS: local admin is full control of this machine. "
                    "Adding an account to it is exactly what an intruder does to keep "
                    "access, and exactly what you do when you set up a new admin user "
                    "-- the two look identical, so this always deserves a glance.\n\n"
                    "BENIGN EXPLANATION: you created or promoted an account on purpose.\n\n"
                    "MALICIOUS EXPLANATION: you did not, or the member/actor is one you "
                    "do not recognise.\n\n"
                    "NEXT STEP: `net localgroup Administrators` to see the members. If "
                    "the addition is not yours, remove it (`net localgroup "
                    "Administrators <name> /delete`), change your own password, and "
                    "treat the host as suspect until explained."
                ),
                evidence={"member": member, "group": group or group_sid, "actor": who},
                mitre_id=self.mitre_id, mitre_name=self.mitre_name,
            ))
        return out


def auth_rules() -> list[Detection]:
    return [
        BruteForceDetection(),
        PasswordSprayDetection(),
        AccountLockoutDetection(),
        NewAdminMemberDetection(),
    ]
