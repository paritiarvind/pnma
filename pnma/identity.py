"""Identity posture: the operator's own accounts, as a three-valued register.

Network and host monitoring answer "what is on my network" and "is the machine
I run on sound". Neither says anything about the identities that actually get
attacked -- the mailbox every password reset flows through, the social
accounts a phisher would clone. This module extends PNMA's posture model to
those, under the same rule as ``host_facts``: **a control nobody has checked is
``unknown``, and unknown never renders as passing.**

Why it is an attestation register and not an integration. Reading MFA state
out of Google or Meta means OAuth scopes, refresh tokens on disk, and a
dependency on vendor APIs that change without notice -- a separate product,
and one whose credential store would itself be the juiciest thing on the host.
Instead the operator records what they verified and when, and the record
*rots*: an attestation older than ``review_days`` degrades to ``unknown`` with
the reason spelled out. That is the honest shape of "I checked this in March".

One live lookup is offered because it needs no delegated access: Have I Been
Pwned. The breached-account API requires a key (stored via ``pnma.secrets``);
the pwned-password range API needs none and is k-anonymous -- only the first
five hex characters of the SHA-1 leave the machine.

Scope: accounts the operator owns. There is deliberately no way to register
someone else's handle for monitoring; the CLI takes no consent flag because
no flag would make it acceptable.
"""

from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .db import Database

# The controls the register knows about, in the order the dashboard shows
# them. `manual` controls are attested; `hibp` ones are measured by lookup.
CONTROLS: dict[str, dict[str, str]] = {
    "mfa": {
        "title": "Multi-factor authentication on",
        "expected": "any second factor; see phishing-resistant below",
        "source": "manual",
    },
    "mfa_phishing_resistant": {
        "title": "Phishing-resistant factor (passkey / security key)",
        "expected": "a passkey or FIDO2 key enrolled; SMS and TOTP do not count",
        "source": "manual",
    },
    "password_unique": {
        "title": "Unique password held in a manager",
        "expected": "generated, not reused anywhere",
        "source": "manual",
    },
    "recovery_reviewed": {
        "title": "Recovery email / phone reviewed",
        "expected": "only addresses and numbers you still control",
        "source": "manual",
    },
    "sessions_reviewed": {
        "title": "Active sessions and connected apps reviewed",
        "expected": "no unrecognised devices or third-party grants",
        "source": "manual",
    },
    "login_alerts": {
        "title": "New-login alerts enabled",
        "expected": "notification on sign-in from a new device",
        "source": "manual",
    },
    "breach_exposure": {
        "title": "No unaddressed breach exposure",
        "expected": "no breach newer than the last password change",
        "source": "hibp",
    },
}

PROVIDERS = ("google", "apple", "microsoft", "meta", "x", "github", "bank", "other")
CATEGORIES = ("email", "social", "finance", "dev", "cloud", "other")
STATES = ("ok", "finding", "unknown")

HIBP_BREACHED = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
HIBP_RANGE = "https://api.pwnedpasswords.com/range/{prefix}"
USER_AGENT = "PNMA/0.1 (personal network monitoring agent; identity posture)"


# -- accounts ---------------------------------------------------------------


def add_account(
    db: Database,
    account_id: str,
    *,
    provider: str,
    category: str,
    label: str,
    handle: str | None = None,
    review_days: int = 90,
    notes: str | None = None,
) -> None:
    if provider not in PROVIDERS:
        raise ValueError(f"provider must be one of {', '.join(PROVIDERS)}")
    if category not in CATEGORIES:
        raise ValueError(f"category must be one of {', '.join(CATEGORIES)}")
    db.execute(
        "INSERT INTO identity_accounts(account_id, provider, category, label, handle, "
        "review_days, notes, created_at) VALUES (?,?,?,?,?,?,?,?) "
        "ON CONFLICT(account_id) DO UPDATE SET provider=excluded.provider, "
        "category=excluded.category, label=excluded.label, handle=excluded.handle, "
        "review_days=excluded.review_days, notes=excluded.notes",
        (account_id, provider, category, label, handle, review_days, notes, time.time()),
    )


def remove_account(db: Database, account_id: str) -> bool:
    db.execute("DELETE FROM identity_facts WHERE account_id = ?", (account_id,))
    cur = db.execute("DELETE FROM identity_accounts WHERE account_id = ?", (account_id,))
    return cur.rowcount > 0


def attest(
    db: Database,
    account_id: str,
    control: str,
    state: str,
    *,
    value: str | None = None,
    reason: str | None = None,
    source: str = "attested",
    evidence: dict[str, Any] | None = None,
) -> bool:
    """Record a control's state. Returns True when the state changed.

    Same contract as ``Database.record_host_fact``: a re-attestation that
    changes nothing refreshes ``attested_at`` (the review clock) but leaves
    ``changed_at`` alone, so the dashboard can tell "still fine" from "fixed".
    """
    if control not in CONTROLS:
        raise ValueError(f"control must be one of {', '.join(CONTROLS)}")
    if state not in STATES:
        raise ValueError("state must be ok, finding or unknown")
    if db.query_one("SELECT 1 FROM identity_accounts WHERE account_id = ?", (account_id,)) is None:
        raise KeyError(f"no such account {account_id!r}; add it first")
    now = time.time()
    prev = db.query_one(
        "SELECT state FROM identity_facts WHERE account_id = ? AND control = ?",
        (account_id, control),
    )
    changed = prev is None or prev["state"] != state
    db.execute(
        "INSERT INTO identity_facts(account_id, control, state, value, reason, source, "
        "evidence, attested_at, changed_at) VALUES (?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(account_id, control) DO UPDATE SET state=excluded.state, "
        "value=excluded.value, reason=excluded.reason, source=excluded.source, "
        "evidence=excluded.evidence, attested_at=excluded.attested_at, "
        "changed_at=CASE WHEN identity_facts.state != excluded.state "
        "THEN excluded.attested_at ELSE identity_facts.changed_at END",
        (
            account_id, control, state, value, reason, source,
            json.dumps(evidence or {}), now, now if changed else None,
        ),
    )
    return changed


# -- reading ----------------------------------------------------------------


def report(db: Database, now: float | None = None) -> dict[str, Any]:
    """Every account with every control, staleness applied.

    A control is returned in the state it was attested *unless* the
    attestation is older than the account's ``review_days``, in which case it
    is reported as ``unknown`` with the original state kept in ``attested_state``.
    Controls never attested are ``unknown`` too. Both are gaps, and the
    summary counts them as such.
    """
    now = now or time.time()
    accounts = [dict(r) for r in db.query(
        "SELECT * FROM identity_accounts ORDER BY category, label"
    )]
    facts = {}
    for r in db.query("SELECT * FROM identity_facts"):
        facts[(r["account_id"], r["control"])] = dict(r)

    out = []
    totals = {"ok": 0, "finding": 0, "unknown": 0, "stale": 0, "never": 0}
    for acc in accounts:
        controls = []
        counts = {"ok": 0, "finding": 0, "unknown": 0}
        for key, meta in CONTROLS.items():
            f = facts.get((acc["account_id"], key))
            if f is None:
                c = {
                    "control": key, "title": meta["title"], "expected": meta["expected"],
                    "state": "unknown", "attested_state": None, "reason": "never attested",
                    "source": meta["source"], "value": None, "attested_at": None,
                    "changed_at": None, "stale": False, "evidence": {},
                }
                totals["never"] += 1
            else:
                age_days = (now - f["attested_at"]) / 86400
                stale = age_days > acc["review_days"]
                try:
                    ev = json.loads(f["evidence"]) if f["evidence"] else {}
                except (TypeError, ValueError):
                    ev = f["evidence"]
                c = {
                    "control": key, "title": meta["title"], "expected": meta["expected"],
                    "state": "unknown" if stale else f["state"],
                    "attested_state": f["state"],
                    "reason": (
                        f"attestation is {age_days:.0f} days old; review window is "
                        f"{acc['review_days']} days"
                        if stale else f["reason"]
                    ),
                    "source": f["source"], "value": f["value"],
                    "attested_at": f["attested_at"], "changed_at": f["changed_at"],
                    "stale": stale, "evidence": ev,
                }
                if stale:
                    totals["stale"] += 1
            counts[c["state"]] += 1
            totals[c["state"]] += 1
            controls.append(c)
        acc["controls"] = controls
        acc["counts"] = counts
        out.append(acc)

    return {
        "summary": {
            "accounts": len(out),
            "controls": len(out) * len(CONTROLS),
            **totals,
        },
        "controls": [dict(control=k, **v) for k, v in CONTROLS.items()],
        "accounts": out,
    }


# -- Have I Been Pwned -------------------------------------------------------


def _http_get(url: str, headers: dict[str, str], timeout: float = 15.0) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https hosts
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def pwned_password_count(password: str) -> int:
    """k-anonymous range query. Only the first 5 hex chars of the SHA-1 leave
    the machine; the password itself is neither stored nor logged."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324 - HIBP protocol
    prefix, suffix = digest[:5], digest[5:]
    status, body = _http_get(HIBP_RANGE.format(prefix=prefix), {"Add-Padding": "true"})
    if status != 200:
        raise RuntimeError(f"pwnedpasswords range API returned {status}")
    for line in body.splitlines():
        h, _, n = line.strip().partition(":")
        if h == suffix:
            return int(n or 0)
    return 0


def check_breaches(db: Database, account_id: str, api_key: str | None) -> dict[str, Any]:
    """Look the account's handle up in HIBP and record `breach_exposure`.

    No key, no handle, or an API error all record ``unknown`` with the reason
    -- the check *could not run*, which is a different fact from "no breaches".
    """
    acc = db.query_one("SELECT * FROM identity_accounts WHERE account_id = ?", (account_id,))
    if acc is None:
        raise KeyError(f"no such account {account_id!r}")
    if not acc["handle"]:
        attest(db, account_id, "breach_exposure", "unknown",
               reason="account has no handle to look up", source="hibp")
        return {"state": "unknown", "reason": "no handle"}
    if not api_key:
        attest(db, account_id, "breach_exposure", "unknown",
               reason="no HIBP API key: pnma secrets set hibp_api_key", source="hibp")
        return {"state": "unknown", "reason": "no api key"}

    url = HIBP_BREACHED.format(account=urllib.parse.quote(acc["handle"])) + "?truncateResponse=false"
    status, body = _http_get(url, {"hibp-api-key": api_key})
    if status == 404:
        attest(db, account_id, "breach_exposure", "ok", value="0 breaches",
               reason="HIBP has no breach containing this handle", source="hibp",
               evidence={"checked_at": time.time()})
        return {"state": "ok", "breaches": []}
    if status != 200:
        attest(db, account_id, "breach_exposure", "unknown",
               reason=f"HIBP returned HTTP {status}", source="hibp")
        return {"state": "unknown", "reason": f"http {status}"}

    breaches = json.loads(body)
    names = sorted(
        ((b.get("Name"), b.get("BreachDate"), b.get("DataClasses", [])) for b in breaches),
        key=lambda t: t[1] or "", reverse=True,
    )
    latest = names[0][1] if names else "-"
    attest(
        db, account_id, "breach_exposure", "finding",
        value=f"{len(names)} breaches, latest {latest}",
        reason="handle appears in breach corpora; rotate the password if it predates the latest",
        source="hibp",
        evidence={"breaches": [
            {"name": n, "date": d, "data": c} for n, d, c in names
        ], "checked_at": time.time()},
    )
    return {"state": "finding", "breaches": [n for n, _, _ in names]}
