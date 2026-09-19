"""Runtime auditor: the agent watching itself.

A tool that sends packets on your behalf should be able to answer, at any
moment, three questions:

* **What did you do?** Every active probe, timestamped, with its target.
* **Why were you allowed to?** The authorisation basis in force at the time.
* **How much noise did you make?** Measured, and capped before the fact.

Most scanning tools answer none of these. That gap is not academic. If a device
on your network falls over during a scan, or an ISP asks why a host is sweeping
its own subnet, or -- worst case -- you need to demonstrate that the agent was
*not* running when something happened elsewhere, the audit trail is the only
artefact that helps. It is also the difference between a hobby scanner and
something you would be comfortable defending.

Two mechanisms:

:class:`NoiseBudget`
    A token bucket over active probes. Enforced *before* transmission, not
    logged after it. Collectors ask permission; a denied request is a skipped
    cycle, never a queued burst. This is what stops "every collector fires at
    once after a suspend/resume" from becoming a sudden scan storm.

:class:`Auditor`
    Wraps every packet-emitting operation, recording authorisation basis and
    outcome to ``scan_runs``, and refusing to proceed when the guard has not
    cleared the network or the budget is exhausted.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, TypeVar

from .db import Database
from .guard import ScopeGuard, ScopeViolation

log = logging.getLogger(__name__)

T = TypeVar("T")


class BudgetExceeded(RuntimeError):
    """The agent tried to make more noise than it is permitted to."""


@dataclass
class NoiseBudget:
    """Token bucket limiting active probes.

    Defaults are deliberately conservative. A home network has perhaps a dozen
    devices; there is no legitimate reason to emit hundreds of probes a minute,
    and staying quiet keeps the agent below the threshold where a router's
    rate limiter or IDS starts caring about it.
    """

    capacity: int = 120          # max probes in a burst
    refill_per_minute: int = 60  # sustained rate
    _tokens: float = field(default=0.0, init=False)
    _last: float = field(default_factory=time.monotonic, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    # Lifetime counters, for the compliance report.
    granted: int = field(default=0, init=False)
    denied: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self._tokens = float(self.capacity)

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last
        self._last = now
        self._tokens = min(
            float(self.capacity),
            self._tokens + elapsed * (self.refill_per_minute / 60.0),
        )

    def try_consume(self, n: int = 1) -> bool:
        """Attempt to spend n probes. Returns False if the budget is exhausted."""
        with self._lock:
            self._refill()
            if self._tokens >= n:
                self._tokens -= n
                self.granted += n
                return True
            self.denied += n
            return False

    def consume(self, n: int = 1) -> None:
        if not self.try_consume(n):
            raise BudgetExceeded(
                f"noise budget exhausted: requested {n} probes, "
                f"{self._tokens:.1f} available "
                f"(refills at {self.refill_per_minute}/min)"
            )

    @property
    def available(self) -> float:
        with self._lock:
            self._refill()
            return self._tokens

    def snapshot(self) -> dict:
        return {
            "available": round(self.available, 1),
            "capacity": self.capacity,
            "refill_per_minute": self.refill_per_minute,
            "granted_total": self.granted,
            "denied_total": self.denied,
        }


class ProbeWindow:
    """Tracks which addresses the agent is actively probing, right now.

    This exists to solve a subtle but serious contamination problem. The passive
    sniffer records ARP replies as ``agent_generated=False`` -- traffic that
    happened whether or not PNMA was running -- and the ARP spoofing detector
    trusts that flag as independent evidence.

    But our own ping and nmap probes *elicit* ARP replies. The sniffer sees
    them, cannot tell them apart from unsolicited ones, and marks them as
    independent evidence. The spoofing detector then reads the agent's own
    footsteps as attack signal.

    So the collectors declare their targets here before transmitting, and the
    sniffer consults it: a reply from an address we are currently probing is
    correctly attributed to us.
    """

    def __init__(self, grace_s: float = 3.0):
        self.grace_s = grace_s
        self._targets: dict[str, float] = {}
        self._lock = threading.Lock()

    def mark(self, ips: list[str], duration_s: float) -> None:
        """Declare that we are about to probe these addresses."""
        expiry = time.monotonic() + duration_s + self.grace_s
        with self._lock:
            for ip in ips:
                self._targets[ip] = expiry

    def clear(self, ips: list[str]) -> None:
        """Probing finished -- but keep the grace period for in-flight replies."""
        expiry = time.monotonic() + self.grace_s
        with self._lock:
            for ip in ips:
                if ip in self._targets:
                    self._targets[ip] = min(self._targets[ip], expiry)

    def is_probing(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            expiry = self._targets.get(ip)
            if expiry is None:
                return False
            if expiry < now:
                del self._targets[ip]
                return False
            return True

    def active_count(self) -> int:
        now = time.monotonic()
        with self._lock:
            self._targets = {k: v for k, v in self._targets.items() if v >= now}
            return len(self._targets)


class Auditor:
    """Gate and record every active operation the agent performs."""

    def __init__(self, db: Database, guard: ScopeGuard, budget: NoiseBudget | None = None):
        self.db = db
        self.guard = guard
        self.budget = budget or NoiseBudget()
        self.probe_window = ProbeWindow()
        self.scope_denials = 0
        self.budget_denials = 0

    def authorised(self) -> bool:
        """Whether the guard has cleared the current network."""
        verdict = self.guard.last_verdict
        return bool(verdict and verdict.allowed)

    def active_operation(
        self,
        kind: str,
        target: str,
        estimated_probes: int,
        fn: Callable[[], T],
        target_ips: list[str] | None = None,
    ) -> T | None:
        """Run a packet-emitting operation under audit, or refuse to.

        Order matters: authorisation, then budget, then transmit. Checking
        after the fact would make the audit trail a record of what went wrong
        rather than a control that prevented it.
        """
        if not self.authorised():
            self.scope_denials += 1
            reason = (
                self.guard.last_verdict.reason
                if self.guard.last_verdict
                else "network never verified"
            )
            self.db.log_scan(
                kind, target,
                error=f"REFUSED (scope): {reason}",
            )
            log.warning("refusing %s on %s -- %s", kind, target, reason)
            return None

        if not self.budget.try_consume(estimated_probes):
            self.budget_denials += 1
            self.db.log_scan(
                kind, target,
                error=(
                    f"REFUSED (noise budget): {estimated_probes} probes "
                    f"requested, {self.budget.available:.0f} available"
                ),
            )
            log.warning(
                "skipping %s on %s -- noise budget exhausted "
                "(this cycle is dropped, not queued)",
                kind, target,
            )
            return None

        # Declare our targets before transmitting, so the passive sniffer can
        # attribute the ARP replies we are about to elicit to us rather than
        # feeding them to the spoofing detector as independent evidence.
        ips = target_ips or []
        if ips:
            self.probe_window.mark(ips, duration_s=min(estimated_probes * 0.5, 600))

        started = time.time()
        try:
            result = fn()
        except ScopeViolation as exc:
            self.scope_denials += 1
            self.db.log_scan(
                kind, target,
                duration_s=time.time() - started,
                error=f"REFUSED (scope): {exc}",
            )
            log.warning("scope violation during %s: %s", kind, exc)
            return None
        except Exception as exc:  # noqa: BLE001
            self.db.log_scan(
                kind, target,
                duration_s=time.time() - started,
                error=f"ERROR: {exc}",
            )
            log.exception("%s failed", kind)
            return None
        finally:
            if ips:
                self.probe_window.clear(ips)

        return result

    # -- reporting ----------------------------------------------------------

    def compliance_report(self, hours: int = 24) -> dict:
        """Evidence of what the agent did, and did not do, in a window.

        Surfaced in the dashboard, printed by ``pnma audit`` and dumped
        verbatim by ``pnma audit --json``. There is no ``audit-report``
        subcommand; this docstring named one that never existed.
        """
        cutoff = time.time() - hours * 3600

        runs = self.db.query(
            "SELECT kind, COUNT(*) AS n, "
            "       SUM(CASE WHEN error IS NULL THEN 1 ELSE 0 END) AS ok, "
            "       SUM(CASE WHEN error LIKE 'REFUSED%' THEN 1 ELSE 0 END) AS refused, "
            "       SUM(CASE WHEN error IS NOT NULL "
            "                 AND error NOT LIKE 'REFUSED%' THEN 1 ELSE 0 END) AS failed "
            "FROM scan_runs WHERE ts >= ? GROUP BY kind ORDER BY n DESC",
            (cutoff,),
        )

        refusals = self.db.query(
            "SELECT ts, kind, target, error FROM scan_runs "
            "WHERE ts >= ? AND error LIKE 'REFUSED%' ORDER BY ts DESC LIMIT 50",
            (cutoff,),
        )

        verdict = self.guard.last_verdict
        net = self.guard.config.network

        return {
            "window_hours": hours,
            "authorisation": {
                "authorised_cidr": net.cidr,
                "gateway_pinned": bool(net.gateway_mac)
                and self.guard.config.guard.enforce_gateway_mac,
                "currently_allowed": bool(verdict and verdict.allowed),
                "reason": verdict.reason if verdict else "not yet checked",
            },
            "activity": [dict(r) for r in runs],
            "noise_budget": self.budget.snapshot(),
            "refusals": {
                "scope": self.scope_denials,
                "budget": self.budget_denials,
                "recent": [dict(r) for r in refusals],
            },
            "posture": self._posture(),
        }

    def _posture(self) -> list[dict]:
        """Self-assessment of the agent's own safety configuration.

        The agent is part of the attack surface it monitors. Anyone reading the
        dashboard deserves to see where it currently sits.
        """
        cfg = self.guard.config
        checks: list[dict] = []

        def add(name: str, ok: bool, detail: str) -> None:
            checks.append({"check": name, "ok": ok, "detail": detail})

        # Judge the bind actually in use, not the one in the file: `serve
        # --bind tailscale` overrides the config at runtime and records what it
        # chose in `effective_bind` / `token_required`. Reading the config
        # here would render a passing check for a socket that is not the one
        # listening -- the exact failure this project exists to prevent.
        bind = getattr(cfg.api, "effective_bind", None) or cfg.api.bind
        loopback = bind in ("127.0.0.1", "localhost", "::1")
        guarded = bool(getattr(cfg.api, "token_required", False))
        if loopback:
            add("API bound to loopback", True,
                f"bind = {bind}. Only this machine can reach the dashboard.")
        elif bind in ("0.0.0.0", "::"):
            add("API not exposed to the LAN", False,
                f"bind = {bind}: every interface. The database is a complete map "
                "of the network; this hands out a recon report.")
        else:
            add("API off loopback, token-guarded", guarded,
                f"bind = {bind}" + (" with a bearer token required on every API "
                "call. Reachable only by devices on that interface, and only "
                "with the token." if guarded else
                " WITHOUT a token. Anything that can reach this address can "
                "read the whole database."))
        add(
            "Gateway fingerprint enforced",
            cfg.guard.enforce_gateway_mac and not cfg.guard.allow_unknown_network,
            "Stops the agent scanning a network it is not authorised for if "
            "this machine moves.",
        )
        add(
            "Scope bypass disabled",
            not cfg.guard.allow_unknown_network,
            "allow_unknown_network disables scope enforcement entirely.",
        )
        add(
            "Polite scan timing",
            cfg.scan.timing <= 3,
            f"nmap -T{cfg.scan.timing}. Aggressive timing crashes IoT devices "
            "and network printers.",
        )
        add(
            "Outbound alerting off",
            not cfg.alerting.webhook_enabled,
            "Auto-start + elevation + recon + webhook egress is the behavioural "
            "profile of a RAT.",
        )
        add(
            "Retention bounded",
            cfg.retention_days > 0,
            f"{cfg.retention_days} days. Presence timestamps reveal when "
            "people are home; keeping them forever is a privacy liability.",
        )
        return checks
