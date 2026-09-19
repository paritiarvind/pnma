"""The scope guard: the single most important safety control in this project.

The threat is mundane and entirely self-inflicted. This agent runs on a laptop.
Laptops move. If the agent simply enumerates "whatever subnet I am on", then
carrying it to an office, a hotel, a coffee shop, or bringing up a corporate
VPN turns it into an unauthorised scanner of someone else's network -- ARP
sweeps and SYN scans, from a host with your name on it. Intent is not visible
in the packets. Depending on jurisdiction that is a computer-misuse offence,
and on an employer network it is an insider-threat incident regardless.

So the agent does not ask "what network am I on?" and proceed. It asks "am I on
*the* network?" and refuses to emit a single packet if the answer is no.

Two checks, both cheap, both passive:

1. **Range pin.** The monitored CIDR comes from config only -- never a CLI flag.
2. **Gateway fingerprint.** The configured gateway IP must currently resolve to
   the configured gateway MAC in the local ARP cache. Being on 192.168.0.0/24
   is not enough; that range is the most common private network on earth and
   every second cafe uses it. The gateway MAC is what makes it *your* network.

The fingerprint check reads the ARP cache, which the OS populated as a side
effect of normal traffic. It sends nothing. That ordering is deliberate: the
guard must be able to clear the agent *before* the agent is allowed to transmit.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from .config import Config
from .fingerprint import normalise_mac
from .netutil import address_in_scope, default_gateway, mac_for_ip

log = logging.getLogger(__name__)


class ScopeViolation(RuntimeError):
    """Raised when the agent is asked to touch something outside its authorisation.

    This is deliberately a hard error and never a warning. A scanner that
    degrades to "log it and carry on" when it cannot confirm its scope is a
    scanner that will eventually scan the wrong network.
    """


@dataclass
class GuardVerdict:
    allowed: bool
    reason: str
    observed_gateway_ip: str | None = None
    observed_gateway_mac: str | None = None
    expected_gateway_mac: str | None = None

    def raise_if_denied(self) -> None:
        if not self.allowed:
            raise ScopeViolation(self.reason)


class ScopeGuard:
    """Authorisation boundary for every packet-emitting operation."""

    def __init__(self, config: Config):
        self.config = config
        self._verdict: GuardVerdict | None = None

    # -- startup check ------------------------------------------------------

    def check_network(self) -> GuardVerdict:
        """Confirm we are attached to the network this agent is authorised for.

        Called once at collector startup and re-checked periodically, because
        a laptop can roam mid-run -- suspend at home, resume at the office.
        """
        net = self.config.network
        guard = self.config.guard

        observed_gw = default_gateway()

        if guard.allow_unknown_network:
            verdict = GuardVerdict(
                allowed=True,
                reason=(
                    "guard.allow_unknown_network is enabled -- scope enforcement "
                    "is BYPASSED. This is intended for first-run setup only."
                ),
                observed_gateway_ip=observed_gw,
            )
            log.warning(verdict.reason)
            self._verdict = verdict
            return verdict

        if observed_gw is None:
            verdict = GuardVerdict(
                allowed=False,
                reason=(
                    "Cannot determine the default gateway, so the current "
                    "network cannot be identified. Refusing to scan."
                ),
            )
            self._verdict = verdict
            return verdict

        if observed_gw != net.gateway_ip:
            verdict = GuardVerdict(
                allowed=False,
                reason=(
                    f"Gateway is {observed_gw}, but this agent is authorised "
                    f"only for {net.gateway_ip}. You appear to be on a "
                    f"different network. Refusing to scan."
                ),
                observed_gateway_ip=observed_gw,
            )
            self._verdict = verdict
            return verdict

        if not guard.enforce_gateway_mac:
            verdict = GuardVerdict(
                allowed=True,
                reason=(
                    f"Gateway IP {observed_gw} matches. MAC fingerprinting is "
                    "disabled, so this is a weaker check than it could be."
                ),
                observed_gateway_ip=observed_gw,
            )
            self._verdict = verdict
            return verdict

        observed_mac = mac_for_ip(net.gateway_ip)
        expected_mac = normalise_mac(net.gateway_mac)

        if observed_mac is None:
            verdict = GuardVerdict(
                allowed=False,
                reason=(
                    f"Gateway {net.gateway_ip} is not in the ARP cache, so its "
                    "identity cannot be confirmed. Refusing to scan. (Try "
                    "pinging the gateway once to populate the cache.)"
                ),
                observed_gateway_ip=observed_gw,
                expected_gateway_mac=expected_mac,
            )
            self._verdict = verdict
            return verdict

        if normalise_mac(observed_mac) != expected_mac:
            verdict = GuardVerdict(
                allowed=False,
                reason=(
                    f"Gateway {net.gateway_ip} resolves to {observed_mac}, but "
                    f"this agent is authorised only for {expected_mac}. Either "
                    "you are on a different network that happens to use the "
                    "same address range, or your gateway has been replaced or "
                    "spoofed. Refusing to scan."
                ),
                observed_gateway_ip=observed_gw,
                observed_gateway_mac=observed_mac,
                expected_gateway_mac=expected_mac,
            )
            self._verdict = verdict
            return verdict

        verdict = GuardVerdict(
            allowed=True,
            reason=f"Gateway {net.gateway_ip} confirmed as {expected_mac}.",
            observed_gateway_ip=observed_gw,
            observed_gateway_mac=observed_mac,
            expected_gateway_mac=expected_mac,
        )
        self._verdict = verdict
        return verdict

    # -- per-target check ---------------------------------------------------

    def assert_target_allowed(self, ip: str) -> None:
        """Gate an individual address before any probe is sent to it.

        Belt and braces alongside :meth:`check_network`. Discovery results are
        untrusted input -- an ARP reply can claim any address it likes, and
        without this check a hostile reply could steer a probe off-network.
        """
        net = self.config.network
        if ip in net.exclude_ips:
            raise ScopeViolation(f"{ip} is on the configured exclusion list")
        if not address_in_scope(ip, net.cidr, net.exclude_cidrs):
            raise ScopeViolation(
                f"{ip} is outside the authorised range {net.cidr} "
                f"(exclusions: {net.exclude_cidrs or 'none'})"
            )

    def filter_targets(self, ips: list[str]) -> list[str]:
        """Return only the addresses this agent may probe."""
        allowed = []
        for ip in ips:
            try:
                self.assert_target_allowed(ip)
                allowed.append(ip)
            except ScopeViolation as exc:
                log.debug("skipping out-of-scope target: %s", exc)
        return allowed

    @property
    def last_verdict(self) -> GuardVerdict | None:
        return self._verdict
