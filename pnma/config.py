"""Configuration loading and validation.

TOML via the standard library ``tomllib`` -- no third-party config dependency,
which keeps the setup bar low for anyone cloning this.

Design rule enforced here: **the monitored network is configuration, never a
command-line argument.** A scanner whose target can be set with a flag is one
typo away from scanning a network you have no authorisation to touch. Making
it configuration-only, and pinning it to a gateway fingerprint (see
``pnma.guard``), is the control that makes this tool safe to carry on a laptop.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONFIG_PATH = Path("config/pnma.toml")


class ConfigError(RuntimeError):
    """Configuration is missing or internally inconsistent."""


@dataclass
class NetworkConfig:
    cidr: str
    gateway_ip: str
    gateway_mac: str = ""
    exclude_cidrs: list[str] = field(default_factory=list)
    exclude_ips: list[str] = field(default_factory=list)


@dataclass
class GuardConfig:
    # If true (default), the agent refuses to run when the gateway MAC does not
    # match the configured fingerprint. This is what stops the agent scanning
    # an office or hotel network when the laptop moves.
    enforce_gateway_mac: bool = True
    # Escape hatch for first-run setup only.
    allow_unknown_network: bool = False


@dataclass
class ApiConfig:
    # Loopback by default. The database is a complete map of the network --
    # devices, open ports, weak services. Serving that to the LAN hands an
    # attacker a finished recon report.
    bind: str = "127.0.0.1"
    port: int = 8787


@dataclass
class CollectorConfig:
    arp_table_interval_s: int = 30
    ping_interval_s: int = 60
    port_scan_interval_s: int = 3600
    detection_interval_s: int = 60
    passive_capture: bool = True
    interface: str = ""
    # Active host discovery (nmap -sn). Without it, unprivileged mode discovers
    # only what the OS ARP cache happens to be holding, which on Windows ages
    # out in under a minute. 900s because a sweep of a /24 at -T2 takes roughly
    # three minutes of low-rate traffic; shorter intervals would keep the
    # network permanently under a sweep for little gain.
    discovery_sweep: bool = True
    discovery_interval_s: int = 900
    # Host posture. Windows-only; the collector declines on other platforms.
    host_posture: bool = True
    # Thirty minutes, and the reason is cost rather than staleness: one run
    # spawns seven PowerShell processes. Posture also genuinely moves slowly --
    # these are configuration states, not traffic.
    host_posture_interval_s: int = 1800
    # Host events (pnma.collectors.host_events): software/autorun diffs, event
    # logs, hidden dirs, notable connections, adapter counters. Five minutes:
    # six PowerShell processes per run, and the event logs are incremental.
    host_events: bool = True
    host_events_interval_s: int = 300


@dataclass
class ScanConfig:
    enabled: bool = True
    nmap_path: str = "nmap"
    # -T2 (polite). Aggressive timing and version probes are documented to
    # crash IoT devices and make network printers emit pages of garbage.
    timing: int = 2
    top_ports: int = 100
    service_detection: bool = False
    # Active confirmation of a flagged exposure: a single non-destructive
    # banner read on a port that already has a CVE advisory, so "port open"
    # becomes "port open, answered <banner>". Off by default -- it is still
    # active, though milder than the scan. Scope-guarded like every probe.
    confirm_exposures: bool = False
    confirm_interval_s: int = 1800


@dataclass
class AlertingConfig:
    # Outbound alerting is OFF by default and must be switched on deliberately.
    # Auto-start + administrator + network recon + webhook egress is the
    # behavioural profile of a RAT, both to EDR heuristics and to a stranger
    # reading this repo.
    local_log: bool = True
    webhook_enabled: bool = False
    webhook_url: str = ""
    # Push-to-phone via ntfy. Off by default; the topic URL is a secret
    # (ntfy_topic_url) read from the OS credential store, not from here.
    ntfy_enabled: bool = False
    # Floor for every OUTBOUND channel (webhook + ntfy). The dashboard and the
    # local log always get everything; only the outbound doorbells are gated,
    # so a low-severity hygiene finding does not buzz a phone.
    outbound_min_severity: str = "high"
    # Local Windows toast for a new alert at or above `toast_min_severity`.
    # Off by default like every other delivery channel, but when on it is the
    # one that adds no egress and no standing config a stranger could abuse --
    # it only ever notifies the person already at the machine. See pnma.notify.
    toast_enabled: bool = False
    toast_min_severity: str = "high"
    # Refresh the known-exploited-vulnerability catalogue from CISA's KEV feed
    # at collector start. Egress -- off by default like every outbound path.
    # The bundled catalogue works offline regardless; this only annotates it
    # with what CISA currently lists as exploited in the wild.
    cve_feed_enabled: bool = False
    # Dead-man's switch: warn if the collector has not completed a detection
    # pass in this long. Silence is the most dangerous state a monitor has;
    # this is the check that notices the monitor itself stopped. 0 disables.
    heartbeat_timeout_s: int = 900


@dataclass
class HoneypotConfig:
    # Ingest a Cowrie honeypot's JSON log as a PNMA sensor. Off unless a log
    # path is given. Passive file read -- no egress. The honeypot itself must
    # run on an isolated segment (see docs/PENTEST_LAB.md); PNMA only reads it.
    enabled: bool = False
    cowrie_log_path: str = ""
    interval_s: int = 60


@dataclass
class MailLogConfig:
    # Ingest the router's emailed system log (TP-Link "Mail Log" and similar).
    # Off unless a mailbox is configured. Read-only IMAP; the password is the
    # secret maillog_imap_password, never set here.
    enabled: bool = False
    imap_host: str = ""
    imap_port: int = 993
    imap_user: str = ""
    folder: str = "INBOX"
    from_filter: str = ""      # only read mail from this sender, if set
    interval_s: int = 300


@dataclass
class Config:
    network: NetworkConfig
    guard: GuardConfig = field(default_factory=GuardConfig)
    api: ApiConfig = field(default_factory=ApiConfig)
    collector: CollectorConfig = field(default_factory=CollectorConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    alerting: AlertingConfig = field(default_factory=AlertingConfig)
    honeypot: HoneypotConfig = field(default_factory=HoneypotConfig)
    maillog: MailLogConfig = field(default_factory=MailLogConfig)
    database: str = "data/pnma.db"
    retention_days: int = 30

    @classmethod
    def load(cls, path: str | Path = DEFAULT_CONFIG_PATH) -> "Config":
        p = Path(path)
        if not p.exists():
            raise ConfigError(
                f"No config at {p}. Copy config/pnma.example.toml to {p} and "
                f"fill in your network details, or run: pnma init"
            )
        with p.open("rb") as fh:
            raw = tomllib.load(fh)

        if "network" not in raw:
            raise ConfigError("config is missing the required [network] section")
        net = raw["network"]
        for required in ("cidr", "gateway_ip"):
            if not net.get(required):
                raise ConfigError(f"[network].{required} is required")

        cfg = cls(
            network=NetworkConfig(**net),
            guard=GuardConfig(**raw.get("guard", {})),
            api=ApiConfig(**raw.get("api", {})),
            collector=CollectorConfig(**raw.get("collector", {})),
            scan=ScanConfig(**raw.get("scan", {})),
            alerting=AlertingConfig(**raw.get("alerting", {})),
            honeypot=HoneypotConfig(**raw.get("honeypot", {})),
            maillog=MailLogConfig(**raw.get("maillog", {})),
            database=raw.get("database", "data/pnma.db"),
            retention_days=raw.get("retention", {}).get("days", 30),
        )
        cfg.validate()
        if cfg.alerting.toast_min_severity not in ("info", "low", "medium", "high", "critical"):
            raise ConfigError(
                f"[alerting].toast_min_severity = {cfg.alerting.toast_min_severity!r} "
                "must be one of: info, low, medium, high, critical"
            )
        if cfg.alerting.outbound_min_severity not in ("info", "low", "medium", "high", "critical"):
            raise ConfigError(
                f"[alerting].outbound_min_severity = {cfg.alerting.outbound_min_severity!r} "
                "must be one of: info, low, medium, high, critical"
            )
        return cfg

    def validate(self) -> None:
        import ipaddress

        try:
            network = ipaddress.IPv4Network(self.network.cidr, strict=False)
        except ValueError as exc:
            raise ConfigError(f"[network].cidr is not a valid IPv4 network: {exc}")

        if network.prefixlen < 22:
            raise ConfigError(
                f"[network].cidr {self.network.cidr} covers {network.num_addresses} "
                "addresses. Refusing: a range that large is almost certainly a "
                "mistake, and scanning it would be both slow and rude."
            )

        try:
            gw = ipaddress.IPv4Address(self.network.gateway_ip)
        except ValueError as exc:
            raise ConfigError(f"[network].gateway_ip is not a valid address: {exc}")

        if gw not in network:
            raise ConfigError(
                f"gateway {gw} is not inside {self.network.cidr} -- one of the "
                "two is wrong, and guessing which would be unsafe."
            )

        if self.guard.enforce_gateway_mac and not self.network.gateway_mac:
            raise ConfigError(
                "guard.enforce_gateway_mac is on but [network].gateway_mac is "
                "empty. Run 'pnma init' to fingerprint your gateway, or set "
                "guard.allow_unknown_network = true to bypass (not recommended)."
            )

        # Scan politeness is a ceiling, not merely a default. Every nmap
        # tutorial on the internet uses -T4, and a user who copies that number
        # into this file would silently start throwing aggressive timing at
        # their own IoT gear -- the exact failure mode portscan.py warns about.
        # Refusing is better than warning: the person who pastes -T4 is by
        # definition not reading the warnings.
        if not isinstance(self.scan.timing, int) or not 0 <= self.scan.timing <= 3:
            raise ConfigError(
                f"[scan].timing = {self.scan.timing!r} is not permitted. PNMA "
                "allows 0-3 (paranoid to normal). Aggressive nmap timing (-T4, "
                "-T5) is documented to crash embedded devices, reboot smart "
                "plugs and make network printers emit pages of garbage. This is "
                "your home network, not a lab."
            )

        if not isinstance(self.scan.top_ports, int) or not 1 <= self.scan.top_ports <= 1000:
            raise ConfigError(
                f"[scan].top_ports = {self.scan.top_ports!r} is out of range "
                "(1-1000). Scanning more than the top 1000 ports on a home "
                "network is slow, noisy, and finds nothing the top 100 missed."
            )

        for name, value in (
            ("arp_table_interval_s", self.collector.arp_table_interval_s),
            ("ping_interval_s", self.collector.ping_interval_s),
            ("port_scan_interval_s", self.collector.port_scan_interval_s),
            ("detection_interval_s", self.collector.detection_interval_s),
        ):
            if not isinstance(value, int) or value < 5:
                raise ConfigError(
                    f"[collector].{name} = {value!r} is too small. Intervals "
                    "below 5 seconds turn the agent into a traffic generator."
                )

        if self.retention_days < 1:
            raise ConfigError(
                "[retention].days must be at least 1. Retention is the control "
                "that stops presence timestamps -- which reveal when people are "
                "home -- accumulating indefinitely."
            )

        if self.api.bind not in ("127.0.0.1", "localhost", "::1"):
            # Not fatal -- someone may genuinely want this on their LAN -- but
            # it must be a conscious act, so we make it loud.
            import warnings

            warnings.warn(
                f"API is bound to {self.api.bind}, not loopback. The PNMA "
                "database is a complete inventory of your network including "
                "open ports and weak services. Anyone who can reach this port "
                "gets that inventory. Make sure this is intentional.",
                stacklevel=2,
            )
