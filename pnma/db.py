"""SQLite storage layer for PNMA.

Two processes share this database: a privileged collector that writes, and an
unprivileged API that mostly reads. WAL mode is what makes that safe.

Four schema decisions here are load-bearing and documented in THREAT_MODEL.md:

1. ``devices.device_id`` is a *composite* identity, not a MAC. Phones rotate
   their MAC per-SSID, so keying on MAC alone makes "new device" fire on every
   reconnect. See ``pnma.fingerprint``.
2. Every row in ``observations`` carries ``agent_generated``. The agent's own
   ARP sweeps churn MAC/IP bindings; a detector that reads that churn as signal
   alerts on its own footsteps. Detectors filter it out at query time.
3. Alerts carry a ``dedup_key``. A detector that re-fires every cycle is a
   self-inflicted denial of service.
4. Observations carry a ``sensor_id``. v1 ships one network sensor, but host
   agents are the obvious next step, and adding the column later means
   backfilling every row.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 0


# An unchanged finding re-raised inside this window does not bump the alert.
ALERT_BUMP_MIN_S = 60.0

SCHEMA_VERSION = 1

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- --------------------------------------------------------------- sensors --
-- A sensor is anything that reports observations. v1 registers exactly one
-- (the network sensor on this host); host/endpoint agents register here later.
CREATE TABLE IF NOT EXISTS sensors (
    sensor_id  TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,           -- network|host
    hostname   TEXT,
    version    TEXT,
    first_seen REAL NOT NULL,
    last_seen  REAL NOT NULL
);

-- --------------------------------------------------------------- devices --
-- device_id is a composite key (see pnma.fingerprint.device_id). For a device
-- with a burned-in vendor MAC it derives from that MAC. For a randomised
-- (locally-administered) MAC it derives from the DHCP fingerprint plus
-- hostname, so one phone stays one device across MAC rotations.
CREATE TABLE IF NOT EXISTS devices (
    device_id         TEXT PRIMARY KEY,
    mac               TEXT,             -- most recently observed MAC
    mac_type          TEXT NOT NULL,    -- 'global' | 'local' (randomised)
    vendor            TEXT,
    hostname          TEXT,
    dhcp_fingerprint  TEXT,             -- hash of DHCP option 55 list
    dhcp_vendor_class TEXT,             -- DHCP option 60
    ip                TEXT,             -- most recently observed IP
    label             TEXT,             -- user-assigned friendly name
    device_class      TEXT,             -- see pnma.profiles.DeviceClass
    class_confidence  TEXT,             -- high|medium|low
    class_signals     TEXT,             -- JSON: why we classified it this way
    first_seen        REAL NOT NULL,
    last_seen         REAL NOT NULL,
    trusted           INTEGER NOT NULL DEFAULT 0,
    notes             TEXT
);
CREATE INDEX IF NOT EXISTS idx_devices_mac       ON devices(mac);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);

-- ---------------------------------------------------------- observations --
-- Append-only evidence log. agent_generated marks rows caused by our own
-- probing (ARP sweep, nmap, ping) so detectors can exclude them.
CREATE TABLE IF NOT EXISTS observations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL NOT NULL,
    sensor_id       TEXT,
    device_id       TEXT,
    mac             TEXT,
    ip              TEXT,
    source          TEXT NOT NULL,      -- passive_arp|passive_dhcp|arp_table|icmp|nmap
    agent_generated INTEGER NOT NULL DEFAULT 0,
    detail          TEXT                -- JSON
);
CREATE INDEX IF NOT EXISTS idx_obs_ts     ON observations(ts);
CREATE INDEX IF NOT EXISTS idx_obs_device ON observations(device_id, ts);
CREATE INDEX IF NOT EXISTS idx_obs_source ON observations(source, agent_generated, ts);

-- -------------------------------------------------------------- bindings --
-- Current and historical MAC <-> IP claims. ARP spoofing shows up here as one
-- IP whose MAC changes, or one MAC claiming many IPs.
CREATE TABLE IF NOT EXISTS bindings (
    mac           TEXT NOT NULL,
    ip            TEXT NOT NULL,
    first_seen    REAL NOT NULL,
    last_seen     REAL NOT NULL,
    obs_count     INTEGER NOT NULL DEFAULT 1,
    passive_count INTEGER NOT NULL DEFAULT 0,  -- seen without us asking
    PRIMARY KEY (mac, ip)
);
CREATE INDEX IF NOT EXISTS idx_bindings_ip ON bindings(ip, last_seen);

-- ----------------------------------------------------------------- ports --
-- Service inventory per device. closed_at is set when a previously open port
-- stops answering, which is itself drift worth keeping.
CREATE TABLE IF NOT EXISTS ports (
    device_id  TEXT NOT NULL,
    port       INTEGER NOT NULL,
    proto      TEXT NOT NULL DEFAULT 'tcp',
    service    TEXT,
    product    TEXT,
    first_seen REAL NOT NULL,
    last_seen  REAL NOT NULL,
    closed_at  REAL,
    risk       TEXT,                    -- null|low|medium|high
    PRIMARY KEY (device_id, port, proto)
);

-- ---------------------------------------------------------- availability --
CREATE TABLE IF NOT EXISTS availability (
    ts        REAL NOT NULL,
    device_id TEXT NOT NULL,
    reachable INTEGER NOT NULL,
    rtt_ms    REAL
);
CREATE INDEX IF NOT EXISTS idx_avail ON availability(device_id, ts);

-- ---------------------------------------------------------------- alerts --
-- dedup_key collapses a repeating condition into one row with a count, so a
-- flapping detector cannot fill the disk or the operator attention budget.
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_key   TEXT NOT NULL UNIQUE,
    rule_id     TEXT NOT NULL,
    severity    TEXT NOT NULL,          -- info|low|medium|high|critical
    title       TEXT NOT NULL,
    description TEXT,
    device_id   TEXT,
    mitre_id    TEXT,
    mitre_name  TEXT,
    evidence    TEXT,                   -- JSON
    status      TEXT NOT NULL DEFAULT 'open',  -- open|acknowledged|resolved
    count       INTEGER NOT NULL DEFAULT 1,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, last_seen);

-- ------------------------------------------------------------- scan_runs --
-- Audit trail of every active probe the agent sent. If something on the
-- network complains about being scanned, this answers "was that us?"
CREATE TABLE IF NOT EXISTS scan_runs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,
    kind       TEXT NOT NULL,           -- arp_sweep|port_scan|ping
    target     TEXT NOT NULL,
    duration_s REAL,
    result     TEXT,
    error      TEXT
);
CREATE INDEX IF NOT EXISTS idx_scan_ts ON scan_runs(ts);

-- ------------------------------------------------------------ host_facts --
-- Posture of the machine PNMA runs on, as opposed to the devices it watches.
-- Deliberately NOT folded into `observations`: that table is about other
-- people's devices and carries `agent_generated` semantics that make no sense
-- for "is Tamper Protection on".
--
-- `state` is the reason this table exists in this shape. A check has three
-- outcomes, not two:
--
--   ok       the control is in the desired state
--   finding  the control is not, and that is worth surfacing
--   unknown  THE CHECK COULD NOT RUN
--
-- The third one is not a nicety. During the 2026-08-24 host review a
-- Security-log query returned "No events were found" when the real answer was
-- "access denied" -- a check that could not run was indistinguishable from a
-- check that passed, and the first draft of that report drew a false negative
-- from it. A collector without `unknown` lies by omission, so `unknown` is
-- stored, surfaced, and counted separately in the dashboard.
--
-- One row per (fact_key) -- latest value wins, with first/last seen retained
-- so a control flipping off is visible as a change rather than silently
-- overwritten.
CREATE TABLE IF NOT EXISTS host_facts (
    fact_key    TEXT PRIMARY KEY,       -- e.g. defender.tamper_protection
    category    TEXT NOT NULL,          -- defender|audit|persistence|network|drivers
    title       TEXT NOT NULL,          -- human label for the dashboard
    state       TEXT NOT NULL,          -- ok|finding|unknown
    value       TEXT,                   -- the measured value, as text
    expected    TEXT,                   -- what "ok" would look like
    reason      TEXT,                   -- why unknown, or what the finding means
    needs_admin INTEGER NOT NULL DEFAULT 0,
    evidence    TEXT,                   -- JSON
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    changed_at  REAL                    -- when `state` last differed
);
CREATE INDEX IF NOT EXISTS idx_host_facts_state ON host_facts(state, category);

-- Identity posture. Accounts are things the operator *owns* (their email,
-- their social profiles), never other people's. Controls are attested by the
-- operator or measured by an opt-in lookup, and every one is three-valued
-- exactly like host_facts: an account nobody has looked at is `unknown`, not
-- `ok`. Handles (email addresses) live only in this local, gitignored file.
CREATE TABLE IF NOT EXISTS identity_accounts (
    account_id  TEXT PRIMARY KEY,       -- slug, e.g. gmail-main
    provider    TEXT NOT NULL,          -- google|apple|microsoft|meta|x|github|bank|other
    category    TEXT NOT NULL,          -- email|social|finance|dev|cloud|other
    label       TEXT NOT NULL,          -- what the dashboard shows
    handle      TEXT,                   -- email / username, masked in the UI
    review_days INTEGER NOT NULL DEFAULT 90,
    notes       TEXT,
    created_at  REAL NOT NULL
);
-- Every change to an existing alert's judgement (severity, title, status),
-- so a refresh is visible history rather than a silent overwrite.
CREATE TABLE IF NOT EXISTS alert_changes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id  INTEGER NOT NULL,
    ts        REAL NOT NULL,
    field     TEXT NOT NULL,            -- severity|title|status
    old_value TEXT,
    new_value TEXT,
    actor     TEXT NOT NULL DEFAULT 'rule'   -- rule|operator
);
CREATE INDEX IF NOT EXISTS idx_alert_changes_alert ON alert_changes(alert_id, ts);
CREATE INDEX IF NOT EXISTS idx_observations_device_ts ON observations(device_id, ts);
CREATE INDEX IF NOT EXISTS idx_observations_ts ON observations(ts);

-- What happened on the monitoring host (pnma.collectors.host_events): a
-- script block, a service install, a new autorun, a hidden directory, a
-- notable outbound connection. agent_generated marks PNMA's own scripts.
-- Lines the router emailed (pnma.collectors.maillog): the WAN side, DHCP
-- leases, admin logins and firewall events a single host cannot see. Keyed by
-- the IP/MAC in the line so a device's investigation can pull the router's
-- view of it. dedup_key collapses the same line re-sent in overlapping mails.
CREATE TABLE IF NOT EXISTS router_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,
    kind       TEXT NOT NULL,          -- dhcp_lease|admin_login|firewall_event|config_change|wan_event
    severity   TEXT,
    title      TEXT NOT NULL,
    ip         TEXT,
    mac        TEXT,
    line       TEXT NOT NULL,
    dedup_key  TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_router_events_ts ON router_events(ts);
CREATE INDEX IF NOT EXISTS idx_router_events_ip ON router_events(ip, ts);

CREATE TABLE IF NOT EXISTS host_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL NOT NULL,
    sensor_id       TEXT,
    kind            TEXT NOT NULL,      -- see host_events.EVENT_KINDS
    summary         TEXT NOT NULL,
    detail          TEXT,               -- JSON
    severity        TEXT,               -- rule hint; null = inventory only
    mitre_id        TEXT,
    agent_generated INTEGER NOT NULL DEFAULT 0,
    dedup_key       TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_host_events_ts ON host_events(ts);
CREATE INDEX IF NOT EXISTS idx_host_events_kind ON host_events(kind, ts);
-- Authentication events from the Windows Security log (pnma.collectors.
-- host_events, only when the collector runs elevated): failed logons (4625),
-- account lockouts (4740), and additions to a security group (4732). Kept as
-- rows so rules can aggregate -- a password spray is a shape across many of
-- them, not any single one.
CREATE TABLE IF NOT EXISTS auth_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    event_id    INTEGER NOT NULL,      -- 4625 | 4740 | 4732
    account     TEXT,                  -- the target account
    domain      TEXT,
    source_ip   TEXT,
    logon_type  TEXT,
    status      TEXT,
    detail      TEXT,                  -- JSON: the full EventData
    dedup_key   TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_auth_events_ts ON auth_events(ts, event_id);
CREATE INDEX IF NOT EXISTS idx_auth_events_acct ON auth_events(account, ts);

-- One row per (process, external destination) the host connected to
-- (pnma.collectors.host_events). Compact -- an endpoint, not every packet --
-- but it keeps the last N sample timestamps so a rule can measure cadence: a
-- process that re-connects to one external ip:port at a fixed interval is the
-- shape of a beacon, and a brand-new external endpoint for a non-browser
-- process is worth a glance.
CREATE TABLE IF NOT EXISTS connection_endpoints (
    process      TEXT NOT NULL,
    path         TEXT,
    raddr        TEXT NOT NULL,
    rport        INTEGER NOT NULL,
    first_seen   REAL NOT NULL,
    last_seen    REAL NOT NULL,
    sample_count INTEGER NOT NULL DEFAULT 1,
    samples      TEXT,                 -- JSON list of recent sample timestamps
    PRIMARY KEY (process, raddr, rport)
);
CREATE INDEX IF NOT EXISTS idx_conn_endpoints_last ON connection_endpoints(last_seen);
CREATE INDEX IF NOT EXISTS idx_conn_endpoints_first ON connection_endpoints(first_seen);

CREATE TABLE IF NOT EXISTS host_software (
    software_id  TEXT PRIMARY KEY,      -- hive:registry key
    name         TEXT NOT NULL,
    version      TEXT,
    publisher    TEXT,
    location     TEXT,
    hive         TEXT,
    installed_at REAL,
    tags         TEXT,                  -- JSON list of class tags
    first_seen   REAL NOT NULL,
    last_seen    REAL NOT NULL,
    removed_at   REAL
);
CREATE TABLE IF NOT EXISTS host_autoruns (
    autorun_id  TEXT PRIMARY KEY,       -- location::name
    location    TEXT NOT NULL,
    name        TEXT NOT NULL,
    command     TEXT,
    signed      INTEGER,                -- 1 valid signature, 0 not, null unknown
    sha256      TEXT,
    tags        TEXT,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    removed_at  REAL
);
CREATE TABLE IF NOT EXISTS host_counters (
    ts         REAL NOT NULL,
    adapter    TEXT NOT NULL,
    bytes_sent REAL NOT NULL,
    bytes_recv REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_host_counters ON host_counters(adapter, ts);

CREATE TABLE IF NOT EXISTS exposure_banners (
    device_id   TEXT NOT NULL,
    port        INTEGER NOT NULL,
    banner      TEXT NOT NULL,
    confirmed_at REAL NOT NULL,
    PRIMARY KEY (device_id, port)
);

CREATE TABLE IF NOT EXISTS identity_facts (
    account_id  TEXT NOT NULL REFERENCES identity_accounts(account_id) ON DELETE CASCADE,
    control     TEXT NOT NULL,          -- see pnma.identity.CONTROLS
    state       TEXT NOT NULL,          -- ok|finding|unknown
    value       TEXT,
    reason      TEXT,
    source      TEXT NOT NULL,          -- attested|hibp
    evidence    TEXT,                   -- JSON
    attested_at REAL NOT NULL,
    changed_at  REAL,
    PRIMARY KEY (account_id, control)
);
"""


class Database:
    """Thin SQLite wrapper. Thread-safe via a lock; one instance per process."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(self.path), check_same_thread=False, timeout=15.0
        )
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            self._conn.commit()

    # -- primitives ---------------------------------------------------------

    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            self._conn.commit()
            return cur

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, tuple(params)).fetchall()

    def data_version(self) -> int:
        """SQLite's cheap change counter: differs between two calls on THIS
        connection iff another connection committed in between. The API's
        long-poll uses it to learn that the collector wrote something without
        scanning any table."""
        with self._lock:
            return int(self._conn.execute("PRAGMA data_version").fetchone()[0])

    def query_one(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- domain helpers -----------------------------------------------------

    def register_sensor(
        self, sensor_id: str, kind: str, hostname: str = "", version: str = ""
    ) -> None:
        now = time.time()
        self.execute(
            """INSERT INTO sensors(sensor_id, kind, hostname, version,
                                   first_seen, last_seen)
               VALUES(?,?,?,?,?,?)
               ON CONFLICT(sensor_id) DO UPDATE SET
                   last_seen = excluded.last_seen,
                   version   = excluded.version""",
            (sensor_id, kind, hostname, version, now, now),
        )

    def record_observation(
        self,
        *,
        source: str,
        agent_generated: bool,
        sensor_id: str | None = None,
        device_id: str | None = None,
        mac: str | None = None,
        ip: str | None = None,
        detail: dict | None = None,
        ts: float | None = None,
    ) -> None:
        self.execute(
            """INSERT INTO observations(ts, sensor_id, device_id, mac, ip,
                                        source, agent_generated, detail)
               VALUES(?,?,?,?,?,?,?,?)""",
            (
                ts or time.time(),
                sensor_id,
                device_id,
                mac,
                ip,
                source,
                int(agent_generated),
                json.dumps(detail) if detail else None,
            ),
        )

    def record_host_fact(
        self,
        *,
        fact_key: str,
        category: str,
        title: str,
        state: str,
        value: str | None = None,
        expected: str | None = None,
        reason: str | None = None,
        needs_admin: bool = False,
        evidence: dict | None = None,
        ts: float | None = None,
    ) -> bool:
        """Upsert one host posture fact. Returns True if `state` changed.

        The return value is what lets a rule distinguish "this box has always
        had script-block logging off" from "script-block logging was turned off
        since we last looked" -- the second is an event, the first is debt.
        """
        if state not in ("ok", "finding", "unknown"):
            raise ValueError(f"invalid host fact state: {state!r}")

        now = ts or time.time()
        prev = self.query_one(
            "SELECT state FROM host_facts WHERE fact_key = ?", (fact_key,)
        )
        changed = prev is not None and prev["state"] != state

        self.execute(
            """INSERT INTO host_facts(fact_key, category, title, state, value,
                                      expected, reason, needs_admin, evidence,
                                      first_seen, last_seen, changed_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(fact_key) DO UPDATE SET
                   category    = excluded.category,
                   title       = excluded.title,
                   state       = excluded.state,
                   value       = excluded.value,
                   expected    = excluded.expected,
                   reason      = excluded.reason,
                   needs_admin = excluded.needs_admin,
                   evidence    = excluded.evidence,
                   last_seen   = excluded.last_seen,
                   changed_at  = CASE WHEN host_facts.state != excluded.state
                                      THEN excluded.last_seen
                                      ELSE host_facts.changed_at END""",
            (
                fact_key,
                category,
                title,
                state,
                value,
                expected,
                reason,
                int(needs_admin),
                json.dumps(evidence) if evidence else None,
                now,
                now,
                now if changed else None,
            ),
        )
        return changed

    def upsert_binding(
        self, mac: str, ip: str, *, passive: bool, ts: float | None = None
    ) -> None:
        now = ts or time.time()
        self.execute(
            """INSERT INTO bindings(mac, ip, first_seen, last_seen, obs_count,
                                    passive_count)
               VALUES(?,?,?,?,1,?)
               ON CONFLICT(mac, ip) DO UPDATE SET
                   last_seen     = excluded.last_seen,
                   obs_count     = obs_count + 1,
                   passive_count = passive_count + excluded.passive_count""",
            (mac, ip, now, now, 1 if passive else 0),
        )

    def raise_alert(
        self,
        *,
        dedup_key: str,
        rule_id: str,
        severity: str,
        title: str,
        description: str = "",
        device_id: str | None = None,
        mitre_id: str | None = None,
        mitre_name: str | None = None,
        evidence: dict | None = None,
        ts: float | None = None,
    ) -> bool:
        """Create or bump an alert. Returns True if this alert is new.

        Bumping refreshes the whole judgement -- severity, title, description,
        technique -- not just the evidence, so an operator never reads stale
        reasoning attached to current telemetry. Each changed field is written
        to ``alert_changes`` so the refresh is visible history rather than a
        silent overwrite.

        Status: a resolved alert reopens (a condition that comes back is news
        again); an acknowledged one reopens only when severity escalates, so a
        flapping rule cannot undo triage but an escalation is never hidden
        behind an old acknowledgement.
        """
        now = ts or time.time()
        existing = self.query_one(
            "SELECT id, severity, title, description, evidence, status, last_seen "
            "FROM alerts WHERE dedup_key = ?",
            (dedup_key,),
        )
        evidence_json = json.dumps(evidence) if evidence else None
        if existing is None:
            self.execute(
                """INSERT INTO alerts(dedup_key, rule_id, severity, title,
                                      description, device_id, mitre_id, mitre_name,
                                      evidence, first_seen, last_seen)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (dedup_key, rule_id, severity, title, description, device_id,
                 mitre_id, mitre_name, evidence_json, now, now),
            )
            return True

        # A finding the rules re-emit unchanged is not news. Detection now runs
        # within seconds of every collector write, so bumping count/last_seen
        # on each pass would inflate "seen on N runs" into the thousands and
        # write the alerts table every few seconds (which the dashboard's
        # change stream would faithfully repaint). Unchanged within the
        # window: leave the row alone.
        if (
            existing["severity"] == severity and existing["title"] == title
            and existing["description"] == description
            and existing["evidence"] == evidence_json
            and existing["status"] != "resolved"
            and now - existing["last_seen"] < ALERT_BUMP_MIN_S
        ):
            return False

        escalated = _severity_rank(severity) > _severity_rank(existing["severity"])
        new_status = existing["status"]
        if existing["status"] == "resolved" or (
            existing["status"] == "acknowledged" and escalated
        ):
            new_status = "open"
        for field, old, new in (
            ("severity", existing["severity"], severity),
            ("title", existing["title"], title),
            ("status", existing["status"], new_status),
        ):
            if old != new:
                self.record_alert_change(existing["id"], field, old, new, ts=now)
        self.execute(
            """UPDATE alerts SET last_seen = ?, count = count + 1, evidence = ?,
                                 severity = ?, title = ?, description = ?,
                                 mitre_id = ?, mitre_name = ?, status = ?
               WHERE id = ?""",
            (now, evidence_json, severity, title, description, mitre_id,
             mitre_name, new_status, existing["id"]),
        )
        return False

    def record_alert_change(
        self,
        alert_id: int,
        field: str,
        old_value: str | None,
        new_value: str | None,
        *,
        actor: str = "rule",
        ts: float | None = None,
    ) -> None:
        self.execute(
            "INSERT INTO alert_changes(alert_id, ts, field, old_value, new_value, actor) "
            "VALUES(?,?,?,?,?,?)",
            (alert_id, ts or time.time(), field, old_value, new_value, actor),
        )

    def record_router_event(self, *, ts: float, kind: str, severity: str | None,
                            title: str, ip: str | None, mac: str | None, line: str,
                            dedup_key: str) -> bool:
        """Persist one parsed router log line; False if this line was seen before."""
        cur = self.execute(
            "INSERT OR IGNORE INTO router_events(ts, kind, severity, title, ip, mac, line, dedup_key) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (ts, kind, severity, title, ip, mac, line, dedup_key),
        )
        return cur.rowcount > 0

    def record_auth_event(self, *, ts: float, event_id: int, account: str | None,
                          domain: str | None, source_ip: str | None,
                          logon_type: str | None, status: str | None,
                          detail: dict | None, dedup_key: str) -> bool:
        """Persist one Windows auth event; False if this record was seen before."""
        cur = self.execute(
            "INSERT OR IGNORE INTO auth_events(ts, event_id, account, domain, source_ip, "
            "logon_type, status, detail, dedup_key) VALUES(?,?,?,?,?,?,?,?,?)",
            (ts, event_id, account, domain, source_ip, logon_type, status,
             __import__("json").dumps(detail) if detail else None, dedup_key),
        )
        return cur.rowcount > 0

    def record_connection_sample(self, *, process: str, path: str | None,
                                 raddr: str, rport: int, ts: float,
                                 keep: int = 40) -> bool:
        """Upsert one external-connection sample. Returns True if this
        (process, destination) was seen for the FIRST time."""
        import json as _json

        row = self.query_one(
            "SELECT samples, sample_count FROM connection_endpoints "
            "WHERE process = ? AND raddr = ? AND rport = ?", (process, raddr, rport))
        if row is None:
            self.execute(
                "INSERT INTO connection_endpoints(process, path, raddr, rport, "
                "first_seen, last_seen, sample_count, samples) VALUES(?,?,?,?,?,?,1,?)",
                (process, path, raddr, rport, ts, ts, _json.dumps([ts])))
            return True
        try:
            samples = _json.loads(row["samples"] or "[]")
        except (TypeError, ValueError):
            samples = []
        samples.append(ts)
        samples = samples[-keep:]
        self.execute(
            "UPDATE connection_endpoints SET last_seen = ?, sample_count = sample_count + 1, "
            "samples = ? WHERE process = ? AND raddr = ? AND rport = ?",
            (ts, _json.dumps(samples), process, raddr, rport))
        return False

    def record_host_event(
        self,
        *,
        kind: str,
        ts: float,
        summary: str,
        detail: dict | None,
        severity: str | None,
        dedup_key: str,
        agent_generated: bool = False,
        mitre_id: str | None = None,
        sensor_id: str | None = None,
    ) -> bool:
        """Insert one host event; returns False if dedup_key was already there."""
        cur = self.execute(
            """INSERT OR IGNORE INTO host_events(ts, sensor_id, kind, summary, detail,
                                                 severity, mitre_id, agent_generated, dedup_key)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (ts, sensor_id, kind, summary, json.dumps(detail) if detail else None,
             severity, mitre_id, int(bool(agent_generated)), dedup_key),
        )
        return cur.rowcount > 0

    def log_scan(
        self,
        kind: str,
        target: str,
        *,
        duration_s: float | None = None,
        result: str | None = None,
        error: str | None = None,
    ) -> None:
        self.execute(
            """INSERT INTO scan_runs(ts, kind, target, duration_s, result, error)
               VALUES(?,?,?,?,?,?)""",
            (time.time(), kind, target, duration_s, result, error),
        )

    def prune(self, retention_days: int) -> dict[str, int]:
        """Enforce retention. Unbounded growth is a self-inflicted outage."""
        cutoff = time.time() - retention_days * 86400
        deleted: dict[str, int] = {}
        for table in ("observations", "availability", "scan_runs"):
            cur = self.execute(f"DELETE FROM {table} WHERE ts < ?", (cutoff,))
            deleted[table] = cur.rowcount
        self.execute(
            "DELETE FROM alerts WHERE status = 'resolved' AND last_seen < ?",
            (cutoff,),
        )
        return deleted
