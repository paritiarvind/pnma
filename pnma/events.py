"""One log, many tables: the SIEM view over what PNMA has recorded.

PNMA already keeps every fact it learned -- ``observations`` (each time a
device was seen and by which sensor), ``scan_runs`` (each thing the agent did
and what came back), ``availability`` (each ping), ``alerts`` and
``alert_changes`` (each judgement and each time it moved), ``host_facts`` and
``ports`` (each control and each service, with the moment they changed). What
was missing was a way to read them as one time-ordered stream, which is what
an analyst does when an alert fires: "show me everything around this device
in the hour before and after".

This module normalises those tables into one event shape::

    {ts, kind, source, device_id, entity, summary, agent_generated, detail}

``kind`` says which table it came from; ``source`` the sensor / scan / rule;
``entity`` the IP, MAC, target or fact key the row is about; ``summary`` a
one-line reading; ``agent_generated`` whether PNMA caused the row itself (its
own scan answering, its own delivery attempt) so a reader can separate what
the network did from what the agent did to it.

Two entry points:

* ``query_events`` -- the log explorer: time window, device, kind, free text.
* ``investigate`` -- the bundle for one alert: everything about its device
  (and any MAC/IP its evidence names) in a window around it, plus that
  alert's own history and the alerts that fired alongside it.

Reads only. Identifiers are returned raw; the dashboard's privacy mask is
applied at the DOM, not here.
"""

from __future__ import annotations

import json
import time
from typing import Any, Iterable

from .db import Database

KINDS = ("observation", "scan", "alert", "alert_change", "availability",
         "host_fact", "host_event", "router", "port", "banner", "delivery")

# scan_runs.kind values that are the agent talking to the operator, not the
# network. They get kind="delivery" so the drawer can show "toast shown /
# ntfy delivered" next to the alert without mixing them into scan history.
DELIVERY_KINDS = ("alert_toast", "alert_ntfy", "alert_webhook")

DEFAULT_LIMIT = 500


def _loads(text: str | None) -> Any:
    if not text:
        return None
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return text


def _event(ts: float, kind: str, source: str | None, *, device_id=None,
           entity=None, summary: str, agent_generated: bool = False,
           detail=None, ref: str | None = None) -> dict[str, Any]:
    return {
        "ts": ts, "kind": kind, "source": source or kind, "device_id": device_id,
        "entity": entity, "summary": summary,
        "agent_generated": bool(agent_generated), "detail": detail, "ref": ref,
    }


def _marks(n: int) -> str:
    return ",".join("?" * n)


# -- per-table readers --------------------------------------------------------

def _observations(db: Database, since: float, until: float, *,
                  device_id: str | None, macs: set[str], ips: set[str],
                  limit: int) -> list[dict]:
    where = ["ts >= ?", "ts <= ?"]
    params: list[Any] = [since, until]
    ors = []
    if device_id:
        ors.append("device_id = ?")
        params.append(device_id)
    if macs:
        ors.append("mac IN (%s)" % _marks(len(macs)))
        params.extend(sorted(macs))
    if ips:
        ors.append("ip IN (%s)" % _marks(len(ips)))
        params.extend(sorted(ips))
    if ors:
        where.append("(" + " OR ".join(ors) + ")")
    rows = db.query(
        "SELECT id, ts, sensor_id, device_id, mac, ip, source, agent_generated, detail "
        "FROM observations WHERE " + " AND ".join(where) + " ORDER BY ts DESC LIMIT ?",
        (*params, limit),
    )
    out = []
    for r in rows:
        who = r["ip"] or r["mac"] or r["device_id"] or "?"
        via = r["source"]
        if r["mac"] and r["ip"]:
            summary = f"{r['ip']} is {r['mac']} ({via})"
        else:
            summary = f"{who} seen via {via}"
        if r["agent_generated"]:
            summary += " -- answered PNMA's own probe"
        detail: dict[str, Any] = {"mac": r["mac"], "ip": r["ip"], "sensor": r["sensor_id"]}
        extra = _loads(r["detail"])
        if isinstance(extra, dict):
            detail.update(extra)
        out.append(_event(r["ts"], "observation", via, device_id=r["device_id"],
                          entity=r["ip"] or r["mac"], summary=summary,
                          agent_generated=r["agent_generated"], detail=detail,
                          ref=f"observation:{r['id']}"))
    return out


def _scans(db: Database, since: float, until: float, *, targets: set[str],
           limit: int) -> list[dict]:
    where = ["ts >= ?", "ts <= ?"]
    params: list[Any] = [since, until]
    if targets:
        # A scan of the whole subnet touched this device too; keep those.
        where.append("(target IN (%s) OR target LIKE '%%/%%' OR kind IN (%s))"
                     % (_marks(len(targets)), _marks(len(DELIVERY_KINDS))))
        params.extend(sorted(targets))
        params.extend(DELIVERY_KINDS)
    rows = db.query(
        "SELECT id, ts, kind, target, duration_s, result, error FROM scan_runs "
        "WHERE " + " AND ".join(where) + " ORDER BY ts DESC LIMIT ?", (*params, limit))
    out = []
    for r in rows:
        delivery = r["kind"] in DELIVERY_KINDS
        what = r["kind"].replace("_", " ")
        if r["error"]:
            summary = f"{what} {r['target']}: {r['error']}"
        else:
            summary = f"{what} {r['target']}: {r['result'] or 'done'}"
        out.append(_event(r["ts"], "delivery" if delivery else "scan", r["kind"],
                          entity=r["target"], summary=summary, agent_generated=True,
                          detail={"duration_s": r["duration_s"], "result": r["result"],
                                  "error": r["error"]},
                          ref=f"scan:{r['id']}"))
    return out


def _alerts(db: Database, since: float, until: float, *, device_id: str | None,
            exclude_id: int | None, limit: int) -> list[dict]:
    where = ["first_seen <= ?", "last_seen >= ?"]
    params: list[Any] = [until, since]
    if device_id:
        where.append("device_id = ?")
        params.append(device_id)
    if exclude_id is not None:
        where.append("id != ?")
        params.append(exclude_id)
    rows = db.query(
        "SELECT id, first_seen, last_seen, rule_id, severity, title, status, device_id, count "
        "FROM alerts WHERE " + " AND ".join(where) + " ORDER BY first_seen DESC LIMIT ?",
        (*params, limit))
    return [_event(r["first_seen"], "alert", r["rule_id"], device_id=r["device_id"],
                   entity=r["title"], summary=f"{r['severity']}: {r['title']}",
                   detail={"alert_id": r["id"], "status": r["status"],
                           "severity": r["severity"], "count": r["count"],
                           "last_seen": r["last_seen"]},
                   ref=f"alert:{r['id']}") for r in rows]


def _alert_changes(db: Database, since: float, until: float, *,
                   alert_id: int | None, device_id: str | None, limit: int) -> list[dict]:
    where = ["c.ts >= ?", "c.ts <= ?"]
    params: list[Any] = [since, until]
    if alert_id is not None:
        where.append("c.alert_id = ?")
        params.append(alert_id)
    elif device_id:
        where.append("a.device_id = ?")
        params.append(device_id)
    rows = db.query(
        "SELECT c.id, c.ts, c.alert_id, c.field, c.old_value, c.new_value, c.actor, "
        "a.title, a.device_id, a.rule_id FROM alert_changes c JOIN alerts a ON a.id = c.alert_id "
        "WHERE " + " AND ".join(where) + " ORDER BY c.ts DESC LIMIT ?", (*params, limit))
    return [_event(r["ts"], "alert_change", r["rule_id"], device_id=r["device_id"],
                   entity=r["title"],
                   summary=f"{r['field']} {r['old_value']} -> {r['new_value']} ({r['actor']})",
                   agent_generated=r["actor"] == "rule",
                   detail={"alert_id": r["alert_id"], "field": r["field"],
                           "old": r["old_value"], "new": r["new_value"], "actor": r["actor"]},
                   ref=f"alert_change:{r['id']}") for r in rows]


def _availability(db: Database, since: float, until: float, *, device_id: str | None,
                  limit: int) -> list[dict]:
    """Only transitions -- 1,400 identical 'reachable' pings a day are not events."""
    where = ["ts >= ?", "ts <= ?"]
    params: list[Any] = [since, until]
    if device_id:
        where.append("device_id = ?")
        params.append(device_id)
    rows = db.query(
        "SELECT ts, device_id, reachable, rtt_ms FROM availability "
        "WHERE " + " AND ".join(where) + " ORDER BY device_id, ts", params)
    out: list[dict] = []
    last: dict[str, int | None] = {}
    for r in rows:
        prev = last.get(r["device_id"])
        if prev is not None and prev != r["reachable"]:
            word = "reachable again" if r["reachable"] else "stopped answering pings"
            out.append(_event(r["ts"], "availability", "ping", device_id=r["device_id"],
                              entity=r["device_id"], summary=word, agent_generated=True,
                              detail={"reachable": r["reachable"], "rtt_ms": r["rtt_ms"]}))
        last[r["device_id"]] = r["reachable"]
    out.sort(key=lambda e: e["ts"], reverse=True)
    return out[:limit]


def _host_facts(db: Database, since: float, until: float, *, fact_key: str | None,
                limit: int) -> list[dict]:
    where = ["COALESCE(changed_at, first_seen) >= ?", "COALESCE(changed_at, first_seen) <= ?"]
    params: list[Any] = [since, until]
    if fact_key:
        where.append("fact_key = ?")
        params.append(fact_key)
    rows = db.query(
        "SELECT fact_key, category, title, state, value, expected, reason, changed_at, first_seen "
        "FROM host_facts WHERE " + " AND ".join(where)
        + " ORDER BY COALESCE(changed_at, first_seen) DESC LIMIT ?",
        (*params, limit))
    return [_event(r["changed_at"] or r["first_seen"], "host_fact", r["category"],
                   entity=r["fact_key"],
                   summary=f"{r['title']}: {r['state']} ({r['value'] or '?'})",
                   agent_generated=True,
                   detail={"state": r["state"], "value": r["value"],
                           "expected": r["expected"], "reason": r["reason"]},
                   ref=f"host_fact:{r['fact_key']}") for r in rows]


def _host_events(db: Database, since: float, until: float, *, kinds: set[str] | None,
                 limit: int) -> list[dict]:
    where = ["ts >= ?", "ts <= ?"]
    params: list[Any] = [since, until]
    if kinds:
        where.append("kind IN (%s)" % _marks(len(kinds)))
        params.extend(sorted(kinds))
    rows = db.query(
        "SELECT id, ts, kind, summary, detail, severity, mitre_id, agent_generated FROM host_events "
        "WHERE " + " AND ".join(where) + " ORDER BY ts DESC LIMIT ?", (*params, limit))
    out = []
    for r in rows:
        d = _loads(r["detail"]) or {}
        out.append(_event(r["ts"], "host_event", r["kind"],
                          entity=(d.get("path") or d.get("name") or d.get("process") or r["kind"]) if isinstance(d, dict) else r["kind"],
                          summary=r["summary"], agent_generated=r["agent_generated"],
                          detail={"severity": r["severity"], "mitre_id": r["mitre_id"],
                                  **(d if isinstance(d, dict) else {})},
                          ref=f"host_event:{r['id']}"))
    return out


def _router(db: Database, since: float, until: float, *, ips: set[str], macs: set[str],
            kinds: set[str] | None, limit: int) -> list[dict]:
    where = ["ts >= ?", "ts <= ?"]
    params: list[Any] = [since, until]
    scoped = []
    if ips:
        scoped.append("ip IN (%s)" % _marks(len(ips)))
        params.extend(sorted(ips))
    if macs:
        scoped.append("lower(mac) IN (%s)" % _marks(len(macs)))
        params.extend(sorted(macs))
    if scoped:
        where.append("(" + " OR ".join(scoped) + ")")
    if kinds:
        where.append("kind IN (%s)" % _marks(len(kinds)))
        params.extend(sorted(kinds))
    rows = db.query(
        "SELECT id, ts, kind, severity, title, ip, mac, line FROM router_events "
        "WHERE " + " AND ".join(where) + " ORDER BY ts DESC LIMIT ?", (*params, limit))
    return [_event(r["ts"], "router", "router:" + r["kind"],
                   device_id=None, entity=r["ip"] or r["mac"],
                   summary=r["title"] + (f" ({r['ip']})" if r["ip"] else ""),
                   detail={"severity": r["severity"], "kind": r["kind"],
                           "ip": r["ip"], "mac": r["mac"], "line": r["line"]},
                   ref=f"router:{r['id']}") for r in rows]


def _ports(db: Database, since: float, until: float, *, device_id: str | None,
           limit: int) -> list[dict]:
    where = ["(first_seen BETWEEN ? AND ? OR closed_at BETWEEN ? AND ?)"]
    params: list[Any] = [since, until, since, until]
    if device_id:
        where.append("device_id = ?")
        params.append(device_id)
    rows = db.query(
        "SELECT device_id, port, proto, service, product, risk, first_seen, closed_at "
        "FROM ports WHERE " + " AND ".join(where)
        + " ORDER BY COALESCE(closed_at, first_seen) DESC LIMIT ?",
        (*params, limit))
    out = []
    for r in rows:
        label = f"{r['port']}/{r['proto']}" + (f" {r['service']}" if r["service"] else "")
        if since <= r["first_seen"] <= until:
            out.append(_event(r["first_seen"], "port", "port_scan", device_id=r["device_id"],
                              entity=label,
                              summary=f"{label} first seen open"
                              + (f" (risk {r['risk']})" if r["risk"] else ""),
                              agent_generated=True,
                              detail={"port": r["port"], "proto": r["proto"],
                                      "service": r["service"], "product": r["product"],
                                      "risk": r["risk"]}))
        if r["closed_at"] and since <= r["closed_at"] <= until:
            out.append(_event(r["closed_at"], "port", "port_scan", device_id=r["device_id"],
                              entity=label, summary=f"{label} no longer open",
                              agent_generated=True,
                              detail={"port": r["port"], "proto": r["proto"]}))
    return out[:limit]


def _banners(db: Database, since: float, until: float, *, device_id: str | None,
             limit: int) -> list[dict]:
    where = ["confirmed_at >= ?", "confirmed_at <= ?"]
    params: list[Any] = [since, until]
    if device_id:
        where.append("device_id = ?")
        params.append(device_id)
    rows = db.query(
        "SELECT device_id, port, banner, confirmed_at FROM exposure_banners "
        "WHERE " + " AND ".join(where) + " ORDER BY confirmed_at DESC LIMIT ?",
        (*params, limit))
    return [_event(r["confirmed_at"], "banner", "confirm_exposure", device_id=r["device_id"],
                   entity=f"{r['port']}/tcp",
                   summary=f"{r['port']}/tcp answered: {r['banner'][:80]}",
                   agent_generated=True, detail={"banner": r["banner"]}) for r in rows]


# -- public API ---------------------------------------------------------------

def query_events(db: Database, *, since: float | None = None, until: float | None = None,
                 device_id: str | None = None, kinds: Iterable[str] | None = None,
                 q: str | None = None, include_agent: bool = True,
                 limit: int = DEFAULT_LIMIT) -> list[dict[str, Any]]:
    """The log explorer. Newest first, capped at ``limit``."""
    until = until or time.time()
    since = since if since is not None else until - 24 * 3600
    wanted = set(kinds) if kinds else set(KINDS)
    limit = max(1, min(int(limit), 5000))
    events: list[dict] = []
    if "observation" in wanted:
        events += _observations(db, since, until, device_id=device_id,
                                macs=set(), ips=set(), limit=limit)
    if "scan" in wanted or "delivery" in wanted:
        scans = _scans(db, since, until, targets=set(), limit=limit)
        events += [e for e in scans if e["kind"] in wanted]
    if "alert" in wanted:
        events += _alerts(db, since, until, device_id=device_id, exclude_id=None, limit=limit)
    if "alert_change" in wanted:
        events += _alert_changes(db, since, until, alert_id=None, device_id=device_id, limit=limit)
    if "availability" in wanted:
        events += _availability(db, since, until, device_id=device_id, limit=limit)
    if "host_fact" in wanted and not device_id:
        events += _host_facts(db, since, until, fact_key=None, limit=limit)
    if "host_event" in wanted and not device_id:
        events += _host_events(db, since, until, kinds=None, limit=limit)
    if "router" in wanted:
        # scoped to the device when one is given, else all router lines
        ips, macs = set(), set()
        if device_id:
            dev = db.query_one("SELECT ip, mac FROM devices WHERE device_id = ?", (device_id,))
            if dev:
                if dev["ip"]:
                    ips.add(dev["ip"])
                if dev["mac"]:
                    macs.add(dev["mac"].lower())
        events += _router(db, since, until, ips=ips, macs=macs, kinds=None, limit=limit)
    if "port" in wanted:
        events += _ports(db, since, until, device_id=device_id, limit=limit)
    if "banner" in wanted:
        events += _banners(db, since, until, device_id=device_id, limit=limit)
    if not include_agent:
        events = [e for e in events if not e["agent_generated"]]
    if q:
        needle = q.lower()
        events = [e for e in events if needle in json.dumps(e, default=str).lower()]
    events.sort(key=lambda e: e["ts"], reverse=True)
    return events[:limit]


_EVIDENCE_MAC_KEYS = ("mac", "macs")
_EVIDENCE_IP_KEYS = ("ip", "ips", "src_ip")


def _identifiers(evidence: Any) -> tuple[set[str], set[str]]:
    macs: set[str] = set()
    ips: set[str] = set()
    if not isinstance(evidence, dict):
        return macs, ips
    for key in _EVIDENCE_MAC_KEYS:
        v = evidence.get(key)
        if isinstance(v, str):
            macs.add(v.lower())
        elif isinstance(v, list):
            macs.update(str(x).lower() for x in v)
    for key in _EVIDENCE_IP_KEYS:
        v = evidence.get(key)
        if isinstance(v, str):
            ips.add(v)
        elif isinstance(v, list):
            ips.update(str(x) for x in v)
    return macs, ips


def investigate(db: Database, alert_id: int, *, before_s: int = 3600,
                after_s: int = 3600, limit: int = 300) -> dict[str, Any] | None:
    """Everything recorded around one alert, oldest context first.

    Window: ``first_seen - before_s`` to ``last_seen + after_s`` (capped at
    now). Rows are matched by the alert's device and by any MAC/IP its
    evidence names -- an ARP-spoof alert has no single device, but its
    evidence lists both claimants, and those are what the analyst wants.
    """
    row = db.query_one("SELECT * FROM alerts WHERE id = ?", (alert_id,))
    if row is None:
        return None
    evidence = _loads(row["evidence"])
    macs, ips = _identifiers(evidence)
    device_id = row["device_id"]
    if device_id:
        dev = db.query_one("SELECT mac, ip FROM devices WHERE device_id = ?", (device_id,))
        if dev:
            if dev["mac"]:
                macs.add(dev["mac"].lower())
            if dev["ip"]:
                ips.add(dev["ip"])
    now = time.time()
    since = row["first_seen"] - before_s
    until = min(now, row["last_seen"] + after_s)
    scoped = bool(device_id or macs or ips)
    events: list[dict] = []
    if scoped:
        targets = ips | macs | ({device_id} if device_id else set())
        events += _observations(db, since, until, device_id=device_id, macs=macs, ips=ips, limit=limit)
        events += _scans(db, since, until, targets=targets, limit=limit)
        if device_id:  # per-device tables; unscoped they would return every device
            events += _availability(db, since, until, device_id=device_id, limit=limit)
            events += _ports(db, since, until, device_id=device_id, limit=limit)
            events += _banners(db, since, until, device_id=device_id, limit=limit)
        if ips or macs:
            events += _router(db, since, until, ips=ips, macs=macs, kinds=None, limit=limit)
    else:
        # Host / identity / agent alerts: the agent's own runs are the context.
        events += [e for e in _scans(db, since, until, targets=set(), limit=limit)
                   if e["source"] in ("host_posture", *DELIVERY_KINDS)]
    if isinstance(evidence, dict) and evidence.get("host_event_id"):
        # A host-event alert: its own row plus what else happened on the host
        # in the window -- the same "what was going on" an analyst wants.
        events += _host_events(db, since, until, kinds=None, limit=limit)
    fact_key = evidence.get("fact_key") if isinstance(evidence, dict) else None
    if fact_key:
        # The control's current row, whenever it last moved: for a host alert
        # that IS the evidence, so it is not confined to the window.
        events += _host_facts(db, 0, now, fact_key=fact_key, limit=limit)
    events += _alert_changes(db, 0, now, alert_id=alert_id, device_id=None, limit=limit)
    related = (_alerts(db, since, until, device_id=device_id, exclude_id=alert_id, limit=50)
               if device_id else [])
    events += related
    events.sort(key=lambda e: e["ts"])
    counts: dict[str, int] = {}
    for e in events:
        counts[e["kind"]] = counts.get(e["kind"], 0) + 1
    return {
        "alert_id": alert_id,
        "device_id": device_id,
        "identifiers": {"macs": sorted(macs), "ips": sorted(ips)},
        "window": {"since": since, "until": until},
        "events": events[-limit:],
        "counts": counts,
        "related_alerts": [
            {**e["detail"], "title": e["entity"], "rule_id": e["source"], "ts": e["ts"]}
            for e in related
        ],
        "truncated": len(events) > limit,
    }
