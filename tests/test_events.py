"""The unified event stream and the per-alert investigation bundle."""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

from fastapi.testclient import TestClient

from pnma import events
from pnma.db import Database


def _db():
    return Database(Path(tempfile.mkdtemp()) / "t.db")


def _seed(db):
    now = time.time()
    db.execute("INSERT INTO devices(device_id, mac, mac_type, ip, first_seen, last_seen) "
               "VALUES('d1','aa:bb:cc:dd:ee:01','global','10.0.0.5',?,?)", (now - 7200, now))
    db.execute("INSERT INTO devices(device_id, mac, mac_type, ip, first_seen, last_seen) "
               "VALUES('d2','aa:bb:cc:dd:ee:02','global','10.0.0.6',?,?)", (now - 7200, now))
    for i in range(3):
        db.execute("INSERT INTO observations(ts, device_id, mac, ip, source, agent_generated) "
                   "VALUES(?, 'd1','aa:bb:cc:dd:ee:01','10.0.0.5','passive_arp',0)", (now - 600 - i,))
    db.execute("INSERT INTO observations(ts, device_id, mac, ip, source, agent_generated) "
               "VALUES(?, 'd2','aa:bb:cc:dd:ee:02','10.0.0.6','arp_table',1)", (now - 500,))
    db.log_scan("port_scan", "10.0.0.5", result="2 open ports")
    db.log_scan("alert_ntfy", "ntfy", result="delivered 1 alerts")
    for ts, up in ((now - 900, 1), (now - 800, 0), (now - 700, 0), (now - 100, 1)):
        db.execute("INSERT INTO availability(ts, device_id, reachable) VALUES(?,?,?)", (ts, "d1", up))
        db.execute("INSERT INTO availability(ts, device_id, reachable) VALUES(?,?,?)", (ts, "d2", up))
    db.raise_alert(dedup_key="a1", rule_id="service_drift", severity="high", title="d1 drift",
                   device_id="d1", evidence={"ip": "10.0.0.5"}, ts=now - 300)
    db.raise_alert(dedup_key="a1", rule_id="service_drift", severity="critical", title="d1 drift",
                   device_id="d1", evidence={"ip": "10.0.0.5"}, ts=now - 200)
    db.raise_alert(dedup_key="a2", rule_id="new_device", severity="low", title="d1 new",
                   device_id="d1", ts=now - 250)
    db.raise_alert(dedup_key="a3", rule_id="arp_spoof", severity="critical", title="gw claimed",
                   evidence={"ip": "10.0.0.5", "macs": ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]},
                   ts=now - 200)
    return now


def test_query_events_unifies_tables_and_folds_ping_to_transitions():
    db = _db(); _seed(db)
    evs = events.query_events(db, limit=100)
    kinds = {e["kind"] for e in evs}
    assert {"observation", "scan", "delivery", "alert", "alert_change", "availability"} <= kinds
    # 4 samples per device -> 2 transitions per device, not 8 rows
    assert sum(1 for e in evs if e["kind"] == "availability") == 4
    assert evs == sorted(evs, key=lambda e: e["ts"], reverse=True)
    # the agent filter removes everything the agent caused
    quiet = events.query_events(db, include_agent=False, limit=100)
    assert all(not e["agent_generated"] for e in quiet)
    assert any(e["kind"] == "observation" for e in quiet)
    assert not any(e["kind"] == "scan" for e in quiet)
    # free text
    assert all("ntfy" in str(e).lower() for e in events.query_events(db, q="ntfy", limit=100))


def test_investigate_scopes_to_device_and_evidence_identifiers():
    db = _db(); _seed(db)
    a1 = db.query_one("SELECT id FROM alerts WHERE dedup_key='a1'")["id"]
    b = events.investigate(db, a1)
    assert b["device_id"] == "d1"
    assert b["identifiers"]["ips"] == ["10.0.0.5"]
    assert b["counts"]["observation"] == 3          # d1 only, not d2's row
    assert b["counts"]["availability"] == 2         # d1's transitions only
    assert b["counts"]["alert_change"] == 1         # the high -> critical escalation
    assert b["counts"]["alert"] == 1                # the other alert on d1 (a2), not a1 itself
    assert b["counts"]["delivery"] == 1
    assert b["events"] == sorted(b["events"], key=lambda e: e["ts"])
    # ARP spoof has no device: matched purely on the MACs/IP its evidence names
    a3 = db.query_one("SELECT id FROM alerts WHERE dedup_key='a3'")["id"]
    b3 = events.investigate(db, a3)
    assert b3["device_id"] is None
    assert b3["counts"]["observation"] == 4         # both claimants' rows
    assert "availability" not in b3["counts"]       # nothing per-device leaks in unscoped


def test_investigate_unknown_alert_is_none():
    assert events.investigate(_db(), 999) is None


def test_api_routes(tmp_path):
    from pnma.api.app import create_app
    from pnma.config import Config

    cfg = Config.load(Path(__file__).resolve().parents[1] / "config" / "pnma.example.toml")
    cfg.database = str(tmp_path / "t.db")
    _seed(Database(Path(cfg.database)))
    c = TestClient(create_app(cfg))
    r = c.get("/api/events?hours=1&limit=10")
    assert r.status_code == 200 and len(r.json()["events"]) == 10
    r = c.get("/api/events?hours=1&kinds=observation&agent=false")
    assert {e["kind"] for e in r.json()["events"]} == {"observation"}
    a1 = c.get("/api/alerts").json()
    a1 = [a for a in (a1["alerts"] if isinstance(a1, dict) else a1) if a["rule_id"] == "service_drift"][0]["id"]
    assert c.get(f"/api/alerts/{a1}/investigate").status_code == 200
    assert c.get("/api/alerts/999/investigate").status_code == 404
