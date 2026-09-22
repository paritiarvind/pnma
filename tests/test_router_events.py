"""Router mail-log lines become queryable events (Logs + investigations)."""
from __future__ import annotations
import tempfile, time
from pathlib import Path
from pnma.db import Database
from pnma import events
from pnma.collectors.maillog import parse_log_line


def _db():
    return Database(Path(tempfile.mkdtemp()) / "t.db")


def test_parser_classifies_and_extracts_ip_mac():
    ev = parse_log_line("Jan 1 [DHCP] assigned 192.168.0.148 to 94:b3:f7:00:03:9e")
    assert ev and ev.kind == "dhcp_lease" and ev.ip == "192.168.0.148"


def test_router_events_reach_query_and_investigate():
    db = _db(); now = time.time()
    db.execute("INSERT INTO devices(device_id,mac,mac_type,ip,label,first_seen,last_seen,trusted) "
               "VALUES('tv','94:b3:f7:00:03:9e','global','192.168.0.148','Living Room TV',?,?,0)", (now-1000, now))
    # a low DHCP line (no alert) and a high firewall line for the same IP
    db.record_router_event(ts=now-60, kind="dhcp_lease", severity="low",
                           title="DHCP lease", ip="192.168.0.148", mac="94:b3:f7:00:03:9e",
                           line="[DHCP] 192.168.0.148", dedup_key="r1")
    db.record_router_event(ts=now-30, kind="firewall_event", severity="high",
                           title="Router firewall flagged an attack", ip="192.168.0.148", mac=None,
                           line="[FW] DoS from 192.168.0.148", dedup_key="r2")
    # dedup
    assert db.record_router_event(ts=now, kind="dhcp_lease", severity="low", title="x",
                                  ip="192.168.0.148", mac=None, line="y", dedup_key="r1") is False
    # Logs tab: router kind present
    evs = events.query_events(db, kinds=["router"], limit=50)
    assert len(evs) == 2 and {e["kind"] for e in evs} == {"router"}
    # raise an alert on the TV so investigate() has a subject, then check the
    # router's view of the device's IP is folded into the bundle
    db.raise_alert(dedup_key="a", rule_id="profile_deviation", severity="medium",
                   title="TV odd", device_id="tv", evidence={"ip": "192.168.0.148"}, ts=now-45)
    aid = db.query_one("SELECT id FROM alerts WHERE dedup_key='a'")["id"]
    bundle = events.investigate(db, aid)
    assert bundle["counts"].get("router") == 2
