"""Detections over the router's own syslog events."""
from __future__ import annotations
import tempfile, time
from pathlib import Path
from pnma.db import Database
from pnma.detections.base import DetectionContext
from pnma.detections.router_rules import RouterEventDetection, router_rules


def _db():
    return Database(Path(tempfile.mkdtemp()) / "t.db")


def test_router_events_become_findings_except_dhcp():
    db = _db(); now = time.time()
    ev = lambda k, sev, ip, key: db.record_router_event(
        ts=now - 60, kind=k, severity=sev, title=f"{k} title", ip=ip, mac=None, line=f"{k} log", dedup_key=key)
    ev("firewall_event", "high", "185.220.101.47", "a")
    ev("config_change", "medium", None, "b")
    ev("admin_login", "medium", "45.13.7.22", "c")
    ev("wan_event", "low", None, "d")
    ev("dhcp_lease", "low", "192.168.0.50", "e")          # noise: recorded, NOT alerted
    f = RouterEventDetection().evaluate(DetectionContext(db=db, now=now))
    kinds = sorted(x.evidence["kind"] for x in f)
    assert kinds == ["admin_login", "config_change", "firewall_event", "wan_event"]
    bysev = {x.evidence["kind"]: x.severity for x in f}
    assert bysev["firewall_event"] == "high" and bysev["admin_login"] == "medium"
    login = next(x for x in f if x.evidence["kind"] == "admin_login")
    assert "45.13.7.22" in login.title                    # source shown
    assert all(r.requires and r.blind_spots for r in router_rules())


def test_router_events_respect_the_window():
    db = _db(); now = time.time()
    db.record_router_event(ts=now - 40 * 3600, kind="config_change", severity="medium",
                           title="old change", ip=None, mac=None, line="x", dedup_key="old")
    assert RouterEventDetection().evaluate(DetectionContext(db=db, now=now)) == []
