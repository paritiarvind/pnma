"""Per-device activity telemetry and the off-hours detection."""
from __future__ import annotations
import tempfile, time, datetime as dt
from pathlib import Path
from pnma.db import Database
from pnma import activity
from pnma.detections.base import DetectionContext
from pnma.detections.sec555_rules import OffHoursActivityDetection


def _db():
    return Database(Path(tempfile.mkdtemp()) / "t.db")


def _add_device(db, did, ip):
    now = time.time()
    db.execute("INSERT INTO devices(device_id,mac,mac_type,ip,label,device_class,first_seen,last_seen,trusted) "
               "VALUES(?,?,'global',?,?,'phone',?,?,0)", (did, "aa:bb:cc:00:00:%s" % did[-2:], ip, "Phone-" + did, now - 40*86400, now))


def _obs(db, did, ts, agent=0):
    db.execute("INSERT INTO observations(ts, device_id, mac, ip, source, agent_generated) "
               "VALUES(?,?,?,?,?,?)", (ts, did, "aa:bb", "10.0.0.1", "passive_arp", agent))


def test_activity_rollup_counts_only_passive():
    db = _db(); now = time.time()
    _add_device(db, "d1", "10.0.0.5")
    for i in range(10):
        _obs(db, "d1", now - i*3600)           # 10 passive, last 24h+
    _obs(db, "d1", now - 60, agent=1)          # an agent probe: must not count
    a = activity.device_activity(db, "d1", now=now)
    assert a["seen_24h"] >= 5 and a["seen_30d"] == 10
    assert a["name"] == "Phone-d1"


def test_envelope_needs_history_and_off_hours_is_conservative():
    db = _db(); now = time.time()
    _add_device(db, "d1", "10.0.0.5")
    # 20 days of history, only ever active 08:00-10:00 local
    base = dt.datetime.fromtimestamp(now).replace(minute=0, second=0, microsecond=0)
    for day in range(1, 21):
        for hour in (8, 9, 10):
            _obs(db, "d1", (base - dt.timedelta(days=day)).replace(hour=hour).timestamp())
    env = activity.active_hour_envelope(db, "d1", now=now)
    assert env["reliable"] and not env["always_on"]
    assert 8 in env["active_hours"] and 3 not in env["active_hours"]
    # 03:00 is off-hours; 09:00 is not
    t3 = base.replace(hour=3).timestamp()
    t9 = base.replace(hour=9).timestamp()
    assert activity.is_off_hours(env, t3) is True
    assert activity.is_off_hours(env, t9) is False
    # a device with too little history is never off-hours
    _add_device(db, "d2", "10.0.0.6")
    _obs(db, "d2", now - 3600)
    assert activity.is_off_hours(activity.active_hour_envelope(db, "d2", now=now), t3) is False


def test_off_hours_rule_fires_only_on_a_real_departure():
    db = _db()
    base = dt.datetime.now().replace(minute=0, second=0, microsecond=0)
    now_3am = base.replace(hour=3).timestamp()
    _add_device(db, "d1", "10.0.0.5")
    # 20 days active 08-10 only, plus one observation right now (03:00)
    for day in range(1, 21):
        for hour in (8, 9, 10):
            _obs(db, "d1", (base - dt.timedelta(days=day)).replace(hour=hour).timestamp())
    _obs(db, "d1", now_3am - 60)
    findings = OffHoursActivityDetection().evaluate(DetectionContext(db=db, now=now_3am))
    assert len(findings) == 1 and findings[0].device_id == "d1"
    assert "03:00" in findings[0].title and "08:00-10:00" in findings[0].description
    # at 09:00 (inside the envelope) it must not fire
    now_9am = base.replace(hour=9).timestamp()
    _obs(db, "d1", now_9am - 60)
    assert OffHoursActivityDetection().evaluate(DetectionContext(db=db, now=now_9am)) == []
