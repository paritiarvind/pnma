"""Windows auth-anomaly detections over auth_events (SEC555-adapted)."""
from __future__ import annotations
import tempfile, time
from pathlib import Path
from pnma.db import Database
from pnma.detections.base import DetectionContext
from pnma.detections.auth_rules import (
    BruteForceDetection, PasswordSprayDetection, AccountLockoutDetection,
    NewAdminMemberDetection, auth_rules,
)


def _db():
    return Database(Path(tempfile.mkdtemp()) / "t.db")


def _fail(db, acct, ts, ip="10.0.0.9"):
    db.record_auth_event(ts=ts, event_id=4625, account=acct, domain="D", source_ip=ip,
                         logon_type="3", status="0xC000006A",
                         detail={"TargetUserName": acct, "IpAddress": ip},
                         dedup_key="f:%s:%f" % (acct, ts))


def test_brute_force_is_deep_and_narrow():
    db = _db(); now = time.time()
    for i in range(9):
        _fail(db, "arvind", now - i * 10)
    _fail(db, "guest", now - 5)              # one other account: not spray, not enough for brute
    f = BruteForceDetection().evaluate(DetectionContext(db=db, now=now))
    assert len(f) == 1 and f[0].evidence["account"] == "arvind" and f[0].evidence["failures"] == 9
    # spray must NOT fire on one deep account
    assert PasswordSprayDetection().evaluate(DetectionContext(db=db, now=now)) == []


def test_spray_is_wide_and_shallow():
    db = _db(); now = time.time()
    for i, acct in enumerate(("a", "b", "c", "d", "e")):
        for j in range(2):                   # 2 each: shallow
            _fail(db, acct, now - i * 30 - j)
    f = PasswordSprayDetection().evaluate(DetectionContext(db=db, now=now))
    assert len(f) == 1 and len(f[0].evidence["accounts"]) == 5
    # brute must NOT fire (no single account is deep)
    assert BruteForceDetection().evaluate(DetectionContext(db=db, now=now)) == []


def test_lockout_and_new_admin():
    db = _db(); now = time.time()
    db.record_auth_event(ts=now - 60, event_id=4740, account="arvind", domain=None, source_ip=None,
                         logon_type=None, status=None, detail={"TargetUserName": "arvind", "SubjectUserName": "SYS$"},
                         dedup_key="lo1")
    lf = AccountLockoutDetection().evaluate(DetectionContext(db=db, now=now))
    assert len(lf) == 1 and "arvind" in lf[0].title
    # 4732 to Administrators fires; to a non-admin group does not
    db.record_auth_event(ts=now - 30, event_id=4732, account="Administrators", domain=None, source_ip=None,
                         logon_type=None, status=None,
                         detail={"TargetUserName": "Administrators", "TargetSid": "S-1-5-32-544",
                                 "MemberName": "hacker", "SubjectUserName": "arvind"}, dedup_key="ad1")
    db.record_auth_event(ts=now - 20, event_id=4732, account="Users", domain=None, source_ip=None,
                         logon_type=None, status=None,
                         detail={"TargetUserName": "Users", "MemberName": "bob"}, dedup_key="ad2")
    af = NewAdminMemberDetection().evaluate(DetectionContext(db=db, now=now))
    assert len(af) == 1 and af[0].evidence["member"] == "hacker"
    assert all(r.requires and "elevated" in r.requires for r in auth_rules())


def test_anomalous_logon_type_flags_rdp_cleartext_explicit(_dbfix=None):
    import tempfile, time
    from pathlib import Path
    from pnma.db import Database
    from pnma.detections.base import DetectionContext
    from pnma.detections.auth_rules import AnomalousLogonTypeDetection
    db = Database(Path(tempfile.mkdtemp()) / "t.db")
    now = time.time()
    # type 10 (RDP) from outside, type 8 (cleartext), type 9 (runas), and a
    # noisy type 3 that must NOT be stored/flagged (rule query excludes it).
    db.record_auth_event(ts=now - 60, event_id=4624, account='arvind', domain='D', source_ip='185.220.101.47',
                         logon_type='10', status=None, detail={'LogonType': '10'}, dedup_key='a')
    db.record_auth_event(ts=now - 50, event_id=4624, account='svc', domain='D', source_ip='10.0.0.9',
                         logon_type='8', status=None, detail={'LogonType': '8'}, dedup_key='b')
    db.record_auth_event(ts=now - 40, event_id=4624, account='arvind', domain='D', source_ip=None,
                         logon_type='9', status=None, detail={'LogonType': '9'}, dedup_key='c')
    db.record_auth_event(ts=now - 30, event_id=4624, account='arvind', domain='D', source_ip=None,
                         logon_type='3', status=None, detail={'LogonType': '3'}, dedup_key='d')
    f = AnomalousLogonTypeDetection().evaluate(DetectionContext(db=db, now=now))
    by = {x.evidence['logon_type']: x for x in f}
    assert set(by) == {'10', '8', '9'}                       # type 3 excluded
    assert by['8'].severity == 'high' and by['10'].severity == 'medium' and by['9'].severity == 'low'
    assert '185.220.101.47' in by['10'].title


def test_auth_collector_keeps_only_interesting_4624(monkeypatch):
    import tempfile, time
    from pathlib import Path
    from pnma.collectors import host_events as he
    from pnma.db import Database
    db = Database(Path(tempfile.mkdtemp()) / "t.db")
    now = int(time.time())
    events = [
        {"record": 1, "id": 4624, "t": now, "data": {"TargetUserName": "arvind", "LogonType": "10", "IpAddress": "9.9.9.9"}},
        {"record": 2, "id": 4624, "t": now, "data": {"TargetUserName": "arvind", "LogonType": "2", "IpAddress": "-"}},   # interactive -> skip
        {"record": 3, "id": 4624, "t": now, "data": {"TargetUserName": "arvind", "LogonType": "3", "IpAddress": "-"}},   # network -> skip
        {"record": 4, "id": 4625, "t": now, "data": {"TargetUserName": "arvind", "LogonType": "3", "IpAddress": "1.2.3.4"}},  # failure -> keep
    ]
    monkeypatch.setattr(he, "_ps_marked", lambda script, timeout=60: (True, {"ok": True, "events": events, "max": 4}, ""))
    c = he.HostEventCollector(db)
    c._collect_auth()
    kept = db.query("SELECT event_id, logon_type FROM auth_events ORDER BY id")
    assert [(r["event_id"], r["logon_type"]) for r in kept] == [(4624, "10"), (4625, "3")]


def test_account_lifecycle_flags_reset_disable_delete():
    import tempfile, time, json
    from pathlib import Path
    from pnma.db import Database
    from pnma.detections.base import DetectionContext
    from pnma.detections.auth_rules import AccountLifecycleDetection
    db = Database(Path(tempfile.mkdtemp()) / "t.db")
    now = time.time()
    db.record_auth_event(ts=now - 60, event_id=4724, account='guest', domain='D', source_ip=None, logon_type=None,
                         status=None, detail={'TargetUserName': 'guest', 'SubjectUserName': 'attacker'}, dedup_key='a')
    db.record_auth_event(ts=now - 50, event_id=4726, account='olduser', domain='D', source_ip=None, logon_type=None,
                         status=None, detail={'TargetUserName': 'olduser', 'SubjectUserName': 'admin'}, dedup_key='b')
    db.record_auth_event(ts=now - 40, event_id=4767, account='arvind', domain='D', source_ip=None, logon_type=None,
                         status=None, detail={'TargetUserName': 'arvind', 'SubjectUserName': 'arvind'}, dedup_key='c')
    f = AccountLifecycleDetection().evaluate(DetectionContext(db=db, now=now))
    by = {x.evidence['event_id']: x for x in f}
    assert set(by) == {'4724', '4726', '4767'}
    assert by['4724'].severity == 'high' and by['4726'].severity == 'high' and by['4767'].severity == 'low'
    assert 'by attacker' in by['4724'].title       # actor != target shown
