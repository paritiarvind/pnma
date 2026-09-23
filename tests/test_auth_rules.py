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
