"""An existing alert's judgement must track its evidence.

`raise_alert` used to refresh only `evidence`, `count` and `last_seen`: a
correlation adding a CORROBORATION paragraph, or a rule escalating severity,
never reached a row that already existed. The operator read stale reasoning
attached to current telemetry. Now every field refreshes and each change is
recorded in `alert_changes`, so a refresh is visible history, and triage state
is only disturbed by an escalation -- never by a flap.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from pnma.db import Database


def _db():
    d = tempfile.mkdtemp()
    return Database(Path(d) / "t.db")


def _raise(db, **kw):
    base = dict(dedup_key="k", rule_id="r", severity="medium", title="t",
                description="d", evidence={"n": 1})
    base.update(kw)
    return db.raise_alert(**base)


def test_refresh_updates_judgement_and_records_history():
    db = _db()
    assert _raise(db) is True
    assert _raise(db, severity="high", title="t2", description="d2",
                  evidence={"n": 2}, mitre_id="T1", mitre_name="x") is False
    row = db.query_one("SELECT * FROM alerts WHERE dedup_key = 'k'")
    assert row["severity"] == "high"
    assert row["title"] == "t2"
    assert row["description"] == "d2"
    assert row["mitre_id"] == "T1"
    assert row["count"] == 2
    changes = db.query("SELECT field, old_value, new_value, actor FROM alert_changes "
                       "WHERE alert_id = ? ORDER BY id", (row["id"],))
    assert [(c["field"], c["old_value"], c["new_value"]) for c in changes] == [
        ("severity", "medium", "high"), ("title", "t", "t2")]
    assert all(c["actor"] == "rule" for c in changes)


def test_flap_does_not_undo_acknowledgement_but_escalation_does():
    db = _db()
    _raise(db)
    db.execute("UPDATE alerts SET status = 'acknowledged' WHERE dedup_key = 'k'")
    _raise(db)                       # same severity: stays acknowledged
    assert db.query_one("SELECT status FROM alerts")["status"] == "acknowledged"
    _raise(db, severity="low")       # de-escalation: still acknowledged
    assert db.query_one("SELECT status FROM alerts")["status"] == "acknowledged"
    _raise(db, severity="critical")  # escalation: news again
    assert db.query_one("SELECT status FROM alerts")["status"] == "open"
    statuses = db.query("SELECT old_value, new_value FROM alert_changes "
                        "WHERE field = 'status'")
    assert [(s["old_value"], s["new_value"]) for s in statuses] == [("acknowledged", "open")]


def test_resolved_alert_reopens_on_any_recurrence():
    db = _db()
    _raise(db)
    db.execute("UPDATE alerts SET status = 'resolved' WHERE dedup_key = 'k'")
    _raise(db)
    assert db.query_one("SELECT status FROM alerts")["status"] == "open"


def test_unchanged_refresh_writes_no_history():
    db = _db()
    _raise(db); _raise(db); _raise(db)
    assert db.query_one("SELECT COUNT(*) AS n FROM alert_changes")["n"] == 0
    assert db.query_one("SELECT count FROM alerts")["count"] == 3
