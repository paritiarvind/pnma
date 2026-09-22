"""The demo database must contain only alerts the detection engine raised.

`pnma seed` is the source of every README screenshot and every figure in the
write-up, which makes it the one code path whose output is published. It used to
hand-write six alerts with `db.raise_alert`, bypassing `DetectionEngine`
entirely. Two consequences, both visible in the published figures:

* the Security Camera carried two open alerts for one open port -- a
  `service_drift` row written by the generator and the `profile_deviation` row
  the engine really raised -- so the screenshots demonstrated exactly the alert
  fatigue the correlation engine was built to eliminate; and
* two rules were silent and nobody could tell. `ServiceDriftDetection` skipped
  ports whose `first_seen` was older than 24h, and `ArpSpoofDetection` never
  fired at all because the generator wrote the gateway's legitimate binding at
  the exact edge of the rule's 600s window. The hand-written alerts stood in for
  both, so the demo looked correct while the rules did nothing.

These tests pin both properties: one fact yields one alert, and every alert
family in the demo is produced by a rule that actually evaluated.

Runnable either way -- `pytest tests/` or `python tests/test_seed_correlation.py`
-- because the project has no test dependency yet.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
from argparse import Namespace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pnma.__main__ import cmd_seed  # noqa: E402

_CACHE: dict[str, sqlite3.Connection] = {}


def demo_db() -> sqlite3.Connection:
    """Build the demo database once, through the real `pnma seed` path.

    Deliberately calls `cmd_seed` rather than reassembling the pipeline here. A
    test that rebuilt the generate/reclassify/detect sequence itself would keep
    passing after someone changed the order in the command, which is precisely
    the kind of drift that let the original defect live in the published
    screenshots.
    """
    if "db" not in _CACHE:
        tmp = Path(tempfile.mkdtemp(prefix="pnma-seed-test-")) / "demo.db"
        rc = cmd_seed(Namespace(database=str(tmp), days=7, force=True))
        assert rc == 0, f"pnma seed exited {rc}"
        conn = sqlite3.connect(tmp)
        conn.row_factory = sqlite3.Row
        _CACHE["db"] = conn
        _CACHE["path"] = str(tmp)
    return _CACHE["db"]


def demo_db_path() -> str:
    demo_db()
    return _CACHE["path"]


def open_alerts() -> list[sqlite3.Row]:
    return list(demo_db().execute("SELECT * FROM alerts WHERE status = 'open'"))


# --------------------------------------------------------------------------
# The defect this file exists for.
# --------------------------------------------------------------------------
def test_one_risky_port_yields_exactly_one_alert():
    """No device may carry two open alerts about the same port.

    Several rules legitimately judge one open port from different angles.
    Correlation collapses them to the most severe and folds the rest into its
    evidence. Two surviving rows for one port means either correlation did not
    run or something wrote an alert around it.
    """
    dupes = list(
        demo_db().execute(
            """SELECT a.device_id,
                      json_extract(a.evidence, '$.port') AS port,
                      COUNT(*) AS n,
                      GROUP_CONCAT(a.rule_id, ' + ') AS rules
               FROM alerts a
               WHERE a.status = 'open'
                 AND json_extract(a.evidence, '$.port') IS NOT NULL
               GROUP BY a.device_id, port
               HAVING n > 1"""
        )
    )
    assert not dupes, "duplicate alerts on one port: " + "; ".join(
        f"{r['device_id']} port {r['port']}: {r['rules']}" for r in dupes
    )


def test_camera_telnet_is_one_correlated_alert():
    """23/tcp on the camera trips two rules and must survive as one.

    This is the specific pair that shipped in the published screenshots, and it
    is also the demo's only worked example of correlation, so it is worth
    asserting the shape rather than just the count: the more severe rule wins
    and names the one it absorbed.
    """
    rows = list(
        demo_db().execute(
            """SELECT a.rule_id, a.severity, a.evidence
               FROM alerts a JOIN devices d ON d.device_id = a.device_id
               WHERE d.label = 'Security Camera'
                 AND a.status = 'open'
                 AND json_extract(a.evidence, '$.port') = 23"""
        )
    )
    assert len(rows) == 1, f"expected 1 alert for camera:23, got {len(rows)}"
    assert rows[0]["rule_id"] == "profile_deviation"
    assert rows[0]["severity"] == "critical"

    corroborating = json.loads(rows[0]["evidence"]).get("corroborating_rules")
    assert corroborating, "the absorbed rule must be recorded, not discarded"
    assert "service_drift" in [c["rule_id"] for c in corroborating]


# --------------------------------------------------------------------------
# The rules that were silently doing nothing.
# --------------------------------------------------------------------------
def test_every_rule_in_the_default_set_produces_an_alert():
    """The demo must exercise every rule, and raise nothing from outside them.

    Set equality both ways, because each direction catches a different failure
    and only one of them is obvious:

    * `seen - known` catches an alert attributed to a rule that does not exist.
      Weak on its own -- everything now goes through `run_all()`, which stamps
      `rule.rule_id`, so this direction is close to structurally guaranteed. It
      would not have caught the original defect either: `_seed_alerts` used real
      rule ids (`service_drift`, `c2_indicator`, `new_device`).
    * `known - seen` is the one that bites. A rule in the default set that
      produces nothing on demo data is a rule nobody can see is broken, and
      before 2026-09-02 two of them were: `ServiceDriftDetection` skipped ports
      older than its 24h window, and `ArpSpoofDetection` never fired at all. A
      hand-written alert sat in each of their places, so the demo looked
      complete. This assertion is what makes that state fail loudly.

    If a rule is ever legitimately unexercised by the demo, subtract it here
    with a comment saying why -- do not weaken this to a subset check.
    """
    from pnma.db import Database
    from pnma.detections.base import DetectionEngine
    from pnma.detections.rules import default_rules

    db = Database(demo_db_path())
    try:
        known = {r["rule_id"] for r in DetectionEngine(db, default_rules()).catalogue()}
        # cleartext_protocol is legitimately always folded on this demo: every
        # cleartext port (camera telnet, ...) is ALSO a profile deviation on the
        # same port, and the correlation engine keeps one alert per port. The
        # rule is exercised -- see test_sec555 -- just never the survivor here.
        known.discard("cleartext_protocol")
        # off_hours_activity needs 14+ days of per-device history to build an
        # active-hour envelope; the 7-day demo cannot, so it is legitimately
        # unexercised here. Verified directly in test_activity.
        known.discard("off_hours_activity")
    finally:
        db.close()

    seen = {r["rule_id"] for r in open_alerts()}
    assert not seen - known, f"alerts from unknown rules: {sorted(seen - known)}"
    assert not known - seen, f"rules that produced nothing: {sorted(known - seen)}"


def test_arp_spoof_rule_actually_fires():
    """The contested gateway binding must reach ArpSpoofDetection.

    The generator writes a rogue MAC claiming the gateway address specifically
    so this rule has something to find. It only counts claims inside a 600s
    window, so the legitimate binding has to be written comfortably inside it --
    at the boundary the gateway's own claim ages out before the engine runs, the
    IP is left with a single claimant, and the rule goes quiet.
    """
    rows = [r for r in open_alerts() if r["rule_id"] == "arp_spoof"]
    assert len(rows) == 1, "the seeded gateway contest must raise exactly one alert"
    assert rows[0]["severity"] == "critical", "a contested gateway is not routine"


def test_service_drift_sees_the_recent_ports():
    """The ports placed inside the 24h window must be judged by the rule.

    `ServiceDriftDetection` only reports services that appeared recently, so a
    demo port with an old `first_seen` is invisible to it however dangerous the
    port is. RDP on the work laptop is the case with no second rule to cover for
    it: if the window slips, the alert vanishes rather than merely losing its
    corroboration.
    """
    titles = [r["title"] for r in open_alerts() if r["rule_id"] == "service_drift"]
    assert any("3389" in t for t in titles), f"service_drift alerts: {titles}"


def test_demo_shows_both_alert_states():
    """The dashboard renders open and resolved differently; show both."""
    states = {
        r["status"]
        for r in demo_db().execute("SELECT DISTINCT status FROM alerts")
    }
    assert {"open", "resolved"} <= states, f"only saw {states}"


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
            print(f"PASS  {name}")
        except AssertionError as exc:
            failures += 1
            print(f"FAIL  {name}\n      {exc}")
    print(f"\n{failures} failed")
    sys.exit(1 if failures else 0)
