"""Detection runs when telemetry arrives, not only on the fixed tick.

Before: rules ran every detection_interval_s (60s), so a passive ARP claim or
a fresh scan result waited up to a minute to be judged, and the dashboard
another minute to show it. Now collectors and the passive thread request a
pass and the main loop drains it within the debounce; the tick stays as the
safety net.
"""

from __future__ import annotations

from pathlib import Path

from pnma import daemon as d
from pnma.config import Config

ROOT = Path(__file__).resolve().parents[1]


def test_scheduler_reports_each_task_by_name():
    done = []
    s = d.Scheduler(on_done=done.append)
    s.every(1, lambda: None, "arp_table")
    s.every(1, lambda: 1 / 0, "broken")
    for t in s._tasks:
        t["next"] = 0  # due now
    s.run_due()
    assert done == ["arp_table", "broken"]  # failure still reports, so a
    # broken collector cannot silently stop event-driven detection either


def _collector(tmp_path):
    cfg = Config.load(ROOT / "config" / "pnma.example.toml")
    cfg.database = str(tmp_path / "t.db")
    return d.Collector(cfg)


def test_request_is_drained_once_and_debounced(tmp_path, monkeypatch):
    c = _collector(tmp_path)
    runs = []
    monkeypatch.setattr(c, "_run_detections", lambda: runs.append(1))
    c._last_detection_ok = 0.0
    c._drain_detection_request()
    assert runs == []                      # nothing requested, nothing run
    c.request_detection()
    c._drain_detection_request()
    assert runs == [1] and c.event_driven_detections == 1
    c._drain_detection_request()
    assert runs == [1]                     # request was consumed
    # a burst: many requests inside the debounce window run once
    import time
    c._last_detection_ok = time.time()
    c.request_detection(); c._drain_detection_request()
    assert runs == [1]                     # deferred, still pending
    assert c._detect_requested.is_set()
    c._last_detection_ok = 0.0
    c._drain_detection_request()
    assert runs == [1, 1]


def test_collectors_request_detection_but_housekeeping_does_not(tmp_path):
    c = _collector(tmp_path)
    for name in ("arp_table", "discovery", "ping", "port_scan", "host_posture", "honeypot"):
        c._detect_requested.clear()
        c._after_task(name)
        assert c._detect_requested.is_set(), name
    for name in ("prune", "guard_recheck", "detect", "heartbeat", "cve_feed_refresh"):
        c._detect_requested.clear()
        c._after_task(name)
        assert not c._detect_requested.is_set(), name


def test_passive_frames_reach_the_hook(tmp_path):
    from pnma.collectors.passive import PassiveCollector
    from pnma.db import Database
    from pnma.guard import ScopeGuard

    cfg = Config.load(ROOT / "config" / "pnma.example.toml")
    cfg.database = str(tmp_path / "t.db")
    hits = []
    pc = PassiveCollector(Database(Path(cfg.database)), ScopeGuard(cfg), "s1", on_observe=lambda: hits.append(1))
    assert pc.on_observe is not None
    # the hook is wired; the handler path itself needs scapy frames and is
    # covered by the passive collector's own tests
