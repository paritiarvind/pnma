"""Beaconing and new-external-destination over connection_endpoints."""
from __future__ import annotations
import json, tempfile, time
from pathlib import Path
from pnma.db import Database
from pnma.detections.base import DetectionContext
from pnma.detections.network_rules import BeaconingDetection, NewExternalDestinationDetection, network_rules


def _db():
    return Database(Path(tempfile.mkdtemp()) / "t.db")


def _endpoint(db, process, raddr, rport, samples, path="C:/Users/Public/x.exe"):
    db.execute("INSERT INTO connection_endpoints(process, path, raddr, rport, first_seen, last_seen, sample_count, samples) "
               "VALUES(?,?,?,?,?,?,?,?)", (process, path, raddr, rport, samples[0], samples[-1], len(samples), json.dumps(samples)))


def test_beaconing_needs_regular_cadence_and_external_public():
    db = _db(); now = time.time()
    regular = [now - 3*3600 + i*600 for i in range(18)]        # every 10 min, low jitter
    _endpoint(db, "svc_helper.exe", "185.220.101.47", 8443, regular)
    # irregular timing to the same shape -> not a beacon
    import random; random.seed(1)
    jittery = [now - 3*3600]
    for _ in range(17):
        jittery.append(jittery[-1] + random.uniform(60, 1800))
    _endpoint(db, "chatapp.exe", "9.9.9.9", 443, jittery)
    # a browser on a perfect cadence -> excluded
    _endpoint(db, "chrome.exe", "142.250.1.1", 443, regular)
    # a private/tailnet destination -> excluded
    _endpoint(db, "svc_helper.exe", "192.168.0.9", 8443, regular)
    f = BeaconingDetection().evaluate(DetectionContext(db=db, now=now))
    assert len(f) == 1 and f[0].evidence["raddr"] == "185.220.101.47"
    assert f[0].evidence["interval_min"] == 10


def test_new_destination_excludes_browsers_and_private():
    db = _db(); now = time.time()
    _endpoint(db, "svc_probe.exe", "45.13.7.22", 443, [now - 300])       # new, non-browser, public
    _endpoint(db, "msedge.exe", "20.20.20.20", 443, [now - 200])          # browser -> excluded
    _endpoint(db, "onedrive.exe", "13.13.13.13", 443, [now - 100])        # sync -> excluded
    _endpoint(db, "svc_probe.exe", "10.0.0.5", 445, [now - 250])          # private -> excluded
    _endpoint(db, "old.exe", "8.8.8.8", 53, [now - 100000])               # old first_seen -> not new
    f = NewExternalDestinationDetection().evaluate(DetectionContext(db=db, now=now))
    assert len(f) == 1 and f[0].evidence["process"] == "svc_probe.exe"
    assert all(r.requires for r in network_rules())
