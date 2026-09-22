"""SEC555-adapted detections that run on data Hearth already collects."""
from __future__ import annotations
import tempfile, time
from pathlib import Path
from pnma.db import Database
from pnma.detections.base import DetectionContext
from pnma.detections.sec555_rules import (
    CleartextProtocolDetection, RandomServiceNameDetection, looks_random,
)


def _db():
    return Database(Path(tempfile.mkdtemp()) / "t.db")


def test_looks_random_is_conservative():
    for good in ("OneDrive", "Intel Graphics", "Wintun", "Tailscale", "AdobeUpdateService", "svchost", "KslD"):
        assert not looks_random(good), good
    for bad in ("aG7kP2xQ", "kd93jfKD82", "a1b2c3d4e5", "4f2a9c1b-88de-4a11", "xZ9qK2wP7m"):
        assert looks_random(bad), bad


def test_cleartext_flags_legacy_ports_but_not_the_host():
    db = _db(); now = time.time()
    db.execute("INSERT INTO meta(key,value) VALUES('own_macs','[\"aa:bb:cc:00:00:01\"]')")
    for did, mac, ip, port, svc in (("cam", "de:ad:be:ef:00:02", "10.0.0.8", 23, "telnet"),
                                    ("nas", "de:ad:be:ef:00:03", "10.0.0.9", 21, "ftp"),
                                    ("web", "de:ad:be:ef:00:04", "10.0.0.10", 443, "https"),
                                    ("self", "aa:bb:cc:00:00:01", "10.0.0.11", 23, "telnet")):
        db.execute("INSERT INTO devices(device_id,mac,mac_type,ip,first_seen,last_seen,trusted) VALUES(?,?,'global',?,?,?,0)",
                   (did, mac, ip, now, now))
        db.execute("INSERT INTO ports(device_id,port,proto,service,first_seen,last_seen) VALUES(?,?,'tcp',?,?,?)",
                   (did, port, svc, now, now))
    f = CleartextProtocolDetection().evaluate(DetectionContext(db=db, now=now))
    devs = {x.device_id for x in f}
    assert devs == {"cam", "nas"}          # https not flagged; the host excluded
    assert any("Telnet" in x.title for x in f) and any("FTP" in x.title for x in f)


def test_random_service_flags_generated_names_only():
    db = _db(); now = time.time()
    import json
    for name in ("aG7kP2xQ", "IntelGraphicsService"):
        db.record_host_event(kind="service_installed", ts=now - 60,
                             summary=f"service installed: {name}",
                             detail={"name": name, "path": "C:/x/" + name + ".exe", "sha256": "d4"},
                             severity="low", dedup_key=f"svc:{name}", agent_generated=False)
    f = RandomServiceNameDetection().evaluate(DetectionContext(db=db, now=now))
    assert len(f) == 1 and "aG7kP2xQ" in f[0].title and f[0].severity == "high"
    assert all(r.requires for r in (CleartextProtocolDetection(), RandomServiceNameDetection()))
