"""Monthly report and forensic evidence bundle (pnma.report)."""

from __future__ import annotations

import hashlib
import json
import tempfile
import time
import zipfile
from pathlib import Path

from pnma import report as R
from pnma.db import Database


def _db():
    return Database(Path(tempfile.mkdtemp()) / "t.db")


def _seed(db):
    now = time.time()
    # a device with an alert, and the host's own adapter with one too
    db.execute("INSERT INTO meta(key,value) VALUES('own_macs',?)", (json.dumps(["aa:bb:cc:00:00:01"]),))
    db.execute("INSERT INTO devices(device_id,mac,mac_type,ip,label,device_class,first_seen,last_seen,trusted) "
               "VALUES('peer','de:ad:be:ef:00:02','global','10.0.0.8','Camera','camera',?,?,0)", (now - 5 * 86400, now))
    db.execute("INSERT INTO devices(device_id,mac,mac_type,ip,device_class,first_seen,last_seen,trusted) "
               "VALUES('self','aa:bb:cc:00:00:01','global','10.0.0.9','unknown',?,?,1)", (now - 5 * 86400, now))
    db.execute("INSERT INTO ports(device_id,port,proto,service,first_seen,last_seen,risk) "
               "VALUES('peer',23,'tcp','telnet',?,?,'high')", (now - 5 * 86400, now))
    db.raise_alert(dedup_key="k1", rule_id="cve_exposure", severity="critical",
                   title="Camera: Telnet exposed", device_id="peer", evidence={"ip": "10.0.0.8"}, ts=now - 3 * 86400)
    db.raise_alert(dedup_key="k2", rule_id="cve_exposure", severity="high",
                   title="Self: SMB", device_id="self", evidence={"ip": "10.0.0.9"}, ts=now - 3 * 86400)
    db.execute("INSERT INTO observations(ts,device_id,mac,ip,source,agent_generated) "
               "VALUES(?,'peer','de:ad:be:ef:00:02','10.0.0.8','passive_arp',0)", (now - 3 * 86400,))
    return now


def test_monthly_report_counts_and_excludes_the_host():
    import datetime as dt
    db = _db(); now = _seed(db)
    d = dt.datetime.fromtimestamp(now)
    rep = R.monthly_report(db, d.year, d.month, version="9.9")
    # opened counts include both alerts...
    assert rep["alerts"]["opened_total"] == 2
    # ...but the host is excluded from the device breakdowns
    names = {t["device_id"] for t in rep["top_devices"]}
    assert "self" not in names and "peer" in names
    assert all(nd["device_id"] != "self" for nd in rep["new_devices"])
    md = R.render_markdown(rep)
    assert "Hearth monthly report" in md and "Camera" in md
    assert "could not see" in md            # blind-spots section always present
    assert "pnma 9.9" in md                 # provenance carried through


def test_evidence_bundle_is_hashed_and_verifiable():
    db = _db(); _seed(db)
    aid = db.query_one("SELECT id FROM alerts WHERE dedup_key='k1'")["id"]
    out = Path(tempfile.mkdtemp())
    res = R.evidence_bundle(db, out_dir=out, alert_id=aid, version="9.9")
    bundle = Path(res["dir"])
    manifest = json.loads((bundle / "MANIFEST.json").read_text())
    # every listed artifact exists and its recorded hash matches the file
    for art in manifest["artifacts"]:
        data = (bundle / art["name"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == art["sha256"], art["name"]
    assert manifest["subject"]["title"].startswith("Camera")
    assert manifest["provenance"]["database_sha256"]
    # the zip carries the same files
    with zipfile.ZipFile(res["zip"]) as z:
        names = [n.split("/", 1)[1] for n in z.namelist()]
        assert "MANIFEST.json" in names and "SHA256SUMS" in names and "alert.json" in names
    # README states what it is not (honest scope)
    readme = (bundle / "README.md").read_text()
    assert "not" in readme and "disk image" in readme


def test_evidence_bundle_by_device_and_bad_input():
    db = _db(); _seed(db)
    out = Path(tempfile.mkdtemp())
    res = R.evidence_bundle(db, out_dir=out, device_id="peer", version="9.9")
    assert (Path(res["dir"]) / "device.json").exists()
    assert (Path(res["dir"]) / "timeline.csv").exists()
    try:
        R.evidence_bundle(db, out_dir=out)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError with no subject")
