"""The known-exploited-vulnerability advisory catalogue and matcher."""

from __future__ import annotations

import json

from pnma import vulns


def _device(**kw):
    d = {"device_id": "d1", "device_class": "unknown", "label": None,
         "hostname": None, "ip": "10.0.0.5", "open_ports": []}
    d.update(kw)
    return d


def _port(port, **kw):
    p = {"port": port, "proto": "tcp", "service": None, "product": None,
         "risk": None, "closed_at": None}
    p.update(kw)
    return p


def test_telnet_matches_mirai_advisory():
    dev = _device(device_class="camera", open_ports=[_port(23, service="telnet")])
    hits = vulns.match_devices([dev])
    ids = {a.advisory_id for a in hits[0]["advisories"]}
    assert "telnet-mirai" in ids


def test_adb_matches_on_port_or_service():
    by_port = _device(open_ports=[_port(5555)])
    by_service = _device(open_ports=[_port(9999, service="adb")])
    for dev in (by_port, by_service):
        ids = {a.advisory_id for a in vulns.match_devices([dev])[0]["advisories"]}
        assert "adb-open" in ids


def test_closed_port_does_not_match():
    dev = _device(open_ports=[_port(23, service="telnet", closed_at=1.0)])
    assert vulns.match_devices([dev]) == []


def test_clean_device_yields_nothing():
    dev = _device(device_class="laptop", open_ports=[])
    assert vulns.match_devices([dev]) == []


def test_iot_web_admin_needs_both_class_and_http():
    # A laptop on 80 is not the IoT-web-admin advisory; a camera on 80 is.
    laptop = _device(device_class="laptop", open_ports=[_port(80, service="http")])
    cam = _device(device_class="camera", open_ports=[_port(80, service="http")])
    assert "iot-http-admin" not in {a.advisory_id for h in vulns.match_devices([laptop]) for a in h["advisories"]}
    assert "iot-http-admin" in {a.advisory_id for a in vulns.match_devices([cam])[0]["advisories"]}


def test_a_broken_predicate_does_not_sink_the_pass(monkeypatch):
    bad = vulns.Advisory(
        advisory_id="bad", title="x", severity="low", summary="", impact="",
        remediation="", sandbox_note="", matches=lambda d: 1 / 0,
    )
    monkeypatch.setattr(vulns, "CATALOGUE", [bad] + vulns.CATALOGUE)
    dev = _device(open_ports=[_port(23)])
    # The bad predicate is skipped; the telnet advisory still matches.
    ids = {a.advisory_id for a in vulns.match_devices([dev])[0]["advisories"]}
    assert "telnet-mirai" in ids and "bad" not in ids


def test_kev_annotation_from_cache(tmp_path):
    db = tmp_path / "pnma.db"
    db.write_text("")  # only the parent dir is used for the cache path
    cache = tmp_path / "kev-cache.json"
    cache.write_text(json.dumps({"cve_ids": ["CVE-2019-0708"]}))
    assert vulns.load_kev_ids(str(db)) == {"CVE-2019-0708"}
    vulns.annotate_with_kev(str(db))
    bluekeep = next(a for a in vulns.CATALOGUE if a.advisory_id == "rdp-bluekeep")
    assert bluekeep.kev_confirmed is True
    # An advisory whose CVE is not in the cache is marked not-confirmed.
    adb = next(a for a in vulns.CATALOGUE if a.advisory_id == "adb-open")
    # adb-open references a CVE not in the cache -> False (checked, absent)
    assert adb.kev_confirmed in (False, None)
