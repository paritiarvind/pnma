"""SEC555/GCDA host-integrity detections: the four snapshot-diff collectors
(trusted-root store, hosts file, listening processes, PowerShell downgrade) and
their rules. The PowerShell boundary (`_ps_marked`) is mocked, so these run on
any platform and exercise the collector's own decisions -- first-run silence,
baseline diff, severity by risk -- and the rules that turn the events into
findings.
"""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

import pytest

from pnma.collectors import host_events as he
from pnma.db import Database
from pnma.detections import host_event_rules as rules
from pnma.detections.base import DetectionContext


def _db():
    return Database(Path(tempfile.mkdtemp()) / "t.db")


class FakeMarked:
    """Stands in for _ps_marked, dispatching on the collector's script."""

    def __init__(self):
        self.certs = []
        self.hosts_lines = []
        self.listeners = []
        self.ps400 = []
        self.firewall = []

    def __call__(self, script, timeout=60):
        if "Cert:" in script:
            return True, {"ok": True, "certs": self.certs}, ""
        if "etc\\hosts" in script:
            return True, {"ok": True, "lines": self.hosts_lines}, ""
        if "-State Listen" in script:
            return True, {"ok": True, "listeners": self.listeners}, ""
        if "Get-NetFirewallRule" in script:
            return True, {"ok": True, "rules": self.firewall}, ""
        if "Windows PowerShell" in script:
            mx = max((e["record"] for e in self.ps400), default=None)
            return True, {"ok": True, "events": self.ps400, "max": mx}, ""
        raise AssertionError("unexpected script: " + script[:80])


@pytest.fixture()
def fake(monkeypatch):
    f = FakeMarked()
    monkeypatch.setattr(he, "_ps_marked", f)
    return f


def _events(db, kind):
    return db.query(f"SELECT * FROM host_events WHERE kind = '{kind}' ORDER BY id")


# ----------------------------------------------------------------- root certs

def test_root_cert_first_run_baselines_then_alerts_on_new(fake):
    db = _db(); c = he.HostEventCollector(db)
    fake.certs = [{"thumb": "AAA", "subject": "CN=Microsoft Root", "issuer": "CN=Microsoft Root", "store": "Cert:\\LocalMachine\\Root"}]
    assert c.collect_root_certs() == (0, "")
    assert not _events(db, "root_cert_added")                 # first run: silent baseline
    fact = db.query_one("SELECT state, value FROM host_facts WHERE fact_key = 'integrity.root_certs'")
    assert fact["state"] == "ok" and "1 roots" in fact["value"]

    fake.certs = fake.certs + [{"thumb": "BBB", "subject": "CN=Interceptor", "issuer": "CN=Interceptor", "store": "Cert:\\CurrentUser\\Root"}]
    n, err = c.collect_root_certs()
    assert n == 1 and err == ""
    ev = _events(db, "root_cert_added")
    assert len(ev) == 1 and ev[0]["severity"] == "medium"
    assert json.loads(ev[0]["detail"])["thumbprint"] == "BBB"
    # a third run, unchanged -> nothing new
    assert c.collect_root_certs()[0] == 0


def test_root_cert_rule_makes_a_finding(fake):
    db = _db()
    db.record_host_event(kind="root_cert_added", ts=time.time() - 60, summary="new trusted root certificate: CN=Interceptor",
                         detail={"thumbprint": "BBB", "subject": "CN=Interceptor", "issuer": "CN=Interceptor", "store": "Cert:\\CurrentUser\\Root"},
                         severity="medium", dedup_key="rootcert:BBB", mitre_id="T1553.004", sensor_id="host")
    f = rules.RogueRootCertDetection().evaluate(DetectionContext(db=db, now=time.time()))
    assert len(f) == 1 and f[0].mitre_id == "T1553.004" and "root certificate" in f[0].title.lower()


# ----------------------------------------------------------------- hosts file

def test_hosts_file_ignores_localhost_and_alerts_on_redirect(fake):
    db = _db(); c = he.HostEventCollector(db)
    fake.hosts_lines = ["127.0.0.1 localhost", "::1 localhost"]
    assert c.collect_hosts_file() == (0, "")
    fact = db.query_one("SELECT state FROM host_facts WHERE fact_key = 'integrity.hosts_file'")
    assert fact["state"] == "ok"                              # localhost-only == no redirects

    fake.hosts_lines = fake.hosts_lines + ["45.13.7.22 login.microsoftonline.com"]
    n, err = c.collect_hosts_file()
    assert n == 1
    ev = _events(db, "hosts_file_changed")
    assert len(ev) == 1 and json.loads(ev[0]["detail"])["entry"].endswith("login.microsoftonline.com")
    fact = db.query_one("SELECT state, value FROM host_facts WHERE fact_key = 'integrity.hosts_file'")
    assert fact["state"] == "finding" and "1 redirect" in fact["value"]


# --------------------------------------------------------------- listeners

def test_new_listener_scores_script_host_high_and_skips_loopback(fake):
    db = _db(); c = he.HostEventCollector(db)
    fake.listeners = [{"port": 445, "laddr": "0.0.0.0", "procpid": 4, "name": "System", "path": ""}]
    assert c.collect_listeners() == (0, "")                   # first run: baseline

    fake.listeners = fake.listeners + [
        {"port": 4444, "laddr": "0.0.0.0", "procpid": 6210, "name": "powershell",
         "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
        {"port": 5000, "laddr": "127.0.0.1", "procpid": 7000, "name": "devserver", "path": "C:\\dev\\dev.exe"},  # loopback -> skipped
    ]
    n, err = c.collect_listeners()
    assert n == 1                                             # only the reachable powershell listener
    ev = _events(db, "listening_process")
    assert len(ev) == 1 and ev[0]["severity"] == "high"
    d = json.loads(ev[0]["detail"])
    assert d["port"] == 4444 and d["script_host_or_userpath"] is True


def test_listener_rule_makes_a_finding(fake):
    db = _db()
    db.record_host_event(kind="listening_process", ts=time.time() - 60, summary="new listener: nc on 0.0.0.0:1337",
                         detail={"name": "nc", "port": 1337, "laddr": "0.0.0.0", "path": "C:\\Users\\x\\Downloads\\nc.exe",
                                 "pid": 9, "script_host_or_userpath": True},
                         severity="high", dedup_key="listener:nc:1337", mitre_id="T1571", sensor_id="host")
    f = rules.NewListeningProcessDetection().evaluate(DetectionContext(db=db, now=time.time()))
    assert len(f) == 1 and "listener" in f[0].title.lower()


# ------------------------------------------------------------- ps downgrade

def test_ps_downgrade_flags_sub_v5_only(fake):
    db = _db(); c = he.HostEventCollector(db)
    fake.ps400 = [
        {"record": 10, "id": 400, "t": time.time() - 30, "level": "Information",
         "props": [], "msg": "Engine state is changed from None to Available. EngineVersion=2.0 RunspaceId=abc"},
        {"record": 11, "id": 400, "t": time.time() - 20, "level": "Information",
         "props": [], "msg": "Engine state is changed from None to Available. EngineVersion=5.1 RunspaceId=def"},
    ]
    n, err = c.collect_ps_downgrade()
    assert n == 1
    ev = _events(db, "powershell_downgrade")
    assert len(ev) == 1 and ev[0]["severity"] == "high"
    assert json.loads(ev[0]["detail"])["engine_version"] == "2.0"


def test_ps_downgrade_rule_makes_a_finding():
    db = _db()
    db.record_host_event(kind="powershell_downgrade", ts=time.time() - 60,
                         summary="PowerShell 2.0 engine started", detail={"engine_version": "2.0", "record": 10},
                         severity="high", dedup_key="psdown:10", mitre_id="T1059.001", sensor_id="host")
    f = rules.PowerShellDowngradeDetection().evaluate(DetectionContext(db=db, now=time.time()))
    assert len(f) == 1 and "v2.0" in f[0].title and f[0].mitre_id == "T1059.001"


# --------------------------------------------------------------- firewall

def test_new_firewall_allow_rule_alerts_after_baseline(fake):
    db = _db(); c = he.HostEventCollector(db)
    fake.firewall = [{"name": "{core-1}", "display": "Core Networking", "group": "Core Networking"}]
    assert c.collect_firewall_rules() == (0, "")             # first run: baseline
    fact = db.query_one("SELECT state, value FROM host_facts WHERE fact_key = 'integrity.firewall_rules'")
    assert fact["state"] == "ok" and "1 inbound" in fact["value"]

    fake.firewall = fake.firewall + [{"name": "{rev-shell}", "display": "Allow TCP 4444", "group": None}]
    n, err = c.collect_firewall_rules()
    assert n == 1
    ev = _events(db, "firewall_rule_added")
    assert len(ev) == 1 and ev[0]["severity"] == "medium"
    assert "4444" in json.loads(ev[0]["detail"])["display"]


def test_firewall_rule_makes_a_finding():
    db = _db()
    db.record_host_event(kind="firewall_rule_added", ts=time.time() - 60,
                         summary="firewall inbound allow rule added: Allow TCP 4444",
                         detail={"name": "{rev}", "display": "Allow TCP 4444", "group": None},
                         severity="medium", dedup_key="fwrule:{rev}", mitre_id="T1562.004", sensor_id="host")
    f = rules.FirewallRuleAddedDetection().evaluate(DetectionContext(db=db, now=time.time()))
    assert len(f) == 1 and f[0].mitre_id == "T1562.004"


# --------------------------------------------------------------- lateral

def test_lateral_connection_first_seen_then_baselined(fake, monkeypatch):
    # collect_connections uses _ps_marked via a different path (self._CONN_PS);
    # patch it to return LAN-peer admin-port connections.
    db = _db(); c = he.HostEventCollector(db)
    conns = [
        {"raddr": "192.168.0.145", "rport": 3389, "lport": 5000, "pid": 4120, "process": "powershell.exe", "path": r"C:\W\ps.exe"},
        {"raddr": "192.168.0.9", "rport": 445, "lport": 5001, "pid": 8, "process": "System", "path": ""},
        {"raddr": "127.0.0.1", "rport": 3389, "lport": 5002, "pid": 9, "process": "loop.exe", "path": ""},   # loopback -> skip
        {"raddr": "100.99.1.1", "rport": 22, "lport": 5003, "pid": 10, "process": "tailscaled.exe", "path": ""},  # tailnet -> skip
        {"raddr": "192.168.0.20", "rport": 443, "lport": 5004, "pid": 11, "process": "chrome.exe", "path": ""},  # not an admin port -> skip
    ]
    monkeypatch.setattr(he, "_ps_marked", lambda script, timeout=60: (True, conns, ""))
    c.collect_connections()
    assert not db.query("SELECT 1 FROM host_events WHERE kind='lateral_connection'")   # first run: baseline
    c.collect_connections()                                                            # unchanged -> still nothing
    ev = db.query("SELECT detail, severity FROM host_events WHERE kind='lateral_connection'")
    assert ev == []
    # a NEW lateral connection appears
    conns.append({"raddr": "192.168.0.55", "rport": 5985, "lport": 5005, "pid": 12, "process": "wsmprovhost.exe", "path": ""})
    c.collect_connections()
    ev = db.query("SELECT detail FROM host_events WHERE kind='lateral_connection'")
    assert len(ev) == 1 and json.loads(ev[0]["detail"])["rport"] == 5985


def test_lateral_rule_makes_a_finding():
    db = _db()
    db.record_host_event(kind="lateral_connection", ts=time.time() - 60,
                         summary="powershell.exe -> 192.168.0.145:3389 (RDP), first seen",
                         detail={"raddr": "192.168.0.145", "rport": 3389, "service": "RDP", "process": "powershell.exe", "pid": 1},
                         severity="medium", dedup_key="lateral:x", mitre_id="T1021", sensor_id="host")
    f = rules.InternalLateralConnectionDetection().evaluate(DetectionContext(db=db, now=time.time()))
    assert len(f) == 1 and "3389" in f[0].title


# --------------------------------------------------------------- defender

def test_defender_events_emit_threats(fake, monkeypatch):
    db = _db(); c = he.HostEventCollector(db)
    evs = [{"record": 5, "id": 1117, "t": time.time() - 30,
            "data": {"Threat Name": "Trojan:Win32/Wacatac.B!ml", "Action Name": "Quarantine",
                     "Path": "C:/Users/Public/x.exe", "Severity Name": "Severe"}}]
    monkeypatch.setattr(he, "_ps_marked", lambda script, timeout=60: (True, {"ok": True, "events": evs, "max": 5}, ""))
    n, err = c.collect_defender_events()
    assert n == 1
    ev = _events(db, "defender_threat")
    assert len(ev) == 1 and ev[0]["severity"] == "high"
    assert json.loads(ev[0]["detail"])["threat"] == "Trojan:Win32/Wacatac.B!ml"


def test_defender_rule_makes_a_finding():
    db = _db()
    db.record_host_event(kind="defender_threat", ts=time.time() - 60, summary="Defender: EICAR (quarantined)",
                         detail={"threat": "EICAR_Test_File", "action": "quarantined", "path": "C:/t/e.com", "severity_name": "Severe"},
                         severity="high", dedup_key="defender:5", mitre_id="T1204", sensor_id="host")
    f = rules.DefenderThreatDetection().evaluate(DetectionContext(db=db, now=time.time()))
    assert len(f) == 1 and "EICAR" in f[0].title


# --------------------------------------------------------------- dns / admin

def test_dns_server_change_baselines_then_alerts(fake, monkeypatch):
    db = _db(); c = he.HostEventCollector(db)
    monkeypatch.setattr(he, "_ps_marked", lambda script, timeout=60: (True, {"ok": True, "adapters": [
        {"alias": "Wi-Fi", "servers": ["192.168.0.1"]}]}, ""))
    assert c.collect_dns_servers() == (0, "")               # first run: baseline
    monkeypatch.setattr(he, "_ps_marked", lambda script, timeout=60: (True, {"ok": True, "adapters": [
        {"alias": "Wi-Fi", "servers": ["192.168.0.1", "45.13.7.22"]}]}, ""))
    n, err = c.collect_dns_servers()
    assert n == 1
    ev = _events(db, "dns_server_changed")
    assert len(ev) == 1 and "45.13.7.22" in json.loads(ev[0]["detail"])["added"]


def test_dns_rule_makes_a_finding():
    db = _db()
    db.record_host_event(kind="dns_server_changed", ts=time.time() - 60, summary="DNS server changed on Wi-Fi",
                         detail={"adapter": "Wi-Fi", "servers": ["45.13.7.22"], "previous": ["192.168.0.1"]},
                         severity="medium", dedup_key="dns:x", mitre_id="T1557", sensor_id="host")
    f = rules.DnsServerChangedDetection().evaluate(DetectionContext(db=db, now=time.time()))
    assert len(f) == 1 and "resolver" in f[0].title.lower()


def test_admin_group_new_member_alerts_high(fake, monkeypatch):
    db = _db(); c = he.HostEventCollector(db)
    monkeypatch.setattr(he, "_ps_marked", lambda script, timeout=60: (True, {"ok": True, "members": ["WKS-arvind"]}, ""))
    assert c.collect_admin_group() == (0, "")               # first run: baseline
    monkeypatch.setattr(he, "_ps_marked", lambda script, timeout=60: (True, {"ok": True, "members": ["WKS-arvind", "WKS-intruder"]}, ""))
    n, err = c.collect_admin_group()
    assert n == 1
    ev = _events(db, "admin_group_changed")
    assert len(ev) == 1 and ev[0]["severity"] == "high"
    assert "intruder" in json.loads(ev[0]["detail"])["member"]


def test_admin_group_rule_makes_a_finding():
    db = _db()
    db.record_host_event(kind="admin_group_changed", ts=time.time() - 60, summary="new local administrator: X",
                         detail={"member": "WKS-intruder", "members": []}, severity="high",
                         dedup_key="admingrp:x", mitre_id="T1098", sensor_id="host")
    f = rules.LocalAdminGroupDiffDetection().evaluate(DetectionContext(db=db, now=time.time()))
    assert len(f) == 1 and "administrator" in f[0].title.lower()


# ------------------------------------------------------- scheduled task / driver

def test_scheduled_task_scores_lolbin_high(fake, monkeypatch):
    db = _db(); c = he.HostEventCollector(db)
    monkeypatch.setattr(he, "_ps_marked", lambda script, timeout=60: (True, {"ok": True, "tasks": [
        {"path": "REPLBASE", "author": "MS", "action": "C:/Program Files/App/app.exe"}]}, ""))
    assert c.collect_scheduled_tasks() == (0, "")            # first run: baseline
    monkeypatch.setattr(he, "_ps_marked", lambda script, timeout=60: (True, {"ok": True, "tasks": [
        {"path": "REPLBASE", "author": "MS", "action": "C:/Program Files/App/app.exe"},
        {"path": "REPLEVIL", "author": None, "action": "powershell.exe -w hidden -enc AAAA"}]}, ""))
    n, err = c.collect_scheduled_tasks()
    assert n == 1
    ev = _events(db, "scheduled_task_added")
    assert len(ev) == 1 and ev[0]["severity"] == "high"
    assert json.loads(ev[0]["detail"])["lolbin_or_userpath"] is True


def test_kernel_driver_unusual_path_is_high(fake, monkeypatch):
    db = _db(); c = he.HostEventCollector(db)
    monkeypatch.setattr(he, "_ps_marked", lambda script, timeout=60: (True, {"ok": True, "drivers": [
        {"name": "vmbus", "path": "C:/Windows/System32/drivers/vmbus.sys", "state": "Running"}]}, ""))
    assert c.collect_kernel_drivers() == (0, "")             # first run: baseline
    monkeypatch.setattr(he, "_ps_marked", lambda script, timeout=60: (True, {"ok": True, "drivers": [
        {"name": "vmbus", "path": "C:/Windows/System32/drivers/vmbus.sys", "state": "Running"},
        {"name": "usbxhci", "path": "C:/Windows/System32/drivers/usbxhci.sys", "state": "Running"},
        {"name": "mimidrv", "path": "C:/Users/Public/mimidrv.sys", "state": "Running"}]}, ""))
    n, err = c.collect_kernel_drivers()
    assert n == 2
    sev = {json.loads(r["detail"])["name"]: r["severity"] for r in _events(db, "kernel_driver_added")}
    assert sev == {"usbxhci": "low", "mimidrv": "high"}      # System32 low, Public high


def test_scheduled_task_and_driver_rules_make_findings():
    db = _db(); now = time.time()
    db.record_host_event(kind="scheduled_task_added", ts=now - 60, summary="scheduled task added: X",
                         detail={"path": "WinUpdate", "action": "powershell -enc AAAA", "lolbin_or_userpath": True},
                         severity="high", dedup_key="schtask:x", mitre_id="T1053.005", sensor_id="host")
    db.record_host_event(kind="kernel_driver_added", ts=now - 60, summary="new kernel driver: mimidrv",
                         detail={"name": "mimidrv", "path": "C:/Users/Public/mimidrv.sys", "unusual_path": True},
                         severity="high", dedup_key="driver:mimidrv", mitre_id="T1543.003", sensor_id="host")
    ctx = DetectionContext(db=db, now=now)
    assert len(rules.ScheduledTaskAddedDetection().evaluate(ctx)) == 1
    f = rules.KernelDriverAddedDetection().evaluate(ctx)
    assert len(f) == 1 and "mimidrv" in f[0].title


# ------------------------------------------------------- credential dump

def test_cred_dump_artifacts_alert_high(fake, monkeypatch):
    db = _db(); c = he.HostEventCollector(db)
    monkeypatch.setattr(he, "_ps_marked", lambda script, timeout=60: (True, {"ok": True, "hits": [
        {"name": "sam", "path": "C:/Windows/Temp/sam", "kind": "hive"},
        {"name": "lsass.dmp", "path": "C:/Users/Public/lsass.dmp", "kind": "lsass_dump"}]}, ""))
    n, err = c.collect_cred_dumps()
    assert n == 2
    ev = _events(db, "credential_hive_dump")
    assert len(ev) == 2 and all(r["severity"] == "high" for r in ev)


def test_cred_dump_rule_makes_a_finding():
    db = _db()
    db.record_host_event(kind="credential_hive_dump", ts=time.time() - 60,
                         summary="credential-dump artifact (registry hive): C:/Windows/Temp/sam",
                         detail={"name": "sam", "path": "C:/Windows/Temp/sam", "artifact": "registry hive"},
                         severity="high", dedup_key="creddump:x", mitre_id="T1003.002", sensor_id="host")
    f = rules.CredentialDumpArtifactDetection().evaluate(DetectionContext(db=db, now=time.time()))
    assert len(f) == 1 and "temp" in f[0].title.lower()
