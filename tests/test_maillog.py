"""Router mail-log parsing and IMAP ingestion (IMAP faked)."""

from __future__ import annotations

import email

from pnma.collectors import maillog
from pnma.collectors.maillog import MailLogCollector, parse_log_line
from pnma.db import Database


def test_parses_dhcp_lease():
    ev = parse_log_line("Jan 1 12:00:00 router [DHCP] assigned 192.168.0.42 to AA:BB:CC:DD:EE:FF")
    assert ev and ev.kind == "dhcp_lease"
    assert ev.ip == "192.168.0.42"
    assert ev.mac == "AA:BB:CC:DD:EE:FF"


def test_parses_admin_login_and_firewall():
    login = parse_log_line("[LOGIN] admin login from 192.168.0.5")
    assert login and login.kind == "admin_login" and login.ip == "192.168.0.5"
    fw = parse_log_line("[Firewall] DoS attack detected from 203.0.113.9")
    assert fw and fw.kind == "firewall_event" and fw.severity == "high"


def test_unrecognised_line_is_none():
    assert parse_log_line("just some noise with no keywords") is None
    assert parse_log_line("") is None


class _FakeIMAP:
    """Minimal IMAP4_SSL stand-in returning one router log email."""

    def __init__(self, host, port):
        self.host = host

    def login(self, u, p):
        return "OK", [b""]

    def select(self, folder):
        return "OK", [b"1"]

    def search(self, charset, *criteria):
        return "OK", [b"1"]

    def fetch(self, mid, spec):
        body = ("[DHCP] assigned 192.168.0.99 to 11:22:33:44:55:66\n"
                "[Firewall] flood blocked from 198.51.100.7\n"
                "nothing interesting here\n")
        msg = email.message_from_string("Subject: Router Log\n\n" + body)
        return "OK", [(b"1", msg.as_bytes())]

    def close(self):
        pass

    def logout(self):
        pass


def test_ingest_raises_alerts(tmp_path, monkeypatch):
    monkeypatch.setattr(maillog.imaplib, "IMAP4_SSL", _FakeIMAP)
    db = Database(tmp_path / "pnma.db")
    mc = MailLogCollector(db, "mail-1", host="imap.example", user="u", password="p")
    r = mc.run_once()
    assert r["ok"] and r["parsed"] == 2 and r["raised"] == 2
    alerts = db.query("SELECT * FROM alerts WHERE rule_id = 'router_maillog'")
    kinds = {a["title"].split(":")[1].strip() for a in alerts}
    assert any("DHCP" in k or "lease" in k for k in kinds)
    fw = db.query_one("SELECT severity FROM alerts WHERE title LIKE '%attack%'")
    assert fw and fw["severity"] == "high"
    db.close()


def test_dry_run_raises_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(maillog.imaplib, "IMAP4_SSL", _FakeIMAP)
    db = Database(tmp_path / "pnma.db")
    mc = MailLogCollector(db, "mail-1", host="imap.example", user="u", password="p")
    r = mc.run_once(dry_run=True)
    assert r["ok"] and r["parsed"] == 2 and r["raised"] == 0
    assert db.query_one("SELECT COUNT(*) n FROM alerts")["n"] == 0
    db.close()


def test_connect_failure_is_not_fatal(tmp_path, monkeypatch):
    def boom(host, port):
        raise OSError("no route to host")

    monkeypatch.setattr(maillog.imaplib, "IMAP4_SSL", boom)
    db = Database(tmp_path / "pnma.db")
    mc = MailLogCollector(db, "mail-1", host="imap.example", user="u", password="p")
    r = mc.run_once()
    assert r["ok"] is False and "reason" in r
    db.close()
