"""Active confirmation probe: a scope-guarded, non-destructive banner read."""

from __future__ import annotations

import socket
import threading
import time

import pytest

from pnma.collectors.confirm import ConfirmationProbe, confirmed_banners
from pnma.db import Database
from pnma.guard import ScopeViolation


class _FakeGuard:
    """Allows loopback, refuses everything else -- enough to test the gate."""

    def __init__(self, allow=("127.0.0.1",)):
        self.allow = set(allow)

    def assert_target_allowed(self, ip):
        if ip not in self.allow:
            raise ScopeViolation(f"{ip} out of scope")


def _banner_server(banner: bytes):
    """A one-shot TCP server on a free loopback port; returns (port, stop)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        try:
            conn, _ = srv.accept()
            if banner:
                conn.sendall(banner)
            time.sleep(0.05)
            conn.close()
        except OSError:
            pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return port, srv


def _seed_device_with_cve_alert(db, ip, port):
    now = time.time()
    db.execute(
        "INSERT INTO devices(device_id, mac, mac_type, ip, first_seen, last_seen, trusted) "
        "VALUES('d1','aa:bb:cc:dd:ee:ff','global',?,?,?,0)", (ip, now, now))
    db.execute(
        "INSERT INTO ports(device_id, port, proto, first_seen, last_seen) "
        "VALUES('d1',?,?,?,?)", (port, "tcp", now, now))
    db.raise_alert(dedup_key="cve:d1:x", rule_id="cve_exposure", severity="high",
                   title="d1 exposure", device_id="d1")


def test_reads_a_banner_and_stores_it(tmp_path):
    port, srv = _banner_server(b"BusyBox telnetd 1.30\r\nlogin: ")
    db = Database(tmp_path / "pnma.db")
    # confirmable set is fixed ports; monkeypatch the instance to accept our port
    _seed_device_with_cve_alert(db, "127.0.0.1", port)
    probe = ConfirmationProbe(db, _FakeGuard())
    probe_ports = {port}
    import pnma.collectors.confirm as c
    old = c.CONFIRMABLE_PORTS
    c.CONFIRMABLE_PORTS = probe_ports
    try:
        r = probe.run_once()
    finally:
        c.CONFIRMABLE_PORTS = old
        srv.close()
    assert r["confirmed"] == 1
    banners = confirmed_banners(db, "d1")
    assert port in banners and "BusyBox" in banners[port]
    db.close()


def test_out_of_scope_target_is_never_probed(tmp_path):
    db = Database(tmp_path / "pnma.db")
    _seed_device_with_cve_alert(db, "8.8.8.8", 23)  # not in the guard's allow set
    probe = ConfirmationProbe(db, _FakeGuard(allow=("127.0.0.1",)))
    r = probe.run_once()
    # The scope guard rejected the only device, so nothing was attempted.
    assert r["attempted"] == 0 and r["confirmed"] == 0
    db.close()


def test_silent_but_open_port_counts_as_confirmation(tmp_path):
    port, srv = _banner_server(b"")  # accepts, sends nothing
    db = Database(tmp_path / "pnma.db")
    _seed_device_with_cve_alert(db, "127.0.0.1", port)
    probe = ConfirmationProbe(db, _FakeGuard(), timeout_s=1.0)
    import pnma.collectors.confirm as c
    old = c.CONFIRMABLE_PORTS
    c.CONFIRMABLE_PORTS = {port}
    try:
        r = probe.run_once()
    finally:
        c.CONFIRMABLE_PORTS = old
        srv.close()
    assert r["confirmed"] == 1
    assert confirmed_banners(db, "d1")[port] == ""  # listening, no banner
    db.close()


def test_closed_port_is_not_confirmed(tmp_path):
    # A port nothing listens on: connection refused -> no confirmation.
    db = Database(tmp_path / "pnma.db")
    _seed_device_with_cve_alert(db, "127.0.0.1", 6553)  # almost certainly closed
    probe = ConfirmationProbe(db, _FakeGuard(), timeout_s=1.0)
    import pnma.collectors.confirm as c
    old = c.CONFIRMABLE_PORTS
    c.CONFIRMABLE_PORTS = {6553}
    try:
        r = probe.run_once()
    finally:
        c.CONFIRMABLE_PORTS = old
    assert r["attempted"] == 1 and r["confirmed"] == 0
    db.close()
