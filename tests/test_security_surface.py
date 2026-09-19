"""The dashboard's security surface, pinned.

Every test here is a red flag that would otherwise be found by the operator
looking at a phone. They run against a throwaway database and never touch
the network: the properties under test are about what the *server* refuses
and what the *page* hides, not about what the collector sees.

Covered:
- the bearer-token gate: /api and /metrics refuse without it, the static
  shell stays open (a login prompt that cannot load is not a login prompt),
  a wrong token is a 401 not a 403, and the compare is not a prefix match;
- bind policy: 0.0.0.0 is refused outright, an off-loopback bind without a
  token is refused, loopback needs nothing, and 'tailscale' resolves through
  the CLI rather than guessing an interface;
- the static allowlist: exactly the files named, no traversal, no listing;
- identity: attestations rot to `unknown` after the review window, a lookup
  with no key records `unknown` rather than `ok`, and a control nobody has
  attested is `unknown`;
- the privacy mask (JavaScript, run under node when available): MACs keep
  only OUI + last octet, IPv4 keeps only the last octet, e-mails keep one
  character of the local part, and operator labels are untouched;
- passive capture's availability check consults the driver, not the
  process's elevation.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pnma import identity as I  # noqa: E402
from pnma.api import app as api  # noqa: E402
from pnma.config import Config  # noqa: E402
from pnma.db import Database  # noqa: E402


@pytest.fixture()
def cfg(tmp_path: Path) -> Config:
    c = Config.load(ROOT / "config" / "pnma.example.toml")
    c.database = str(tmp_path / "t.db")
    return c


def _client(cfg: Config, token: str | None = None):
    from fastapi.testclient import TestClient

    return TestClient(api.create_app(cfg, token=token))


# -- token gate -------------------------------------------------------------


def test_api_refuses_without_token(cfg):
    c = _client(cfg, token="s3cret")
    for path in ("/api/summary", "/api/devices", "/api/host", "/api/identity", "/metrics"):
        r = c.get(path)
        assert r.status_code == 401, path
        assert r.headers.get("www-authenticate") == "Bearer"
        # The body must not leak anything: no counts, no devices.
        assert set(r.json()) == {"error"}


def test_api_refuses_wrong_and_prefix_tokens(cfg):
    c = _client(cfg, token="s3cret")
    for bad in ("wrong", "s3cre", "s3cret-longer", ""):
        r = c.get("/api/summary", headers={"Authorization": "Bearer " + bad})
        assert r.status_code == 401, bad
    # Basic auth carrying the right string is still not a bearer token.
    r = c.get("/api/summary", headers={"Authorization": "Basic s3cret"})
    assert r.status_code == 401


def test_api_accepts_token_and_mutations_are_gated(cfg):
    c = _client(cfg, token="s3cret")
    ok = {"Authorization": "Bearer s3cret"}
    assert c.get("/api/summary", headers=ok).status_code == 200
    # Writes without the token are refused before they reach a handler.
    r = c.post("/api/alerts/1/acknowledge")
    assert r.status_code == 401
    r = c.post("/api/identity/x/mfa", json={"state": "ok"})
    assert r.status_code == 401


def test_static_shell_open_even_when_gated(cfg):
    c = _client(cfg, token="s3cret")
    for path in ("/", "/app.js", "/viz.js", "/style.css", "/manifest.webmanifest", "/icon.svg"):
        r = c.get(path)
        assert r.status_code == 200, path


def test_no_token_means_no_gate_on_loopback(cfg):
    c = _client(cfg, token=None)
    assert c.get("/api/summary").status_code == 200


# -- bind policy ------------------------------------------------------------


def test_serve_refuses_all_interfaces(cfg, monkeypatch):
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: pytest.fail("must not start"))
    for host in ("0.0.0.0", "::"):
        with pytest.raises(SystemExit, match="refusing to bind to all interfaces"):
            api.serve(cfg, bind=host, token="anything")


def test_serve_refuses_off_loopback_without_token(cfg, monkeypatch):
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: pytest.fail("must not start"))
    with pytest.raises(SystemExit, match="needs a dashboard token"):
        api.serve(cfg, bind="100.100.1.2", token=None)
    with pytest.raises(SystemExit, match="needs a dashboard token"):
        api.serve(cfg, bind="192.168.0.5", token=None)


def test_serve_loopback_needs_nothing(cfg, monkeypatch):
    started = {}
    monkeypatch.setattr("uvicorn.run", lambda app, host, port, **k: started.update(host=host))
    api.serve(cfg, bind="127.0.0.1", token=None)
    assert started["host"] == "127.0.0.1"


def test_serve_tailscale_resolves_via_cli_and_still_needs_token(cfg, monkeypatch):
    monkeypatch.setattr(api, "tailscale_ip", lambda: "100.64.0.9")
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: pytest.fail("must not start"))
    with pytest.raises(SystemExit, match="needs a dashboard token"):
        api.serve(cfg, bind="tailscale", token=None)
    started = {}
    monkeypatch.setattr("uvicorn.run", lambda app, host, port, **k: started.update(host=host))
    api.serve(cfg, bind="tailscale", token="t")
    assert started["host"] == "100.64.0.9"


def test_serve_tailscale_absent_is_an_error_not_a_fallback(cfg, monkeypatch):
    monkeypatch.setattr(api, "tailscale_ip", lambda: None)
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: pytest.fail("must not start"))
    with pytest.raises(SystemExit, match="no Tailscale address"):
        api.serve(cfg, bind="tailscale", token="t")


def test_no_token_flag_is_loopback_only(cfg, monkeypatch):
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: pytest.fail("must not start"))
    with pytest.raises(SystemExit, match="only allowed on loopback"):
        api.serve(cfg, bind="100.64.0.9", token="t", no_token=True)
    started = {}
    monkeypatch.setattr("uvicorn.run", lambda app, host, port, **k: started.update(host=host))
    api.serve(cfg, bind="127.0.0.1", token="t", no_token=True)
    assert started["host"] == "127.0.0.1"


def test_openapi_schema_is_gated_too(cfg):
    c = _client(cfg, token="s3cret")
    assert c.get("/openapi.json").status_code == 401
    assert c.get("/openapi.json", headers={"Authorization": "Bearer s3cret"}).status_code == 200


def test_self_audit_judges_effective_bind(cfg, monkeypatch):
    """The Agent tab must not show a passing loopback check for a socket that
    is not the one listening. serve() records what it bound; the auditor reads
    that, not the config file."""
    from pnma.audit import Auditor
    from pnma.guard import ScopeGuard

    def posture(cfg_):
        db = Database(cfg_.database)
        guard = ScopeGuard(cfg_)
        checks = Auditor(db, guard).compliance_report(1)["posture"]
        return {c["check"]: c["ok"] for c in checks}

    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    api.serve(cfg, bind="127.0.0.1", token=None)
    assert posture(cfg)["API bound to loopback"] is True

    api.serve(cfg, bind="100.64.0.9", token="t")
    p = posture(cfg)
    assert "API bound to loopback" not in p
    assert p["API off loopback, token-guarded"] is True

    # Simulate a future code path that binds off loopback with no token: the
    # check must FAIL, not vanish.
    cfg.api.effective_bind = "192.168.0.5"
    cfg.api.token_required = False
    assert posture(cfg)["API off loopback, token-guarded"] is False


# -- static allowlist -------------------------------------------------------


def test_static_allowlist_is_exact(cfg):
    c = _client(cfg)
    for path in ("/index.html", "/web/app.js", "/static/", "/../config/pnma.toml",
                 "/app.js/../../config/pnma.toml", "/%2e%2e/pnma/db.py", "/pnma.toml"):
        r = c.get(path)
        assert r.status_code in (404, 405), path
        assert b"cidr" not in r.content and b"gateway_mac" not in r.content


def test_every_allowlisted_file_exists():
    for _route, (name, _mt) in api.STATIC_FILES.items():
        assert (api.WEB_DIR / name).exists(), name


# -- identity ---------------------------------------------------------------


def test_identity_unattested_is_unknown(cfg):
    db = Database(cfg.database)
    I.add_account(db, "m", provider="google", category="email", label="Mail")
    rep = I.report(db)
    states = {c["control"]: c["state"] for c in rep["accounts"][0]["controls"]}
    assert set(states.values()) == {"unknown"}
    assert rep["summary"]["never"] == len(I.CONTROLS)
    assert rep["summary"]["ok"] == 0


def test_identity_attestation_rots_to_unknown(cfg):
    db = Database(cfg.database)
    I.add_account(db, "m", provider="google", category="email", label="Mail", review_days=30)
    I.attest(db, "m", "mfa", "ok", value="passkey")
    fresh = I.report(db)["accounts"][0]["controls"][0]
    assert fresh["state"] == "ok" and not fresh["stale"]
    stale = I.report(db, now=time.time() + 31 * 86400)["accounts"][0]["controls"][0]
    assert stale["state"] == "unknown"
    assert stale["stale"] is True
    assert stale["attested_state"] == "ok"        # the history is kept, not erased
    assert "days old" in stale["reason"]


def test_identity_reattest_refreshes_clock_not_changed_at(cfg):
    db = Database(cfg.database)
    I.add_account(db, "m", provider="google", category="email", label="Mail")
    assert I.attest(db, "m", "mfa", "ok") is True
    row = db.query_one("SELECT attested_at, changed_at FROM identity_facts")
    time.sleep(0.01)
    assert I.attest(db, "m", "mfa", "ok") is False
    row2 = db.query_one("SELECT attested_at, changed_at FROM identity_facts")
    assert row2["attested_at"] > row["attested_at"]
    assert row2["changed_at"] == row["changed_at"]
    assert I.attest(db, "m", "mfa", "finding") is True


def test_hibp_without_key_records_unknown_not_ok(cfg):
    db = Database(cfg.database)
    I.add_account(db, "m", provider="google", category="email", label="Mail", handle="a@b.example")
    res = I.check_breaches(db, "m", api_key=None)
    assert res["state"] == "unknown"
    fact = db.query_one("SELECT state, reason FROM identity_facts WHERE control='breach_exposure'")
    assert fact["state"] == "unknown" and "hibp_api_key" in fact["reason"]


def test_hibp_http_error_records_unknown(cfg, monkeypatch):
    db = Database(cfg.database)
    I.add_account(db, "m", provider="google", category="email", label="Mail", handle="a@b.example")
    monkeypatch.setattr(I, "_http_get", lambda url, headers, timeout=15.0: (503, ""))
    assert I.check_breaches(db, "m", api_key="k")["state"] == "unknown"


def test_hibp_404_is_ok_and_200_is_finding(cfg, monkeypatch):
    db = Database(cfg.database)
    I.add_account(db, "m", provider="google", category="email", label="Mail", handle="a@b.example")
    monkeypatch.setattr(I, "_http_get", lambda url, headers, timeout=15.0: (404, ""))
    assert I.check_breaches(db, "m", api_key="k")["state"] == "ok"
    body = json.dumps([{"Name": "Foo", "BreachDate": "2024-01-01", "DataClasses": ["Passwords"]}])
    monkeypatch.setattr(I, "_http_get", lambda url, headers, timeout=15.0: (200, body))
    res = I.check_breaches(db, "m", api_key="k")
    assert res["state"] == "finding" and res["breaches"] == ["Foo"]


def test_pwned_password_only_sends_prefix(monkeypatch):
    seen = {}

    def fake(url, headers, timeout=15.0):
        seen["url"] = url
        return 200, "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3\nAAAAA:1\n"

    monkeypatch.setattr(I, "_http_get", fake)
    assert I.pwned_password_count("password") == 3
    # Only the five-character prefix travels; the remaining 35 hex characters
    # of the digest, and the password itself, stay on this machine.
    assert seen["url"].endswith("/range/5BAA6")
    assert "1E4C9B93F3F0682250B6CF8331B7EE68FD8" not in seen["url"]


def test_identity_api_validates_and_404s(cfg):
    c = _client(cfg)
    assert c.post("/api/identity/nope/mfa", json={"state": "ok"}).status_code == 404
    db = Database(cfg.database)
    I.add_account(db, "m", provider="google", category="email", label="Mail")
    assert c.post("/api/identity/m/not_a_control", json={"state": "ok"}).status_code == 400
    assert c.post("/api/identity/m/mfa", json={"state": "maybe"}).status_code == 400
    assert c.post("/api/identity/m/mfa", json={"state": "ok"}).status_code == 200


# -- privacy mask (JavaScript) ---------------------------------------------


NODE = shutil.which("node")

MASK_HARNESS = r"""
globalThis.window = globalThis;
globalThis.localStorage = { getItem: () => null, setItem: () => {} };
globalThis.location = { hash: '', reload: () => {} };
globalThis.history = { replaceState: () => {} };
globalThis.document = { addEventListener: () => {}, getElementById: () => null,
                        querySelectorAll: () => [], createElementNS: () => ({ setAttribute(){}, appendChild(){} }),
                        createTextNode: (t) => ({ t }) };
globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => ({}) });
require(process.argv[2]);
const m = window.PNMA.mask;
window.PNMA.learnName('Bastion');
const out = {
  mac: m('seen 98:03:8e:00:11:22 on eth3'),
  macdash: m('98-03-8E-00-11-22'),
  ip: m('Gateway 192.168.0.1 confirmed'),
  cidr: m('scope 192.168.0.0/24'),
  email: m('someone@example.com'),
  host: m('host Bastion posture'),
  label: m('Living room TV'),
  json: m(JSON.stringify({ip: '10.0.0.77', mac: 'aa:bb:cc:dd:ee:ff'})),
};
console.log(JSON.stringify(out));
"""


@pytest.mark.skipif(NODE is None, reason="node not installed")
def test_privacy_mask_hides_identifiers(tmp_path):
    harness = tmp_path / "h.js"
    harness.write_text(MASK_HARNESS, encoding="utf-8")
    r = subprocess.run([NODE, str(harness), str(api.WEB_DIR / "viz.js")],
                       capture_output=True, text=True, encoding="utf-8", timeout=30, check=False)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["mac"] == "seen 98:03:8e:··:··:22 on eth3"
    assert out["macdash"] == "98:03:8E:··:··:22"
    assert out["ip"] == "Gateway ·.·.·.1 confirmed"
    assert out["cidr"] == "scope ·.·.·.0/24"
    assert out["email"] == "s···@example.com"
    assert out["host"] == "host B··· posture"
    assert out["label"] == "Living room TV"
    assert "10.0.0.77" not in out["json"] and "dd:ee:ff" not in out["json"]
    assert "·.·.·.77" in out["json"] and "aa:bb:cc:··:··:ff" in out["json"]


# -- passive capture gate ---------------------------------------------------


def test_capture_gate_asks_driver_not_elevation(monkeypatch):
    from pnma.collectors import passive

    pytest.importorskip("scapy")
    monkeypatch.setattr(passive, "is_elevated", lambda: False)
    monkeypatch.setattr(passive, "_probe_capture", lambda interface="": (True, "ok"))
    assert passive.capture_available() == (True, "available")

    monkeypatch.setattr(passive, "_probe_capture", lambda interface="": (False, "Permission denied"))
    ok, why = passive.capture_available()
    assert not ok and "Permission denied" in why and "Administrator" in why

    monkeypatch.setattr(passive, "is_elevated", lambda: True)
    ok, why = passive.capture_available()
    assert not ok and "even elevated" in why
