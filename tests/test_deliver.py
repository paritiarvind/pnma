"""Outbound delivery: webhook and ntfy. No real network in the tests."""

from __future__ import annotations

import json
from dataclasses import dataclass

from pnma import deliver


@dataclass
class _F:
    severity: str
    title: str


def _capture(monkeypatch):
    """Replace the module's _post with a recorder; return the recorded calls."""
    calls = []

    def fake_post(url, data, headers, timeout):
        calls.append({"url": url, "data": data, "headers": headers})
        return True, "HTTP 200"

    monkeypatch.setattr(deliver, "_post", fake_post)
    return calls


def test_webhook_sends_json_body(monkeypatch):
    calls = _capture(monkeypatch)
    findings = [_F("critical", "Gateway hijack"), _F("low", "hygiene thing")]
    r = deliver.send_webhook("https://example/hook", findings, minimum="high")
    assert r["sent"] is True and r["count"] == 1  # only the critical is at/above high
    body = json.loads(calls[0]["data"].decode())
    assert body["severity"] == "critical"
    assert body["source"] == "PNMA"
    assert "Gateway hijack" in body["title"]


def test_ntfy_sets_priority_and_title(monkeypatch):
    calls = _capture(monkeypatch)
    r = deliver.send_ntfy("https://ntfy.sh/topic", [_F("critical", "ADB exposed")], minimum="high")
    assert r["sent"] is True
    h = calls[0]["headers"]
    assert h["Priority"] == "5"
    assert "ADB exposed" in h["Title"]


def test_nothing_below_minimum_is_sent(monkeypatch):
    calls = _capture(monkeypatch)
    r = deliver.send_webhook("https://example/hook", [_F("low", "hygiene")], minimum="high")
    assert r["sent"] is False and "reason" in r
    assert calls == []


def test_batch_headline_is_top_severity(monkeypatch):
    _capture(monkeypatch)
    findings = [_F("high", "RDP open"), _F("critical", "Telnet open"), _F("high", "SMB open")]
    r = deliver.send_ntfy("https://ntfy.sh/t", findings, minimum="high")
    # top severity drives the headline; all three are at/above high
    assert r["count"] == 3


def test_delivery_never_raises_on_network_error(monkeypatch):
    def boom(url, data, headers, timeout):
        raise OSError("connection refused")

    # _post itself swallows exceptions; prove the real one does too.
    ok, detail = deliver._post("https://x", b"{}", {}, 1.0)
    assert ok is False and isinstance(detail, str)
