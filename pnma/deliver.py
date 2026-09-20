"""Outbound alert delivery: webhook and ntfy (push-to-phone).

This is the module that actually *sends* an alert somewhere other than the
dashboard and the local log. Until it existed, ``[alerting].webhook_enabled``
was a config flag that nothing read -- the audit even scored "outbound alerting
off" against a switch with no wire behind it. Now there is a wire, and it is
still off by default, for the reason stated everywhere else in this codebase:
an agent that auto-starts, runs elevated, maps the network and then makes
outbound requests is the behavioural profile of a remote-access trojan, and the
honest default for that shape is silence unless the operator asks.

Two transports, both opt-in, both carrying only what a person needs to decide
whether to walk to a screen -- severity, title, count -- never the evidence
blob, never a device's MAC or a person's email. The dashboard, behind the token
gate, is where the detail lives; a push notification is a doorbell, not a file.

* **webhook** -- POST a small JSON body to a URL (Slack/Discord/Home Assistant/
  your own endpoint). The URL is a secret (`webhook_url`), read from the OS
  credential store, never the config file.
* **ntfy** -- POST to an ntfy topic, which the ntfy phone app subscribes to.
  Self-host it on the tailnet for a phone alert that never leaves your own
  devices; the topic and (optional) server are secrets too.

Every send is best-effort and never raises into the collector: a delivery
channel that can crash the monitor is worse than one that occasionally drops a
message. Failures are logged and, so the operator can see them, recorded in
``scan_runs`` as a delivery attempt.
"""

from __future__ import annotations

import json
import logging
import urllib.request

log = logging.getLogger("pnma.deliver")

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

# ntfy maps a priority 1-5 and lets us tag with an emoji; line these up with
# our severities so a critical actually buzzes the phone and a low does not.
_NTFY_PRIORITY = {"critical": "5", "high": "4", "medium": "3", "low": "2", "info": "1"}
_NTFY_TAGS = {"critical": "rotating_light", "high": "warning",
              "medium": "eyes", "low": "information_source", "info": "information_source"}


def _at_or_above(severity: str, minimum: str) -> bool:
    try:
        return SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(minimum)
    except ValueError:
        return False


def _summarise(findings) -> tuple[str, str, str] | None:
    """(headline, body, top_severity) for a batch, or None if nothing qualifies.

    Deliberately terse and identifier-free: the point is to get someone to the
    dashboard, not to reproduce the alert in a push notification that syncs to
    who-knows-where.
    """
    if not findings:
        return None
    top = max(findings, key=lambda f: SEVERITY_ORDER.index(f.severity)
              if f.severity in SEVERITY_ORDER else 0)
    headline = f"PNMA: {top.severity.upper()} -- {top.title}"
    if len(findings) > 1:
        body = (f"{top.title}\nand {len(findings) - 1} more new "
                f"alert{'s' if len(findings) > 2 else ''}. "
                "Open the dashboard's Alerts tab.")
    else:
        body = f"{top.title}\nOpen the dashboard's Alerts tab for what to do."
    return headline[:200], body, top.severity


def _post(url: str, data: bytes, headers: dict, timeout: float) -> tuple[bool, str]:
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - operator-supplied URL
            return 200 <= resp.status < 300, f"HTTP {resp.status}"
    except Exception as exc:  # noqa: BLE001 - delivery must never raise into the collector
        return False, str(exc)


def send_webhook(url: str, findings, *, minimum: str = "high", timeout: float = 10.0) -> dict:
    """POST a compact JSON alert to a webhook URL. Best-effort."""
    urgent = [f for f in findings if _at_or_above(f.severity, minimum)]
    summary = _summarise(urgent)
    if not summary:
        return {"sent": False, "reason": "nothing at or above minimum"}
    headline, body, sev = summary
    payload = json.dumps({
        "source": "PNMA",
        "severity": sev,
        "count": len(urgent),
        "title": headline,
        "text": body,
    }).encode("utf-8")
    ok, detail = _post(url, payload, {"Content-Type": "application/json"}, timeout)
    return {"sent": ok, "detail": detail, "count": len(urgent)}


def send_ntfy(topic_url: str, findings, *, minimum: str = "high", timeout: float = 10.0) -> dict:
    """POST to an ntfy topic (the phone channel). Best-effort.

    ``topic_url`` is the full topic URL, e.g. ``https://ntfy.sh/my-topic`` or
    ``http://<tailnet-host>/pnma``. ntfy reads the headline from the Title
    header and the severity from Priority; the body is the request body.
    """
    urgent = [f for f in findings if _at_or_above(f.severity, minimum)]
    summary = _summarise(urgent)
    if not summary:
        return {"sent": False, "reason": "nothing at or above minimum"}
    headline, body, sev = summary
    headers = {
        "Title": headline.encode("utf-8").decode("latin-1", "replace"),
        "Priority": _NTFY_PRIORITY.get(sev, "3"),
        "Tags": _NTFY_TAGS.get(sev, "warning"),
    }
    ok, detail = _post(topic_url, body.encode("utf-8"), headers, timeout)
    return {"sent": ok, "detail": detail, "count": len(urgent)}
