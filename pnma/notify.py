"""Local notifications: a Windows toast for an alert that cannot wait.

Zero egress. This is the one delivery channel that costs the agent nothing
on its own safety posture (see ``pnma audit``): the machine the collector
runs on tells the person sitting at it, and nothing leaves the host.

The toast is raised through PowerShell's WinRT projection rather than a
third-party package, for the same reason the dashboard has no chart library:
one fewer dependency to vet, and the mechanism is the same one BurntToast
uses, so it is well trodden. PowerShell's own AppUserModelId is used as the
notifier, which is registered on every Windows 10/11 install -- registering
one for PNMA would need a Start Menu shortcut, which is a footprint this
project does not leave.

Failure is silent by design (logged, never raised): a notification path
that can crash the collector is worse than no notification path.
"""

from __future__ import annotations

import logging
import platform
import subprocess
from xml.sax.saxutils import escape

log = logging.getLogger("pnma.notify")

# PowerShell's registered AppUserModelId -- the notifier every WinRT toast
# raised from a PowerShell process shows under.
_POWERSHELL_AUMID = (
    r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"
)

_SCRIPT = r"""
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$xml = [Console]::In.ReadToEnd()
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast = New-Object Windows.UI.Notifications.ToastNotification $doc
$toast.Tag = 'pnma'
$toast.Group = 'pnma'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('%s').Show($toast)
""" % _POWERSHELL_AUMID

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def available() -> bool:
    return platform.system() == "Windows"


def toast(title: str, body: str, *, timeout_s: float = 10.0) -> bool:
    """Show a toast. Returns True if PowerShell accepted it."""
    if not available():
        return False
    # ToastGeneric: first <text> is the headline, the second the body.
    # Both escaped -- alert titles carry device names that came off the
    # network, and an XML document is not the place to trust them.
    xml = (
        '<toast scenario="reminder"><visual><binding template="ToastGeneric">'
        f"<text>{escape(title)}</text><text>{escape(body)}</text>"
        "</binding></visual></toast>"
    )
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command", _SCRIPT],
            input=xml, capture_output=True, text=True, timeout=timeout_s, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("toast failed: %s", exc)
        return False
    if proc.returncode != 0:
        log.warning("toast failed (%d): %s", proc.returncode, proc.stderr.strip()[:300])
        return False
    return True


def wants_toast(severity: str, minimum: str) -> bool:
    """True when ``severity`` is at or above the configured minimum."""
    try:
        return SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(minimum)
    except ValueError:
        return False


def toast_findings(findings, minimum: str = "high") -> bool:
    """One toast for a batch of new findings, or none.

    Batched deliberately: five critical alerts from one detection pass are
    one event ("something just happened on the network"), and five toasts in
    a row are how a person learns to dismiss without reading.
    """
    urgent = [f for f in findings if wants_toast(f.severity, minimum)]
    if not urgent:
        return False
    urgent.sort(key=lambda f: SEVERITY_ORDER.index(f.severity), reverse=True)
    head = urgent[0]
    title = f"PNMA: {head.severity.upper()} -- {head.title}"
    if len(urgent) > 1:
        body = f"and {len(urgent) - 1} more new alert{'s' if len(urgent) > 2 else ''}. Open the dashboard's Alerts tab."
    else:
        body = "Open the dashboard's Alerts tab for what to do."
    return toast(title[:200], body)
