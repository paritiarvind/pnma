"""PNMA's own PowerShell helper scripts must self-attribute.

The 4104 script-block detector (suspicious_powershell) reads only blocks that
do NOT carry the agent marker; the rule's own docs say "PNMA's own scripts are
stamped and excluded". The shipped .ps1 helpers manage the collector
(enumerating and stopping 'pnma collect' processes, registering a scheduled
task) -- process-hunting that reads as a suspicious block -- so they must carry
the marker, or the agent alerts on itself. This is the regression guard for
that: the fix that stopped 18 self-inflicted suspicious_powershell alerts on
the live host.
"""

from __future__ import annotations

import pathlib

from pnma.collectors.host_events import classify_script_block, script_block_severity
from pnma.collectors.host_windows import AGENT_MARKER

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ("start-pnma.ps1", "setup-elevated-collect.ps1")


def test_pnma_ps_scripts_carry_the_agent_marker():
    for name in SCRIPTS:
        text = (ROOT / name).read_text(encoding="utf-8")
        assert AGENT_MARKER in text, (
            f"{name} must contain {AGENT_MARKER!r} so the collector attributes "
            "its 4104 script block to the agent instead of raising "
            "suspicious_powershell on PNMA's own collector management"
        )


def test_the_marker_is_load_bearing_for_the_setup_script():
    # Prove the marker is doing real work: the setup script's own content, with
    # the marker removed, classifies as a notable block. So the marker (not the
    # content being innocent) is what keeps it from alerting.
    text = (ROOT / "setup-elevated-collect.ps1").read_text(encoding="utf-8")
    without = text.replace(AGENT_MARKER, "")
    hits = classify_script_block(without)
    assert hits, "expected the setup script to match at least one 4104 pattern"
    assert script_block_severity(hits) is not None, (
        "without the marker this script would raise an alert -- which is exactly "
        "why the marker must be present"
    )
