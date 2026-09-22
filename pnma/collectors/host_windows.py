"""Host posture collection for the machine PNMA runs on.

Every other collector in this package looks *outward* at devices on the
network. This one looks at the operator's own machine, and that inversion
changes the ethics rather than just the target: the network collectors are
constrained because housemates share the LAN and did not consent to being
watched, whereas this inspects a machine its operator owns. So the consent
problem gets easier here -- and a different problem gets harder.

**The hard problem is honesty about what could not be measured.**

This module exists because of a specific failure. During a host review on
2026-08-24, a PowerShell query for logon events returned::

    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624}
      -> "No events were found that match the specified selection criteria."

which reads exactly like a clean result. The real answer, visible only when
the log was probed a different way, was ``UnauthorizedAccessException`` -- the
process was not elevated and never got to look. A check that *could not run*
was indistinguishable from a check that *passed*, and a first draft of that
report drew a false negative from it.

So every check here returns one of three states, never two:

``ok``
    The control is in the desired state.
``finding``
    It is not, and that is worth surfacing.
``unknown``
    The check could not run. Stored, surfaced, and counted separately.

That is also the honest answer to "why not just run Wazuh". Wazuh reports what
it collected. This reports what it could not, which on an unelevated box is a
third of the interesting surface. A posture dashboard that renders `unknown`
as green is worse than no dashboard, because it manufactures confidence.

Nothing here changes system state. Every check is a read.
"""

from __future__ import annotations

import json
import logging
import platform
import subprocess
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


class HostCollectorUnavailable(RuntimeError):
    """This platform or environment cannot be inspected by this collector."""


# States. Kept as module constants so a typo becomes an ImportError rather
# than a row that silently never matches a dashboard filter.
OK = "ok"
FINDING = "finding"
UNKNOWN = "unknown"


@dataclass
class Fact:
    """One measured aspect of host posture."""

    key: str
    category: str
    title: str
    state: str
    value: str | None = None
    expected: str | None = None
    reason: str | None = None
    needs_admin: bool = False
    evidence: dict = field(default_factory=dict)


# --------------------------------------------------------------- plumbing --


def is_windows() -> bool:
    return platform.system() == "Windows"


def is_elevated() -> bool:
    """Whether this process can read the Security log and Defender exclusions."""
    if not is_windows():
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


# Stamped onto every script PNMA runs so its own 4104 script blocks can be
# told apart from anyone else's (see host_events.collect_winevents).
AGENT_MARKER = "# pnma-agent"


def _ps(script: str, timeout: int = 45) -> tuple[bool, object, str]:
    """Run PowerShell, parse JSON output.

    Returns ``(ok, parsed, error)``. ``ok`` is False whenever we did not get
    usable output -- and the caller must turn that into ``unknown``, never into
    a passing result. That rule is the whole point of this module.
    """
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        AGENT_MARKER + "\n" + script,
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return False, None, f"PowerShell timed out after {timeout}s"
    except OSError as exc:
        return False, None, f"could not launch PowerShell: {exc}"

    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()

    if not out:
        return False, None, err or f"no output (exit {proc.returncode})"

    try:
        return True, json.loads(out), ""
    except json.JSONDecodeError:
        return False, None, f"unparseable output: {out[:200]}"


def _bool_fact(
    key: str,
    category: str,
    title: str,
    ok_when: bool,
    value: object,
    expected: str,
    *,
    needs_admin: bool = False,
    finding_reason: str = "",
) -> Fact:
    return Fact(
        key=key,
        category=category,
        title=title,
        state=OK if ok_when else FINDING,
        value=str(value),
        expected=expected,
        reason=None if ok_when else (finding_reason or None),
        needs_admin=needs_admin,
    )


def _unknown(
    key: str, category: str, title: str, reason: str, *, needs_admin: bool = False
) -> Fact:
    return Fact(
        key=key,
        category=category,
        title=title,
        state=UNKNOWN,
        reason=reason,
        needs_admin=needs_admin,
    )


# ----------------------------------------------------------------- checks --


def check_defender(elevated: bool) -> list[Fact]:
    """Defender engine state, and the exclusion list that needs elevation."""
    facts: list[Fact] = []

    ok, data, err = _ps(
        "$s = Get-MpComputerStatus; $p = Get-MpPreference; "
        "[pscustomobject]@{"
        "  rtp        = $s.RealTimeProtectionEnabled;"
        "  tamper     = $s.IsTamperProtected;"
        "  fullScan   = $s.FullScanAge;"
        "  sigAge     = $s.AntivirusSignatureAge;"
        "  pua        = $p.PUAProtection;"
        "  netProt    = $p.EnableNetworkProtection;"
        "  removable  = $p.DisableRemovableDriveScanning;"
        "  behaviour  = $p.DisableBehaviorMonitoring;"
        "  script     = $p.DisableScriptScanning"
        "} | ConvertTo-Json -Compress"
    )
    if not ok or not isinstance(data, dict):
        return [
            _unknown(
                "defender.status",
                "defender",
                "Microsoft Defender status",
                f"Defender WMI provider did not answer: {err}",
            )
        ]

    facts.append(
        _bool_fact(
            "defender.realtime",
            "defender",
            "Real-time protection",
            bool(data.get("rtp")),
            data.get("rtp"),
            "enabled",
            finding_reason="Real-time protection is off. Nothing is scanning on access.",
        )
    )
    facts.append(
        _bool_fact(
            "defender.tamper_protection",
            "defender",
            "Tamper Protection",
            bool(data.get("tamper")),
            data.get("tamper"),
            "enabled",
            finding_reason=(
                "Defender settings can be changed by anything running as admin, "
                "including malware that gets there first. Cannot be enabled by "
                "script -- Windows Security UI only, by design."
            ),
        )
    )

    # FullScanAge returns 4294967295 (UINT32 max) as a sentinel for "never".
    scan_age = data.get("fullScan")
    never_scanned = scan_age is None or int(scan_age) >= 4294967295
    facts.append(
        Fact(
            key="defender.full_scan",
            category="defender",
            title="Full scan history",
            state=FINDING if never_scanned else OK,
            value="never run" if never_scanned else f"{scan_age} days ago",
            expected="run at least once",
            reason=(
                "A full scan has never run on this host. Quick scans cover active "
                "memory and common paths only -- dormant files elsewhere on disk "
                "have never been examined."
            )
            if never_scanned
            else None,
        )
    )

    # PUAProtection: 0 disabled, 1 enabled (blocks), 2 audit (detects only).
    pua = data.get("pua")
    facts.append(
        Fact(
            key="defender.pua",
            category="defender",
            title="Potentially unwanted application protection",
            state=OK if pua == 1 else FINDING,
            value={0: "disabled", 1: "enabled", 2: "audit only"}.get(pua, str(pua)),
            expected="enabled",
            reason=(
                "PUA protection is in audit mode: it detects unwanted software "
                "and takes no action. Cracks, bundleware and activation scripts "
                "are seen and allowed."
            )
            if pua == 2
            else ("PUA protection is disabled." if pua == 0 else None),
        )
    )
    facts.append(
        _bool_fact(
            "defender.network_protection",
            "defender",
            "Network protection",
            data.get("netProt") == 1,
            {0: "disabled", 1: "enabled", 2: "audit"}.get(data.get("netProt")),
            "enabled",
            finding_reason="Outbound connections to known-malicious hosts are not blocked.",
        )
    )
    facts.append(
        _bool_fact(
            "defender.removable_scan",
            "defender",
            "Removable drive scanning",
            not data.get("removable"),
            "disabled" if data.get("removable") else "enabled",
            "enabled",
            finding_reason=(
                "USB media is not scanned. Often disabled deliberately for "
                "performance -- confirm this was a choice."
            ),
        )
    )

    # Exclusions: the one place a deliberate carve-out hides, and unreadable
    # without elevation. This MUST be `unknown`, never `ok`.
    if not elevated:
        facts.append(
            _unknown(
                "defender.exclusions",
                "defender",
                "Defender exclusion list",
                "Requires elevation: Get-MpPreference returns 'N/A: Must be an "
                "administrator to view exclusions'. An exclusion covering an "
                "attacker's working directory would be invisible from here.",
                needs_admin=True,
            )
        )
    else:
        # `@($p.ExclusionPath)` wraps a $null in a one-element array, so an
        # account with NO exclusions came back as [null] in all four categories
        # and was counted as four exclusions -- a false high-severity alert on a
        # clean machine. Filter inside PowerShell so the null never becomes a
        # list element in the first place.
        ok, data, err = _ps(
            "$p = Get-MpPreference; [pscustomobject]@{"
            "  path=@($p.ExclusionPath | Where-Object { $_ });"
            "  proc=@($p.ExclusionProcess | Where-Object { $_ });"
            "  ext=@($p.ExclusionExtension | Where-Object { $_ });"
            "  ip=@($p.ExclusionIpAddress | Where-Object { $_ })"
            "} | ConvertTo-Json -Compress -Depth 4"
        )
        if not ok or not isinstance(data, dict):
            facts.append(
                _unknown(
                    "defender.exclusions",
                    "defender",
                    "Defender exclusion list",
                    f"query failed even elevated: {err}",
                    needs_admin=True,
                )
            )
        else:
            # Defence in depth against the failure mode this whole module exists
            # for. Unelevated, Get-MpPreference does not error -- it returns the
            # literal string "N/A: Must be an administrator to view exclusions"
            # in every category. That is the Get-WinEvent "No events were found"
            # problem again: a refusal shaped like an answer. If we are somehow
            # here without real privilege, the honest result is `unknown`, never
            # a count of four sentinel strings.
            cleaned: dict[str, list[str]] = {}
            blocked = False
            for k in ("path", "proc", "ext", "ip"):
                values = []
                for item in data.get(k) or []:
                    if not item:
                        continue
                    text = str(item)
                    if "must be an administrator" in text.lower():
                        blocked = True
                        continue
                    values.append(text)
                cleaned[k] = values

            if blocked:
                facts.append(
                    _unknown(
                        "defender.exclusions",
                        "defender",
                        "Defender exclusion list",
                        "Get-MpPreference reported 'must be an administrator' "
                        "rather than returning the list. The check ran but was "
                        "refused, which is not the same as there being no "
                        "exclusions.",
                        needs_admin=True,
                    )
                )
            else:
                total = sum(len(v) for v in cleaned.values())
                facts.append(
                    Fact(
                        key="defender.exclusions",
                        category="defender",
                        title="Defender exclusion list",
                        state=OK if total == 0 else FINDING,
                        value=f"{total} exclusion(s)",
                        expected="none, or all deliberate and documented",
                        reason=(
                            "Exclusions present. Each one is a directory or "
                            "process Defender ignores entirely -- review every "
                            "entry."
                        )
                        if total
                        else None,
                        needs_admin=True,
                        evidence=cleaned if total else None,
                    )
                )

    return facts


def check_powershell_logging() -> list[Fact]:
    """Script block, module, and transcription logging.

    All three live under HKLM policy keys and are readable unelevated, so an
    absent key is a real negative rather than a permissions artifact.
    """
    base = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
    specs = [
        (
            "ScriptBlockLogging",
            "EnableScriptBlockLogging",
            "powershell.script_block",
            "PowerShell script block logging",
            "Deobfuscated PowerShell is not recorded. Base64 and string-"
            "concatenation payloads execute leaving no readable trace -- this "
            "is the single highest-value PowerShell control.",
        ),
        (
            "ModuleLogging",
            "EnableModuleLogging",
            "powershell.module",
            "PowerShell module logging",
            "Pipeline execution detail is not recorded.",
        ),
        (
            "Transcription",
            "EnableTranscripting",
            "powershell.transcription",
            "PowerShell transcription",
            "Session transcripts, which capture command output as well as "
            "commands, are not being written.",
        ),
    ]

    facts: list[Fact] = []
    for subkey, value_name, key, title, why in specs:
        ok, data, err = _ps(
            f"$v = (Get-ItemProperty -Path '{base}\\{subkey}' "
            f"-Name '{value_name}' -ErrorAction SilentlyContinue).'{value_name}'; "
            "[pscustomobject]@{ set = ($v -eq 1) } | ConvertTo-Json -Compress"
        )
        if not ok or not isinstance(data, dict):
            facts.append(_unknown(key, "audit", title, f"registry read failed: {err}"))
            continue
        facts.append(
            _bool_fact(
                key,
                "audit",
                title,
                bool(data.get("set")),
                "configured" if data.get("set") else "not configured",
                "enabled",
                finding_reason=why,
            )
        )
    return facts


def check_process_auditing(elevated: bool) -> list[Fact]:
    """4688 process creation, and whether it records the command line."""
    facts: list[Fact] = []

    key = r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    ok, data, err = _ps(
        f"$v = (Get-ItemProperty -Path '{key}' "
        "-Name 'ProcessCreationIncludeCmdLine_Enabled' -ErrorAction SilentlyContinue)"
        ".ProcessCreationIncludeCmdLine_Enabled; "
        "[pscustomobject]@{ set = ($v -eq 1) } | ConvertTo-Json -Compress"
    )
    if not ok or not isinstance(data, dict):
        facts.append(
            _unknown(
                "audit.cmdline",
                "audit",
                "Process creation command line (4688)",
                f"registry read failed: {err}",
            )
        )
    else:
        facts.append(
            _bool_fact(
                "audit.cmdline",
                "audit",
                "Process creation command line (4688)",
                bool(data.get("set")),
                "configured" if data.get("set") else "not configured",
                "enabled",
                finding_reason=(
                    "Process creation events, if logged at all, record the "
                    "executable but not its arguments -- which is where the "
                    "interesting part of an attack usually lives."
                ),
            )
        )

    # auditpol needs elevation. Unelevated it prints nothing and exits non-zero,
    # which is exactly the shape of output that must not be read as "disabled".
    if not elevated:
        facts.append(
            _unknown(
                "audit.policy",
                "audit",
                "Logon / process audit policy",
                "auditpol requires elevation. Unelevated it returns no output, "
                "which is indistinguishable from 'no auditing configured'.",
                needs_admin=True,
            )
        )
    else:
        ok, data, err = _ps(
            "$o = auditpol /get /subcategory:'Logon','Process Creation' | Out-String; "
            "[pscustomobject]@{ raw = $o } | ConvertTo-Json -Compress"
        )
        if not ok or not isinstance(data, dict):
            facts.append(
                _unknown(
                    "audit.policy",
                    "audit",
                    "Logon / process audit policy",
                    f"auditpol failed: {err}",
                    needs_admin=True,
                )
            )
        else:
            raw = str(data.get("raw", ""))
            enabled = "Success" in raw
            facts.append(
                _bool_fact(
                    "audit.policy",
                    "audit",
                    "Logon / process audit policy",
                    enabled,
                    "auditing enabled" if enabled else "no success auditing",
                    "Success and Failure on Logon and Process Creation",
                    needs_admin=True,
                    finding_reason="Logon and process creation are not being audited.",
                )
            )

    return facts


def check_log_clearing(elevated: bool) -> list[Fact]:
    """Event 1102 (Security cleared) and 104 (any other log cleared).

    ATT&CK T1070.001. The Security half needs elevation; the System half does
    not, so this check genuinely returns different confidence for its two parts
    and says so rather than averaging them into one reassuring green.
    """
    facts: list[Fact] = []

    ok, data, err = _ps(
        "$n = @(Get-WinEvent -FilterHashtable @{LogName='System'; Id=104} "
        "-ErrorAction SilentlyContinue).Count; "
        "[pscustomobject]@{ count = $n } | ConvertTo-Json -Compress"
    )
    if not ok or not isinstance(data, dict):
        facts.append(
            _unknown(
                "audit.log_cleared_system",
                "audit",
                "Non-Security event logs cleared",
                f"query failed: {err}",
            )
        )
    else:
        n = int(data.get("count") or 0)
        facts.append(
            Fact(
                key="audit.log_cleared_system",
                category="audit",
                title="Non-Security event logs cleared",
                state=FINDING if n else OK,
                value=f"{n} clear event(s)",
                expected="none",
                reason=(
                    f"{n} event-log clear operation(s) recorded (Event 104). "
                    "Investigate who and when."
                )
                if n
                else None,
                evidence={"event_id": 104, "count": n},
            )
        )

    if not elevated:
        facts.append(
            _unknown(
                "audit.log_cleared_security",
                "audit",
                "Security audit log cleared (T1070.001)",
                "The Security log is unreadable without elevation. Note that "
                "-FilterHashtable reports 'No events were found' here rather "
                "than an access error, so an unelevated check looks like a "
                "clean result and is not one.",
                needs_admin=True,
            )
        )
    else:
        ok, data, err = _ps(
            "try { $n = @(Get-WinEvent -FilterHashtable "
            "@{LogName='Security'; Id=1102} -ErrorAction Stop).Count } "
            "catch { $n = 0 }; "
            "[pscustomobject]@{ count = $n } | ConvertTo-Json -Compress"
        )
        if not ok or not isinstance(data, dict):
            facts.append(
                _unknown(
                    "audit.log_cleared_security",
                    "audit",
                    "Security audit log cleared (T1070.001)",
                    f"query failed even elevated: {err}",
                    needs_admin=True,
                )
            )
        else:
            n = int(data.get("count") or 0)
            facts.append(
                Fact(
                    key="audit.log_cleared_security",
                    category="audit",
                    title="Security audit log cleared (T1070.001)",
                    state=FINDING if n else OK,
                    value=f"{n} clear event(s)",
                    expected="none",
                    reason=(
                        f"The Security log has been cleared {n} time(s). This is "
                        "a deliberate act -- Windows does not do it on its own."
                    )
                    if n
                    else None,
                    needs_admin=True,
                    evidence={"event_id": 1102, "count": n},
                )
            )

    return facts


def check_unsigned_drivers() -> list[Fact]:
    """Running kernel drivers not signed by Microsoft (T1014).

    Readable unelevated, and the strongest single negative available: a clean
    result here rules out most rootkit-class persistence.
    """
    ok, data, err = _ps(
        "$bad = @(); "
        "Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | "
        "Where-Object State -eq 'Running' | ForEach-Object { "
        "  $p = $_.PathName -replace '^\\\\\\?\\?\\\\','' -replace '^\\\\SystemRoot','C:\\Windows'; "
        "  if ($p -and (Test-Path $p -ErrorAction SilentlyContinue)) { "
        "    $s = Get-AuthenticodeSignature $p -ErrorAction SilentlyContinue; "
        "    if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch 'Microsoft') { "
        "      $bad += \"$($_.Name)|$($s.Status)\" } } }; "
        "[pscustomobject]@{ drivers = @($bad) } | ConvertTo-Json -Compress -Depth 3",
        timeout=180,
    )
    if not ok or not isinstance(data, dict):
        return [
            _unknown(
                "drivers.unsigned",
                "drivers",
                "Non-Microsoft kernel drivers running",
                f"driver enumeration failed: {err}",
            )
        ]

    drivers = data.get("drivers") or []
    if isinstance(drivers, str):
        drivers = [drivers]
    return [
        Fact(
            key="drivers.unsigned",
            category="drivers",
            title="Non-Microsoft kernel drivers running",
            state=FINDING if drivers else OK,
            value=f"{len(drivers)} driver(s)",
            expected="none, or all attributable to installed software",
            reason=(
                "Kernel-mode code not signed by Microsoft is loaded. Legitimate "
                "for VPN, virtualisation and capture drivers -- attribute each one."
            )
            if drivers
            else None,
            evidence={"drivers": drivers},
        )
    ]


def check_scheduled_tasks() -> list[Fact]:
    """Non-Microsoft tasks running as SYSTEM (T1053.005)."""
    ok, data, err = _ps(
        "$t = @(Get-ScheduledTask -ErrorAction SilentlyContinue | "
        "Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' -and "
        "$_.State -ne 'Disabled' -and $_.Principal.UserId -match 'SYSTEM' } | "
        "ForEach-Object { \"$($_.TaskPath)$($_.TaskName)\" }); "
        "[pscustomobject]@{ tasks = @($t) } | ConvertTo-Json -Compress -Depth 3"
    )
    if not ok or not isinstance(data, dict):
        return [
            _unknown(
                "persistence.system_tasks",
                "persistence",
                "Non-Microsoft scheduled tasks running as SYSTEM",
                f"task enumeration failed: {err}",
            )
        ]

    tasks = data.get("tasks") or []
    if isinstance(tasks, str):
        tasks = [tasks]
    return [
        Fact(
            key="persistence.system_tasks",
            category="persistence",
            title="Non-Microsoft scheduled tasks running as SYSTEM",
            state=FINDING if tasks else OK,
            value=f"{len(tasks)} task(s)",
            expected="none, or all deliberate and documented",
            reason=(
                "Third-party code runs on a timer with full system privilege. "
                "Each entry needs an owner you can name."
            )
            if tasks
            else None,
            evidence={"tasks": tasks},
        )
    ]


def check_smb_exposure() -> list[Fact]:
    """SMB signing, and whether the firewall actually admits SMB.

    Both halves matter together. A listening socket is not exposure if the
    firewall drops inbound traffic to it -- reading the socket table alone
    produces a confident, wrong finding.
    """
    ok, data, err = _ps(
        "$c = Get-SmbServerConfiguration -ErrorAction SilentlyContinue; "
        "$fw = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow "
        "-ErrorAction SilentlyContinue | Where-Object DisplayName -match "
        "'SMB|NetBIOS|File and Printer').Count; "
        # NetworkCategory is an enum -- ConvertTo-Json emits it as an integer,
        # so stringify it here rather than guessing at the numeric mapping.
        "$prof = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | "
        "ForEach-Object { [string]$_.NetworkCategory }); "
        "[pscustomobject]@{ require=$c.RequireSecuritySignature; "
        "enable=$c.EnableSecuritySignature; smb1=$c.EnableSMB1Protocol; "
        "allowRules=$fw; categories=@($prof) } | ConvertTo-Json -Compress -Depth 3"
    )
    if not ok or not isinstance(data, dict):
        return [
            _unknown(
                "network.smb",
                "network",
                "SMB signing and exposure",
                f"SMB/firewall query failed: {err}",
            )
        ]

    facts = [
        Fact(
            key="network.smb_signing",
            category="network",
            title="SMB signing required",
            state=OK if data.get("require") else FINDING,
            value=f"require={data.get('require')}, offer={data.get('enable')}",
            expected="required",
            reason=(
                "SMB signing is not required. This is the Windows workstation "
                "default rather than a weakened setting, but it is what makes "
                "NTLM relay work on a flat LAN."
            )
            if not data.get("require")
            else None,
            evidence=data,
        ),
        Fact(
            key="network.smb1",
            category="network",
            title="SMBv1 protocol",
            state=OK if not data.get("smb1") else FINDING,
            value="disabled" if not data.get("smb1") else "ENABLED",
            expected="disabled",
            reason="SMBv1 is enabled. This is the EternalBlue-era protocol."
            if data.get("smb1")
            else None,
        ),
    ]

    rules = int(data.get("allowRules") or 0)
    cats = data.get("categories") or []
    if isinstance(cats, (str, int)):
        cats = [cats]
    cats = [str(c) for c in cats]
    facts.append(
        Fact(
            key="network.smb_reachable",
            category="network",
            title="SMB reachable from the network",
            state=FINDING if rules else OK,
            value=f"{rules} inbound allow rule(s); profile(s): {', '.join(cats) or 'unknown'}",
            expected="no inbound allow rules for SMB",
            reason=(
                "The firewall admits SMB from the network. Combined with signing "
                "not being required, this is a usable relay target."
            )
            if rules
            else None,
            evidence={"allow_rules": rules, "categories": cats},
        )
    )
    return facts


# ------------------------------------------------------------- collector ---


class HostPostureCollector:
    """Reads host security posture into ``host_facts``.

    Windows-only for now. The split between elevated and unelevated checks is
    surfaced rather than hidden: ``collect()`` reports how many facts came back
    ``unknown`` so the dashboard can say "12 checks could not run" instead of
    quietly rendering them as passing.
    """

    source = "host_windows"

    def __init__(self, db, sensor_id: str = "host", auditor=None):
        self.db = db
        self.sensor_id = sensor_id
        self.auditor = auditor
        self.last_run: float | None = None

    @staticmethod
    def available() -> tuple[bool, str]:
        if not is_windows():
            return False, f"host posture collection is Windows-only (this is {platform.system()})"
        return True, ""

    def collect(self) -> dict:
        ok, reason = self.available()
        if not ok:
            raise HostCollectorUnavailable(reason)

        elevated = is_elevated()
        log.info("host posture collection starting (elevated=%s)", elevated)

        facts: list[Fact] = []
        for name, fn in (
            ("defender", lambda: check_defender(elevated)),
            ("powershell", check_powershell_logging),
            ("process_audit", lambda: check_process_auditing(elevated)),
            ("log_clearing", lambda: check_log_clearing(elevated)),
            ("drivers", check_unsigned_drivers),
            ("tasks", check_scheduled_tasks),
            ("smb", check_smb_exposure),
        ):
            try:
                facts.extend(fn())
            except Exception as exc:  # noqa: BLE001 - one bad check must not stop the rest
                log.exception("host check %s failed", name)
                facts.append(
                    _unknown(
                        f"{name}.error",
                        "audit",
                        f"Check group: {name}",
                        f"collector raised {type(exc).__name__}: {exc}",
                    )
                )

        changes = 0
        for f in facts:
            if self.db.record_host_fact(
                fact_key=f.key,
                category=f.category,
                title=f.title,
                state=f.state,
                value=f.value,
                expected=f.expected,
                reason=f.reason,
                needs_admin=f.needs_admin,
                evidence=f.evidence or None,
            ):
                changes += 1

        summary = {
            "total": len(facts),
            "ok": sum(1 for f in facts if f.state == OK),
            "finding": sum(1 for f in facts if f.state == FINDING),
            "unknown": sum(1 for f in facts if f.state == UNKNOWN),
            "changed": changes,
            "elevated": elevated,
        }
        log.info(
            "host posture: %(ok)s ok, %(finding)s findings, %(unknown)s could not run "
            "(elevated=%(elevated)s)",
            summary,
        )
        import time

        self.last_run = time.time()
        return summary
