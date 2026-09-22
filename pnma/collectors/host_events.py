"""What happened on this machine: the host as an event source.

`host_windows.py` answers "is this control in the right state?". This module
answers the other half of what an analyst asks about the monitoring host --
"what changed, and when?" -- and writes it as a stream the dashboard's
investigation log can show next to network events:

* **Installed software** -- the Uninstall registry keys (never `Win32_Product`,
  which reconfigures every MSI package just by being queried). Snapshot in
  `host_software`; each run diffs against the last and emits
  `software_installed` / `software_removed` events. Entries are classified
  by *class*, not by a name blocklist: remote-access tooling, activation /
  crack tooling, no publisher, installed outside Program Files, installed in
  the last week.
* **Autoruns** -- Run / RunOnce keys (HKLM, HKCU, WOW6432Node) and both Startup
  folders. Snapshot in `host_autoruns`; diff -> `autorun_added` /
  `autorun_removed`. Classified by command shape (script host, LOLBin,
  user-writable path).
* **Windows event logs** the current user can read without elevation:
  PowerShell/Operational 4104 (script blocks -- Windows logs the ones it
  considers suspicious even when the script-block-logging policy is off,
  which is this host's current state), System 7045 (service installed),
  System 104 (log cleared). The Security log (4688, 4698, 1102) needs
  elevation and is reported as a blind spot, not silently skipped.
* **Hidden directories** newly created under the user profile, ProgramData,
  Temp, Public and the drive root.
* **Outbound connections** that are worth a second look: a script host or
  LOLBin talking to the internet, a Tor-shaped port, a persistent connection
  to an uncommon port. Ordinary browser traffic is not recorded.
* **Adapter counters** (bytes in/out per interface) so a rule can spot an
  upload that is far outside the host's own recent norm.

Every writer follows the `host_windows` contract: something we could not
read is an `unknown`, never a pass. PNMA's own PowerShell is stamped with a
marker so its script blocks are attributed (`agent_generated=1`), the same
way the passive collector attributes ARP replies to its own probes.

Reads only. Never executes anything it finds. Windows-only; on other
platforms `available()` says so and the daemon does not schedule it.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any

from ..db import Database
from .host_windows import AGENT_MARKER, _ps, is_windows

log = logging.getLogger(__name__)

EVENT_KINDS = (
    "software_installed", "software_removed", "autorun_added", "autorun_removed",
    "powershell_block", "service_installed", "log_cleared", "hidden_dir_created",
    "connection",
)

# --------------------------------------------------------------- classifiers
# Pure functions: (entry) -> list of class tags. Tested without Windows.

REMOTE_ACCESS = re.compile(
    r"anydesk|teamviewer|rustdesk|screenconnect|connectwise|netsupport|ammyy|"
    r"splashtop|ultraviewer|logmein|gotomypc|atera|level\.io|remote ?utilities|"
    r"supremo|dwservice|meshagent|meshcentral|zoho ?assist|bomgar|beyondtrust|"
    r"radmin|vnc|dameware|simplehelp|action1|pulseway|syncro|ninja(rmm|one)|tacticalrmm",
    re.I)
ACTIVATION_TOOLING = re.compile(
    r"\bkms\b|kmspico|kms.?auto|\bmas\b|massgrave|activat(or|ion.?renewal)|"
    r"crack|keygen|\bloader\b|\bpatch(er)?\b|hwid|ohook|autokms|re-?loader",
    re.I)
TOR_SOFTWARE = re.compile(r"tor browser|\btor\b|torproject", re.I)
# Reverse tunnels / proxies: expose this machine to the internet from inside
# the LAN, bypassing the router. Legitimate for a developer; T1572 for an
# intruder. Either way the operator should know it is installed.
TUNNEL_TOOLING = re.compile(
    r"\bngrok\b|cloudflared|devtunnel|localtonet|localtunnel|\bbore\b|\bfrp[cs]?\b|"
    r"chisel|\bplink\b|pinggy|serveo|tailscale funnel|zrok",
    re.I)
HACKTOOL = re.compile(
    r"mimikatz|metasploit|cobalt|sliver|brute ?ratel|nmap|zenmap|wireshark|"
    r"npcap|sharphound|bloodhound|rubeus|impacket|responder|hashcat|john the ripper|"
    r"cain|netcat|ncat|psexec|pstools|sysinternals|advanced (ip|port) scanner|angry ip",
    re.I)
USER_WRITABLE = re.compile(
    r"\\(appdata|temp|tmp|downloads|public|programdata|users\\[^\\]+\\desktop|recycle)\\",
    re.I)
SCRIPT_HOST = re.compile(
    r"\b(powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|"
    r"msbuild|installutil|regasm|regsvcs|cmd|conhost|forfiles|pcalua|msiexec|curl|wget)(\.exe)?\b",
    re.I)

# Known-benign publishers whose autoruns and installs are not "unknown".
TRUSTED_PUBLISHERS = re.compile(
    r"microsoft|intel|nvidia|amd|realtek|apple|google|mozilla|adobe|logitech|"
    r"dell|hp inc|lenovo|asus|razer|discord|valve|steam|spotify|zoom|slack|"
    r"dropbox|tailscale|anthropic|oracle|python software foundation|node\.js|git|"
    r"docker|jetbrains|github|epic games|electronic arts|ubisoft|corsair|samsung|"
    r"7-zip|igor pavlov|videolan|obs project|notepad\+\+|don ho|wireguard",
    re.I)


def classify_software(entry: dict) -> list[str]:
    """Class tags for one installed-software entry. Empty = nothing notable."""
    name = entry.get("name") or ""
    publisher = entry.get("publisher") or ""
    tags: list[str] = []
    if REMOTE_ACCESS.search(name) or REMOTE_ACCESS.search(publisher):
        tags.append("remote_access")
    if ACTIVATION_TOOLING.search(name):
        tags.append("activation_tooling")
    if TOR_SOFTWARE.search(name) or TOR_SOFTWARE.search(publisher):
        tags.append("tor")
    if HACKTOOL.search(name):
        tags.append("security_tooling")
    if TUNNEL_TOOLING.search(name) or TUNNEL_TOOLING.search(publisher):
        tags.append("tunnel")
    if not publisher.strip():
        tags.append("no_publisher")
    # Only the install location counts, and a Burn bootstrapper cache under
    # ProgramData\Package Cache is how every VC++ redistributable is stored.
    loc = entry.get("location") or ""
    if loc and USER_WRITABLE.search(loc) and "package cache" not in loc.lower():
        tags.append("user_writable_path")
    if publisher and TRUSTED_PUBLISHERS.search(publisher):
        tags.append("trusted_publisher")
    installed = entry.get("installed_at")
    if installed and time.time() - installed < 7 * 86400:
        tags.append("recent")
    return tags


def software_severity(tags: list[str]) -> str | None:
    """Severity for a software finding, or None when it is just inventory."""
    if "activation_tooling" in tags or "remote_access" in tags:
        return "high"
    if "tor" in tags or "security_tooling" in tags or "tunnel" in tags:
        return "medium"
    if "trusted_publisher" in tags:
        return None  # a known vendor installing under AppData is how they ship
    if "user_writable_path" in tags and "no_publisher" in tags:
        return "medium"
    if "no_publisher" in tags and "recent" in tags:
        return "low"
    return None


PNMA_OWN = re.compile(r"start-pnma\.ps1|pnma", re.I)


# `cmd.exe /q /c del /q "C:\\Program Files\\..."`: the RunOnce an installer
# leaves to remove its own cached setup binary (OneDrive does this on every
# update). cmd.exe deleting one file under Program Files is not a script host.
_CLEANUP_RUNONCE = re.compile(
    r'^"?[A-Za-z]:\\windows\\system32\\cmd\.exe"?\s+/q\s+/c\s+del\s+/q\s+"?[A-Za-z]:\\program files',
    re.I)


def classify_autorun(entry: dict) -> list[str]:
    command = entry.get("command") or ""
    tags: list[str] = []
    if PNMA_OWN.search(command) or PNMA_OWN.search(entry.get("name") or ""):
        # PNMA's own Startup shortcut launches powershell; attributing it is
        # the same honesty as the passive collector ignoring its own probes.
        return ["pnma_own"]
    if _CLEANUP_RUNONCE.search(command) and "runonce" in (entry.get("where") or "").lower():
        return ["installer_cleanup"]
    if SCRIPT_HOST.search(command):
        tags.append("script_host")
    if USER_WRITABLE.search(command):
        tags.append("user_writable_path")
    if re.search(r"-enc|-e |frombase64|hidden|-nop|bypass|iex|downloadstring|invoke-", command, re.I):
        tags.append("obfuscated_or_downloader")
    if entry.get("signed") is False:
        tags.append("unsigned")
    if REMOTE_ACCESS.search(command):
        tags.append("remote_access")
    return tags


def autorun_severity(tags: list[str]) -> str | None:
    if "obfuscated_or_downloader" in tags:
        return "high"
    if "script_host" in tags and "user_writable_path" in tags:
        return "high"
    if "remote_access" in tags or "script_host" in tags:
        return "medium"
    if "user_writable_path" in tags or "unsigned" in tags:
        return "low"
    return None


# 4104 script-block patterns. Selected from the Splunk security_content 4104
# analytics (Apache-2.0) for behaviours that need no data source beyond the
# PowerShell operational log: encoded/fileless content, download cradles,
# in-memory loading, defence tampering, credential tooling, recon, persistence.
SCRIPT_PATTERNS: list[tuple[str, str, str, str]] = [
    # (tag, severity, regex, technique)
    ("encoded_command", "medium", r"-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}|FromBase64String\(", "T1027.010"),
    ("download_cradle", "high", r"DownloadString|DownloadFile|Invoke-WebRequest|iwr\s|Net\.WebClient|Start-BitsTransfer|Invoke-RestMethod.*(http|ftp)", "T1105"),
    ("invoke_expression", "medium", r"\bIEX\b|Invoke-Expression", "T1059.001"),
    ("memory_stream", "high", r"MemoryStream|GzipStream|DeflateStream|\[Reflection\.Assembly\]::Load|Assembly\]::Load\(", "T1620"),
    ("defender_tamper", "high", r"Add-MpPreference.*Exclusion|Set-MpPreference.*-Disable|DisableRealtimeMonitoring|Remove-MpPreference", "T1562.001"),
    ("amsi_bypass", "critical", r"AmsiUtils|amsiInitFailed|AmsiScanBuffer|System\.Management\.Automation\.AmsiUtils", "T1562.001"),
    ("credential_tooling", "critical", r"Invoke-Mimikatz|sekurlsa|Invoke-Kerberoast|Rubeus|lsass|Get-GPPPassword|Invoke-DCSync", "T1003"),
    ("offensive_framework", "critical", r"Invoke-Empire|PowerSploit|Invoke-Shellcode|Invoke-ReflectivePEInjection|Nishang|PowerView|Get-DomainUser|Invoke-Obfuscation", "T1059.001"),
    ("recon", "low", r"AntiVirusProduct|Get-NetTCPConnection|Get-WmiObject.*Win32_(Product|Process|Service)|whoami|Get-LocalUser|Get-LocalGroupMember", "T1082"),
    ("persistence", "medium", r"Register-ScheduledTask|New-ScheduledTask|schtasks|CurrentVersion\\\\Run|New-Service|sc\.exe create", "T1053.005"),
    ("clipboard_or_screen", "medium", r"Get-Clipboard|CopyFromScreen|Set-Clipboard", "T1115"),
    ("hidden_window", "medium", r"-w(indowstyle)?\s+hidden|-nop\b|-noni\b|-ep bypass|ExecutionPolicy Bypass", "T1564.003"),
    ("shadow_copy", "high", r"vssadmin.*delete|Win32_ShadowCopy|wbadmin.*delete", "T1490"),
    ("log_tamper", "high", r"Clear-EventLog|wevtutil.*cl\b|Remove-EventLog|Limit-EventLog", "T1070.001"),
]
_COMPILED_SCRIPT_PATTERNS = [(t, s, re.compile(r, re.I | re.S), m) for t, s, r, m in SCRIPT_PATTERNS]

# Windows' own module boilerplate accounts for most Warning-level 4104 rows
# on a machine with the policy off. It is not a script anyone wrote.
_BOILERPLATE = re.compile(
    r"\$__cmdletization_|Microsoft\.PowerShell\.Core\\Set-StrictMode -Off|ObjectModelWrapper|"
    # Cmdlet proxy definitions (the Defender module's Set-MpPreference has a
    # parameter literally named DisableRealtimeMonitoring): parameter blocks
    # with aliases and validators are a module loading, not a script running.
    r"\[Parameter\(ParameterSetName=.{0,200}\[Alias\(|\[ValidateNotNullOrEmpty\(\)\]\s*\[(switch|bool|string)\]\s*\$\{",
    re.I | re.S)


def classify_script_block(text: str) -> list[tuple[str, str, str]]:
    """(tag, severity, technique) for every pattern the block matches."""
    if not text or _BOILERPLATE.search(text):
        return []
    hits = []
    for tag, sev, rx, mitre in _COMPILED_SCRIPT_PATTERNS:
        if rx.search(text):
            hits.append((tag, sev, mitre))
    return hits


def script_block_severity(hits: list[tuple[str, str, str]]) -> str | None:
    if not hits:
        return None
    order = ["info", "low", "medium", "high", "critical"]
    top = max(hits, key=lambda h: order.index(h[1]))
    sev = top[1]
    # Two independent behaviours in one block (a cradle AND a hidden window)
    # is the classic one-liner; step up once.
    tags = {h[0] for h in hits}
    if len(tags) >= 2 and sev != "critical":
        sev = order[min(len(order) - 1, order.index(sev) + 1)]
    return sev


# Ports where a connection is worth noting regardless of process.
TOR_PORTS = {9001, 9030, 9050, 9051, 9150}
COMMON_PORTS = {80, 443, 53, 22, 25, 465, 587, 993, 995, 123, 8080, 8443, 5223, 5228,
                3478, 3479, 3480, 3481, 4244, 5222, 1900, 5353, 853, 41641}
BROWSERS = re.compile(r"chrome|msedge|firefox|brave|opera|vivaldi|iexplore|safari", re.I)
_PRIVATE = re.compile(r"^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1$|fe80|fc|fd|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|0\.0\.0\.0|::$)")


def is_private_address(addr: str) -> bool:
    return bool(_PRIVATE.match(addr or ""))


def classify_connection(conn: dict) -> list[str]:
    """Tags for one established outbound connection; empty = ordinary."""
    proc = (conn.get("process") or "").lower()
    path = conn.get("path") or ""
    port = int(conn.get("rport") or 0)
    tags: list[str] = []
    if is_private_address(conn.get("raddr") or ""):
        return tags
    if port in TOR_PORTS or proc in ("tor.exe", "tor") or "tor browser" in path.lower():
        tags.append("tor_shaped")
    if SCRIPT_HOST.search(proc) and proc not in ("curl.exe", "wget.exe", "msiexec.exe"):
        tags.append("script_host_network")
    if path and USER_WRITABLE.search(path):
        tags.append("user_writable_binary")
    if port not in COMMON_PORTS and not BROWSERS.search(proc) and "tor_shaped" not in tags:
        tags.append("uncommon_port")
    return tags


def connection_severity(tags: list[str]) -> str | None:
    if "script_host_network" in tags:
        return "high"
    if "tor_shaped" in tags:
        return "medium"
    if "uncommon_port" in tags and "user_writable_binary" in tags:
        return "medium"
    if "uncommon_port" in tags:
        return "low"
    # A binary under AppData talking on 443 is every Electron app; a tag, not
    # a finding, on its own.
    return None


# --------------------------------------------------------------- collection

_PATH_IN_CMD = re.compile(r'^"?([A-Za-z]:\\[^"]+?\.(exe|sys|dll))"?', re.I)


def _sha256_of(command_or_path: str | None) -> str | None:
    """SHA-256 of the file a service/autorun command names, if it resolves.
    Never executes anything; a hash is what an analyst takes to a sandbox or
    a reputation lookup by hand (PNMA itself makes no such lookup)."""
    if not command_or_path:
        return None
    raw = command_or_path.strip()
    raw = raw.replace("\\SystemRoot", os.environ.get("SystemRoot", "C:\\Windows")).replace("\\??\\", "")
    m = _PATH_IN_CMD.match(raw)
    path = m.group(1) if m else (raw if raw.lower().endswith((".exe", ".sys", ".dll")) else None)
    if not path or not os.path.isfile(path):
        return None
    try:
        import hashlib
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _ps_marked(script: str, timeout: int = 60):
    # _ps already stamps the marker; kept as the seam the tests mock.
    return _ps(script, timeout=timeout)


@dataclass
class RunSummary:
    events: int = 0
    unknown: list[str] = field(default_factory=list)
    detail: dict = field(default_factory=dict)


class HostEventCollector:
    """Runs every sub-collector, records the result, never raises."""

    source = "host_events"
    # Events read per log per run. With script-block logging ON this is the
    # number that matters -- 4104 volume grows by orders of magnitude.
    WINEVENT_CAP = 1000

    def __init__(self, db: Database, sensor_id: str = "host"):
        self.db = db
        self.sensor_id = sensor_id
        self.last_run: float | None = None
        self.last_summary: RunSummary | None = None

    @staticmethod
    def available() -> tuple[bool, str]:
        if not is_windows():
            return False, "host event collection is Windows-only"
        return True, ""

    # -- public entry --------------------------------------------------------

    def run_once(self) -> RunSummary:
        started = time.time()
        summary = RunSummary()
        for name, fn in (
            ("software", self.collect_software),
            ("autoruns", self.collect_autoruns),
            ("winevents", self.collect_winevents),
            ("hidden_dirs", self.collect_hidden_dirs),
            ("connections", self.collect_connections),
            ("counters", self.collect_counters),
        ):
            try:
                n, unknown = fn()
                summary.events += n
                summary.detail[name] = n
                if unknown:
                    summary.unknown.append(f"{name}: {unknown}")
            except Exception as exc:  # noqa: BLE001 - one source must not stop the rest
                log.exception("host events: %s failed", name)
                summary.unknown.append(f"{name}: {type(exc).__name__}: {exc}")
        self.db.log_scan(
            "host_events", "localhost", duration_s=time.time() - started,
            result=f"{summary.events} events ({', '.join(f'{k} {v}' for k, v in summary.detail.items())})",
            error="; ".join(summary.unknown) or None,
        )
        # Coverage facts: what this collector could and could not read. These
        # are the honest half -- an empty stream from a log we cannot open
        # must show as unknown, not as quiet.
        self.db.record_host_fact(
            fact_key="events.security_log", category="audit",
            title="Security event log readable (4688/4698/1102)",
            state="unknown" if any("Security" in u for u in summary.unknown) else "ok",
            value="needs elevation" if any("Security" in u for u in summary.unknown) else "readable",
            expected="readable", needs_admin=True,
            reason="Process creation, scheduled-task creation and audit-log-cleared events live in the Security log, which an unelevated collector cannot open. Run the collector elevated to close this gap.",
        )
        self.last_run = time.time()
        self.last_summary = summary
        return summary

    # -- helpers -------------------------------------------------------------

    def _emit(self, *, kind: str, ts: float, summary: str, detail: dict,
              severity: str | None, dedup_key: str, agent_generated: bool = False,
              mitre_id: str | None = None) -> bool:
        return self.db.record_host_event(
            kind=kind, ts=ts, summary=summary, detail=detail, severity=severity,
            dedup_key=dedup_key, agent_generated=agent_generated, mitre_id=mitre_id,
            sensor_id=self.sensor_id,
        )

    def _meta(self, key: str) -> str | None:
        row = self.db.query_one("SELECT value FROM meta WHERE key = ?", (key,))
        return row["value"] if row else None

    def _set_meta(self, key: str, value: str) -> None:
        self.db.execute("INSERT INTO meta(key, value) VALUES(?, ?) "
                        "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))

    # -- installed software --------------------------------------------------

    _SOFTWARE_PS = r"""
$keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
          'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
          'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')
$out = foreach ($k in $keys) {
  Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
    [pscustomobject]@{ key = $_.PSChildName; name = [string]$_.DisplayName; version = [string]$_.DisplayVersion;
      publisher = [string]$_.Publisher; installed = [string]$_.InstallDate; location = [string]$_.InstallLocation;
      uninstall = [string]$_.UninstallString; hive = ($k -split ':')[0] + $(if ($k -match 'WOW6432Node') { '32' } else { '' }) }
  }
}
@($out) | ConvertTo-Json -Compress
"""

    def collect_software(self) -> tuple[int, str]:
        ok, rows, err = _ps_marked(self._SOFTWARE_PS)
        if not ok:
            return 0, f"Uninstall keys: {err}"
        if isinstance(rows, dict):
            rows = [rows]
        now = time.time()
        seen: dict[str, dict] = {}
        for r in rows or []:
            entry = self._software_entry(r)
            seen[entry["id"]] = entry
        prev = {row["software_id"]: dict(row) for row in self.db.query("SELECT * FROM host_software")}
        first_run = not prev
        n = 0
        for sid, e in seen.items():
            tags = classify_software(e)
            e["tags"] = tags
            self.db.execute(
                """INSERT INTO host_software(software_id, name, version, publisher, location, hive,
                                             installed_at, tags, first_seen, last_seen)
                   VALUES(?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(software_id) DO UPDATE SET name=excluded.name, version=excluded.version,
                     publisher=excluded.publisher, location=excluded.location, tags=excluded.tags,
                     installed_at=COALESCE(excluded.installed_at, host_software.installed_at),
                     last_seen=excluded.last_seen, removed_at=NULL""",
                (sid, e["name"], e["version"], e["publisher"], e["location"], e["hive"],
                 e["installed_at"], json.dumps(tags), now, now))
            if sid not in prev and not first_run:
                sev = software_severity(tags)
                if self._emit(kind="software_installed", ts=e["installed_at"] or now,
                              summary=f"installed: {e['name']} {e['version'] or ''} ({e['publisher'] or 'no publisher'})".strip(),
                              detail=e, severity=sev, dedup_key=f"software:{sid}",
                              mitre_id="T1219" if "remote_access" in tags else "T1553" if "activation_tooling" in tags else None):
                    n += 1
        for sid, p in prev.items():
            if sid not in seen and not p.get("removed_at"):
                self.db.execute("UPDATE host_software SET removed_at = ? WHERE software_id = ?", (now, sid))
                if self._emit(kind="software_removed", ts=now, summary=f"removed: {p['name']}",
                              detail={"name": p["name"], "publisher": p["publisher"]},
                              severity=None, dedup_key=f"software_removed:{sid}:{int(now)}"):
                    n += 1
        # The standing fact. Only the high classes are posture debt (remote
        # access and activation tooling: a standing door, or a known stealer
        # carrier); the rest -- Nmap, a tunnel, Tor -- are inventory the Host
        # tab lists, because a fact has no acknowledge path and a ring that
        # can never recover from the operator's own tools is alert fatigue.
        flagged = [e for e in seen.values() if software_severity(e["tags"])]
        debt = [e for e in flagged if software_severity(e["tags"]) == "high"]
        self.db.record_host_fact(
            fact_key="software.flagged", category="persistence",
            title="Installed software of a notable class",
            state="finding" if debt else "ok",
            value=(", ".join(f"{e['name']} [{'/'.join(e['tags'])}]" for e in debt[:6]) if debt
                   else (f"{len(flagged)} notable, none high: " + ", ".join(e["name"] for e in flagged[:6]) if flagged else "none")),
            expected="no remote-access or activation/crack tooling",
            reason=("Remote-access tools give whoever holds the account a desktop here; activation/crack "
                    "tooling is the most common stealer carrier on home PCs. Uninstall, or if it is "
                    "deliberate, this stays a finding by design.") if debt else None,
            evidence={"count": len(seen), "flagged": [{"name": e["name"], "tags": e["tags"]} for e in flagged]},
        )
        return n, ""

    @staticmethod
    def _software_entry(r: dict) -> dict:
        installed_at = None
        raw = (r.get("installed") or "").strip()
        if re.fullmatch(r"\d{8}", raw):
            try:
                installed_at = time.mktime(time.strptime(raw, "%Y%m%d"))
            except ValueError:
                installed_at = None
        name = (r.get("name") or "").strip()
        return {
            "id": f"{r.get('hive') or 'HKLM'}:{r.get('key') or name}",
            "name": name, "version": (r.get("version") or "").strip() or None,
            "publisher": (r.get("publisher") or "").strip() or None,
            "location": (r.get("location") or "").strip() or None,
            "uninstall": (r.get("uninstall") or "").strip() or None,
            "hive": r.get("hive") or "HKLM", "installed_at": installed_at,
        }

    # -- autoruns ------------------------------------------------------------

    _AUTORUNS_PS = r"""
$out = @()
foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')) {
  $p = Get-ItemProperty $k -ErrorAction SilentlyContinue
  if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
    $out += [pscustomobject]@{ where = $k; name = $_.Name; command = [string]$_.Value } } }
}
foreach ($d in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
  if ($d -and (Test-Path $d)) { Get-ChildItem $d -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object {
    $target = $_.FullName; $args = ''
    if ($_.Extension -eq '.lnk') { try { $lnk = (New-Object -ComObject WScript.Shell).CreateShortcut($_.FullName); $target = $lnk.TargetPath; $args = [string]$lnk.Arguments } catch {} }
    $out += [pscustomobject]@{ where = $d; name = $_.Name; command = ([string]('"' + $target + '" ' + $args)).Trim() } } }
}
foreach ($o in $out) {
  $exe = $null
  if ($o.command -match '^"([^"]+\.exe)"') { $exe = $matches[1] } elseif ($o.command -match '^([^\s]+\.exe)') { $exe = $matches[1] }
  if (-not $exe -and $o.command -match '^"([^"]+)"' -and (Test-Path $matches[1])) { $exe = $matches[1] }
  $signed = $null; $sha = $null
  if ($exe -and (Test-Path $exe)) {
    try { $signed = ((Get-AuthenticodeSignature $exe).Status -eq 'Valid') } catch {}
    try { $sha = (Get-FileHash -Algorithm SHA256 $exe -ErrorAction Stop).Hash.ToLower() } catch {}
  }
  $o | Add-Member -NotePropertyName signed -NotePropertyValue $signed
  $o | Add-Member -NotePropertyName exe -NotePropertyValue $exe
  $o | Add-Member -NotePropertyName sha256 -NotePropertyValue $sha
}
@($out) | ConvertTo-Json -Compress
"""

    def collect_autoruns(self) -> tuple[int, str]:
        ok, rows, err = _ps_marked(self._AUTORUNS_PS)
        if not ok:
            return 0, f"Run keys / Startup folders: {err}"
        if isinstance(rows, dict):
            rows = [rows]
        now = time.time()
        seen: dict[str, dict] = {}
        for r in rows or []:
            e = {"where": r.get("where") or "", "name": r.get("name") or "",
                 "command": r.get("command") or "", "signed": r.get("signed"),
                 "exe": r.get("exe") or None, "sha256": r.get("sha256") or None}
            e["id"] = f"{e['where']}::{e['name']}"
            e["tags"] = classify_autorun(e)
            seen[e["id"]] = e
        prev = {row["autorun_id"]: dict(row) for row in self.db.query("SELECT * FROM host_autoruns")}
        first_run = not prev
        n = 0
        for aid, e in seen.items():
            self.db.execute(
                """INSERT INTO host_autoruns(autorun_id, location, name, command, signed, sha256, tags, first_seen, last_seen)
                   VALUES(?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(autorun_id) DO UPDATE SET command=excluded.command, signed=excluded.signed,
                     sha256=excluded.sha256, tags=excluded.tags, last_seen=excluded.last_seen, removed_at=NULL""",
                (aid, e["where"], e["name"], e["command"],
                 None if e["signed"] is None else int(bool(e["signed"])), e["sha256"], json.dumps(e["tags"]), now, now))
            if aid not in prev and not first_run:
                if self._emit(kind="autorun_added", ts=now,
                              summary=f"autorun added: {e['name']} -> {e['command'][:120]}",
                              detail=e, severity=autorun_severity(e["tags"]),
                              dedup_key=f"autorun:{aid}", mitre_id="T1547.001"):
                    n += 1
            elif aid in prev and prev[aid].get("sha256") and e["sha256"] and prev[aid]["sha256"] != e["sha256"]:
                if self._emit(kind="autorun_added", ts=now,
                              summary=f"autorun binary changed on disk: {e['name']} ({e['exe']})",
                              detail={**e, "previous_sha256": prev[aid]["sha256"]}, severity="medium",
                              dedup_key=f"autorun_hash:{aid}:{e['sha256'][:12]}", mitre_id="T1547.001"):
                    n += 1
            elif aid in prev and prev[aid]["command"] != e["command"]:
                if self._emit(kind="autorun_added", ts=now,
                              summary=f"autorun changed: {e['name']} -> {e['command'][:120]}",
                              detail={**e, "previous": prev[aid]["command"]}, severity=autorun_severity(e["tags"]) or "low",
                              dedup_key=f"autorun:{aid}:{int(now)}", mitre_id="T1547.001"):
                    n += 1
        for aid, p in prev.items():
            if aid not in seen and not p.get("removed_at"):
                self.db.execute("UPDATE host_autoruns SET removed_at = ? WHERE autorun_id = ?", (now, aid))
                if self._emit(kind="autorun_removed", ts=now, summary=f"autorun removed: {p['name']}",
                              detail={"name": p["name"], "command": p["command"]}, severity=None,
                              dedup_key=f"autorun_removed:{aid}:{int(now)}"):
                    n += 1
        flagged = [e for e in seen.values() if autorun_severity(e["tags"])]
        debt = [e for e in flagged if autorun_severity(e["tags"]) in ("high", "medium")]
        self.db.record_host_fact(
            fact_key="autoruns.flagged", category="persistence",
            title="Autorun entries of a notable shape",
            state="finding" if debt else "ok",
            value=", ".join(f"{e['name']} [{'/'.join(e['tags'])}]" for e in flagged[:6]) or "none",
            expected="none, or all accounted for by the operator",
            reason=("A Run key or Startup item that launches a script host, points into a user-writable "
                    "path, is unsigned, or carries download/obfuscation flags. Persistence is where "
                    "an intruder lives between reboots.") if flagged else None,
            evidence={"count": len(seen), "flagged": [{"name": e["name"], "command": e["command"], "tags": e["tags"]} for e in flagged]},
        )
        return n, ""

    # -- windows event logs --------------------------------------------------

    _WINEVENT_PS = r"""
param()
$log = '%(log)s'; $since = %(since)s
$idx = '(' + ((@(%(ids)s) | ForEach-Object { "EventID=$_" }) -join ' or ') + ')'
$xpath = "*[System[$idx and (EventRecordID > $since)]]"
$out = @()
try {
  # Oldest-first from the cursor, capped: a burst larger than the cap is read
  # across successive runs instead of skipped, and the caller sees the cap.
  $evs = @(Get-WinEvent -LogName $log -FilterXPath $xpath -Oldest -MaxEvents %(cap)s -ErrorAction Stop)
  foreach ($e in $evs) {
    $props = @($e.Properties | ForEach-Object { [string]$_.Value })
    $out += [pscustomobject]@{ record = $e.RecordId; id = $e.Id; t = [int]([DateTimeOffset]$e.TimeCreated).ToUnixTimeSeconds(); level = $e.LevelDisplayName; props = $props; msg = ([string]$e.Message) }
  }
  $res = [pscustomobject]@{ ok = $true; events = $out; max = ($evs | Measure-Object -Property RecordId -Maximum).Maximum; saturated = ($evs.Count -ge %(cap)s) }
} catch {
  if ($_.Exception.Message -match 'No events were found') { $res = [pscustomobject]@{ ok = $true; events = @(); max = $null } }
  else { $res = [pscustomobject]@{ ok = $false; error = $_.Exception.Message } }
}
$res | ConvertTo-Json -Compress -Depth 4
"""

    def _read_log(self, log_name: str, ids: list[int], cursor_key: str) -> tuple[list[dict], str]:
        since = int(self._meta(cursor_key) or 0)
        script = self._WINEVENT_PS % {"log": log_name, "ids": ",".join(str(i) for i in ids),
                                      "since": since, "cap": self.WINEVENT_CAP}
        ok, res, err = _ps_marked(script, timeout=90)
        if not ok:
            return [], f"{log_name}: {err}"
        if not res.get("ok"):
            return [], f"{log_name}: {res.get('error')}"
        events = res.get("events") or []
        if isinstance(events, dict):
            events = [events]
        mx = res.get("max")
        if mx:
            self._set_meta(cursor_key, str(int(mx)))
        if res.get("saturated"):
            # More than the cap arrived since the last run. Nothing was skipped
            # (the cursor only advanced to the last row read), but the log is
            # ahead of us; say so rather than look caught up.
            return events, f"{log_name}: {self.WINEVENT_CAP}-event cap hit; catching up next run"
        return events, ""

    def collect_winevents(self) -> tuple[int, str]:
        n = 0
        problems: list[str] = []
        # PowerShell 4104
        evs, err = self._read_log("Microsoft-Windows-PowerShell/Operational", [4104], "host_events_cursor_ps")
        if err:
            problems.append(err)
        scanned = 0
        for e in evs:
            props = e.get("props") or []
            text = props[2] if len(props) > 2 else (props[-1] if props else "")
            scanned += 1
            hits = classify_script_block(text)
            agent = AGENT_MARKER in (text or "")
            if not hits and not agent:
                continue
            sev = None if agent else script_block_severity(hits)
            tags = sorted({h[0] for h in hits})
            self._emit(
                kind="powershell_block", ts=float(e.get("t") or time.time()),
                summary=("PNMA's own script" if agent else "script block: " + ", ".join(tags) + f" ({len(text or '')} chars)"),
                detail={"tags": tags, "level": e.get("level"), "record": e.get("record"),
                        "excerpt": (text or "")[:600], "techniques": sorted({h[2] for h in hits})},
                severity=sev, dedup_key=f"ps4104:{e.get('record')}", agent_generated=agent,
                mitre_id=(max(hits, key=lambda h: ["info", "low", "medium", "high", "critical"].index(h[1]))[2] if hits else None),
            )
            n += 1
        self.db.record_host_fact(
            fact_key="events.powershell_log", category="audit",
            title="PowerShell script-block log readable (4104)",
            state="unknown" if any("PowerShell" in p for p in problems) else "ok",
            value=(problems[0] if problems else f"readable; {scanned} new blocks scanned this run"),
            expected="readable",
            reason=("Without the script-block-logging policy Windows records only the blocks it judges "
                    "suspicious itself; turn the policy on (see the PowerShell posture finding) to see everything."),
        )
        # System 7045 / 104
        evs, err = self._read_log("System", [7045, 104], "host_events_cursor_system")
        if err:
            problems.append(err)
        for e in evs:
            props = e.get("props") or []
            ts = float(e.get("t") or time.time())
            if int(e.get("id") or 0) == 7045:
                name = props[0] if props else "?"
                path = props[1] if len(props) > 1 else ""
                start = props[3] if len(props) > 3 else ""
                tags = []
                if USER_WRITABLE.search(path or ""):
                    tags.append("user_writable_path")
                if SCRIPT_HOST.search(path or ""):
                    tags.append("script_host")
                if REMOTE_ACCESS.search(name + " " + path):
                    tags.append("remote_access")
                sev = "high" if tags else "low"
                sha = _sha256_of(path)
                self._emit(kind="service_installed", ts=ts,
                           summary=f"service installed: {name} -> {path[:120]}",
                           detail={"name": name, "path": path, "start": start, "tags": tags, "record": e.get("record"), "sha256": sha},
                           severity=sev, dedup_key=f"svc7045:{e.get('record')}", mitre_id="T1543.003")
                n += 1
            elif int(e.get("id") or 0) == 104:
                self._emit(kind="log_cleared", ts=ts,
                           summary="an event log was cleared: " + (props[0] if props else (e.get("msg") or "")[:80]),
                           detail={"props": props, "record": e.get("record")}, severity="high",
                           dedup_key=f"log104:{e.get('record')}", mitre_id="T1070.001")
                n += 1
        # Security (needs elevation). Get-WinEvent hides an access failure
        # behind "no events were found" when a filter is used, so probe the
        # log directly: unelevated this raises "unauthorized operation".
        ok, res, err = _ps_marked(
            "try { $null = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop; "
            "$r = [pscustomobject]@{ ok = $true } } catch { $r = [pscustomobject]@{ ok = $false; error = $_.Exception.Message } }; "
            "$r | ConvertTo-Json -Compress")
        if not ok or not (res or {}).get("ok"):
            problems.append("Security: " + ((res or {}).get("error") or err or "unreadable"))
        else:
            evs, err = self._read_log("Security", [4698, 1102, 4720], "host_events_cursor_security")
            if err:
                problems.append("Security: " + err)
            for e in evs:
                props = e.get("props") or []
                ts = float(e.get("t") or time.time())
                eid = int(e.get("id") or 0)
                if eid == 1102:
                    self._emit(kind="log_cleared", ts=ts, summary="the Security audit log was cleared",
                               detail={"props": props[:4], "record": e.get("record")}, severity="high",
                               dedup_key=f"sec1102:{e.get('record')}", mitre_id="T1070.001")
                    n += 1
                elif eid == 4698:
                    name = props[4] if len(props) > 4 else "?"
                    self._emit(kind="service_installed", ts=ts, summary=f"scheduled task created: {name}",
                               detail={"task": name, "record": e.get("record"), "xml": (props[5] if len(props) > 5 else "")[:1500]},
                               severity="medium", dedup_key=f"sec4698:{e.get('record')}", mitre_id="T1053.005")
                    n += 1
                elif eid == 4720:
                    self._emit(kind="service_installed", ts=ts, summary=f"local account created: {props[0] if props else '?'}",
                               detail={"props": props[:6], "record": e.get("record")}, severity="high",
                               dedup_key=f"sec4720:{e.get('record')}", mitre_id="T1136.001")
                    n += 1
        return n, "; ".join(problems)

    # -- hidden directories --------------------------------------------------

    _HIDDEN_PS = r"""
$roots = @($env:USERPROFILE, $env:APPDATA, $env:LOCALAPPDATA, $env:ProgramData, $env:TEMP, $env:PUBLIC, $env:SystemDrive + '\', $env:USERPROFILE + '\Downloads', $env:USERPROFILE + '\Desktop', $env:USERPROFILE + '\Documents') | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
$skip = 'AppData|\$Recycle\.Bin|System Volume Information|\\\.git$|\\Application Data$|\\Local Settings$|\\Cookies$|\\Recent$|\\SendTo$|\\Templates$|\\NetHood$|\\PrintHood$|\\Start Menu$|\\My Documents$|\\Documents and Settings$|Recovery$|PerfLogs$|\\\.cache$|\\\.vscode|\\\.claude|\\\.nuget|\\\.npm|\\\.ssh$|\\\.gradle|\\\.m2$|\\\.docker|\\\.android|\\\.cargo|\\\.rustup|\\\.conda|\\\.matplotlib|\\\.jupyter|\\\.ipython|\\\.dotnet|\\\.config$|\\\.local$|\\\.pnpm|\\\.yarn|\\\.bun|\\\.cursor|\\\.continue|\\\.ollama|\\\.tailscale|\\\.wdm|Packages$|Microsoft$|Temporary Internet Files$|\\WindowsApps$|\\Package Cache$|\\Config\.Msi$'
$since = (Get-Date).AddSeconds(-%(window)s)
$out = foreach ($r in $roots) {
  Get-ChildItem -LiteralPath $r -Directory -Force -Depth 1 -ErrorAction SilentlyContinue | Where-Object {
    ($_.Attributes -band [IO.FileAttributes]::Hidden) -and $_.CreationTime -gt $since -and ($_.FullName -notmatch $skip) } |
    ForEach-Object { [pscustomobject]@{ path = $_.FullName; created = [int]([DateTimeOffset]$_.CreationTime).ToUnixTimeSeconds(); attrs = [string]$_.Attributes } }
}
@($out | Sort-Object path -Unique) | ConvertTo-Json -Compress
"""

    def collect_hidden_dirs(self) -> tuple[int, str]:
        last = float(self._meta("host_events_hidden_last") or 0)
        window = int(time.time() - last) + 60 if last else 7 * 86400
        ok, rows, err = _ps_marked(self._HIDDEN_PS % {"window": window}, timeout=120)
        self._set_meta("host_events_hidden_last", str(time.time()))
        if not ok:
            if "no output" in err:
                return 0, ""
            return 0, f"hidden-dir scan: {err}"
        if isinstance(rows, dict):
            rows = [rows]
        n = 0
        for r in rows or []:
            path = r.get("path") or ""
            tags = ["user_writable_path"] if USER_WRITABLE.search(path + "\\") else []
            if "System" in (r.get("attrs") or ""):
                tags.append("system_attribute")
            if self._emit(kind="hidden_dir_created", ts=float(r.get("created") or time.time()),
                          summary=f"hidden directory created: {path}",
                          detail={"path": path, "attributes": r.get("attrs"), "tags": tags},
                          severity="medium" if ("system_attribute" in tags and "user_writable_path" in tags) else "low",
                          dedup_key=f"hidden:{path.lower()}", mitre_id="T1564.001"):
                n += 1
        return n, ""

    # -- outbound connections ------------------------------------------------

    _CONN_PS = r"""
$procs = @{}
Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procs[$_.Id] = @{ name = $_.ProcessName; path = $_.Path } }
$out = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | ForEach-Object {
  $p = $procs[[int]$_.OwningProcess]
  [pscustomobject]@{ raddr = [string]$_.RemoteAddress; rport = [int]$_.RemotePort; lport = [int]$_.LocalPort; pid = [int]$_.OwningProcess;
    process = if ($p) { [string]$p.name + '.exe' } else { '' }; path = if ($p) { [string]$p.path } else { '' } }
}
@($out) | ConvertTo-Json -Compress
"""

    def collect_connections(self) -> tuple[int, str]:
        ok, rows, err = _ps_marked(self._CONN_PS)
        if not ok:
            if "no output" in err:
                return 0, ""
            return 0, f"connections: {err}"
        if isinstance(rows, dict):
            rows = [rows]
        now = time.time()
        n = 0
        external = 0
        for r in rows or []:
            if is_private_address(r.get("raddr") or ""):
                continue
            external += 1
            tags = classify_connection(r)
            sev = connection_severity(tags)
            if not sev:
                continue
            key = f"conn:{(r.get('process') or '?').lower()}:{r.get('raddr')}:{r.get('rport')}:{int(now // 3600)}"
            if self._emit(kind="connection", ts=now,
                          summary=f"{r.get('process') or 'pid ' + str(r.get('pid'))} -> {r.get('raddr')}:{r.get('rport')} [{', '.join(tags)}]",
                          detail={**r, "tags": tags}, severity=sev, dedup_key=key,
                          mitre_id="T1090.003" if "tor_shaped" in tags else "T1105" if "script_host_network" in tags else "T1571"):
                n += 1
        self.db.record_host_fact(
            fact_key="events.connections", category="network",
            title="Outbound connection sampling",
            state="ok", value=f"{external} external connections sampled last run",
            expected="sampled each run",
            reason="Only notable connections are recorded (script hosts, Tor-shaped ports, uncommon ports, binaries in user-writable paths). Ordinary browser and system traffic is not logged.",
        )
        return n, ""

    # -- adapter counters ----------------------------------------------------

    _COUNTERS_PS = r"""
@(Get-NetAdapterStatistics -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{ name = $_.Name; sent = [double]$_.SentBytes; recv = [double]$_.ReceivedBytes } }) | ConvertTo-Json -Compress
"""

    def collect_counters(self) -> tuple[int, str]:
        ok, rows, err = _ps_marked(self._COUNTERS_PS)
        if not ok:
            return 0, f"adapter counters: {err}"
        if isinstance(rows, dict):
            rows = [rows]
        now = time.time()
        for r in rows or []:
            self.db.execute("INSERT INTO host_counters(ts, adapter, bytes_sent, bytes_recv) VALUES(?,?,?,?)",
                            (now, r.get("name"), float(r.get("sent") or 0), float(r.get("recv") or 0)))
        self.db.execute("DELETE FROM host_counters WHERE ts < ?", (now - 7 * 86400,))
        return 0, ""
