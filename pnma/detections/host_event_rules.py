"""Rules over the host event stream (pnma.collectors.host_events) and two
derived signals: an ARP sweep seen by the passive collector, and an upload far
outside the host's own recent norm.

Every rule here reads only `agent_generated = 0` rows, and every rule states
its data source in `requires` so the coverage view can say which of these
can fire on this build at all. That field is borrowed from the shape of the
Splunk security_content catalogue: a detection without its data source is
not a detection.
"""

from __future__ import annotations

import json
import statistics
import time

from .base import Detection, DetectionContext, Finding

WINDOW_S = 24 * 3600


def _rows(ctx: DetectionContext, kind: str, *, min_severity: bool = True):
    sql = ("SELECT id, ts, kind, summary, detail, severity, mitre_id FROM host_events "
           "WHERE kind = ? AND agent_generated = 0 AND ts >= ?")
    if min_severity:
        sql += " AND severity IS NOT NULL"
    return ctx.db.query(sql + " ORDER BY ts DESC LIMIT 200", (kind, ctx.now - WINDOW_S))


def _detail(row) -> dict:
    try:
        return json.loads(row["detail"] or "{}")
    except (TypeError, ValueError):
        return {}


class _HostEventRule(Detection):
    """Shared shape: one finding per notable host event of one kind."""

    kind = ""
    requires = ""

    def describe(self, row, d: dict) -> tuple[str, str]:
        raise NotImplementedError

    def evaluate(self, ctx: DetectionContext) -> list[Finding]:
        out = []
        for row in _rows(ctx, self.kind):
            d = _detail(row)
            title, description = self.describe(row, d)
            out.append(Finding(
                dedup_key=f"host_event:{self.kind}:{row['id']}",
                severity=row["severity"] or self.severity,
                title=title,
                description=description + (
                    "\n\nFOR LEARNING: this rule reads " + self.requires + "."),
                evidence={"host_event_id": row["id"], "kind": row["kind"], **d},
                mitre_id=row["mitre_id"] or self.mitre_id,
                mitre_name=self.mitre_name,
            ))
        return out


class SuspiciousPowerShellDetection(_HostEventRule):
    rule_id = "suspicious_powershell"
    name = "Suspicious PowerShell script block"
    severity = "medium"
    kind = "powershell_block"
    mitre_id = "T1059.001"
    mitre_name = "Command and Scripting Interpreter: PowerShell"
    requires = ("Microsoft-Windows-PowerShell/Operational event 4104; with the script-block-logging "
                "policy OFF (this host's state) Windows records only blocks it judges suspicious itself")
    blind_spots = (
        "Sees only script blocks Windows logged. With script-block logging off, that is the subset "
        "Windows itself flagged; turn the policy on to see everything. Cannot see the process that "
        "ran the block (that is 4688 with command-line capture, also a finding on this host), so "
        "'who ran it' is not answered here. PNMA's own scripts are stamped and excluded; an AI "
        "coding assistant or an admin's own tooling will show up and should be recognised, not "
        "dismissed."
    )

    def describe(self, row, d):
        tags = ", ".join(d.get("tags") or [])
        return (
            f"PowerShell block matched: {tags}",
            f"A script block logged at {time.strftime('%H:%M:%S', time.localtime(row['ts']))} matched "
            f"{tags}.\n\n  Excerpt  {(d.get('excerpt') or '')[:300]!r}\n\n"
            "WHY THIS MATTERS: encoded commands, download cradles, in-memory loading and defence "
            "tampering are how commodity malware and hands-on intruders run on Windows without "
            "touching disk. A block matching more than one of these at once is the classic one-liner.\n\n"
            "BENIGN EXPLANATION: your own tooling -- a package manager, an installer, a remote "
            "management agent, or an AI assistant running PowerShell on your behalf -- routinely "
            "uses encoded commands and web requests. Match the time against what you were doing.\n\n"
            "MALICIOUS EXPLANATION: you were not running anything at that time, or the excerpt "
            "references a host, domain or path you do not recognise.\n\n"
            "NEXT STEP: open the Investigation log for the full excerpt. If unrecognised, run "
            "`Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} "
            "-MaxEvents 50` for context, and treat the machine as suspect until explained."
        )


class NewServiceDetection(_HostEventRule):
    rule_id = "service_installed"
    name = "New service, scheduled task or local account"
    severity = "low"
    kind = "service_installed"
    mitre_id = "T1543.003"
    mitre_name = "Create or Modify System Process: Windows Service"
    requires = "System event 7045 (readable); Security 4698 / 4720 only when the collector runs elevated"
    blind_spots = (
        "7045 is readable unelevated; scheduled-task (4698) and account-creation (4720) events are "
        "in the Security log and only appear when the collector is elevated -- see the "
        "'Security event log readable' host fact. A service installed while the collector was "
        "not running is still caught on the next run (the log persists), but an intruder who "
        "clears the log first is not."
    )

    def describe(self, row, d):
        tags = d.get("tags") or []
        what = row["summary"]
        return (
            what[:90],
            f"{what}\n\n  Path     {d.get('path') or d.get('task') or '-'}\n"
            f"  Start    {d.get('start') or '-'}\n  SHA-256  {d.get('sha256') or 'not hashed'}\n"
            + (f"  Flags    {', '.join(tags)}\n" if tags else "") +
            "\nWHY THIS MATTERS: a service runs as SYSTEM at boot; a scheduled task or new account "
            "survives a reboot and a password change. These are the persistence mechanisms an "
            "intruder installs once and relies on.\n\n"
            "BENIGN EXPLANATION: a driver update, a VPN client, a game controller, an app you just "
            "installed (Claude, Tailscale, Intel graphics all install services).\n\n"
            "MALICIOUS EXPLANATION: the path is under AppData, Temp, ProgramData or Public, the "
            "binary is a script host, the name mimics a Windows component, or you installed nothing "
            "at that time.\n\n"
            "NEXT STEP: `Get-Service -Name '<name>' | Format-List *` and look up the SHA-256 by hand "
            "before deciding. Do not run the binary. If it is not yours: `sc.exe stop <name>`, "
            "`sc.exe delete <name>`, then hand the file to the sandbox (docs/PENTEST_LAB.md)."
        )


class AutorunChangeDetection(_HostEventRule):
    rule_id = "autorun_changed"
    name = "Autorun entry added or changed"
    severity = "medium"
    kind = "autorun_added"
    mitre_id = "T1547.001"
    mitre_name = "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder"
    requires = "Run/RunOnce registry keys and both Startup folders, diffed each run"
    blind_spots = (
        "Only Run/RunOnce and Startup folders. Services, scheduled tasks, WMI subscriptions, COM "
        "hijacks and shell extensions are other autostart locations this rule does not read "
        "(Sysinternals Autoruns covers ~40 of them). A change between two runs that is reverted "
        "before the next run is invisible."
    )

    def describe(self, row, d):
        return (
            row["summary"][:90],
            f"{row['summary']}\n\n  Where    {d.get('where') or '-'}\n  Command  {d.get('command') or '-'}\n"
            f"  Signed   {d.get('signed')}\n  SHA-256  {d.get('sha256') or 'not hashed'}\n"
            + (f"  Was      {d.get('previous') or d.get('previous_sha256')}\n" if d.get('previous') or d.get('previous_sha256') else "") +
            "\nWHY THIS MATTERS: a Run key is the cheapest persistence on Windows -- one registry "
            "value and the program starts at every logon. A changed binary at the same path is the "
            "quieter version of the same thing.\n\n"
            "BENIGN EXPLANATION: an app you installed added itself to startup; an update replaced "
            "its binary (hash change with a valid signature).\n\n"
            "MALICIOUS EXPLANATION: the command launches powershell/wscript/mshta/rundll32, has "
            "-enc or -w hidden flags, or points into AppData/Temp/Public.\n\n"
            "NEXT STEP: Task Manager > Startup apps to see and disable it; `Get-AuthenticodeSignature "
            "'<exe>'` to check the signer; look up the hash by hand. If unrecognised, remove the "
            "value and quarantine the file for the sandbox."
        )


class SoftwareInstalledDetection(_HostEventRule):
    rule_id = "software_flagged"
    name = "Software of a notable class installed"
    severity = "medium"
    kind = "software_installed"
    mitre_id = "T1219"
    mitre_name = "Remote Access Software"
    requires = "Uninstall registry keys (HKLM, WOW6432Node, HKCU), diffed each run"
    blind_spots = (
        "Only software that registers an uninstall entry. Portable executables, MSIX/Store apps "
        "that skip the Uninstall key, and anything run from a USB stick or Downloads are not "
        "inventory. Classification is by name/publisher/location class, not by signature, so a "
        "renamed tool passes and a legitimate tool named like one is flagged."
    )

    def describe(self, row, d):
        tags = ", ".join(d.get("tags") or [])
        return (
            f"Installed: {d.get('name') or '?'} [{tags}]",
            f"{row['summary']}\n\n  Publisher  {d.get('publisher') or 'none'}\n"
            f"  Location   {d.get('location') or '-'}\n  Class      {tags}\n\n"
            "WHY THIS MATTERS: remote-access tools give whoever holds the account a desktop on "
            "this machine; activation/crack tooling is the single most common carrier of stealers "
            "on home PCs (and this host has history there); tunnels expose it to the internet from "
            "inside the LAN; security tooling in the wrong hands is reconnaissance.\n\n"
            "BENIGN EXPLANATION: you installed it (Nmap, Npcap and ngrok on this host are yours).\n\n"
            "MALICIOUS EXPLANATION: you did not, or it appeared alongside a scam call, a cracked "
            "installer, or a browser 'update'.\n\n"
            "NEXT STEP: if yours, acknowledge this alert -- it will not repeat for this entry. If "
            "not, uninstall it, change passwords from another device, and review the autoruns and "
            "services alerts from the same day."
        )


class HiddenDirectoryDetection(_HostEventRule):
    rule_id = "hidden_dir_created"
    name = "Hidden directory created"
    severity = "low"
    kind = "hidden_dir_created"
    mitre_id = "T1564.001"
    mitre_name = "Hide Artifacts: Hidden Files and Directories"
    requires = "directory listing (depth 1) under profile, AppData, ProgramData, Temp, Public and the drive root"
    blind_spots = (
        "Depth 1 under a fixed set of roots, hidden attribute only. A hidden directory deeper in "
        "the tree, on another drive, or an alternate data stream is not seen. Many vendors create "
        "hidden directories legitimately (Intel, Office, package managers); the well-known ones "
        "are skipped, the rest are shown for you to judge."
    )

    def describe(self, row, d):
        return (
            f"Hidden directory: {(d.get('path') or '')[-70:]}",
            f"{row['summary']}\n\n  Attributes  {d.get('attributes') or '-'}\n\n"
            "WHY THIS MATTERS: staging areas for stolen data, dropped tools and persistence are "
            "usually hidden directories in user-writable paths.\n\n"
            "BENIGN EXPLANATION: an installer or driver created it (Intel, Office, Windows "
            "components), or a developer tool's cache.\n\n"
            "MALICIOUS EXPLANATION: it is under AppData/Temp/Public with the System attribute "
            "as well, contains executables or archives, or was created at a time nothing was "
            "installed.\n\n"
            "NEXT STEP: `Get-ChildItem -Force '<path>'` to see what is inside; do not open "
            "executables from it. If it holds tools or archives you do not recognise, quarantine "
            "the directory for the sandbox."
        )


class LogClearedDetection(_HostEventRule):
    rule_id = "log_cleared"
    name = "Event log cleared"
    severity = "high"
    kind = "log_cleared"
    mitre_id = "T1070.001"
    mitre_name = "Indicator Removal: Clear Windows Event Logs"
    requires = "System event 104 (readable); Security 1102 only when elevated"
    blind_spots = "Clearing the log that records the clearing is the attacker's last step, not the first; the earlier events are gone."

    def describe(self, row, d):
        return (
            "An event log was cleared",
            f"{row['summary']}\n\n"
            "WHY THIS MATTERS: nobody clears an event log by accident. This is either an admin "
            "tidying up or an intruder removing evidence, and on a single-owner machine you know "
            "which.\n\n"
            "BENIGN EXPLANATION: you cleared it (Event Viewer > Clear Log) or a disk-cleanup tool did.\n\n"
            "MALICIOUS EXPLANATION: you did not.\n\n"
            "NEXT STEP: treat the host as compromised until explained; check the autoruns, "
            "services and software alerts from the same day, and change passwords from another device."
        )


class NotableConnectionDetection(_HostEventRule):
    rule_id = "notable_connection"
    name = "Notable outbound connection"
    severity = "low"
    kind = "connection"
    mitre_id = "T1571"
    mitre_name = "Non-Standard Port"
    requires = "Get-NetTCPConnection sampled each run (established connections only)"
    blind_spots = (
        "A sample every few minutes, not a flow log: a connection that opens and closes between "
        "samples is missed, UDP is not seen, and there is no byte count per connection. Tor is "
        "recognised by its default ports and process name only -- a bridge on 443 looks like "
        "HTTPS. Sysmon event 3 or a firewall log would close these gaps; neither is present."
    )

    def describe(self, row, d):
        tags = ", ".join(d.get("tags") or [])
        return (
            f"{d.get('process') or 'process'} -> {d.get('raddr')}:{d.get('rport')} [{tags}]",
            f"{row['summary']}\n\n  Process  {d.get('process') or '-'} (pid {d.get('pid')})\n"
            f"  Path     {d.get('path') or '-'}\n  Remote   {d.get('raddr')}:{d.get('rport')}\n\n"
            "WHY THIS MATTERS: a script host (powershell, wscript, mshta, rundll32...) with an "
            "internet connection is a download cradle or a beacon; Tor-shaped ports are how "
            "ransomware and stealers reach their operators; an uncommon port from a binary under "
            "AppData is the shape of a commodity RAT.\n\n"
            "BENIGN EXPLANATION: a game, a VPN, a chat app, a developer tool, or your own Tor "
            "Browser. Look at the process path.\n\n"
            "MALICIOUS EXPLANATION: the process is a script host, the path is under Temp/Public, "
            "or the remote address is one you cannot account for.\n\n"
            "NEXT STEP: `Get-Process -Id <pid> | Format-List Path,StartTime,Company` and "
            "`Get-NetTCPConnection -OwningProcess <pid>`; look up the remote address by hand. If "
            "unrecognised, kill the process and quarantine its binary."
        )


class ArpSweepDetection(Detection):
    """Many devices answered ARP to one MAC in a short window, and it was not us."""

    rule_id = "arp_sweep_seen"
    name = "Network scan seen (ARP sweep)"
    severity = "medium"
    mitre_id = "T1046"
    mitre_name = "Network Service Discovery"
    requires = "passive ARP capture (FULL mode): the hwdst of unsolicited replies"
    blind_spots = (
        "Only sweeps that provoke ARP replies the sensor can see -- a scan of the sensor's own "
        "subnet from inside it. A port scan of one host, a scan from another VLAN, or a scanner "
        "that already has the ARP cache populated does not show. PNMA's own sweeps are attributed "
        "and excluded, and so are replies to the sensor host's own MACs and to the gateway -- "
        "both ask the LAN who is who as a matter of course, so a scan run FROM this machine by "
        "someone else is not seen by this rule."
    )
    WINDOW_S = 180
    MIN_TARGETS = 8   # a home LAN has 10-20 devices; a sweep touches most of them

    def evaluate(self, ctx: DetectionContext) -> list[Finding]:
        rows = ctx.db.query(
            "SELECT ts, mac, ip, detail FROM observations WHERE source = 'passive_arp' "
            "AND agent_generated = 0 AND ts >= ? ORDER BY ts", (ctx.now - 2 * 3600,))
        # The sensor's own MACs (written by the daemon at start) and the
        # gateway: both ask the whole LAN who is who as a matter of course.
        own: set[str] = set()
        for key in ("own_macs",):
            m = ctx.db.query_one("SELECT value FROM meta WHERE key = ?", (key,))
            if m and m["value"]:
                try:
                    own.update(x.lower() for x in json.loads(m["value"]))
                except ValueError:
                    pass
        gw = ctx.db.query_one("SELECT value FROM meta WHERE key = 'gateway_mac'")
        if gw and gw["value"]:
            own.add(gw["value"].lower())
        by_dst: dict[str, list[tuple[float, str, str]]] = {}
        for r in rows:
            try:
                d = json.loads(r["detail"] or "{}")
            except ValueError:
                d = {}
            dst = (d.get("hwdst") or "").lower()
            if not dst or dst in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or dst in own:
                continue
            by_dst.setdefault(dst, []).append((r["ts"], r["ip"], r["mac"]))
        out = []
        for dst, hits in by_dst.items():
            hits.sort()
            i = 0
            best: list[tuple[float, str, str]] = []
            for j in range(len(hits)):
                while hits[j][0] - hits[i][0] > self.WINDOW_S:
                    i += 1
                window = hits[i:j + 1]
                if len({ip for _, ip, _ in window}) > len({ip for _, ip, _ in best}):
                    best = window
            if best:
                window = best
                targets = {ip for _, ip, _ in window}
                if len(targets) >= self.MIN_TARGETS:
                    dev = ctx.db.query_one("SELECT device_id, label, hostname, vendor FROM devices WHERE lower(mac) = ?", (dst,))
                    who = (dev["label"] or dev["hostname"] or dev["vendor"] or dst) if dev else dst
                    start = window[0][0]
                    out.append(Finding(
                        dedup_key=f"arp_sweep:{dst}:{int(start // 600)}",
                        severity=self.severity,
                        title=f"{who} swept the network: {len(targets)} devices answered it in {int(window[-1][0] - start) or 1}s",
                        description=(
                            f"{len(targets)} different devices sent ARP replies to {dst} within "
                            f"{self.WINDOW_S}s, starting {time.strftime('%H:%M:%S', time.localtime(start))}. "
                            "That is the footprint of a host discovery sweep (nmap -sn, an IP scanner app, "
                            "or a worm looking for neighbours).\n\n"
                            "WHY THIS MATTERS: reconnaissance is the first thing anything new on a network does, "
                            "human or malware. Knowing which device did it is most of the answer.\n\n"
                            "BENIGN EXPLANATION: you ran a scan from another device, a phone app like Fing, a "
                            "smart-home hub discovering devices, or a printer driver install.\n\n"
                            "MALICIOUS EXPLANATION: the scanning device is one you do not recognise, or a "
                            "device that has no business enumerating the LAN (a TV, a bulb, a camera).\n\n"
                            "NEXT STEP: open the device from the Network tab; check what else it did around "
                            "that time in the Investigation log. If it is not yours, untrust it and block it "
                            "at the router."
                        ),
                        device_id=dev["device_id"] if dev else None,
                        evidence={"scanner_mac": dst, "targets": sorted(targets)[:50],
                                  "count": len(targets), "window_s": self.WINDOW_S, "start": start},
                        triggers_triage_scan=True,
                    ))
        return out


class UploadSpikeDetection(Detection):
    """Bytes sent on an adapter in the last window far above the host's own recent norm."""

    rule_id = "upload_spike"
    name = "Unusual upload volume from this host"
    severity = "medium"
    mitre_id = "T1041"
    mitre_name = "Exfiltration Over C2 Channel"
    requires = "Get-NetAdapterStatistics sampled each run (bytes sent per adapter)"
    blind_spots = (
        "Host-only: PNMA cannot see other devices' traffic volume (the router exposes no counters). "
        "Per-adapter totals, not per-process -- a cloud backup, a video call, a game upload and an "
        "exfiltration all look the same here; the value is the anomaly, not the attribution. Needs "
        "six hours of samples before it can judge."
    )
    WINDOW_S = 600
    BASELINE_S = 6 * 3600
    MIN_BYTES = 500 * 1024 * 1024
    RATIO = 5.0

    def evaluate(self, ctx: DetectionContext) -> list[Finding]:
        out = []
        adapters = [r["adapter"] for r in ctx.db.query("SELECT DISTINCT adapter FROM host_counters")]
        for name in adapters:
            rows = ctx.db.query("SELECT ts, bytes_sent FROM host_counters WHERE adapter = ? AND ts >= ? ORDER BY ts",
                                (name, ctx.now - self.BASELINE_S))
            if len(rows) < 8:
                continue
            # per-interval deltas (counter resets -> skip negative)
            deltas = []
            for a, b in zip(rows, rows[1:]):
                dt = b["ts"] - a["ts"]
                db_ = b["bytes_sent"] - a["bytes_sent"]
                if dt > 0 and db_ >= 0:
                    deltas.append((b["ts"], db_ / dt))
            if len(deltas) < 6:
                continue
            recent = [rate for ts, rate in deltas if ts >= ctx.now - self.WINDOW_S]
            older = [rate for ts, rate in deltas if ts < ctx.now - self.WINDOW_S]
            if not recent or len(older) < 4:
                continue
            recent_rate = max(recent)
            base = statistics.median(older) or 1.0
            recent_bytes = recent_rate * self.WINDOW_S
            if recent_bytes >= self.MIN_BYTES and recent_rate >= self.RATIO * base:
                out.append(Finding(
                    dedup_key=f"upload_spike:{name}:{int(ctx.now // 3600)}",
                    severity=self.severity,
                    title=f"{name}: ~{recent_bytes / 1e6:.0f} MB uploaded in 10 min, {recent_rate / base:.0f}x the 6h norm",
                    description=(
                        f"Adapter {name} sent at ~{recent_rate / 1e6:.1f} MB/s over the last "
                        f"{self.WINDOW_S // 60} minutes against a median of {base / 1e6:.2f} MB/s over "
                        "the previous six hours.\n\n"
                        "WHY THIS MATTERS: data leaves a compromised machine in bulk, usually once. "
                        "A spike this size against this host's own norm is worth thirty seconds of "
                        "your attention.\n\n"
                        "BENIGN EXPLANATION: a cloud backup, a large upload you started, a video call, "
                        "a game or OS sync, or a torrent.\n\n"
                        "MALICIOUS EXPLANATION: you were not uploading anything, and the Notable "
                        "connection alerts show a process you do not recognise.\n\n"
                        "NEXT STEP: Task Manager > Performance > network, or `Get-NetTCPConnection "
                        "-State Established` to see who is talking; if nothing accounts for it, "
                        "disconnect from the network and investigate the process list."
                    ),
                    evidence={"adapter": name, "recent_rate_bps": recent_rate, "baseline_bps": base,
                              "window_s": self.WINDOW_S, "samples": len(deltas)},
                ))
        return out


class RogueRootCertDetection(_HostEventRule):
    rule_id = "rogue_root_certificate"
    name = "New trusted root certificate"
    severity = "medium"
    kind = "root_cert_added"
    mitre_id = "T1553.004"
    mitre_name = "Subvert Trust Controls: Install Root Certificate"
    requires = "the machine and user Trusted Root stores (Cert:\\LocalMachine\\Root, Cert:\\CurrentUser\\Root); read unelevated, diffed against the host's own baseline"
    blind_spots = (
        "Snapshot-diff of the Root stores, so it sees an added root on the next collector pass, "
        "not the instant it lands. It cannot tell a corporate or antivirus root (benign) from a "
        "malicious one by itself -- it shows the subject and issuer so you can. The first run "
        "establishes the baseline silently; only roots added after that are reported."
    )

    def describe(self, row, d):
        return (
            "New trusted root certificate installed",
            f"{row['summary']}\n\n"
            f"  Subject   {d.get('subject') or '-'}\n"
            f"  Issuer    {d.get('issuer') or '-'}\n"
            f"  Store     {d.get('store') or '-'}\n"
            f"  Thumbprint {d.get('thumbprint') or '-'}\n\n"
            "WHY THIS MATTERS: a trusted root CA can vouch for ANY site. Installing one is how "
            "traffic interception (a proxy, a MitM) gets your machine to trust a certificate it "
            "should not -- the whole padlock model turns on this store staying honest.\n\n"
            "BENIGN EXPLANATION: your employer's device management, an antivirus that inspects "
            "HTTPS, or a developer tool (a local proxy like Fiddler/mitmproxy) that you set up "
            "added it.\n\n"
            "MALICIOUS EXPLANATION: you did not install anything that would add a root, or the "
            "subject/issuer is a name you cannot place.\n\n"
            "NEXT STEP: find it with `Get-ChildItem Cert:\\LocalMachine\\Root, Cert:\\CurrentUser\\Root | "
            "Where-Object Thumbprint -eq '<thumb>'`. If you cannot explain it, remove it "
            "(certlm.msc / certmgr.msc) and treat any HTTPS you did since as observed."
        )


class HostsFileTamperDetection(_HostEventRule):
    rule_id = "hosts_file_tampered"
    name = "Hosts file redirect added"
    severity = "medium"
    kind = "hosts_file_changed"
    mitre_id = "T1565.001"
    mitre_name = "Data Manipulation: Stored Data Manipulation"
    requires = "C:\\Windows\\System32\\drivers\\etc\\hosts (world-readable), diffed against the host's own baseline of non-comment, non-localhost lines"
    blind_spots = (
        "Compares non-comment lines to the last snapshot, localhost entries ignored. It sees that "
        "a redirect was added, not who added it. The first run is the baseline; a redirect already "
        "present then is recorded as posture, not alerted -- so a pre-existing tamper is shown on "
        "the Host tab rather than as a new event."
    )

    def describe(self, row, d):
        return (
            "A redirect was added to the hosts file",
            f"{row['summary']}\n\n  Entry  {d.get('entry') or '-'}\n\n"
            "WHY THIS MATTERS: the hosts file overrides DNS, silently. One line can send your "
            "bank's domain to an attacker's server, or point a security/update domain at nowhere "
            "so protection stops reaching home -- with no certificate warning if a rogue root is "
            "also in play.\n\n"
            "BENIGN EXPLANATION: you (or a developer tool, or an ad-blocker's hosts list) added it "
            "on purpose.\n\n"
            "MALICIOUS EXPLANATION: you did not edit this file, and the name it maps is one you "
            "actually use, or the address is not one you recognise.\n\n"
            "NEXT STEP: open the file (`notepad C:\\Windows\\System32\\drivers\\etc\\hosts`, as "
            "admin). Remove any line you did not add; a legitimate one is rare on a home machine."
        )


class NewListeningProcessDetection(_HostEventRule):
    rule_id = "new_listening_process"
    name = "New listening process"
    severity = "low"
    kind = "listening_process"
    mitre_id = "T1571"
    mitre_name = "Non-Standard Port"
    requires = "Get-NetTCPConnection (Listen) plus the owning process, unelevated; diffed against the host's own baseline of (process, port), loopback-only listeners excluded"
    blind_spots = (
        "Sampled each pass, so a listener that opens and closes between passes is missed, and it "
        "is this host only. Loopback-only listeners (127.0.0.1/::1) are excluded as not reachable. "
        "It names the process behind the port, which a network scan cannot -- but a legitimate dev "
        "server or game host also opens a new listener, so it is scored high only when the process "
        "is a script host or lives in a user-writable path, low otherwise."
    )

    def describe(self, row, d):
        risky = d.get("script_host_or_userpath")
        return (
            f"New listener: {d.get('name') or '?'} on port {d.get('port')}",
            f"{row['summary']}\n\n"
            f"  Process  {d.get('name') or '?'}\n"
            f"  Path     {d.get('path') or '-'}\n"
            f"  Listen   {d.get('laddr') or '-'}:{d.get('port')}\n\n"
            "WHY THIS MATTERS: a process listening for INBOUND connections is offering a way in. "
            "A backdoor, a remote-access tool, or a reverse shell's handler all show up here as a "
            "new listener that was not there before.\n\n"
            "BENIGN EXPLANATION: you started a dev server, a game host, a media/file share, or a "
            "remote-desktop/sync tool.\n\n"
            + ("MALICIOUS EXPLANATION: the listener is a script host (PowerShell, wscript, mshta) "
               "or a binary in AppData/Temp/Downloads -- almost nothing legitimate listens from "
               "there.\n\n" if risky else
               "MALICIOUS EXPLANATION: the process is one you cannot place, or the port is one you "
               "did not mean to open to the network.\n\n") +
            "NEXT STEP: `Get-Process -Id " + str(d.get("pid") or "<pid>") + "` and check its path and "
            "signature. If it is unfamiliar, stop it and quarantine the binary; close the port at "
            "the Windows Firewall."
        )


class PowerShellDowngradeDetection(_HostEventRule):
    rule_id = "powershell_downgrade"
    name = "PowerShell engine downgrade"
    severity = "high"
    kind = "powershell_downgrade"
    mitre_id = "T1059.001"
    mitre_name = "Command and Scripting Interpreter: PowerShell"
    requires = "the classic 'Windows PowerShell' event log, event 400 (EngineVersion); readable unelevated"
    blind_spots = (
        "Reads the EngineVersion reported by event 400. It catches the v2 engine being started, "
        "which is the point -- it does not see what the downgraded session then did (that would "
        "need the very logging the downgrade defeats). On Windows 11 nothing legitimate starts a "
        "sub-v5 engine, so this is nearly false-positive-free."
    )

    def describe(self, row, d):
        return (
            f"PowerShell downgraded to v{d.get('engine_version') or '?'}",
            f"{row['summary']}\n\n  Engine version  {d.get('engine_version') or '?'}\n\n"
            "WHY THIS MATTERS: PowerShell v5+ logs script blocks and screens them through AMSI. "
            "Starting the old v2 engine (`powershell -Version 2`) turns both OFF -- it is a "
            "deliberate move to run hidden, and there is almost no honest reason to do it on a "
            "modern machine.\n\n"
            "BENIGN EXPLANATION: a rare legacy installer or a developer explicitly testing on the "
            "v2 engine. If .NET 2.0/3.5 is not even installed, the engine cannot start and this "
            "will not fire.\n\n"
            "MALICIOUS EXPLANATION: you did not ask for an old PowerShell -- something chose the "
            "version that is not watched.\n\n"
            "NEXT STEP: treat the session as unlogged and the host as suspect. Check the 4688 "
            "process events and the autoruns/services from the same minute; the parent process "
            "that launched it is the thread to pull."
        )


class FirewallRuleAddedDetection(_HostEventRule):
    rule_id = "firewall_rule_added"
    name = "New inbound firewall allow rule"
    severity = "medium"
    kind = "firewall_rule_added"
    mitre_id = "T1562.004"
    mitre_name = "Impair Defenses: Disable or Modify System Firewall"
    requires = "Get-NetFirewallRule (enabled, inbound, Allow), unelevated; diffed against the host's own baseline"
    blind_spots = (
        "Snapshot-diff of enabled inbound ALLOW rules, so it sees a new hole on the next pass, not "
        "the instant it opens; a rule added and removed between passes is missed. It reports that a "
        "rule was added, not what program requested it. Installers legitimately add rules, so the "
        "displayed name/group is what tells an app you installed from a hole you did not open."
    )

    def describe(self, row, d):
        return (
            "A new inbound firewall allow rule was added",
            f"{row['summary']}\n\n"
            f"  Rule    {d.get('display') or d.get('name') or '-'}\n"
            f"  Group   {d.get('group') or '-'}\n\n"
            "WHY THIS MATTERS: an inbound allow rule is an opening in the wall -- it lets outside "
            "connections reach a program on this machine. Malware that wants to be reachable (a "
            "backdoor, a remote-access tool) opens one for itself.\n\n"
            "BENIGN EXPLANATION: you just installed software that accepts connections (a game, a "
            "media server, a dev tool, remote desktop) and allowed it through the firewall.\n\n"
            "MALICIOUS EXPLANATION: nothing you installed explains it, or the rule allows a broad "
            "range of ports or a program in a user-writable path.\n\n"
            "NEXT STEP: `Get-NetFirewallRule -DisplayName '<name>' | Get-NetFirewallApplicationFilter` "
            "shows which program it opens. If you cannot place it, disable the rule (wf.msc) and "
            "investigate that program."
        )


class InternalLateralConnectionDetection(_HostEventRule):
    rule_id = "internal_lateral_connection"
    name = "Internal connection on a lateral-movement port"
    severity = "low"
    kind = "lateral_connection"
    mitre_id = "T1021"
    mitre_name = "Remote Services"
    requires = "this host's own established TCP connections to a LAN peer on an admin port (SMB/RDP/WinRM/SSH); diffed against the host's own first-seen baseline"
    blind_spots = (
        "This host's own outbound connections only -- it sees this machine reaching another, not "
        "one LAN device talking to a third. First-seen per (process, peer, port): a connection you "
        "make routinely (a file server on SMB) alerts once, then is baselined. Loopback, link-local "
        "and the tailnet are excluded. It cannot see UDP or a session shorter than the sampling gap."
    )

    def describe(self, row, d):
        svc = d.get("service") or "an admin service"
        return (
            f"This computer connected to {d.get('raddr')}:{d.get('rport')} ({svc})",
            f"{row['summary']}\n\n"
            f"  From process  {d.get('process') or '?'}\n"
            f"  To            {d.get('raddr')}:{d.get('rport')} ({svc})\n\n"
            "WHY THIS MATTERS: moving from one machine to another over SMB, RDP, WinRM or SSH is how "
            "an intruder spreads across a network once they have a foothold. This host reaching a "
            "LAN peer on one of those ports for the first time is that shape.\n\n"
            "BENIGN EXPLANATION: you opened a file share on a NAS or another PC (SMB), remoted into "
            "a machine yourself (RDP/SSH), or a backup/management tool runs on a schedule.\n\n"
            "MALICIOUS EXPLANATION: you did not initiate it, the source process is a script host or "
            "an unfamiliar binary, or the peer is a device that should not be offering that service.\n\n"
            "NEXT STEP: match the peer against the Network tab. If it is your NAS/PC and you started "
            "this, trust it and it will not alert again. If not, isolate this host and the peer and "
            "investigate the process that made the connection."
        )


class DefenderThreatDetection(_HostEventRule):
    rule_id = "defender_threat"
    name = "Windows Defender detected a threat"
    severity = "high"
    kind = "defender_threat"
    mitre_id = "T1204"
    mitre_name = "User Execution"
    requires = "Microsoft-Windows-Windows Defender/Operational events 1116 (detected) and 1117 (action taken); readable unelevated"
    blind_spots = (
        "Surfaces Defender's own verdicts, so it only sees what Defender caught -- a threat Defender "
        "misses, or that ran while real-time protection was off (see the Defender posture facts), is "
        "not here. It reports the detection and the action Defender took; whether the action fully "
        "cleaned the machine is a separate question. This is a strong signal precisely because the "
        "false-positive rate of Defender's own engine is low."
    )

    def describe(self, row, d):
        threat = d.get("threat") or "a threat"
        action = d.get("action") or "detected"
        return (
            f"Defender flagged {threat}",
            f"{row['summary']}\n\n"
            f"  Threat   {threat}\n"
            f"  Action   {action}\n"
            f"  Path     {d.get('path') or '-'}\n"
            f"  Severity {d.get('severity_name') or '-'}\n\n"
            "WHY THIS MATTERS: this is your own antivirus reporting real malware or a potentially "
            "unwanted program on this machine. Defender rarely cries wolf, so a verdict here is worth "
            "taking at face value.\n\n"
            "BENIGN EXPLANATION: a hacking tool or keygen you keep on purpose (Defender flags those "
            "as PUA), or a security sample you are studying in a folder Defender still scans.\n\n"
            "MALICIOUS EXPLANATION: you did not put anything there that would trip the AV -- something "
            "arrived on its own.\n\n"
            "NEXT STEP: open Windows Security > Protection history for the full entry. If the action "
            "was 'quarantined'/'removed' you are likely fine; if 'allowed' or 'blocked' only, act -- "
            "and check the autoruns, services and PowerShell alerts from the same time for what "
            "dropped it."
        )


class DnsServerChangedDetection(_HostEventRule):
    rule_id = "dns_server_changed"
    name = "DNS resolver changed"
    severity = "medium"
    kind = "dns_server_changed"
    mitre_id = "T1557"
    mitre_name = "Adversary-in-the-Middle"
    requires = "Get-DnsClientServerAddress per adapter, unelevated; diffed against the host's own baseline"
    blind_spots = (
        "Snapshot-diff per adapter, so it sees a changed resolver on the next pass. Joining a "
        "different network or a VPN legitimately changes DNS, so on a laptop that moves around this "
        "will speak up for those too -- the baseline re-settles once you are back. It sees which "
        "server is configured, not what it answered."
    )

    def describe(self, row, d):
        return (
            f"DNS resolver changed on {d.get('adapter') or 'an adapter'}",
            f"{row['summary']}\n\n"
            f"  Adapter   {d.get('adapter') or '-'}\n"
            f"  Now       {', '.join(d.get('servers') or []) or '-'}\n"
            f"  Was       {', '.join(d.get('previous') or []) or '-'}\n\n"
            "WHY THIS MATTERS: the DNS resolver turns every name your machine looks up into an "
            "address. Point it at an attacker's server and they can silently send your bank, your "
            "email, anything, to a machine they control -- often with no visible warning.\n\n"
            "BENIGN EXPLANATION: you joined a new network, turned on a VPN, or switched to a custom "
            "resolver (1.1.1.1, a Pi-hole) yourself.\n\n"
            "MALICIOUS EXPLANATION: you changed nothing, and the new server is an address you cannot "
            "place.\n\n"
            "NEXT STEP: `Get-DnsClientServerAddress` to confirm, and set it back to your router or a "
            "resolver you trust (Network settings > adapter > DNS). Pair this with the rogue-root and "
            "hosts-file findings -- together they are the interception toolkit."
        )


class LocalAdminGroupDiffDetection(_HostEventRule):
    rule_id = "local_admin_group_diff"
    name = "New local administrator"
    severity = "high"
    kind = "admin_group_changed"
    mitre_id = "T1098"
    mitre_name = "Account Manipulation"
    requires = "Get-LocalGroupMember on the Administrators group (SID S-1-5-32-544), unelevated; diffed against the host's own baseline"
    blind_spots = (
        "Reads the local Administrators group directly, so it works without elevation -- unlike the "
        "4732-based rule, which needs the elevated Security log. Snapshot-diff, so a member added and "
        "removed between passes is missed. It sees who is an administrator now, not who made them one "
        "(that is the 4732 event, elevated)."
    )

    def describe(self, row, d):
        return (
            f"New local administrator: {d.get('member') or '?'}",
            f"{row['summary']}\n\n  Member  {d.get('member') or '?'}\n\n"
            "WHY THIS MATTERS: local administrator is full control of this machine. Adding an account "
            "to that group is how an intruder makes their access permanent and total -- it is one of "
            "the most reliable signs of a real compromise.\n\n"
            "BENIGN EXPLANATION: you added a new user and made them an admin on purpose, or joined a "
            "management/domain setup that manages the group.\n\n"
            "MALICIOUS EXPLANATION: you did not add anyone, and the name is an account you do not "
            "recognise or did not expect to have admin.\n\n"
            "NEXT STEP: `Get-LocalGroupMember Administrators` to confirm. If it is not yours, remove "
            "it (`Remove-LocalGroupMember`), change your password from another device, and treat the "
            "host as compromised -- work the autoruns, services and logon alerts around the same time."
        )


class ScheduledTaskAddedDetection(_HostEventRule):
    rule_id = "scheduled_task_created"
    name = "New scheduled task"
    severity = "low"
    kind = "scheduled_task_added"
    mitre_id = "T1053.005"
    mitre_name = "Scheduled Task/Job: Scheduled Task"
    requires = "Get-ScheduledTask, unelevated; diffed against the host's own baseline (complements the elevated 4698 event)"
    blind_spots = (
        "Snapshot-diff, so it sees a task on the next pass, and a task added and removed between "
        "passes is missed. It reads every task including user-context ones the 4698 Security event "
        "can miss, but scores by the action's shape, not by signature -- a signed installer's task "
        "in a normal path is low, a script-host or user-writable-path action is high. Installers add "
        "tasks routinely, so a low here is usually just that."
    )

    def describe(self, row, d):
        risky = d.get("lolbin_or_userpath")
        return (
            f"New scheduled task: {d.get('path') or '?'}",
            f"{row['summary']}\n\n"
            f"  Task     {d.get('path') or '?'}\n"
            f"  Runs     {d.get('action') or '-'}\n"
            f"  Author   {d.get('author') or '-'}\n\n"
            "WHY THIS MATTERS: a scheduled task runs on a trigger -- at logon, on a timer -- which "
            "makes it a durable way for something to keep coming back after a reboot. Persistence "
            "lives here.\n\n"
            "BENIGN EXPLANATION: you installed software; most apps register update or maintenance "
            "tasks, and Windows itself adds many.\n\n"
            + ("MALICIOUS EXPLANATION: the task runs a script host (PowerShell, mshta, rundll32) or a "
               "binary in AppData/Temp/Public -- the hallmark of a task added to persist, not to "
               "maintain an app.\n\n" if risky else
               "MALICIOUS EXPLANATION: the task and its action are not something you can trace to an "
               "app you installed.\n\n") +
            "NEXT STEP: `Get-ScheduledTask -TaskPath '<path>' | Select-Object -ExpandProperty Actions`. "
            "If you cannot place it, disable it (`Disable-ScheduledTask`) and investigate the program "
            "it runs."
        )


class KernelDriverAddedDetection(_HostEventRule):
    rule_id = "new_kernel_driver"
    name = "New kernel driver"
    severity = "low"
    kind = "kernel_driver_added"
    mitre_id = "T1543.003"
    mitre_name = "Create or Modify System Process: Windows Service"
    requires = "Win32_SystemDriver, unelevated; diffed against the host's own baseline"
    blind_spots = (
        "Snapshot-diff of the loaded driver set. It flags a new driver and scores it by where it "
        "loads from -- high from an unusual path (the bring-your-own-vulnerable-driver shape), low "
        "from System32/DriverStore where Windows Update and normal peripherals put theirs. It does "
        "not verify the signature, so a signed-but-malicious or a legitimately-unsigned vendor "
        "driver both rest on the path heuristic and your own recognition."
    )

    def describe(self, row, d):
        odd = d.get("unusual_path")
        return (
            f"New kernel driver: {d.get('name') or '?'}",
            f"{row['summary']}\n\n"
            f"  Driver  {d.get('name') or '?'}\n"
            f"  Path    {d.get('path') or '-'}\n\n"
            "WHY THIS MATTERS: a kernel driver runs with the highest privilege on the machine. "
            "Attackers load one to hide (a rootkit) or bring a known-vulnerable driver along to "
            "abuse it (BYOVD) and switch off security from below.\n\n"
            "BENIGN EXPLANATION: Windows Update, a new peripheral, or software you installed (a VPN, "
            "a game anti-cheat, a virtualization tool) added it -- these are common and load from "
            "the normal system paths.\n\n"
            + ("MALICIOUS EXPLANATION: this driver loads from a path outside System32/DriverStore, "
               "which almost nothing legitimate does.\n\n" if odd else
               "MALICIOUS EXPLANATION: you installed nothing that would add a driver, and the name is "
               "not one you can tie to hardware or an app.\n\n") +
            "NEXT STEP: look the driver name up, and check its signature with "
            "`Get-AuthenticodeSignature '<path>'`. An unsigned or unknown driver from an odd path "
            "should be treated as hostile -- isolate the host and investigate."
        )


class CredentialDumpArtifactDetection(_HostEventRule):
    rule_id = "credential_dump_artifact"
    name = "Credential-dump artifact on disk"
    severity = "high"
    kind = "credential_hive_dump"
    mitre_id = "T1003.002"
    mitre_name = "OS Credential Dumping: Security Account Manager"
    requires = "filenames (never contents) under Temp/LocalAppData Temp/Windows Temp/Public/Downloads: sam/system/security hives and *lsass*.dmp"
    blind_spots = (
        "Matches filenames only, in a fixed set of throwaway directories -- it never opens a file, "
        "and a dump written elsewhere or renamed is missed. A hive named sam/system/security or an "
        "lsass .dmp in a temp folder is almost never legitimate, so the false-positive rate is very "
        "low; the one benign case is a crash dump of lsass, or a manual Task Manager dump."
    )

    def describe(self, row, d):
        return (
            f"{d.get('artifact') or 'Credential-dump artifact'} in a temp folder",
            f"{row['summary']}\n\n  File  {d.get('path') or '?'}\n\n"
            "WHY THIS MATTERS: this is the on-disk residue of credential theft. The SAM/SYSTEM/"
            "SECURITY registry hives hold local password hashes; an lsass dump holds the passwords "
            "and tokens of everyone logged in. Finding one in a temp folder means someone was "
            "harvesting credentials on this machine.\n\n"
            "BENIGN EXPLANATION: a real crash produced an lsass dump, or you dumped a process "
            "yourself for debugging. Hive files named sam/system/security in temp have essentially "
            "no benign explanation.\n\n"
            "MALICIOUS EXPLANATION: you did not create it -- treat every credential that could be on "
            "this machine as compromised.\n\n"
            "NEXT STEP: do NOT open the file. Capture it with `pnma quarantine '<path>'` for the "
            "record, then change the passwords of every account used on this machine from another "
            "device, and treat the host as compromised until you find how it got there."
        )


class ShadowCopyDeletionDetection(_HostEventRule):
    rule_id = "shadow_copy_deleted"
    name = "Volume shadow copies deleted (ransomware precursor)"
    severity = "high"
    kind = "shadow_copies_deleted"
    mitre_id = "T1490"
    mitre_name = "Inhibit System Recovery"
    requires = "Win32_ShadowCopy count, diffed against the host's own baseline (needs the collector elevated)"
    blind_spots = (
        "Watches the shadow-copy COUNT dropping from a non-empty set to zero -- it catches the "
        "wipe, not the deletion command, and it can only protect what exists: if System Protection "
        "is off there are no shadow copies to lose (and no rollback either). It does not watch files "
        "being encrypted -- that is Defender's job (surfaced by the defender_threat rule), and this "
        "fires earlier, at the moment the safety net is cut."
    )

    def describe(self, row, d):
        prev = d.get("previous_count")
        return (
            "All volume shadow copies were deleted",
            f"{row['summary']}\n\n"
            f"  Restore points before  {prev}\n"
            f"  Restore points now      0\n\n"
            "WHY THIS MATTERS: shadow copies are the restore points you would use to roll a machine "
            "back. Ransomware deletes them ALL right before it starts encrypting, precisely so you "
            "cannot recover without paying. A full wipe of the set is one of the most reliable "
            "early-warning signs of an active ransomware attack.\n\n"
            "BENIGN EXPLANATION: you ran Disk Cleanup, turned System Protection off, or deleted "
            "restore points by hand; a disk-space tool can also clear them under pressure.\n\n"
            "MALICIOUS EXPLANATION: you did none of those, especially if it coincides with unfamiliar "
            "processes, high disk activity, or files changing extension.\n\n"
            "NEXT STEP: if it was not you, act now -- DISCONNECT this machine from the network and "
            "power/storage to stop encryption in progress, then recover from an OFFLINE backup. Do "
            "not reboot repeatedly. Check the Defender, autoruns and PowerShell alerts from the same "
            "minute for what did it."
        )


class UsbStorageDetection(_HostEventRule):
    rule_id = "usb_storage_added"
    name = "New USB storage device"
    severity = "low"
    kind = "usb_storage_added"
    mitre_id = "T1091"
    mitre_name = "Replication Through Removable Media"
    requires = "the USBSTOR device enumeration (a durable record of USB mass-storage ever attached), diffed against the host's own baseline"
    blind_spots = (
        "USB MASS STORAGE only -- a phone or camera mounting as MTP/WPD is not here, nor is a "
        "malicious USB device pretending to be a keyboard (a 'rubber ducky'). It reads the durable "
        "enumeration, so a drive plugged in only briefly is still caught, but it reports that a "
        "device was attached, not what was copied to or from it."
    )

    def describe(self, row, d):
        return (
            f"New USB storage device: {(d.get('name') or d.get('model') or '?').replace('_', ' ')[:60]}",
            f"{row['summary']}\n\n"
            f"  Device  {(d.get('name') or '-').replace('_', ' ')}\n"
            f"  Model   {(d.get('model') or '-').replace('_', ' ')}\n\n"
            "WHY THIS MATTERS: removable media is how an infection crosses from another machine onto "
            "this one, and how data walks out of a house that has no other exfat path. Knowing which "
            "drives have touched this machine is basic hygiene.\n\n"
            "BENIGN EXPLANATION: you plugged in your own USB stick, an external drive, or a phone in "
            "file-transfer mode -- by far the common case.\n\n"
            "MALICIOUS EXPLANATION: a drive you do not recognise was connected, or one appeared while "
            "you were away from the machine.\n\n"
            "NEXT STEP: if it is yours, nothing to do -- mark this resolved. If not, scan it before "
            "opening anything (`Start-MpScan -ScanType CustomScan -ScanPath <drive>:`), and be wary "
            "of running anything from it."
        )


def host_event_rules() -> list[Detection]:
    return [
        SuspiciousPowerShellDetection(),
        NewServiceDetection(),
        AutorunChangeDetection(),
        SoftwareInstalledDetection(),
        HiddenDirectoryDetection(),
        LogClearedDetection(),
        NotableConnectionDetection(),
        ArpSweepDetection(),
        UploadSpikeDetection(),
        RogueRootCertDetection(),
        HostsFileTamperDetection(),
        NewListeningProcessDetection(),
        PowerShellDowngradeDetection(),
        FirewallRuleAddedDetection(),
        InternalLateralConnectionDetection(),
        DefenderThreatDetection(),
        DnsServerChangedDetection(),
        LocalAdminGroupDiffDetection(),
        ShadowCopyDeletionDetection(),
        ScheduledTaskAddedDetection(),
        KernelDriverAddedDetection(),
        CredentialDumpArtifactDetection(),
    ]
