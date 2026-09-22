"""PNMA command line.

Note what is deliberately absent: there is no ``--target``, ``--network`` or
``--range`` flag anywhere in this interface. The monitored network comes from
the config file and nowhere else. A scanner whose target can be set on the
command line is one shell-history recall away from being pointed at a network
you have no authorisation for, and "I typed the wrong flag" is not a defence
anyone has to accept. See :mod:`pnma.guard`.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .config import DEFAULT_CONFIG_PATH, Config, ConfigError


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s  %(levelname)-7s %(name)-28s %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger("scapy").setLevel(logging.ERROR)


def cmd_init(args) -> int:
    """Fingerprint the current network and write a config for it."""
    from .fingerprint import normalise_mac
    from .netutil import default_gateway, mac_for_ip, read_arp_table

    dest = Path(args.config)
    if dest.exists() and not args.force:
        print(f"{dest} already exists. Use --force to overwrite.")
        return 1

    gw = default_gateway()
    if not gw:
        print(
            "Could not determine the default gateway. Are you connected to a "
            "network? PNMA needs to know which network it is authorised for."
        )
        return 1

    gw_mac = mac_for_ip(gw)
    if not gw_mac:
        print(
            f"Gateway {gw} is not in the ARP cache yet.\n"
            f"Run:  ping {gw}\n"
            "then try again -- PNMA fingerprints the gateway MAC so it can "
            "tell your network apart from any other network using the same "
            "address range."
        )
        return 1

    octets = gw.split(".")
    cidr = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"

    # Virtualisation host-only adapters otherwise fill the inventory with hosts
    # that are not on the monitored network at all.
    excludes = sorted(
        {
            f"{'.'.join(e.ip.split('.')[:3])}.0/24"
            for e in read_arp_table()
            if e.mac.startswith(("00:50:56", "00:0c:29", "08:00:27", "00:15:5d"))
        }
    )

    template = Path(__file__).parent.parent / "config" / "pnma.example.toml"
    content = template.read_text(encoding="utf-8") if template.exists() else ""
    if content:
        import re

        content = re.sub(r'^cidr = ".*"', f'cidr = "{cidr}"', content, flags=re.M)
        content = re.sub(
            r'^gateway_ip = ".*"', f'gateway_ip = "{gw}"', content, flags=re.M
        )
        content = re.sub(
            r'^gateway_mac = ".*"',
            f'gateway_mac = "{normalise_mac(gw_mac)}"',
            content,
            flags=re.M,
        )
        content = re.sub(
            r"^exclude_cidrs = \[.*\]",
            f"exclude_cidrs = {json.dumps(excludes)}",
            content,
            flags=re.M,
        )
    else:
        content = (
            f'database = "data/pnma.db"\n\n[network]\ncidr = "{cidr}"\n'
            f'gateway_ip = "{gw}"\ngateway_mac = "{normalise_mac(gw_mac)}"\n'
            f"exclude_cidrs = {json.dumps(excludes)}\nexclude_ips = []\n"
        )

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content, encoding="utf-8")

    print(f"Wrote {dest}\n")
    print(f"  Network        {cidr}")
    print(f"  Gateway        {gw}")
    print(f"  Gateway MAC    {normalise_mac(gw_mac)}")
    if excludes:
        print(f"  Excluded       {', '.join(excludes)}  (virtualisation adapters)")
    print(
        "\nThis file is gitignored. It identifies your network, and a gateway "
        "MAC is enough to locate your home via public wardriving databases -- "
        "so do not commit it or put it in a screenshot.\n"
    )
    print("Next:  pnma check   then   pnma collect")
    return 0


def cmd_check(args) -> int:
    """Verify configuration, authorisation and capability without scanning."""
    from .collectors.passive import capture_available, is_elevated
    from .collectors.portscan import PortScanCollector
    from .db import Database
    from .guard import ScopeGuard

    cfg = Config.load(args.config)
    print("PNMA preflight\n" + "=" * 58)
    print(f"  config          {args.config}")
    print(f"  database        {cfg.database}")
    print(f"  authorised net  {cfg.network.cidr}")
    print(f"  gateway         {cfg.network.gateway_ip} / {cfg.network.gateway_mac}")
    print(f"  API bind        {cfg.api.bind}:{cfg.api.port}")
    print(f"  scan timing     -T{cfg.scan.timing} (top {cfg.scan.top_ports} ports)")
    print(f"  retention       {cfg.retention_days} days")

    print("\nScope guard")
    guard = ScopeGuard(cfg)
    verdict = guard.check_network()
    print(f"  {'ALLOWED' if verdict.allowed else 'DENIED'}: {verdict.reason}")

    print("\nCapability")
    elevated = is_elevated()
    print(f"  elevated        {'yes' if elevated else 'no'}")
    ok, reason = capture_available()
    print(f"  passive capture {'available' if ok else 'unavailable'} -- {reason}")
    db = Database(cfg.database)
    scanner = PortScanCollector(db, guard, "preflight")
    print(f"  nmap            {'found' if scanner.available() else 'NOT FOUND'}")

    # Reported here because a fresh clone ships only the built-in table, and
    # nothing else tells the reader that a 40,000-entry one is a command away.
    # Vendor feeds device classification, so "77 entries" and "39,939 entries"
    # are materially different tools.
    from . import oui as oui_mod

    if oui_mod._OUI_FILE.exists():
        with oui_mod._OUI_FILE.open(encoding="utf-8") as fh:
            entries = sum(1 for _ in fh)
        print(f"  oui table       {entries:,} entries (vendored IEEE registry)")
    else:
        print(
            f"  oui table       {len(oui_mod._BUILTIN)} built-in entries only "
            "-- run: pnma oui-update"
        )

    if not ok:
        print(
            "\n  PNMA will run in UNPRIVILEGED mode. Inventory, port scanning,\n"
            "  service drift, C2 indicators and availability all work. Device\n"
            "  identity across MAC randomisation and frame-level ARP spoof\n"
            "  detection do not."
        )
    db.close()
    return 0 if verdict.allowed else 2


def cmd_collect(args) -> int:
    from .daemon import Collector

    cfg = Config.load(args.config)
    return Collector(cfg).run()


def cmd_serve(args) -> int:
    from .api.app import serve

    cfg = Config.load(args.config)
    if args.database:
        # Changes which database is *read*. It cannot change which network may
        # be touched -- the API never transmits, and scope lives in the config.
        cfg.database = args.database
    from . import secrets as S

    token = S.get_secret("dashboard_token")
    print(f"Reading:   {cfg.database}")
    serve(cfg, bind=args.bind, token=token, no_token=args.no_token)
    return 0


def cmd_seed(args) -> int:
    from .db import Database
    from .seed import generate

    path = args.database or "data/pnma-demo.db"
    if Path(path).exists() and not args.force:
        print(f"{path} already exists. Use --force to regenerate.")
        return 1
    if Path(path).exists():
        Path(path).unlink()

    db = Database(path)
    stats = generate(db, days=args.days)

    # Classify the synthetic devices so the profile rules have something to
    # judge, exactly as they would after a real scan.
    from .inventory import reclassify

    gw = db.query_one("SELECT value FROM meta WHERE key = 'gateway_ip'")
    for row in db.query("SELECT device_id FROM devices"):
        reclassify(db, row["device_id"], gw["value"] if gw else None)

    from .detections.base import DetectionEngine
    from .detections.rules import default_rules

    # Every alert in the demo database is raised here, by the real engine, from
    # the evidence `generate()` wrote. `default_rules()` covers both halves, so
    # network and host findings meet the same correlation pass.
    #
    # The generator deliberately raises none of its own. It used to hand-write
    # six with `db.raise_alert`, which put rows in the demo that no rule had
    # evaluated -- and since `pnma seed` is the source of every screenshot, the
    # published figures showed a device carrying two alerts for one open port:
    # the duplicate-alert fatigue the correlation engine exists to eliminate.
    from .seed import resolve_one_alert

    DetectionEngine(db, default_rules()).run_all()
    resolved = resolve_one_alert(db)
    db.close()

    host = stats["host_facts"]
    print(f"Generated synthetic network in {path}")
    print(f"  {stats['devices']} devices on {stats['network']}")
    print(f"  {stats['availability_samples']:,} availability samples "
          f"over {args.days} days")
    print(f"  {host['total']} host posture facts "
          f"({host.get('ok', 0)} ok / {host.get('finding', 0)} finding / "
          f"{host.get('unknown', 0)} unknown, "
          f"{host['blocked_by_privilege']} blocked by privilege)")
    if resolved:
        print("  1 availability alert closed, so both alert states are shown")
    print(
        "\nThis data is entirely synthetic. Use it for screenshots and the\n"
        "write-up so no real MAC, hostname or SSID is ever published.\n"
    )
    print(f"View it:  pnma serve --database {path}")
    return 0


def cmd_identity(args) -> int:
    """Identity posture register. See pnma.identity for why it is attested."""
    from . import identity as I
    from .db import Database

    cfg = Config.load(args.config)
    db = Database(cfg.database)

    if args.action == "list":
        rep = I.report(db)
        s = rep["summary"]
        print(f"{s['accounts']} accounts, {s['controls']} controls: "
              f"{s['ok']} ok, {s['finding']} finding, {s['unknown']} unknown "
              f"({s['stale']} stale, {s['never']} never attested)")
        for acc in rep["accounts"]:
            print(f"\n  {acc['label']}  [{acc['account_id']}: {acc['provider']}/{acc['category']}]")
            for c in acc["controls"]:
                mark = {"ok": "ok     ", "finding": "FINDING", "unknown": "unknown"}[c["state"]]
                extra = c["reason"] or c["value"] or ""
                print(f"    {mark}  {c['title']:52} {extra}")
        if not rep["accounts"]:
            print("  none. Add one: pnma identity add gmail-main --provider google "
                  "--category email --label 'Main mailbox'")
        return 0

    if args.action == "add":
        try:
            I.add_account(db, args.account_id, provider=args.provider, category=args.category,
                          label=args.label, handle=args.handle, review_days=args.review_days)
        except ValueError as exc:
            print(f"error: {exc}")
            return 1
        print(f"added {args.account_id}; every control is 'unknown' until you attest it")
        return 0

    if args.action == "remove":
        print("removed" if I.remove_account(db, args.account_id) else "no such account")
        return 0

    if args.action == "attest":
        try:
            changed = I.attest(db, args.account_id, args.control, args.state,
                               value=args.value, reason=args.reason)
        except (KeyError, ValueError) as exc:
            print(f"error: {exc}")
            return 1
        print(f"{args.account_id}.{args.control} = {args.state}"
              + (" (changed)" if changed else " (re-attested, unchanged)"))
        return 0

    if args.action == "breaches":
        from . import secrets as S

        try:
            res = I.check_breaches(db, args.account_id, S.get_secret("hibp_api_key"))
        except KeyError as exc:
            print(f"error: {exc}")
            return 1
        print(res)
        return 0

    if args.action == "pwned":
        import getpass

        try:
            pw = getpass.getpass("Password to check (input hidden, never stored): ")
        except (EOFError, KeyboardInterrupt):
            print("\naborted")
            return 1
        n = I.pwned_password_count(pw)
        print(f"seen {n:,} times in known breaches" if n else "not in the pwned-passwords corpus")
        return 0 if not n else 2

    return 1


def cmd_secrets(args) -> int:
    """Manage API keys. Values are never printed back, only their status."""
    from . import secrets as S

    store, encrypted = S.backend()

    if args.action == "status":
        print(f"Credential store: {store}")
        if not encrypted:
            print(
                "  WARNING: no OS credential store on this platform. Secrets fall\n"
                "  back to environment variables, which are NOT encrypted at rest."
            )
        print()
        for s in S.status():
            mark = "set" if s["set"] else "-"
            enc = "encrypted" if s["encrypted_at_rest"] else (
                "PLAINTEXT (env)" if s["set"] else ""
            )
            print(f"  {s['name']:22} {mark:4} {s['source'] or '':18} {enc}")
            print(f"  {'':22} {s['description']}")
        return 0

    if not args.name:
        print("Which secret? Run: pnma secrets status")
        return 1

    if args.action == "delete":
        ok = S.delete_secret(args.name)
        print("deleted" if ok else "nothing to delete")
        return 0

    # `set` -- read from a prompt that does not echo, so the value never lands
    # in shell history or in a `ps` listing.
    import getpass

    try:
        value = getpass.getpass(f"Value for {args.name} (input hidden): ")
    except (EOFError, KeyboardInterrupt):
        print("\naborted")
        return 1

    try:
        ok, msg = S.set_secret(args.name, value)
    except (KeyError, ValueError) as exc:
        print(f"error: {exc}")
        return 1

    print(("stored: " if ok else "NOT stored: ") + msg)
    return 0 if ok else 1


def cmd_audit(args) -> int:
    from .audit import Auditor
    from .db import Database
    from .guard import ScopeGuard

    cfg = Config.load(args.config)
    db = Database(cfg.database)
    guard = ScopeGuard(cfg)
    guard.check_network()
    report = Auditor(db, guard).compliance_report(args.hours)

    if args.json:
        print(json.dumps(report, indent=2))
        db.close()
        return 0

    print(f"PNMA activity audit -- last {report['window_hours']}h\n" + "=" * 58)
    auth = report["authorisation"]
    print(f"  authorised range  {auth['authorised_cidr']}")
    print(f"  gateway pinned    {auth['gateway_pinned']}")
    print(f"  currently allowed {auth['currently_allowed']}")
    print(f"  {auth['reason']}")

    print("\nActivity")
    if not report["activity"]:
        print("  (none recorded)")
    for row in report["activity"]:
        print(
            f"  {row['kind']:<18} {row['n']:>5} runs   "
            f"ok={row['ok']:<5} refused={row['refused']:<5} failed={row['failed']}"
        )

    budget = report["noise_budget"]
    print(
        f"\nNoise budget        {budget['available']}/{budget['capacity']} "
        f"available, refills {budget['refill_per_minute']}/min"
    )
    print(
        f"  granted {budget['granted_total']}, denied {budget['denied_total']}"
    )

    print("\nSafety posture")
    for check in report["posture"]:
        mark = "PASS" if check["ok"] else "WARN"
        print(f"  [{mark}] {check['check']}")
        if not check["ok"]:
            print(f"         {check['detail']}")

    if report["refusals"]["recent"]:
        print("\nRefused operations")
        for r in report["refusals"]["recent"][:10]:
            print(f"  {r['kind']} -> {r['target']}: {r['error']}")

    db.close()
    return 0


def cmd_oui_update(args) -> int:
    """Refresh the vendored OUI table from the IEEE registry.

    Deliberately a command rather than something the agent does on its own: a
    vendor lookup that reaches the network turns every device discovery into an
    outbound request and fails on an isolated segment. `--from-file` exists for
    exactly that case -- fetch the registry on a machine that has internet, copy
    it across, import it here.
    """
    from . import oui as oui_mod

    if args.from_file:
        path = Path(args.from_file)
        if not path.exists():
            print(f"No such file: {path}")
            return 1
        print(f"Reading {path}")
        text = path.read_text(encoding="utf-8", errors="replace")
    else:
        url = args.url or oui_mod.IEEE_OUI_URL
        print(f"Fetching {url}")
        try:
            text = oui_mod.fetch_registry(url)
        except OSError as exc:
            print(f"Download failed: {exc}")
            print(
                "\nIf this machine has no internet access, fetch the registry\n"
                "elsewhere and import it:  pnma oui-update --from-file oui.csv"
            )
            return 1

    registry = oui_mod.parse_registry(text)
    if not registry:
        print("Parsed 0 usable entries -- refusing to replace the table.")
        return 1
    print(f"Parsed {len(registry):,} MA-L assignments")

    # Run before writing, so --check and a real update report identically and a
    # failed table swap cannot hide a contradiction.
    mismatches = oui_mod.check_builtins(registry)
    if mismatches:
        print(
            f"\n{len(mismatches)} built-in entr"
            + ("y" if len(mismatches) == 1 else "ies")
            + " the registry contradicts:"
        )
        for oui_key, ours, theirs in mismatches:
            print(f"  {oui_key}  built-in {ours!r}")
            print(f"             registry {theirs!r}" if theirs else
                  "             registry: not assigned")
        print(
            "\nThe vendored table takes precedence over these once written, so "
            "lookups\nare already correct. Correct `_BUILTIN` in pnma/oui.py "
            "too -- it is what\nships when no CSV is present. Intentional "
            "overrides belong in `_ALIASES`,\nwhich this check skips."
        )
    else:
        print("\nBuilt-in table agrees with the registry.")

    if args.check:
        print("\n--check: nothing written.")
        return 1 if mismatches else 0

    written = oui_mod.write_table(registry)
    print(f"\nWrote {written:,} entries to {oui_mod._OUI_FILE}")
    return 0


def cmd_report(args) -> int:
    """Write a monthly summary report (Markdown)."""
    import datetime as _dt
    from pathlib import Path

    from .db import Database
    from .daemon import VERSION
    from . import report as R

    cfg = Config.load(args.config)
    db = Database(cfg.database)
    if args.month:
        year, month = (int(x) for x in args.month.split("-"))
    else:
        today = _dt.date.today().replace(day=1) - _dt.timedelta(days=1)
        year, month = today.year, today.month
    rep = R.monthly_report(db, year, month, version=VERSION)
    md = R.render_markdown(rep)
    if args.out:
        out = Path(args.out)
    else:
        Path("reports").mkdir(exist_ok=True)
        out = Path("reports") / f"{R.BRAND.lower()}-{year:04d}-{month:02d}.md"
    out.write_text(md, encoding="utf-8")
    print(f"  wrote {out}")
    print(f"  {rep['alerts']['opened_total']} alerts opened, "
          f"{rep['alerts']['resolved_total']} resolved, "
          f"{rep['alerts']['still_open_total']} still open in {rep['period']['label']}")
    return 0


def cmd_evidence(args) -> int:
    """Gather a forensic evidence bundle for one alert or device."""
    from pathlib import Path

    from .db import Database
    from .daemon import VERSION
    from . import report as R

    cfg = Config.load(args.config)
    db = Database(cfg.database)
    out_dir = Path(args.out) if args.out else Path("evidence")
    try:
        result = R.evidence_bundle(
            db, out_dir=out_dir, alert_id=args.alert, device_id=args.device,
            version=VERSION, before_h=args.before, after_h=args.after)
    except ValueError as exc:
        print(f"  {exc}")
        return 2
    print(f"  bundle:  {result['dir']}")
    print(f"  zip:     {result['zip']}")
    print(f"  files:   {len(result['manifest']['artifacts']) + 3} "
          f"(each with a SHA-256 in MANIFEST.json)")
    print("  verify:  sha256sum -c SHA256SUMS   (inside the folder)")
    return 0


def cmd_detections(args) -> int:
    from .db import Database
    from .detections.base import DetectionEngine
    from .detections.rules import default_rules

    cfg = Config.load(args.config)
    db = Database(cfg.database)
    catalogue = DetectionEngine(db, default_rules()).catalogue()
    if args.json:
        print(json.dumps(catalogue, indent=2))
    else:
        print("PNMA detection rules\n" + "=" * 58)
        for rule in catalogue:
            mitre = (
                f"{rule['mitre_id']} ({rule['mitre_name']})"
                if rule["mitre_id"]
                else "-- not an ATT&CK technique"
            )
            print(f"\n  {rule['rule_id']}  [{rule['severity']}]")
            print(f"    {rule['name']}")
            print(f"    MITRE: {mitre}")
            if rule["blind_spots"]:
                print(f"    BLIND SPOTS: {rule['blind_spots']}")
    db.close()
    return 0


def cmd_vulns(args) -> int:
    import time as _time

    from . import vulns
    from .db import Database

    cfg = Config.load(args.config)
    if args.refresh:
        print("Refreshing from CISA KEV (outbound HTTPS)...")
        result = vulns.refresh_kev(cfg.database)
        if result.get("ok"):
            print(f"  {result['count']} CVEs in catalogue.")
        else:
            print(f"  refresh failed: {result.get('error')}. Using bundled catalogue.")
    vulns.annotate_with_kev(cfg.database)

    db = Database(cfg.database)
    now = _time.time()
    devices = []
    for row in db.query("SELECT * FROM devices"):
        d = dict(row)
        d["open_ports"] = [
            dict(p) for p in db.query(
                "SELECT port, proto, service, product, risk FROM ports "
                "WHERE device_id = ? AND closed_at IS NULL",
                (d["device_id"],),
            )
        ]
        devices.append(d)
    db.close()

    matches = vulns.match_devices(devices)
    if args.json:
        print(json.dumps([
            {
                "device_id": m["device"]["device_id"],
                "label": m["device"].get("label") or m["device"].get("hostname"),
                "advisories": [
                    {
                        "id": a.advisory_id, "title": a.title, "severity": a.severity,
                        "references": a.references, "kev_confirmed": a.kev_confirmed,
                    }
                    for a in m["advisories"]
                ],
            }
            for m in matches
        ], indent=2))
        return 0

    if not matches:
        print("No device matches a known-exploited-vulnerability advisory. "
              "That is not a clean bill of health -- see `pnma vulns --json` "
              "and the catalogue's stated limits.")
        return 0

    print("Known-exploited-vulnerability exposure\n" + "=" * 58)
    print("Matched on exposure class, not a version-exact CVE test. This says "
          "'this surface is exploited in the wild', not 'this firmware is "
          "vulnerable'. Confirmation is a lab exercise -- see PENTEST_LAB.md.\n")
    for m in matches:
        d = m["device"]
        name = d.get("label") or d.get("hostname") or d.get("ip") or d["device_id"]
        print(f"\n  {name}  ({d.get('ip') or 'no ip'})")
        for a in m["advisories"]:
            kev = "  [CISA-KEV: exploited in the wild]" if a.kev_confirmed else ""
            print(f"    [{a.severity}] {a.title}{kev}")
            print(f"        {a.remediation}")
            print(f"        refs: {', '.join(a.references)}")
    return 0


def cmd_honeypot(args) -> int:
    from .collectors.honeypot import HoneypotCollector
    from .db import Database

    cfg = Config.load(args.config)
    log_path = args.log or cfg.honeypot.cowrie_log_path
    if not log_path:
        print("No Cowrie log path. Pass --log <path> or set [honeypot].cowrie_log_path.")
        return 2
    db = Database(cfg.database)
    hp = HoneypotCollector(db, "hp-" + __import__("socket").gethostname()[:8], log_path)
    if not hp.available():
        print(f"Log not found: {log_path}")
        db.close()
        return 2
    summary = hp.run_once()
    db.close()
    if not summary.get("ok"):
        print(f"Ingest failed: {summary.get('reason')}")
        return 1
    print(f"Ingested {summary['sources']} source(s), {summary['logins']} login "
          f"attempt(s), {summary['commands']} command(s). See the Alerts tab.")
    return 0


def cmd_maillog(args) -> int:
    from .collectors.maillog import MailLogCollector, parse_log_body
    from .db import Database

    cfg = Config.load(args.config)
    if args.sample:
        # Parse a local file of router log lines and print what was recognised.
        with open(args.sample, encoding="utf-8", errors="replace") as fh:
            events = parse_log_body(fh.read())
        print(f"Recognised {len(events)} event(s):")
        for ev in events:
            print(f"  [{ev.severity}] {ev.kind}: {ev.title}"
                  + (f" ({ev.ip})" if ev.ip else ""))
        return 0

    ml = cfg.maillog
    if not (ml.imap_host and ml.imap_user):
        print("Configure [maillog] (imap_host, imap_user) and set the password:\n"
              "  pnma secrets set maillog_imap_password")
        return 2
    from . import secrets as _secrets
    pw = _secrets.get_secret("maillog_imap_password")
    if not pw:
        print("No maillog_imap_password secret set. Run: pnma secrets set maillog_imap_password")
        return 2
    db = Database(cfg.database)
    mc = MailLogCollector(db, "mail-cli", host=ml.imap_host, user=ml.imap_user,
                          password=pw, folder=ml.folder, from_filter=ml.from_filter,
                          port=ml.imap_port)
    r = mc.run_once(dry_run=args.dry_run)
    db.close()
    if not r.get("ok"):
        print(f"Ingest failed: {r.get('reason')}")
        return 1
    verb = "would raise" if args.dry_run else "raised"
    print(f"{r['messages']} message(s), {r['parsed']} event(s) parsed, {verb} "
          f"{r.get('raised', 0)} alert(s).")
    return 0


def cmd_quarantine(args) -> int:
    """Copy a suspect file into data/quarantine as a password-protected zip.

    The hand-off format for a sandbox: the file never runs here, the archive
    cannot be opened by accident (password "infected", the industry habit),
    and the SHA-256 is recorded next to it so the sample can be matched to
    the alert that pointed at it and looked up by hand. PNMA itself makes no
    reputation lookup -- that is egress, and it is your call, not the agent's.
    """
    import hashlib
    import shutil
    import subprocess
    import time
    from pathlib import Path

    src = Path(args.path)
    if not src.is_file():
        print(f"not a file: {src}")
        return 2
    h = hashlib.sha256()
    with open(src, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    digest = h.hexdigest()
    qdir = Path(args.database or "data").parent / "quarantine" if args.database else Path("data/quarantine")
    qdir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    archive = qdir / f"{stamp}-{digest[:12]}.zip"
    # 7-Zip encrypts; Python's zipfile cannot write passwords. Fall back to a
    # plain zip with a loud name so the operator knows it is NOT protected.
    seven = shutil.which("7z") or shutil.which("7za")
    protected = False
    if seven:
        r = subprocess.run([seven, "a", "-tzip", "-pinfected", "-mem=AES256", str(archive), str(src)],
                           capture_output=True, text=True, check=False)
        protected = r.returncode == 0
    if not protected:
        import zipfile
        archive = archive.with_name(archive.stem + "-UNPROTECTED.zip")
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
            z.write(src, src.name)
    note = archive.with_suffix(".txt")
    note.write_text(
        f"source: {src}\nsha256: {digest}\nsize: {src.stat().st_size}\n"
        f"quarantined: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"password: {'infected' if protected else 'NONE -- install 7-Zip for a protected archive'}\n"
        f"note: {args.note or ''}\n", encoding="utf-8")
    print(f"  sha256   {digest}")
    print(f"  archive  {archive}{'' if protected else '  (NOT password-protected: 7z not found)'}")
    print(f"  note     {note}")
    print("  next     move the archive to the sandbox VM (docs/PENTEST_LAB.md, 'Sandbox');"
          " look the hash up by hand before opening anything.")
    return 0


def cmd_notify_test(args) -> int:
    """Send a test alert through the enabled outbound channels + local toast."""
    from dataclasses import dataclass

    from . import deliver, notify, secrets

    cfg = Config.load(args.config)

    @dataclass
    class _F:
        severity: str = "high"
        title: str = "PNMA test alert -- if you can read this, delivery works"

    findings = [_F()]
    any_channel = False
    if cfg.alerting.toast_enabled or args.force:
        ok = notify.toast("PNMA test alert", "Local toast delivery works.")
        print(f"  toast: {'sent' if ok else 'not shown (non-Windows or blocked)'}")
        any_channel = True
    if cfg.alerting.webhook_enabled or (args.force and secrets.get_secret('webhook_url')):
        url = secrets.get_secret("webhook_url")
        if url:
            r = deliver.send_webhook(url, findings, minimum="info")
            print(f"  webhook: {'sent' if r.get('sent') else r.get('detail', r.get('reason'))}")
            any_channel = True
        else:
            print("  webhook: enabled but no webhook_url secret set")
    if cfg.alerting.ntfy_enabled or (args.force and secrets.get_secret('ntfy_topic_url')):
        topic = secrets.get_secret("ntfy_topic_url")
        if topic:
            r = deliver.send_ntfy(topic, findings, minimum="info")
            print(f"  ntfy: {'sent' if r.get('sent') else r.get('detail', r.get('reason'))}")
            any_channel = True
        else:
            print("  ntfy: enabled but no ntfy_topic_url secret set")
    if not any_channel:
        print("No outbound channel enabled. Enable one in config, or pass --force "
              "to test whatever secrets are set.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pnma",
        description="Personal Network Monitoring Agent",
        epilog=(
            "The monitored network is set in the config file only -- there is "
            "deliberately no command-line option to change it."
        ),
    )
    parser.add_argument("-c", "--config", default=str(DEFAULT_CONFIG_PATH))
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="fingerprint this network and write a config")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("check", help="preflight: config, authorisation, capability")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("collect", help="run the collector (privileged half)")
    p.set_defaults(func=cmd_collect)

    p = sub.add_parser("serve", help="run the dashboard (unprivileged half)")
    p.add_argument(
        "--bind",
        help="address to listen on; 'tailscale' resolves this host's tailnet IP. "
        "Anything off loopback requires the dashboard_token secret.",
    )
    p.add_argument(
        "--no-token", action="store_true",
        help="serve unauthenticated; loopback only (e.g. the demo database)",
    )
    p.add_argument("--database", help="override the database path")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("seed", help="generate a synthetic demo network")
    p.add_argument("--database", help="output path (default data/pnma-demo.db)")
    p.add_argument("--days", type=int, default=7)
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_seed)

    p = sub.add_parser("audit", help="what the agent did, and its safety posture")
    p.add_argument("--hours", type=int, default=24)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser(
        "oui-update", help="refresh the MAC vendor table from the IEEE registry"
    )
    p.add_argument("--url", default=None, help="registry URL (default: IEEE)")
    p.add_argument(
        "--from-file", help="import a registry CSV already downloaded elsewhere"
    )
    p.add_argument(
        "--check", action="store_true",
        help="report disagreements without writing; exits 1 if any are found",
    )
    p.set_defaults(func=cmd_oui_update)

    p = sub.add_parser("quarantine", help="zip a suspect file (password 'infected') with its hash for the sandbox")
    p.add_argument("path", help="file to quarantine; it is copied, never run")
    p.add_argument("--note", default="", help="why: the alert id or what pointed at it")
    p.add_argument("--database", default=None, help=argparse.SUPPRESS)
    p.set_defaults(func=cmd_quarantine)

    p = sub.add_parser("report", help="write a monthly summary report (Markdown)")
    p.add_argument("--month", help="YYYY-MM (default: last complete month)")
    p.add_argument("--out", help="output file (default reports/<brand>-YYYY-MM.md)")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("evidence", help="gather a forensic evidence bundle for an alert or device")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--alert", type=int, help="alert id")
    g.add_argument("--device", help="device id")
    p.add_argument("--out", help="output directory (default evidence/)")
    p.add_argument("--before", type=float, default=6, help="hours of context before (default 6)")
    p.add_argument("--after", type=float, default=6, help="hours of context after (default 6)")
    p.set_defaults(func=cmd_evidence)

    p = sub.add_parser("detections", help="list rules and their blind spots")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_detections)

    p = sub.add_parser(
        "vulns",
        help="match your devices against known-exploited-vulnerability advisories",
    )
    p.add_argument("--json", action="store_true")
    p.add_argument(
        "--refresh", action="store_true",
        help="pull CISA's Known Exploited list first (outbound HTTPS to cisa.gov)",
    )
    p.set_defaults(func=cmd_vulns)

    p = sub.add_parser("honeypot", help="ingest a Cowrie honeypot log into alerts")
    p.add_argument("--log", help="path to cowrie.json (overrides config)")
    p.set_defaults(func=cmd_honeypot)

    p = sub.add_parser("maillog", help="ingest the router's emailed system log (IMAP)")
    p.add_argument("--dry-run", action="store_true",
                   help="parse and report, but raise no alerts and mark nothing read")
    p.add_argument("--sample", help="parse a local file of router log lines instead of IMAP")
    p.set_defaults(func=cmd_maillog)

    p = sub.add_parser(
        "notify-test", help="send a test alert through the enabled delivery channels"
    )
    p.add_argument(
        "--force", action="store_true",
        help="try every channel that has a secret/toast, even if disabled in config",
    )
    p.set_defaults(func=cmd_notify_test)

    p = sub.add_parser("identity", help="your own accounts, as a three-valued posture register")
    p.set_defaults(func=cmd_identity)
    isub = p.add_subparsers(dest="action", required=True)
    q = isub.add_parser("list", help="accounts and their controls, staleness applied")
    q = isub.add_parser("add", help="register an account you own")
    q.add_argument("account_id", help="slug, e.g. gmail-main")
    q.add_argument("--provider", required=True)
    q.add_argument("--category", required=True)
    q.add_argument("--label", required=True, help="what the dashboard shows")
    q.add_argument("--handle", help="email or username; stays in the local DB, masked in the UI")
    q.add_argument("--review-days", type=int, default=90,
                   help="attestations older than this degrade to unknown")
    q = isub.add_parser("remove", help="forget an account and its attestations")
    q.add_argument("account_id")
    q = isub.add_parser("attest", help="record what you verified")
    q.add_argument("account_id")
    q.add_argument("control")
    q.add_argument("state", choices=["ok", "finding", "unknown"])
    q.add_argument("--value")
    q.add_argument("--reason")
    q = isub.add_parser("breaches", help="look the account's handle up in Have I Been Pwned")
    q.add_argument("account_id")
    q = isub.add_parser("pwned", help="k-anonymous check of a password (prompted, never stored)")

    p = sub.add_parser("secrets", help="manage API keys in the OS credential store")
    p.add_argument(
        "action", choices=["status", "set", "delete"], help="what to do"
    )
    p.add_argument("name", nargs="?", help="secret name (see: pnma secrets status)")
    p.set_defaults(func=cmd_secrets)

    args = parser.parse_args(argv)
    _setup_logging(args.verbose)

    try:
        return args.func(args)
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
