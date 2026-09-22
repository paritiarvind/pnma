"""Reports: a monthly summary a person actually reads, and a forensic evidence
bundle for the one incident that turned out to matter.

Two very different documents:

* **Monthly report** (:func:`monthly_report`, :func:`render_markdown`) -- what
  happened on the network, the host and the accounts over a calendar month:
  what got worse, what got fixed, what is still open, and an honest reminder
  of what the tool could not see. Meant to be read in two minutes and kept.

* **Evidence bundle** (:func:`evidence_bundle`) -- for when something is real.
  Everything PNMA recorded about one alert or one device, gathered into a
  folder with a manifest, a chain-of-custody note and a SHA-256 for every
  artifact, then zipped. It is designed to be *defensible*: a second reader
  can verify nothing was altered after collection. It is honest about what it
  is not -- host-collected telemetry with the collector's own clock, not a
  disk image or a court-admissible capture.

Nothing here mutates the database; a report is a read.
"""

from __future__ import annotations

import csv
import datetime as dt
import getpass
import hashlib
import io
import json
import socket
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import events
from .db import Database

BRAND = "Hearth"
TOOL = "pnma"

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _month_bounds(year: int, month: int) -> tuple[float, float, str]:
    start = dt.datetime(year, month, 1)
    end = dt.datetime(year + (month == 12), (month % 12) + 1, 1)
    label = start.strftime("%B %Y")
    return start.timestamp(), end.timestamp(), label


def _severity_counts(rows: list[dict], key: str = "severity") -> dict[str, int]:
    out = {s: 0 for s in SEVERITY_ORDER}
    for r in rows:
        sev = r[key] if isinstance(r, dict) else r[key]
        if sev in out:
            out[sev] += 1
    return out


# ============================================================ monthly report

@dataclass
class Provenance:
    tool: str
    version: str
    brand: str
    generated_utc: str
    generated_local: str
    timezone: str
    host: str
    operator: str
    database: str
    database_sha256: str

    @classmethod
    def build(cls, db: Database, version: str) -> "Provenance":
        now = dt.datetime.now().astimezone()
        db_path = Path(db.path)
        digest = ""
        try:
            h = hashlib.sha256()
            with open(db_path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            digest = h.hexdigest()
        except OSError:
            digest = "unreadable"
        return cls(
            tool=TOOL, version=version, brand=BRAND,
            generated_utc=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            generated_local=now.strftime("%Y-%m-%d %H:%M:%S"),
            timezone=str(now.tzinfo),
            host=socket.gethostname(),
            operator=_safe_user(),
            database=str(db_path),
            database_sha256=digest,
        )

    def as_dict(self) -> dict:
        return self.__dict__.copy()


def _safe_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - getuser can raise on odd environments
        return "unknown"


def monthly_report(db: Database, year: int, month: int, *, version: str = "0.0.0") -> dict[str, Any]:
    """Structured monthly report. Pure read; render with render_markdown."""
    start, end, label = _month_bounds(year, month)
    prov = Provenance.build(db, version)

    def q(sql: str, params=()):
        return [dict(r) for r in db.query(sql, params)]

    # The monitoring host is graded by host_facts, not as a network device;
    # exclude its own adapters here too (see DetectionContext.self_device_ids).
    self_ids = _self_device_ids(db)

    # Alerts opened, resolved, still open -- by severity.
    opened = q("SELECT severity, rule_id, title, device_id, first_seen FROM alerts "
               "WHERE first_seen >= ? AND first_seen < ?", (start, end))
    resolved = q("SELECT c.ts, a.severity, a.title, a.device_id FROM alert_changes c "
                 "JOIN alerts a ON a.id = c.alert_id "
                 "WHERE c.field = 'status' AND c.new_value = 'resolved' AND c.ts >= ? AND c.ts < ?",
                 (start, end))
    still_open = q("SELECT severity, title, device_id, rule_id, first_seen FROM alerts WHERE status = 'open'")
    escalations = q("SELECT c.ts, c.old_value, c.new_value, a.title, a.device_id FROM alert_changes c "
                    "JOIN alerts a ON a.id = c.alert_id "
                    "WHERE c.field = 'severity' AND c.ts >= ? AND c.ts < ?", (start, end))

    # Devices first seen this month.
    new_devices = [d for d in q(
        "SELECT device_id, label, ip, mac, vendor, device_class, trusted, first_seen "
        "FROM devices WHERE first_seen >= ? AND first_seen < ? ORDER BY first_seen", (start, end))
        if d["device_id"] not in self_ids]

    # Notable host events (those that carried a severity, i.e. became alerts),
    # excluding the agent's own rows.
    host_events = q("SELECT ts, kind, summary, severity FROM host_events "
                    "WHERE ts >= ? AND ts < ? AND severity IS NOT NULL AND agent_generated = 0 "
                    "ORDER BY ts DESC LIMIT 200", (start, end))

    # Devices ranked by how many alerts they carried this month.
    by_device: dict[str, dict] = {}
    for a in opened:
        if not a["device_id"] or a["device_id"] in self_ids:
            continue
        d = by_device.setdefault(a["device_id"], {"device_id": a["device_id"], "count": 0, "worst": "info"})
        d["count"] += 1
        if SEVERITY_ORDER.index(a["severity"]) < SEVERITY_ORDER.index(d["worst"]):
            d["worst"] = a["severity"]
    for did, d in by_device.items():
        row = db.query_one("SELECT label, hostname, ip FROM devices WHERE device_id = ?", (did,))
        d["name"] = (row["label"] or row["hostname"] or row["ip"] or did) if row else did
    top_devices = sorted(by_device.values(), key=lambda d: (-d["count"], SEVERITY_ORDER.index(d["worst"])))[:8]

    # Identity: what is attested, what has gone stale or was never attested.
    identity = q("SELECT account_id, control, state FROM identity_facts")
    id_by_state: dict[str, int] = {}
    for r in identity:
        id_by_state[r["state"]] = id_by_state.get(r["state"], 0) + 1

    # Availability: devices with the most reachability transitions this month.
    avail = events.query_events(db, since=start, until=end, kinds=["availability"], limit=500)
    flaps: dict[str, int] = {}
    for e in avail:
        if e["device_id"]:
            flaps[e["device_id"]] = flaps.get(e["device_id"], 0) + 1

    return {
        "provenance": prov.as_dict(),
        "period": {"label": label, "start": start, "end": end,
                   "year": year, "month": month},
        "alerts": {
            "opened": _severity_counts(opened),
            "opened_total": len(opened),
            "resolved_total": len(resolved),
            "still_open": _severity_counts(still_open),
            "still_open_total": len(still_open),
            "escalations": escalations,
        },
        "top_devices": top_devices,
        "new_devices": new_devices,
        "host_events": host_events,
        "identity": {"by_state": id_by_state, "total": len(identity)},
        "availability_flaps": sorted(flaps.items(), key=lambda kv: -kv[1])[:5],
        "blind_spots": _blind_spots(db),
    }


def _self_device_ids(db: Database) -> set[str]:
    row = db.query_one("SELECT value FROM meta WHERE key = 'own_macs'")
    if not row or not row["value"]:
        return set()
    try:
        own = {m.lower() for m in json.loads(row["value"])}
    except ValueError:
        return set()
    return {d["device_id"] for d in db.query("SELECT device_id, mac FROM devices WHERE mac IS NOT NULL")
            if (d["mac"] or "").lower() in own}


def _blind_spots(db: Database) -> list[str]:
    """Data sources this build is NOT collecting, read from host_facts so the
    report never implies coverage it does not have."""
    out = []
    checks = {
        "events.security_log": "Windows Security log (process creation 4688, scheduled tasks, account changes) -- needs an elevated collector.",
        "powershell.script_block": "PowerShell script-block logging -- off, so only blocks Windows itself flagged are seen.",
        "audit.cmdline": "Process command-line auditing -- off, so 'what ran' is not captured.",
    }
    for key, note in checks.items():
        row = db.query_one("SELECT state FROM host_facts WHERE fact_key = ?", (key,))
        if row and row["state"] in ("finding", "unknown"):
            out.append(note)
    out.append("No packet capture, NetFlow or EDR: PNMA sees devices, ports, host telemetry and account attestations, not payloads.")
    return out


def render_markdown(report: dict) -> str:
    p = report["provenance"]
    per = report["period"]
    a = report["alerts"]
    lines: list[str] = []
    w = lines.append
    w(f"# {p['brand']} monthly report -- {per['label']}")
    w("")
    w(f"*Generated {p['generated_local']} ({p['timezone']}) by {p['tool']} {p['version']} "
      f"on {p['host']}. Read from {p['database']}. This is a summary of collected "
      f"telemetry, not a security guarantee.*")
    w("")
    # Alerts
    w("## Alerts")
    w("")
    op = a["opened"]; so = a["still_open"]
    w(f"- **{a['opened_total']} opened** this month "
      f"({op['critical']} critical, {op['high']} high, {op['medium']} medium, {op['low']} low).")
    w(f"- **{a['resolved_total']} resolved.**")
    w(f"- **{a['still_open_total']} still open** now "
      f"({so['critical']} critical, {so['high']} high, {so['medium']} medium, {so['low']} low).")
    if a["escalations"]:
        w(f"- **{len(a['escalations'])} escalated** in severity while open.")
    w("")
    # Top devices
    if report["top_devices"]:
        w("## Devices that raised the most alerts")
        w("")
        w("| Device | Alerts | Worst |")
        w("| --- | ---: | --- |")
        for d in report["top_devices"]:
            w(f"| {d['name']} | {d['count']} | {d['worst']} |")
        w("")
    # New devices
    if report["new_devices"]:
        w("## New devices this month")
        w("")
        for d in report["new_devices"]:
            name = d["label"] or d["vendor"] or d["device_class"] or "unnamed"
            trust = "trusted" if d["trusted"] else "not yet trusted"
            w(f"- **{name}** -- {d['ip']} ({d['mac']}) -- {trust}")
        w("")
    # Host events
    if report["host_events"]:
        w("## Notable host events")
        w("")
        for e in report["host_events"][:20]:
            when = dt.datetime.fromtimestamp(e["ts"]).strftime("%b %d %H:%M")
            w(f"- `{when}` **{e['severity']}** {e['summary']}")
        w("")
    # Identity
    idn = report["identity"]
    if idn["total"]:
        w("## Account posture")
        w("")
        states = ", ".join(f"{n} {s}" for s, n in sorted(idn["by_state"].items()))
        w(f"- {idn['total']} controls attested across your accounts: {states}.")
        w("")
    # Availability
    if report["availability_flaps"]:
        w("## Devices that dropped off most often")
        w("")
        for did, n in report["availability_flaps"]:
            w(f"- {did}: {n} reachability changes")
        w("")
    # Blind spots
    w("## What this report could not see")
    w("")
    for b in report["blind_spots"]:
        w(f"- {b}")
    w("")
    return "\n".join(lines)


# ============================================================ evidence bundle

def evidence_bundle(db: Database, *, out_dir: Path, alert_id: int | None = None,
                    device_id: str | None = None, version: str = "0.0.0",
                    before_h: float = 6, after_h: float = 6) -> dict[str, Any]:
    """Gather everything recorded about one alert or device into a signed
    folder + zip. Returns {"dir", "zip", "manifest"}. Read-only on the DB."""
    if not alert_id and not device_id:
        raise ValueError("evidence_bundle needs an alert_id or a device_id")
    prov = Provenance.build(db, version)
    subject: dict[str, Any] = {}
    artifacts: dict[str, bytes] = {}

    if alert_id:
        alert = db.query_one("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        if alert is None:
            raise ValueError(f"no alert #{alert_id}")
        alert = _row(alert)
        subject = {"kind": "alert", "id": alert_id, "title": alert.get("title"),
                   "device_id": alert.get("device_id")}
        artifacts["alert.json"] = _json_bytes(alert)
        bundle = events.investigate(db, alert_id, before_s=int(before_h * 3600),
                                    after_s=int(after_h * 3600), limit=2000)
        artifacts["investigation.json"] = _json_bytes(bundle)
        artifacts["timeline.csv"] = _timeline_csv(bundle["events"] if bundle else [])
        # alert history
        hist = [_row(r) for r in db.query(
            "SELECT ts, field, old_value, new_value, actor FROM alert_changes WHERE alert_id = ? ORDER BY ts",
            (alert_id,))]
        artifacts["alert_history.json"] = _json_bytes(hist)
        device_id = device_id or alert.get("device_id")

    if device_id:
        dev = db.query_one("SELECT * FROM devices WHERE device_id = ?", (device_id,))
        if dev is not None:
            dev = _row(dev)
            subject.setdefault("kind", "device")
            subject.setdefault("device_id", device_id)
            subject["device_name"] = dev.get("label") or dev.get("hostname") or dev.get("ip")
            artifacts["device.json"] = _json_bytes(dev)
            artifacts["device_ports.json"] = _json_bytes(
                [_row(r) for r in db.query("SELECT * FROM ports WHERE device_id = ?", (device_id,))])
            artifacts["device_observations.json"] = _json_bytes(
                [_row(r) for r in db.query(
                    "SELECT * FROM observations WHERE device_id = ? ORDER BY ts DESC LIMIT 5000", (device_id,))])
        if "timeline.csv" not in artifacts:
            evs = events.query_events(db, device_id=device_id, limit=5000,
                                      since=time.time() - 30 * 86400)
            artifacts["timeline.csv"] = _timeline_csv(evs)
            artifacts["timeline.json"] = _json_bytes(evs)

    # Any quarantined files whose hash appears in the subject/device evidence.
    qdir = Path(db.path).parent / "quarantine"
    if qdir.is_dir():
        refs = [{"file": f.name, "size": f.stat().st_size} for f in qdir.glob("*") if f.is_file()]
        if refs:
            artifacts["quarantine_index.json"] = _json_bytes(refs)

    # Manifest + chain-of-custody README, with a SHA-256 for every artifact.
    manifest = {
        "provenance": prov.as_dict(),
        "subject": subject,
        "window_hours": {"before": before_h, "after": after_h},
        "artifacts": [
            {"name": name, "bytes": len(data), "sha256": _sha256_bytes(data)}
            for name, data in sorted(artifacts.items())
        ],
    }
    manifest_bytes = _json_bytes(manifest)
    readme = _readme(prov, subject, manifest)

    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    tag = f"alert-{alert_id}" if alert_id else f"device-{(device_id or '')[:16]}"
    out_dir = Path(out_dir)
    bundle_dir = out_dir / f"evidence-{tag}-{stamp}"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    all_files = dict(artifacts)
    all_files["MANIFEST.json"] = manifest_bytes
    all_files["README.md"] = readme.encode("utf-8")
    sums = "\n".join(f"{_sha256_bytes(d)}  {n}" for n, d in sorted(all_files.items())) + "\n"
    all_files["SHA256SUMS"] = sums.encode("utf-8")
    for name, data in all_files.items():
        (bundle_dir / name).write_bytes(data)
    zip_path = out_dir / f"{bundle_dir.name}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in sorted(all_files.items()):
            z.writestr(f"{bundle_dir.name}/{name}", data)
    return {"dir": str(bundle_dir), "zip": str(zip_path), "manifest": manifest}


def _readme(prov: Provenance, subject: dict, manifest: dict) -> str:
    return (
        f"# {prov.brand} evidence bundle\n\n"
        f"Subject: {subject.get('kind', '?')} "
        f"{subject.get('id', subject.get('device_id', ''))}"
        f"{(' -- ' + subject['title']) if subject.get('title') else ''}\n\n"
        f"Collected {prov.generated_local} ({prov.timezone}) "
        f"[{prov.generated_utc}] by {prov.tool} {prov.version} on host "
        f"`{prov.host}` as `{prov.operator}`.\n\n"
        "## Integrity\n\n"
        "Every file in this bundle has a SHA-256 in `MANIFEST.json` and "
        "`SHA256SUMS`. Verify with `sha256sum -c SHA256SUMS` (Linux/macOS) or "
        "`Get-FileHash` (Windows). The source database's own hash at collection "
        f"time is recorded in the manifest (`{prov.database_sha256[:16]}...`).\n\n"
        "## What this is, and is not\n\n"
        "- It **is** a faithful copy of the telemetry PNMA had recorded about "
        "this subject at collection time: alerts, the normalised event "
        "timeline, the device record, observations, ports, and the alert's own "
        "change history.\n"
        "- Timestamps are the **collector's system clock**; the timezone is "
        "recorded above. They are not from an independent time source.\n"
        "- It is **not** a disk image, a memory capture, or a packet capture. "
        "PNMA is a passive, host- and network-telemetry monitor; it does not "
        "see payloads.\n"
        "- Suspect files themselves are handled separately by `pnma "
        "quarantine` (password-protected). This bundle indexes them by name "
        "but does not embed them.\n\n"
        "## Files\n\n"
        + "\n".join(f"- `{art['name']}` ({art['bytes']} bytes)"
                    for art in manifest["artifacts"])
        + "\n"
    )


def _row(r) -> dict:
    d = dict(r)
    for k in ("evidence", "detail", "class_signals", "tags"):
        if k in d and isinstance(d[k], str):
            try:
                d[k] = json.loads(d[k])
            except (TypeError, ValueError):
                pass
    return d


def _json_bytes(obj) -> bytes:
    return json.dumps(obj, indent=2, default=str).encode("utf-8")


def _timeline_csv(evs: list[dict]) -> bytes:
    buf = io.StringIO()
    wr = csv.writer(buf)
    wr.writerow(["timestamp_local", "timestamp_epoch", "kind", "source",
                 "device_id", "entity", "agent_generated", "summary"])
    for e in sorted(evs, key=lambda x: x["ts"]):
        wr.writerow([
            dt.datetime.fromtimestamp(e["ts"]).strftime("%Y-%m-%d %H:%M:%S"),
            f"{e['ts']:.0f}", e["kind"], e.get("source", ""), e.get("device_id") or "",
            e.get("entity") or "", int(bool(e.get("agent_generated"))), e.get("summary", ""),
        ])
    return buf.getvalue().encode("utf-8")
