"""Read-mostly HTTP API and dashboard host.

This is the *unprivileged* half of PNMA. It never captures, never scans, never
sends a packet to the monitored network. It reads the database and serves the
dashboard. Keeping it that way is the entire point of the process split: if
this process is compromised, the attacker gets a read of the database, not raw
capture rights on the network.

Bound to loopback by default. The database is a complete map of the network --
every device, every open port, every weak service -- which is to say a finished
reconnaissance report. Serving it to the LAN is a decision, not a default.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel

from ..config import Config
from ..db import Database

WEB_DIR = Path(__file__).parent.parent / "web"


def _rows(rows) -> list[dict[str, Any]]:
    out = []
    for row in rows:
        d = dict(row)
        if d.get("evidence"):
            try:
                d["evidence"] = json.loads(d["evidence"])
            except (TypeError, ValueError):
                pass
        out.append(d)
    return out


class AttestRequest(BaseModel):
    state: str
    value: str | None = None
    reason: str | None = None


class TrustRequest(BaseModel):
    trusted: bool = True
    label: str | None = None


# The dashboard's whole static surface, by name. There is no static mount and
# no catch-all on purpose: a directory listing or a path-traversal bug here
# would serve whatever sits beside the web files, and the point of an
# allowlist is that adding a file is a visible diff rather than a side effect
# of dropping something in a folder.
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript"),
    "/viz.js": ("viz.js", "application/javascript"),
    "/style.css": ("style.css", "text/css"),
    "/manifest.webmanifest": ("manifest.webmanifest", "application/manifest+json"),
    "/icon.svg": ("icon.svg", "image/svg+xml"),
    "/icon-192.png": ("icon-192.png", "image/png"),
    "/icon-512.png": ("icon-512.png", "image/png"),
}


def create_app(config: Config, token: str | None = None) -> FastAPI:
    """Build the API.

    ``token``, when set, gates every ``/api`` and ``/metrics`` route behind
    ``Authorization: Bearer <token>``. The static shell stays open: it is the
    same few files for everyone and contains no data, and a login prompt
    that cannot load is not a login prompt. Compared in constant time.
    """
    import hmac

    app = FastAPI(
        title="PNMA",
        description="Personal Network Monitoring Agent",
        version="0.1.0",
        docs_url="/api/docs",
    )
    db = Database(config.database)

    if token:
        @app.middleware("http")
        async def require_token(request: Request, call_next):
            path = request.url.path
            if path.startswith("/api") or path in ("/metrics", "/openapi.json"):
                header = request.headers.get("authorization", "")
                supplied = header[7:] if header.lower().startswith("bearer ") else ""
                if not hmac.compare_digest(supplied, token):
                    return JSONResponse(
                        {"error": "dashboard token required"},
                        status_code=401,
                        headers={"WWW-Authenticate": "Bearer"},
                    )
            return await call_next(request)

    # -- dashboard ----------------------------------------------------------

    def _static(name: str, media_type: str):
        def handler():
            return FileResponse(WEB_DIR / name, media_type=media_type)
        return handler

    for route, (name, media_type) in STATIC_FILES.items():
        app.get(route, include_in_schema=False)(_static(name, media_type))

    # -- summary ------------------------------------------------------------

    @app.get("/api/summary")
    def summary():
        now = time.time()
        online_window = 900

        devices_total = db.query_one("SELECT COUNT(*) n FROM devices")["n"]
        devices_online = db.query_one(
            "SELECT COUNT(*) n FROM devices WHERE last_seen >= ?",
            (now - online_window,),
        )["n"]
        untrusted = db.query_one(
            "SELECT COUNT(*) n FROM devices WHERE trusted = 0 AND last_seen >= ?",
            (now - online_window,),
        )["n"]

        by_sev = {
            r["severity"]: r["n"]
            for r in db.query(
                "SELECT severity, COUNT(*) n FROM alerts "
                "WHERE status = 'open' GROUP BY severity"
            )
        }
        open_alerts = sum(by_sev.values())

        avail = db.query_one(
            "SELECT AVG(reachable) * 100 AS pct, COUNT(*) n FROM availability "
            "WHERE ts >= ?",
            (now - 86400,),
        )
        latency = db.query_one(
            "SELECT AVG(rtt_ms) avg, MAX(rtt_ms) max, COUNT(*) n "
            "FROM availability WHERE ts >= ? AND rtt_ms IS NOT NULL",
            (now - 3600,),
        )

        return {
            "generated_at": now,
            "devices": {
                "total": devices_total,
                "online": devices_online,
                "untrusted_online": untrusted,
                "online_window_s": online_window,
            },
            "alerts": {"open": open_alerts, "by_severity": by_sev},
            "availability_24h_pct": round(avail["pct"], 2) if avail["pct"] else None,
            "latency_1h": {
                "avg_ms": round(latency["avg"], 1) if latency["avg"] else None,
                "max_ms": round(latency["max"], 1) if latency["max"] else None,
                "samples": latency["n"],
            },
        }

    # -- alerts -------------------------------------------------------------

    @app.get("/api/alerts")
    def alerts(status: str = "open", limit: int = 100):
        if status == "all":
            rows = db.query(
                "SELECT * FROM alerts ORDER BY "
                "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
                "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, "
                "last_seen DESC LIMIT ?",
                (limit,),
            )
        else:
            rows = db.query(
                "SELECT * FROM alerts WHERE status = ? ORDER BY "
                "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
                "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, "
                "last_seen DESC LIMIT ?",
                (status, limit),
            )
        return {"alerts": _rows(rows)}

    @app.post("/api/alerts/{alert_id}/{action}")
    def alert_action(alert_id: int, action: str):
        if action not in ("acknowledge", "resolve", "reopen"):
            raise HTTPException(400, "action must be acknowledge, resolve or reopen")
        new_status = {
            "acknowledge": "acknowledged",
            "resolve": "resolved",
            "reopen": "open",
        }[action]
        row = db.query_one("SELECT status FROM alerts WHERE id = ?", (alert_id,))
        if row is None:
            raise HTTPException(404, "no such alert")
        if row["status"] != new_status:
            db.execute(
                "UPDATE alerts SET status = ? WHERE id = ?", (new_status, alert_id)
            )
            db.record_alert_change(
                alert_id, "status", row["status"], new_status, actor="operator"
            )
            writes["n"] += 1
        return {"id": alert_id, "status": new_status}

    # -- devices ------------------------------------------------------------

    @app.get("/api/devices")
    def devices():
        now = time.time()
        rows = db.query("SELECT * FROM devices ORDER BY last_seen DESC")
        out = []
        for row in rows:
            d = dict(row)
            d["online"] = (now - d["last_seen"]) < 900
            d["open_ports"] = [
                dict(p)
                for p in db.query(
                    "SELECT port, proto, service, product, risk FROM ports "
                    "WHERE device_id = ? AND closed_at IS NULL ORDER BY port",
                    (d["device_id"],),
                )
            ]
            d["open_alerts"] = db.query_one(
                "SELECT COUNT(*) n FROM alerts "
                "WHERE device_id = ? AND status = 'open'",
                (d["device_id"],),
            )["n"]
            out.append(d)
        return {"devices": out}

    @app.get("/api/devices/{device_id}")
    def device_detail(device_id: str):
        row = db.query_one("SELECT * FROM devices WHERE device_id = ?", (device_id,))
        if row is None:
            raise HTTPException(404, "no such device")
        d = dict(row)
        d["ports"] = _rows(
            db.query("SELECT * FROM ports WHERE device_id = ? ORDER BY port", (device_id,))
        )
        d["alerts"] = _rows(
            db.query(
                "SELECT * FROM alerts WHERE device_id = ? ORDER BY last_seen DESC LIMIT 50",
                (device_id,),
            )
        )
        d["availability"] = _rows(
            db.query(
                "SELECT ts, reachable, rtt_ms FROM availability "
                "WHERE device_id = ? AND ts >= ? ORDER BY ts",
                (device_id, time.time() - 86400),
            )
        )
        return d

    @app.post("/api/devices/{device_id}/trust")
    def trust(device_id: str, req: TrustRequest):
        from ..inventory import set_trusted

        row = db.query_one("SELECT 1 FROM devices WHERE device_id = ?", (device_id,))
        if row is None:
            raise HTTPException(404, "no such device")
        set_trusted(db, device_id, req.trusted, req.label)
        writes["n"] += 1
        # Trusting a device resolves its outstanding new-device alert; that is
        # the whole point of the action.
        if req.trusted:
            db.execute(
                "UPDATE alerts SET status = 'resolved' "
                "WHERE device_id = ? AND rule_id = 'new_device' AND status = 'open'",
                (device_id,),
            )
        return {"device_id": device_id, "trusted": req.trusted}

    # -- timeseries ---------------------------------------------------------

    @app.get("/api/latency")
    def latency(hours: int = 24, buckets: int = 96):
        now = time.time()
        start = now - hours * 3600
        width = (hours * 3600) / buckets
        rows = db.query(
            "SELECT CAST((ts - ?) / ? AS INTEGER) AS bucket, "
            "       AVG(rtt_ms) avg_rtt, "
            "       AVG(reachable) * 100 AS up_pct, "
            "       COUNT(*) n "
            "FROM availability WHERE ts >= ? GROUP BY bucket ORDER BY bucket",
            (start, width, start),
        )
        return {
            "start": start,
            "bucket_width_s": width,
            "points": [
                {
                    "t": start + r["bucket"] * width,
                    "rtt": round(r["avg_rtt"], 2) if r["avg_rtt"] else None,
                    "up_pct": round(r["up_pct"], 1) if r["up_pct"] is not None else None,
                }
                for r in rows
            ],
        }

    # -- change notification: the dashboard's live cursor --------------------
    # A long-poll, not SSE: EventSource cannot send the bearer header this
    # API requires, and a token in the query string would land in access
    # logs. fetch() with the existing wrapper is enough. The cursor is
    # SQLite's data_version (another connection committed) joined with this
    # process's own write counter (an operator action through this API),
    # so a phone acknowledging an alert moves the laptop's view too.
    writes = {"n": 0}

    def _cursor() -> str:
        return f"{db.data_version()}:{writes['n']}"

    @app.get("/api/changes")
    def api_changes(cursor: str | None = None, wait: float = 25):
        wait = max(0.0, min(float(wait), 30.0))
        deadline = time.monotonic() + wait
        current = _cursor()
        if cursor is None:
            return {"cursor": current, "changed": False, "ts": time.time()}
        while current == cursor and time.monotonic() < deadline:
            time.sleep(0.5)
            current = _cursor()
        return {"cursor": current, "changed": current != cursor, "ts": time.time()}

    # -- the log: one stream over every table (see pnma.events) ------------

    @app.get("/api/events")
    def api_events(
        hours: float = 24,
        device_id: str | None = None,
        kinds: str | None = None,
        q: str | None = None,
        agent: bool = True,
        since: float | None = None,
        limit: int = 500,
    ):
        """SIEM-style log explorer. `kinds` is comma-separated (see events.KINDS);
        `agent=false` hides rows PNMA's own probes produced; `since` (epoch)
        overrides `hours` and is what the live cursor in the dashboard sends."""
        from .. import events as ev

        now = time.time()
        lo = since if since is not None else now - hours * 3600
        wanted = [k for k in (kinds or "").split(",") if k] or None
        rows = ev.query_events(db, since=lo, until=now, device_id=device_id,
                               kinds=wanted, q=q, include_agent=agent, limit=limit)
        return {"events": rows, "kinds": list(ev.KINDS), "since": lo, "until": now}

    @app.get("/api/alerts/{alert_id}/investigate")
    def api_investigate(alert_id: int, before_h: float = 1, after_h: float = 1):
        """Everything recorded around one alert: the analyst's evidence bundle."""
        from .. import events as ev

        bundle = ev.investigate(db, alert_id, before_s=int(before_h * 3600),
                                after_s=int(after_h * 3600))
        if bundle is None:
            raise HTTPException(404, "no such alert")
        return bundle

    @app.get("/api/timeline")
    def timeline(hours: int = 24):
        rows = db.query(
            "SELECT id, ts, kind, target, duration_s, result, error FROM scan_runs "
            "WHERE ts >= ? ORDER BY ts DESC LIMIT 200",
            (time.time() - hours * 3600,),
        )
        return {"events": _rows(rows)}

    # -- self-assessment ----------------------------------------------------

    @app.get("/api/audit")
    def audit(hours: int = 24):
        """The agent's own activity and posture. See pnma.audit."""
        from ..audit import Auditor
        from ..guard import ScopeGuard

        guard = ScopeGuard(config)
        guard.check_network()
        return Auditor(db, guard).compliance_report(hours)

    @app.get("/api/detections")
    def detections():
        """What this build can detect, and what it cannot."""
        from ..detections.base import DetectionEngine
        from ..detections.rules import default_rules

        return {"rules": DetectionEngine(db, default_rules()).catalogue()}

    @app.get("/api/sensors")
    def sensors():
        return {"sensors": _rows(db.query("SELECT * FROM sensors"))}

    # -- host posture -------------------------------------------------------

    @app.get("/api/host")
    def host():
        """Security posture of the machine PNMA runs on.

        `state` is three-valued -- ok / finding / **unknown** -- and the third
        one is not decoration. `unknown` means the check could not run, almost
        always because the collector was not elevated. It must never render as
        passing: a dashboard that paints unmeasured controls green manufactures
        confidence it has not earned.
        """
        rows = _rows(
            db.query(
                "SELECT fact_key, category, title, state, value, expected, "
                "reason, needs_admin, evidence, first_seen, last_seen, changed_at "
                "FROM host_facts "
                "ORDER BY CASE state WHEN 'finding' THEN 0 WHEN 'unknown' THEN 1 "
                "ELSE 2 END, category, fact_key"
            )
        )
        for r in rows:
            r["needs_admin"] = bool(r["needs_admin"])
            # `_rows()` has already decoded `evidence`. Decoding it a second
            # time here raised TypeError on the dict it had just produced, and
            # the handler swallowed that and substituted {} -- so the evidence
            # on every host fact that had any was silently discarded before it
            # ever reached the dashboard.
            #
            # Evidence that did not parse is passed through as the raw string
            # rather than replaced: the fact card renders that case as
            # "evidence (unparsed)", and a panel whose argument is that it never
            # hides what it could not show must not drop evidence for failing to
            # parse.
            if r.get("evidence") is None:
                r["evidence"] = {}

        states = [r["state"] for r in rows]
        last_run = max((r["last_seen"] for r in rows), default=None)

        # Elevation is inferred rather than stored: if anything needing admin
        # came back unknown, the last collection ran unprivileged.
        blocked = [r for r in rows if r["state"] == "unknown" and r["needs_admin"]]

        return {
            "summary": {
                "total": len(rows),
                "ok": states.count("ok"),
                "finding": states.count("finding"),
                "unknown": states.count("unknown"),
                "blocked_by_privilege": len(blocked),
                "elevated": not blocked and bool(rows),
                "last_run": last_run,
            },
            "facts": rows,
        }

    @app.get("/api/attack")
    def attack():
        """ATT&CK coverage: which techniques this deployment has evidence for.

        Deliberately reports the empty tactics too. A coverage view that only
        lists what you found tells you nothing about what you cannot see, and
        the gaps are the reason to look at it.
        """
        from .. import mitre

        rows = db.query(
            "SELECT mitre_id, severity, COUNT(*) AS n FROM alerts "
            "WHERE mitre_id IS NOT NULL AND status = 'open' "
            "GROUP BY mitre_id, severity"
        )
        observed = [r["mitre_id"] for r in rows]
        return {
            "coverage": mitre.coverage(observed),
            "techniques": [
                dict(mitre.describe(r["mitre_id"]) or {}, severity=r["severity"], count=r["n"])
                for r in rows
            ],
        }

    @app.get("/api/attack/navigator")
    def attack_navigator():
        """Export an ATT&CK Navigator layer for the observed techniques.

        Navigator (github.com/mitre-attack/attack-navigator) renders this JSON
        straight onto the matrix. Handing an analyst a layer file is a far
        better answer to "what does this thing cover" than a screenshot of a
        list, and it is the format the rest of the ecosystem already speaks.
        """
        from .. import mitre

        rows = db.query(
            "SELECT mitre_id, severity, COUNT(*) AS n FROM alerts "
            "WHERE mitre_id IS NOT NULL AND status = 'open' GROUP BY mitre_id, severity"
        )
        return mitre.navigator_layer(
            [(r["mitre_id"], r["severity"], r["n"]) for r in rows]
        )

    # -- identity posture ---------------------------------------------------

    @app.get("/api/identity")
    def identity_report():
        """The operator's own accounts, three-valued. See pnma.identity."""
        from .. import identity

        return identity.report(db)

    @app.post("/api/identity/{account_id}/{control}")
    def identity_attest(account_id: str, control: str, req: AttestRequest):
        from .. import identity

        try:
            changed = identity.attest(
                db, account_id, control, req.state, value=req.value, reason=req.reason
            )
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        writes["n"] += 1
        return {"account_id": account_id, "control": control, "state": req.state,
                "changed": changed}

    # -- prometheus ---------------------------------------------------------

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics():
        """Prometheus exposition, for the optional Grafana stack in docker/."""
        now = time.time()
        lines: list[str] = []

        def metric(name: str, help_text: str, mtype: str, value, labels: str = ""):
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} {mtype}")
            lines.append(f"{name}{labels} {value}")

        total = db.query_one("SELECT COUNT(*) n FROM devices")["n"]
        online = db.query_one(
            "SELECT COUNT(*) n FROM devices WHERE last_seen >= ?", (now - 900,)
        )["n"]
        metric("pnma_devices_total", "Known devices", "gauge", total)
        metric("pnma_devices_online", "Devices seen in last 15m", "gauge", online)

        lines.append("# HELP pnma_alerts_open Open alerts by severity")
        lines.append("# TYPE pnma_alerts_open gauge")
        for r in db.query(
            "SELECT severity, COUNT(*) n FROM alerts WHERE status='open' "
            "GROUP BY severity"
        ):
            lines.append(f'pnma_alerts_open{{severity="{r["severity"]}"}} {r["n"]}')

        lat = db.query_one(
            "SELECT AVG(rtt_ms) a FROM availability WHERE ts >= ? AND rtt_ms IS NOT NULL",
            (now - 3600,),
        )
        if lat["a"]:
            metric(
                "pnma_gateway_latency_ms",
                "Mean RTT over the last hour",
                "gauge",
                round(lat["a"], 2),
            )

        avail = db.query_one(
            "SELECT AVG(reachable) a FROM availability WHERE ts >= ?", (now - 86400,)
        )
        if avail["a"] is not None:
            metric(
                "pnma_availability_ratio",
                "Mean reachability over 24h",
                "gauge",
                round(avail["a"], 4),
            )

        risky = db.query_one(
            "SELECT COUNT(*) n FROM ports WHERE closed_at IS NULL AND risk = 'high'"
        )["n"]
        metric(
            "pnma_high_risk_ports", "Open ports classified high risk", "gauge", risky
        )
        return "\n".join(lines) + "\n"

    @app.get("/api/health")
    def health():
        return {"ok": True, "time": time.time()}

    return app


def tailscale_ip() -> str | None:
    """This host's Tailscale IPv4, or None when Tailscale is absent or down.

    Asks the CLI rather than scanning interfaces for 100.64.0.0/10: the CLI is
    authoritative about which address is actually routed on the tailnet, and
    an interface that still holds a stale CGNAT address after the client
    stops would otherwise bind a socket nobody can reach.
    """
    import shutil
    import subprocess

    exe = shutil.which("tailscale")
    if not exe:
        default = Path(r"C:\Program Files\Tailscale\tailscale.exe")
        exe = str(default) if default.exists() else None
    if not exe:
        return None
    try:
        out = subprocess.run(
            [exe, "ip", "-4"], capture_output=True, text=True, timeout=5, check=False
        ).stdout.strip().splitlines()
    except (OSError, subprocess.SubprocessError):
        return None
    return out[0].strip() if out else None


def serve(
    config: Config,
    bind: str | None = None,
    token: str | None = None,
    no_token: bool = False,
) -> None:
    """Run the dashboard.

    Off-loopback binds require a token. "Off loopback" includes the tailnet:
    WireGuard authenticates the *device*, the token authenticates the *person*
    holding it, and a phone left on a table is exactly the case where those
    differ. ``0.0.0.0`` is refused outright -- the database is a finished
    recon report of the network, and no token makes broadcasting it to the
    LAN a good default.
    """
    import ipaddress

    import uvicorn

    host = bind or config.api.bind
    if host == "tailscale":
        host = tailscale_ip()
        if not host:
            raise SystemExit(
                "serve: --bind tailscale but no Tailscale address found. "
                "Is the client installed and signed in? (tailscale status)"
            )
    if host in ("0.0.0.0", "::"):
        raise SystemExit(
            "serve: refusing to bind to all interfaces. Bind to loopback, or to "
            "the tailnet with --bind tailscale, so only your own devices can reach it."
        )
    loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    if no_token:
        # Explicit opt-out, loopback only: the demo database for screenshots,
        # or a laptop nobody else logs in to. Never combinable with a bind
        # anyone else could reach.
        if not loopback:
            raise SystemExit("serve: --no-token is only allowed on loopback")
        token = None
    if not loopback and not token:
        raise SystemExit(
            f"serve: binding to {host} needs a dashboard token. "
            "Run: pnma secrets set dashboard_token"
        )

    # Recorded so the self-audit (`/api/audit`, `pnma audit`) judges the
    # socket that is actually listening rather than the one in the file.
    config.api.effective_bind = host
    config.api.token_required = bool(token)

    print(f"Dashboard: http://{host}:{config.api.port}" +
          ("  (token required)" if token else ""))
    uvicorn.run(
        create_app(config, token=token),
        host=host,
        port=config.api.port,
        log_level="info",
    )
