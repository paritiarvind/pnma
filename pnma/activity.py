"""Per-device network activity, from the passive observations Hearth already
collects -- no new sensor, no configuration.

Hearth cannot measure bytes per device on its own: that needs the router's
per-client counters or a mirror port, neither of which a single host has. What
it *can* measure, passively, is *presence and rhythm* -- how often a device is
seen, and at which hours -- from the ARP/DHCP frames the collector records. On
a home network that is most of what "usage" means: which devices are chatty,
which are new, which are awake right now, and which just did something at an
hour they never normally do.

This module turns `observations` into:

* :func:`device_activity` -- a rollup for one device (seen counts over 24h/7d/
  30d, its active-hour histogram, first/last seen).
* :func:`compare_devices` -- the same for every device, ranked, for the
  "who is busiest / newest / quietest" comparison.
* :func:`active_hour_envelope` and :func:`is_off_hours` -- the learned
  daily-rhythm envelope and whether a given moment falls outside it, which the
  off-hours detection reads.

Reads only. Only unsolicited observations (``agent_generated = 0``) count, so a
device's rhythm is its own, not an echo of the agent's scans.
"""

from __future__ import annotations

import datetime as dt
import time
from typing import Any

from .db import Database

DAY = 86400
# A device needs at least this much history before its rhythm means anything;
# below it, "off hours" is just "we have not watched long enough".
MIN_HISTORY_DAYS = 14
# A device active nearly around the clock (a TV, a hub, the gateway) has no
# meaningful "off hours"; only devices that come and go do.
ALWAYS_ON_HOURS = 21


def _local_hour(ts: float) -> int:
    return dt.datetime.fromtimestamp(ts).hour


def device_activity(db: Database, device_id: str, *, now: float | None = None) -> dict[str, Any]:
    """Presence rollup for one device over the last 24h / 7d / 30d."""
    now = now or time.time()
    row = db.query_one("SELECT label, hostname, ip, mac, device_class, trusted, first_seen, last_seen "
                       "FROM devices WHERE device_id = ?", (device_id,))
    def seen(since: float) -> int:
        r = db.query_one("SELECT COUNT(*) n FROM observations WHERE device_id = ? "
                         "AND agent_generated = 0 AND ts >= ?", (device_id, since))
        return r["n"] if r else 0
    hours = _hour_histogram(db, device_id, now - 30 * DAY, now)
    first_obs = db.query_one("SELECT MIN(ts) t FROM observations WHERE device_id = ? AND agent_generated = 0",
                             (device_id,))
    history_days = ((now - first_obs["t"]) / DAY) if first_obs and first_obs["t"] else 0.0
    name = (row["label"] or row["hostname"] or row["ip"] or device_id) if row else device_id
    return {
        "device_id": device_id,
        "name": name,
        "ip": row["ip"] if row else None,
        "device_class": row["device_class"] if row else None,
        "trusted": bool(row["trusted"]) if row else False,
        "seen_24h": seen(now - DAY),
        "seen_7d": seen(now - 7 * DAY),
        "seen_30d": seen(now - 30 * DAY),
        "active_hours": sorted(h for h, n in hours.items() if n),
        "active_hour_count": sum(1 for n in hours.values() if n),
        "hour_histogram": {str(h): hours.get(h, 0) for h in range(24)},
        "history_days": round(history_days, 1),
        "online_now": bool(row and now - row["last_seen"] < 900),
        "first_seen": row["first_seen"] if row else None,
        "last_seen": row["last_seen"] if row else None,
    }


def _hour_histogram(db: Database, device_id: str, since: float, until: float) -> dict[int, int]:
    hist = {h: 0 for h in range(24)}
    for r in db.query("SELECT ts FROM observations WHERE device_id = ? AND agent_generated = 0 "
                      "AND ts >= ? AND ts < ?", (device_id, since, until)):
        hist[_local_hour(r["ts"])] += 1
    return hist


def compare_devices(db: Database, *, now: float | None = None) -> list[dict[str, Any]]:
    """Activity rollup for every device, busiest first -- the comparison view.
    The monitoring host's own adapters are excluded (their traffic is the
    agent, not a peer)."""
    now = now or time.time()
    own = _own_device_ids(db)
    out = []
    for d in db.query("SELECT device_id FROM devices"):
        if d["device_id"] in own:
            continue
        out.append(device_activity(db, d["device_id"], now=now))
    out.sort(key=lambda a: -a["seen_7d"])
    return out


def _own_device_ids(db: Database) -> set[str]:
    import json
    row = db.query_one("SELECT value FROM meta WHERE key = 'own_macs'")
    if not row or not row["value"]:
        return set()
    try:
        own = {m.lower() for m in json.loads(row["value"])}
    except ValueError:
        return set()
    return {d["device_id"] for d in db.query("SELECT device_id, mac FROM devices WHERE mac IS NOT NULL")
            if (d["mac"] or "").lower() in own}


def active_hour_envelope(db: Database, device_id: str, *, now: float | None = None,
                         days: int = 30) -> dict[str, Any]:
    """The device's learned daily rhythm: which hours it is normally active,
    and whether that rhythm is well-enough established to judge against."""
    now = now or time.time()
    first = db.query_one("SELECT MIN(ts) t FROM observations WHERE device_id = ? AND agent_generated = 0",
                         (device_id,))
    history_days = ((now - first["t"]) / DAY) if first and first["t"] else 0.0
    hist = _hour_histogram(db, device_id, now - days * DAY, now)
    active = {h for h, n in hist.items() if n > 0}
    return {
        "history_days": history_days,
        "active_hours": sorted(active),
        "active_hour_count": len(active),
        "reliable": history_days >= MIN_HISTORY_DAYS and len(active) > 0,
        "always_on": len(active) >= ALWAYS_ON_HOURS,
        "histogram": hist,
    }


def is_off_hours(envelope: dict, ts: float) -> bool:
    """True if `ts` falls at an hour the device is never normally active, given
    a reliable, non-always-on envelope. Conservative: an unreliable envelope
    (too little history) or an always-on device is never 'off hours'."""
    if not envelope["reliable"] or envelope["always_on"]:
        return False
    return _local_hour(ts) not in set(envelope["active_hours"])
