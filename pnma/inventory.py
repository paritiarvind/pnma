"""Device inventory: turning raw observations into a stable device record.

This is the join point between :mod:`pnma.fingerprint` (who is this?) and
:mod:`pnma.db` (what have we seen?). Every collector funnels through
:func:`observe` so that identity resolution, vendor lookup, binding history and
the agent-generated flag are applied in exactly one place.
"""

from __future__ import annotations

import json
import logging
import time

from . import oui
from .db import Database
from .fingerprint import is_real_endpoint, resolve_identity

log = logging.getLogger(__name__)

# Sources that represent traffic we did not solicit. Used to decide whether a
# binding observation counts as independent evidence -- see THREAT_MODEL.md
# "The agent observing itself".
PASSIVE_SOURCES = {"passive_arp", "passive_dhcp"}


def observe(
    db: Database,
    *,
    mac: str,
    ip: str | None,
    source: str,
    sensor_id: str,
    hostname: str | None = None,
    param_request_list: list[int] | None = None,
    vendor_class: str | None = None,
    detail: dict | None = None,
    ts: float | None = None,
    agent_generated: bool | None = None,
) -> str | None:
    """Record a sighting and return the resolved device_id.

    Returns None for addresses that are not real endpoints (broadcast,
    multicast), which otherwise clutter every ARP table on earth.

    ``agent_generated`` normally derives from the source, but the passive
    sniffer overrides it: an ARP reply is only independent evidence if we did
    not provoke it. See :class:`pnma.audit.ProbeWindow`.
    """
    if not is_real_endpoint(mac):
        return None

    now = ts or time.time()
    if agent_generated is None:
        agent_generated = source not in PASSIVE_SOURCES

    identity = resolve_identity(
        mac,
        hostname=hostname,
        param_request_list=param_request_list,
        vendor_class=vendor_class,
    )
    device_id = identity.device_id
    vendor = oui.lookup(identity.mac)

    existing = db.query_one(
        "SELECT device_id, first_seen, hostname, dhcp_fingerprint, "
        "       dhcp_vendor_class, label, trusted "
        "FROM devices WHERE device_id = ?",
        (device_id,),
    )

    if existing is None:
        db.execute(
            """INSERT INTO devices(device_id, mac, mac_type, vendor, hostname,
                                   dhcp_fingerprint, dhcp_vendor_class, ip,
                                   first_seen, last_seen)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (
                device_id,
                identity.mac,
                identity.mac_type,
                vendor,
                hostname,
                identity.fingerprint,
                vendor_class,
                ip,
                now,
                now,
            ),
        )
        log.info(
            "new device %s mac=%s vendor=%s strategy=%s confidence=%s",
            device_id, identity.mac, vendor or "?",
            identity.strategy, identity.confidence,
        )
        # Classify immediately so the very first alert about this device is
        # judged against the right baseline. Re-run after any port scan, when
        # observed services give a much stronger signal.
        gw = db.query_one("SELECT value FROM meta WHERE key = 'gateway_ip'")
        reclassify(db, device_id, gw["value"] if gw else None)
    else:
        # COALESCE so a later observation that lacks hostname/fingerprint never
        # erases what an earlier, richer one told us.
        db.execute(
            """UPDATE devices SET
                   mac               = ?,
                   last_seen         = ?,
                   ip                = COALESCE(?, ip),
                   vendor            = COALESCE(?, vendor),
                   hostname          = COALESCE(?, hostname),
                   dhcp_fingerprint  = COALESCE(?, dhcp_fingerprint),
                   dhcp_vendor_class = COALESCE(?, dhcp_vendor_class)
               WHERE device_id = ?""",
            (
                identity.mac, now, ip, vendor, hostname,
                identity.fingerprint, vendor_class, device_id,
            ),
        )

    db.record_observation(
        source=source,
        agent_generated=agent_generated,
        sensor_id=sensor_id,
        device_id=device_id,
        mac=identity.mac,
        ip=ip,
        detail=detail,
        ts=now,
    )

    if ip:
        # A binding only counts as passive evidence if we did not provoke it.
        db.upsert_binding(
            identity.mac,
            ip,
            passive=(source in PASSIVE_SOURCES and not agent_generated),
            ts=now,
        )

    return device_id


def reclassify(db: Database, device_id: str, gateway_ip: str | None = None) -> None:
    """Re-run device classification using every signal currently available.

    Called after a scan, because an observed listening port is the strongest
    classification signal there is -- it is behaviour rather than something the
    device claims about itself. A printer that only became identifiable once we
    saw 9100/tcp should be reclassified immediately, since its whole baseline
    changes with it.
    """
    from .profiles import classify

    row = db.query_one(
        "SELECT mac, hostname, dhcp_vendor_class, ip FROM devices "
        "WHERE device_id = ?",
        (device_id,),
    )
    if row is None:
        return

    ports = [
        p["port"]
        for p in db.query(
            "SELECT port FROM ports WHERE device_id = ? AND closed_at IS NULL",
            (device_id,),
        )
    ]

    result = classify(
        mac=row["mac"],
        hostname=row["hostname"],
        vendor_class=row["dhcp_vendor_class"],
        open_ports=ports,
        is_gateway=bool(gateway_ip and row["ip"] == gateway_ip),
    )

    db.execute(
        "UPDATE devices SET device_class = ?, class_confidence = ?, "
        "class_signals = ? WHERE device_id = ?",
        (
            result.device_class.value,
            result.confidence,
            json.dumps(result.signals),
            device_id,
        ),
    )


def device_count(db: Database) -> int:
    row = db.query_one("SELECT COUNT(*) AS n FROM devices")
    return int(row["n"]) if row else 0


def online_devices(db: Database, window_s: int = 300) -> list[dict]:
    """Devices seen within the window. 'Online' is always a guess; say how big."""
    cutoff = time.time() - window_s
    return [
        dict(r)
        for r in db.query(
            "SELECT * FROM devices WHERE last_seen >= ? ORDER BY last_seen DESC",
            (cutoff,),
        )
    ]


def set_trusted(db: Database, device_id: str, trusted: bool, label: str | None = None):
    """Mark a device as known-good.

    Trust is how the new-device detector stops shouting about your own
    hardware. It is an explicit human act, never inferred -- a detector that
    auto-trusts whatever it sees is not a detector.
    """
    if label is not None:
        db.execute(
            "UPDATE devices SET trusted = ?, label = ? WHERE device_id = ?",
            (int(trusted), label, device_id),
        )
    else:
        db.execute(
            "UPDATE devices SET trusted = ? WHERE device_id = ?",
            (int(trusted), device_id),
        )
