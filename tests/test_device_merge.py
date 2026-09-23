"""A randomised-MAC device must not show up twice.

fingerprint.resolve_identity gives a device an ephemeral id ('e:', from its
MAC) until its DHCP fingerprint or hostname appears, then a durable id ('f:',
from that fingerprint). The two are meant to merge; inventory.observe now does
it. This guards that: the ephemeral row and all its history fold into the
durable one, keeping the earliest first_seen and any trust the operator set --
the fix for the duplicate device rows found on the live host.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from pnma import inventory
from pnma.db import Database

LOCAL_MAC = "02:11:22:33:44:55"   # locally-administered (randomised) address


def _db():
    return Database(Path(tempfile.mkdtemp()) / "t.db")


def test_ephemeral_device_merges_into_its_fingerprint_identity():
    db = _db()

    # First sighting: randomised MAC, nothing else -> ephemeral 'e:' identity.
    e_id = inventory.observe(db, mac=LOCAL_MAC, ip="192.168.0.50", source="arp_table_read", sensor_id="s1")
    assert e_id.startswith("e:")

    # The operator trusts it and it accrues history under the ephemeral id.
    inventory.set_trusted(db, e_id, True, label="Kid's phone")
    db.raise_alert(dedup_key="k1", rule_id="new_device", severity="low", title="seen", device_id=e_id)
    first_seen_before = db.query_one("SELECT first_seen FROM devices WHERE device_id = ?", (e_id,))["first_seen"]

    # Later the device offers a hostname -> durable 'f:' identity; the two merge.
    f_id = inventory.observe(db, mac=LOCAL_MAC, ip="192.168.0.50", source="passive_dhcp",
                             sensor_id="s1", hostname="kids-iphone", ts=first_seen_before + 3600)
    assert f_id.startswith("f:")
    assert f_id != e_id

    # Exactly one device row now, and it is the durable one.
    rows = db.query("SELECT device_id, first_seen, trusted, label FROM devices")
    assert len(rows) == 1
    row = rows[0]
    assert row["device_id"] == f_id
    assert db.query_one("SELECT 1 FROM devices WHERE device_id = ?", (e_id,)) is None

    # History and operator intent carried over.
    assert row["trusted"] == 1
    assert row["label"] == "Kid's phone"
    assert row["first_seen"] == first_seen_before            # earliest kept
    moved = db.query_one("SELECT device_id FROM alerts WHERE dedup_key = 'k1'")
    assert moved["device_id"] == f_id                        # the alert followed the device


def test_merge_is_a_noop_without_an_ephemeral_row():
    db = _db()
    # A device that presents a hostname immediately gets an 'f:' id with no
    # prior ephemeral row; nothing to merge, one clean row.
    f_id = inventory.observe(db, mac=LOCAL_MAC, ip="192.168.0.51", source="passive_dhcp",
                             sensor_id="s1", hostname="printer")
    assert f_id.startswith("f:")
    assert db.query_one("SELECT COUNT(*) c FROM devices")["c"] == 1
