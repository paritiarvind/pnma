"""A port scan must be able to account for its own effect on the network.

On 2026-08-24 the first live scan was followed by a printer that answered
nothing, and there was no way to tell whether the scan had knocked it over or it
had gone to sleep on its own -- the last availability sample predated the scan by
thirty minutes. `PortScanCollector` now brackets every batch with an ICMP sample
of its own targets, so that question is answerable from the database.

These tests pin the three outcomes that matter, especially the exonerating one:
a host that was already silent before the scan must never be reported as
something the scan silenced.

Runnable as `pytest tests/` or `python tests/test_portscan_liveness.py`.
"""

from __future__ import annotations

import sys
import tempfile
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pnma.collectors import portscan as portscan_mod  # noqa: E402
from pnma.collectors.portscan import PortScanCollector  # noqa: E402
from pnma.config import ScanConfig  # noqa: E402
from pnma.db import Database  # noqa: E402

ALICE = "192.168.0.10"
BOB = "192.168.0.11"


def make_collector() -> tuple[PortScanCollector, Database]:
    """A collector wired to a real database and a stub guard.

    The guard is stubbed rather than constructed because these tests are about
    what gets recorded, not about authorisation -- and `_scan_batch` is reached
    below the guard, which `scan()` has already applied to the target list.
    """
    path = Path(tempfile.mkdtemp(prefix="pnma-liveness-test-")) / "t.db"
    db = Database(str(path))
    for device_id, ip in (("dev-alice", ALICE), ("dev-bob", BOB)):
        db.execute(
            "INSERT INTO devices(device_id, mac, mac_type, ip, first_seen, last_seen) "
            "VALUES(?,?,?,?,?,?)",
            (device_id, f"aa:bb:cc:00:00:0{device_id[-1]}", "global", ip, 0, 0),
        )
    guard = types.SimpleNamespace(config=types.SimpleNamespace(scan=ScanConfig()))
    return PortScanCollector(db, guard, "test-sensor"), db


# A complete, well-formed nmap document reporting its own failure: this is what
# a refused raw socket actually produces. Note the zero <host> elements and
# exit="error" -- parsed naively it is indistinguishable from a clean scan that
# found no open ports.
NMAP_ERROR_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -oX -" start="1788321320" version="7.99">
<scaninfo type="syn" protocol="tcp" numservices="100" services="7,9,13"/>
<runstats><finished time="1788321321" exit="error"
  errormsg="Couldn't open a raw socket or eth handle."/>
<hosts up="1" down="0" total="0"/></runstats>
</nmaprun>"""

NMAP_OK_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -oX -" start="1788321320" version="7.99">
<runstats><finished time="1788321321" exit="success"/></runstats>
</nmaprun>"""


def run_batch(
    collector,
    db,
    *,
    before: dict,
    after: dict,
    nmap_fails: bool = False,
    stdout: str = NMAP_OK_XML,
    returncode: int = 0,
    stderr: str = "",
):
    """Drive `_scan_batch` with scripted ping results and no real nmap."""
    # Which sample we are serving is driven by whether the scan has run, not by
    # a ping counter. Counting assumes each phase issues exactly len(batch)
    # probes in a stable order -- true today, but if _sample_liveness ever
    # retries or dedupes, a counter silently starts serving the wrong table and
    # the tests keep passing while measuring the wrong thing.
    phase = {"scanned": False}

    def fake_ping(ip, timeout_s=2):
        return (after if phase["scanned"] else before)[ip]

    def fake_run(*_args, **_kwargs):
        phase["scanned"] = True
        if nmap_fails:
            raise OSError("nmap exploded")
        return types.SimpleNamespace(
            stdout=stdout, returncode=returncode, stderr=stderr
        )

    real_ping, real_run = portscan_mod.ping_host, portscan_mod.subprocess.run
    portscan_mod.ping_host = fake_ping
    portscan_mod.subprocess.run = fake_run
    try:
        collector._scan_batch([ALICE, BOB], deep=False)
    finally:
        portscan_mod.ping_host = real_ping
        portscan_mod.subprocess.run = real_run

    return db.query_one(
        "SELECT * FROM scan_runs WHERE kind = 'port_scan' ORDER BY id DESC LIMIT 1"
    )


UP = (True, 4.0)
DOWN = (False, None)


def test_both_samples_are_written_to_availability():
    """Two targets, bracketed, must leave four availability points.

    This is what closes the thirty-minute gap: the history now contains a
    reading immediately either side of every scan, rather than whatever the
    ping collector happened to record last.
    """
    c, db = make_collector()
    run_batch(c, db, before={ALICE: UP, BOB: UP}, after={ALICE: UP, BOB: UP})

    rows = db.query("SELECT device_id, reachable FROM availability ORDER BY ts")
    assert len(rows) == 4, f"expected 4 samples, got {len(rows)}"
    assert {r["device_id"] for r in rows} == {"dev-alice", "dev-bob"}
    assert all(r["reachable"] == 1 for r in rows)


def test_host_that_stops_answering_is_named_in_the_audit_trail():
    """Up before, silent after: the address must be named, not counted."""
    c, db = make_collector()
    row = run_batch(c, db, before={ALICE: UP, BOB: UP}, after={ALICE: UP, BOB: DOWN})

    assert "stopped answering across the scan" in row["result"]
    assert BOB in row["result"], row["result"]
    assert ALICE not in row["result"].split("stopped answering")[1]


def test_already_silent_host_is_not_blamed_on_the_scan():
    """The printer case, and the reason the bracket is worth the packets.

    A host that was ignoring ICMP *before* the scan cannot have been silenced by
    it. Reporting it as scan-induced would manufacture exactly the false
    attribution this feature exists to prevent.
    """
    c, db = make_collector()
    row = run_batch(c, db, before={ALICE: UP, BOB: DOWN}, after={ALICE: UP, BOB: DOWN})

    assert "stopped answering" not in row["result"], row["result"]
    assert "icmp 1/2 before, 1/2 after" in row["result"], row["result"]


def test_liveness_is_recorded_even_when_nmap_fails():
    """A scan that errored still sent packets, so it still needs accounting for.

    Recording only on the success path would leave the noisiest runs -- timeouts
    and crashes, the ones most likely to have disturbed something -- as the ones
    with no evidence either way.
    """
    c, db = make_collector()
    row = run_batch(
        c, db,
        before={ALICE: UP, BOB: UP},
        after={ALICE: UP, BOB: DOWN},
        nmap_fails=True,
    )

    assert row["error"], "the nmap failure must still be recorded"
    assert "icmp" in (row["result"] or ""), "liveness missing from a failed scan"
    assert BOB in row["result"]
    assert len(db.query("SELECT 1 FROM availability")) == 4


def test_nmap_failure_in_valid_xml_is_not_recorded_as_a_clean_scan():
    """The refusal-shaped-as-an-answer case, and the one that actually bit.

    A refused raw socket makes nmap quit while still emitting a complete XML
    document: zero hosts, and the failure only in `runstats/finished[@exit]`.
    Parsed naively that is "0 open ports" -- a clean bill of health for a scan
    that never sent a packet, which is the most dangerous sentence this tool can
    write. Seen live on 2026-09-02 against the real gateway.
    """
    c, db = make_collector()
    row = run_batch(
        c, db,
        before={ALICE: UP, BOB: UP},
        after={ALICE: UP, BOB: UP},
        stdout=NMAP_ERROR_XML,
    )

    assert row["error"], "a failed scan must not be recorded with error=None"
    assert "raw socket" in row["error"], row["error"]
    assert "open ports" not in (row["result"] or ""), (
        f"a scan that never ran must not claim port results: {row['result']!r}"
    )
    assert "icmp" in (row["result"] or ""), "liveness is still worth recording"


def test_nonzero_exit_is_reported_even_with_parseable_output():
    """Exit status is checked independently of what nmap printed."""
    c, db = make_collector()
    row = run_batch(
        c, db,
        before={ALICE: UP, BOB: UP},
        after={ALICE: UP, BOB: UP},
        returncode=2,
        stderr="strange error\nQUITTING!",
    )
    assert row["error"] and "exited 2" in row["error"], row["error"]
    assert "QUITTING!" in row["error"]


def test_a_genuinely_clean_scan_is_still_clean():
    """The guard must not turn every empty result into an error.

    A scan that ran correctly and found nothing open is a real and common
    outcome -- four of the five devices in the 2026-08-24 house scan were
    exactly this. It has to stay distinguishable from a scan that failed.
    """
    c, db = make_collector()
    row = run_batch(c, db, before={ALICE: UP, BOB: UP}, after={ALICE: UP, BOB: UP})

    assert row["error"] is None, f"clean scan reported an error: {row['error']!r}"
    assert "0 open ports across 2 hosts" in row["result"]


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
            print(f"PASS  {name}")
        except AssertionError as exc:
            failures += 1
            print(f"FAIL  {name}\n      {exc}")
    print(f"\n{failures} failed")
    sys.exit(1 if failures else 0)
