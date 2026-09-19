"""The vendor table must be checkable against its source.

`_BUILTIN` is hand-written, and on 2026-08-24 its very first entry identified the
author's own gateway as ARRIS when the IEEE registry says TP-Link. Vendor feeds
device classification, profiling, and the written advice built on top of those,
so a wrong entry does not stay a cosmetic error. Comparing against the registry
found twelve more on 2026-09-02.

These tests pin the machinery that catches the next one, and the two rules that
keep a registry refresh from doing damage of its own: deliberate aliases must
survive it, and "Private" must not be presented as a vendor.

Runnable as `pytest tests/` or `python tests/test_oui.py`.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pnma import oui as oui_mod  # noqa: E402


class Skipped(Exception):
    """A test that did not run. Reported as SKIP, never counted as a pass."""


try:  # pragma: no cover - depends on whether pytest is installed
    import pytest

    skip = pytest.skip
except ImportError:
    def skip(reason: str):
        raise Skipped(reason)

# Real rows from the IEEE registry, including the two shapes that break naive
# parsers: an organisation name containing a comma inside quotes, and a block
# whose assignee withheld their name.
REGISTRY_CSV = '''Registry,Assignment,Organization Name,Organization Address
MA-L,98038E,TP-Link Systems Inc.,10 Mauchly  Irvine CA US 92618
MA-L,E80AB9,"Cisco Systems, Inc",80 West Tasman Drive San Jose CA US 94568
MA-L,ACDE48,Private,
MA-L,080027,PCS Systemtechnik GmbH,Muenchen DE
MA-L,D073D5,LIFI LABS MANAGEMENT PTY LTD,Melbourne AU
MA-M,0055DA0,Some Smaller Block Holder,Somewhere
'''


def registry() -> dict[str, str]:
    return oui_mod.parse_registry(REGISTRY_CSV)


def test_quoted_commas_survive_parsing():
    """A quarter of registry rows quote a comma inside the org name.

    Hand-splitting on "," turns "Cisco Systems, Inc" into "Cisco Systems" and
    silently drops the rest, which looks plausible enough to go unnoticed.
    """
    assert registry()["e8:0a:b9"] == "Cisco Systems, Inc"


def test_only_ma_l_blocks_are_imported():
    """MA-M and MA-S blocks share a 24-bit prefix between several assignees.

    Keying them on three octets would attribute a device to whichever assignee
    happened to be parsed last -- a confident answer with no basis.
    """
    assert "00:55:da" not in registry()


def test_private_is_not_treated_as_a_vendor():
    """The registry's way of saying the assignee withheld their name.

    Rendered on a dashboard, "Private" reads as a company called Private, which
    is worse than "unknown vendor" because it looks like an answer.
    """
    assert "ac:de:48" not in registry()


def test_check_builtins_catches_a_wrong_entry():
    """The regression test for the defect that started this: the gateway OUI."""
    original = dict(oui_mod._BUILTIN)
    try:
        oui_mod._BUILTIN["98:03:8e"] = "ARRIS / CommScope"
        found = oui_mod.check_builtins(registry())
        assert any(
            oui == "98:03:8e" and theirs == "TP-Link Systems Inc."
            for oui, _ours, theirs in found
        ), f"the ARRIS mislabel was not caught: {found}"
    finally:
        oui_mod._BUILTIN.clear()
        oui_mod._BUILTIN.update(original)


def test_check_builtins_ignores_deliberate_aliases():
    """Aliases disagree on purpose, so the check must not report them.

    If intentional overrides showed up as findings, the output would be noise
    and the next real mislabel would be read as more of the same.
    """
    assert "08:00:27" in oui_mod._ALIASES
    reported = {oui for oui, _, _ in oui_mod.check_builtins(registry())}
    assert "08:00:27" not in reported
    assert "d0:73:d5" not in reported


def test_the_shipped_builtin_table_agrees_with_its_source():
    """Guards the real table, not a fixture.

    Fails if someone hand-edits `_BUILTIN` with a vendor the registry
    contradicts -- which is exactly how the original defect got in.

    Skips, loudly, when no vendored CSV is present: there is genuinely nothing
    to compare against, but a guard that quietly returns is the same shape as
    the bug this module exists to prevent, so it must never read as a pass.
    """
    if not oui_mod._OUI_FILE.exists():
        skip("no vendored oui.csv to check against -- run `pnma oui-update`")
    import csv

    with oui_mod._OUI_FILE.open(newline="", encoding="utf-8") as fh:
        table = {r[0]: r[1] for r in csv.reader(fh) if len(r) >= 2}
    mismatches = oui_mod.check_builtins(table)
    assert not mismatches, "built-in table contradicts the vendored registry: " + str(
        mismatches
    )


def test_aliases_survive_a_registry_refresh():
    """A refresh must not rename LIFX to its registrant's legal name.

    `is_iot_vendor` matches "lifx" as a substring, so losing the alias would
    also lose the IoT classification and, with it, the scan-fragility guard that
    keeps version probes away from the device.
    """
    tmp = Path(tempfile.mkdtemp(prefix="pnma-oui-test-")) / "oui.csv"
    real_file, real_cache = oui_mod._OUI_FILE, oui_mod._cache
    try:
        oui_mod.write_table(registry(), path=tmp)
        oui_mod._OUI_FILE = tmp
        oui_mod._cache = None

        assert oui_mod.lookup("d0:73:d5:11:22:33") == "LIFX"
        assert oui_mod.is_iot_vendor("d0:73:d5:11:22:33")
        assert oui_mod.lookup("08:00:27:11:22:33") == "Oracle VirtualBox"
        # ...while a plain registry entry comes through unchanged.
        assert oui_mod.lookup("98:03:8e:00:11:22") == "TP-Link Systems Inc."
    finally:
        oui_mod._OUI_FILE, oui_mod._cache = real_file, real_cache


def test_write_table_replaces_atomically():
    """A truncated download must not be able to destroy a working table."""
    tmp = Path(tempfile.mkdtemp(prefix="pnma-oui-test-")) / "oui.csv"
    oui_mod.write_table({"aa:bb:cc": "First Vendor"}, path=tmp)
    assert "First Vendor" in tmp.read_text(encoding="utf-8")

    oui_mod.write_table(registry(), path=tmp)
    body = tmp.read_text(encoding="utf-8")
    assert "First Vendor" not in body, "the replacement must be complete"
    assert "TP-Link Systems Inc." in body
    assert not tmp.with_name(tmp.name + ".tmp").exists(), "temp file left behind"


if __name__ == "__main__":
    failures = skipped = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
            print(f"PASS  {name}")
        except Skipped as exc:
            skipped += 1
            print(f"SKIP  {name}")
            print(f"      {exc}")
        except AssertionError as exc:
            failures += 1
            print(f"FAIL  {name}")
            print(f"      {exc}")
    print()
    print(f"{failures} failed, {skipped} skipped")
    sys.exit(1 if failures else 0)
