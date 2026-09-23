"""Unit tests for the dashboard's render components, under node with a
minimal DOM -- the pieces the page is built from, each driven from a fixture
and inspected without standing up the API.

Covered here:

* viz.js  -- ring (posture donut + score), coverageHead (the combined
  measured-and-passing score), networkCounts (the three-valued network
  domain), severityBar, tile, postureBanner (verdict + deduped chips).
* app.js  -- alertRow (the xN dupes chip), rollupRows (identical-title
  roll-up), and the per-alert response checklist: coverage of every rule
  in the live database, phase rendering + progress, ticking a step
  persisting to localStorage and completing a phase, and the privacy mask
  reaching the gateway address inside a checklist step.

The event log has its own file (test_ui_eventlog.py); this one is the rest.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

from pnma.api import app as api

NODE = shutil.which("node")

# A DOM just big enough for el()/svg()/clear() and the components' own reads.
# svg nodes are real Nodes too (not stubs) so a ring's score text is visible;
# localStorage is a working in-memory store, except the privacy key which is
# driven by the MASK env so the mask can be exercised.
HARNESS_HEAD = r"""
class Node {
  constructor(tag) { this.tagName = String(tag).toUpperCase(); this.attrs = {}; this.children = []; this._text = ''; this.listeners = {}; this.dataset = {}; this.style = {}; this.hidden = false; this.checked = false; }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'class') this.className = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  appendChild(c) { if (c == null) return c; if (typeof c === 'string') c = document.createTextNode(c); c.parentNode = this; this.children.push(c); return c; }
  removeChild(c) { this.children = this.children.filter((x) => x !== c); }
  get firstChild() { return this.children[0] || null; }
  get lastChild() { return this.children[this.children.length - 1] || null; }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
  set textContent(v) { this._text = String(v); this.children = []; }
  addEventListener(t, fn) { (this.listeners[t] = this.listeners[t] || []).push(fn); }
  fire(t) { (this.listeners[t] || []).forEach((fn) => fn({ target: this, preventDefault() {} })); }
  click() { this.fire('click'); }
  get classList() { const self = this; return { add(c) { self.className = ((self.className || '') + ' ' + c).trim(); }, remove(c) { self.className = (self.className || '').split(' ').filter((x) => x !== c).join(' '); }, toggle(c, on) { const has = (self.className || '').split(' ').includes(c); const want = on === undefined ? !has : on; this[want ? 'add' : 'remove'](c); }, contains(c) { return (self.className || '').split(' ').includes(c); } }; }
  all() { return [this].concat(...this.children.filter((c) => c instanceof Node).map((c) => c.all())); }
  querySelectorAll(sel) { const cls = sel.replace(/^\./, ''); return this.all().filter((n) => n !== this && (n.className || '').split(' ').includes(cls)); }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
}
class Text { constructor(t) { this.textContent = String(t); } }
const __store = {};
globalThis.window = globalThis;
globalThis.localStorage = {
  getItem: (k) => k === 'pnma.privacy' ? process.env.MASK : (k in __store ? __store[k] : null),
  setItem: (k, v) => { __store[k] = String(v); },
  removeItem: (k) => { delete __store[k]; },
};
globalThis.__store = __store;
globalThis.location = { hash: '', search: '', reload: () => {} };
globalThis.history = { replaceState: () => {} };
globalThis.document = {
  addEventListener: () => {}, getElementById: () => null, querySelectorAll: () => [], querySelector: () => null,
  createElement: (t) => new Node(t), createTextNode: (t) => new Text(t),
  createElementNS: (ns, t) => new Node(t), hidden: false,
  body: new Node('body'), documentElement: new Node('html'), dispatchEvent() {},
};
globalThis.CustomEvent = class {};
globalThis.requestAnimationFrame = (fn) => fn();
globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => ({}), text: async () => '{}' });
globalThis.setInterval = () => 0; globalThis.setTimeout = (fn) => 0; globalThis.clearTimeout = () => {};
require(process.argv[2]); require(process.argv[3]);
const V = window.PNMA.__viz;
const A = window.PNMA.__alerts;
const out = {};
"""

HARNESS_TAIL = "\nconsole.log(JSON.stringify(out));\n"


def _run(tmp_path, body: str, mask: str = "0"):
    assert NODE, "node not installed"
    harness = tmp_path / "h.js"
    harness.write_text(HARNESS_HEAD + body + HARNESS_TAIL, encoding="utf-8")
    env = dict(os.environ, MASK=mask)
    r = subprocess.run(
        [NODE, str(harness), str(api.WEB_DIR / "viz.js"), str(api.WEB_DIR / "app.js")],
        capture_output=True, text=True, encoding="utf-8", timeout=30, check=False, env=env,
    )
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


pytestmark = pytest.mark.skipif(NODE is None, reason="node not installed")


# ----------------------------------------------------------------- viz.js

def test_ring_score_is_ok_over_total(tmp_path):
    out = _run(tmp_path, r"""
    const card = V.ring('Host', { ok: 5, finding: 10, unknown: 5 }, 'sub', { unit: 'check' });
    out.text = card.textContent;
    out.arcs = card.querySelectorAll('ring__arc').length;   // three states present -> 3 arcs
    const empty = V.ring('Identity', { ok: 0, finding: 0, unknown: 0 }, 'none', { unit: 'control' });
    out.emptyText = empty.textContent;
    """)
    assert "25%" in out["text"]          # 5 / 20
    assert out["arcs"] == 3
    assert "20 checks" in out["text"]
    assert "no data" in out["emptyText"] and "—" in out["emptyText"]


def test_coverage_head_combines_three_domains(tmp_path):
    out = _run(tmp_path, r"""
    const net = { ok: 10, finding: 2, unknown: 0 };
    const hs = { ok: 5, finding: 10, unknown: 4 };
    const is = { ok: 5, finding: 1, unknown: 15 };
    out.text = V.coverageHead(net, hs, is).textContent;      // 20 ok / 52 total
    out.empty = V.coverageHead({ok:0,finding:0,unknown:0},{ok:0,finding:0,unknown:0},{ok:0,finding:0,unknown:0}).textContent;
    """)
    assert "38%" in out["text"]                 # round(20/52*100)
    assert "measured and passing" in out["text"]
    assert "32 points to win back" in out["text"]   # 52 - 20
    assert "—" in out["empty"] and "nothing measured yet" in out["empty"]
    assert "measured and passing" not in out["empty"]   # honest empty state


def test_network_counts_are_three_valued(tmp_path):
    out = _run(tmp_path, r"""
    const now = Date.now() / 1000;
    const devices = [
      { trusted: true, last_seen: now - 10 },              // ok
      { trusted: false, last_seen: now - 10 },             // finding (seen today, untrusted)
      { trusted: true, last_seen: now - 200000 },          // unknown (stale > 1d)
      { trusted: false, last_seen: now - 200000 },         // unknown (stale beats trust)
    ];
    out.c = V.networkCounts(devices);
    """)
    assert out["c"] == {"ok": 1, "finding": 1, "unknown": 2}


def test_severity_bar_segments_and_empty(tmp_path):
    out = _run(tmp_path, r"""
    const bar = V.severityBar({ critical: 1, high: 2, medium: 0, low: 3 });
    out.segs = bar.querySelectorAll('sevbar__seg').length;   // three non-zero severities
    out.empty = V.severityBar({}).textContent;
    """)
    assert out["segs"] == 3
    assert "no open alerts" in out["empty"]


def test_posture_banner_verdict_and_chip_dedup(tmp_path):
    out = _run(tmp_path, r"""
    const summary = { alerts: { open: 6, by_severity: { critical: 1, high: 2, medium: 3 } }, generated_at: Date.now()/1000 };
    const alerts = [
      { id: 1, severity: 'critical', rule_id: 'arp_spoof', title: 'gateway claimed' },
      { id: 2, severity: 'high', rule_id: 'suspicious_powershell', title: 'ps a' },
      { id: 3, severity: 'high', rule_id: 'suspicious_powershell', title: 'ps b' },   // same rule+sev -> folds
      { id: 4, severity: 'medium', rule_id: 'host_posture', title: 'setting' },       // not chipped (only crit/high)
    ];
    const devices = [{ online: true }, { online: false }];
    const pb = V.postureBanner(summary, alerts, 5, devices);
    out.verdict = pb.querySelector('pb__verdict').textContent;
    out.chips = pb.querySelectorAll('pb__chip').length;
    out.text = pb.textContent;
    """)
    assert out["verdict"] == "Action needed now"       # a critical is open
    assert out["chips"] == 2                            # arp_spoof + one folded suspicious_powershell
    assert "×2" in out["text"]                    # the folded chip shows x2
    assert "1 critical, 2 high, 3 medium open" in out["text"]


# ----------------------------------------------------------------- app.js

def test_alert_row_shows_dupes_chip(tmp_path):
    out = _run(tmp_path, r"""
    const a = { id: 9, severity: 'medium', rule_id: 'suspicious_powershell', title: 'encoded_command', status: 'open', last_seen: Date.now()/1000 };
    const one = A.alertRow(a, () => {}, null, 1);
    const many = A.alertRow(a, () => {}, null, 15);
    out.oneHasChip = !!one.querySelector('alertrow__dupes');
    out.manyChip = many.querySelector('alertrow__dupes') ? many.querySelector('alertrow__dupes').textContent : null;
    """)
    assert out["oneHasChip"] is False
    assert out["manyChip"] == "×15"


def test_rollup_groups_identical_titles_and_opens_newest(tmp_path):
    out = _run(tmp_path, r"""
    const base = { severity: 'medium', rule_id: 'suspicious_powershell', title: 'encoded_command', status: 'open' };
    const run = [
      Object.assign({ id: 1, last_seen: 100 }, base),
      Object.assign({ id: 2, last_seen: 300 }, base),      // newest of this group
      Object.assign({ id: 3, last_seen: 200 }, base),
      { id: 4, severity: 'medium', rule_id: 'autorun_changed', title: 'new autorun', status: 'open', last_seen: 150 },
    ];
    let opened = null;
    const rows = A.rollupRows(run, (a) => { opened = a.id; }, null);
    out.rowCount = rows.length;                            // two groups
    out.firstChip = rows[0].querySelector('alertrow__dupes') ? rows[0].querySelector('alertrow__dupes').textContent : null;
    rows[0].fire('click');
    out.opened = opened;                                  // opens the newest in the group
    """)
    assert out["rowCount"] == 2
    assert out["firstChip"] == "×3"
    assert out["opened"] == 2


def test_checklist_covers_every_live_rule(tmp_path):
    out = _run(tmp_path, r"""
    // Every rule id seen in the production database must resolve to a family,
    // and no family may be empty.
    const live = ['suspicious_powershell','new_external_destination','host_posture','new_device',
      'autorun_changed','service_installed','unmeasured_control','profile_deviation','arp_spoof',
      'beaconing','control_disabled','cve_exposure','hidden_dir_created','identity_posture',
      'identity_unreviewed','service_drift','upload_spike','availability'];
    const missing = [];
    for (const r of live) { const fam = A.RULE_CHECKLIST[r]; if (!fam || !A.CHECKLIST[fam]) missing.push(r); }
    out.missing = missing;
    const phases = ['confirm','investigate','contain','remediate','verify'];
    const empty = [];
    for (const [k, v] of Object.entries(A.CHECKLIST)) {
      let n = 0; for (const p of phases) { if (Array.isArray(v[p])) n += v[p].length; }
      if (n === 0) empty.push(k);
    }
    out.empty = empty;
    out.families = Object.keys(A.CHECKLIST).length;
    """)
    assert out["missing"] == []
    assert out["empty"] == []
    assert out["families"] >= 12


def test_checklist_renders_phases_with_progress(tmp_path):
    out = _run(tmp_path, r"""
    const alert = { id: 42, rule_id: 'beaconing', severity: 'high' };
    const ck = A.checklistFor(alert);
    out.phases = ck.querySelectorAll('checklist__phase').length;
    out.steps = ck.querySelectorAll('checklist__step').length;
    out.progress = ck.querySelector('checklist__count').textContent;
    """)
    assert out["phases"] == 5                    # beaconing/host_network defines all five
    assert out["steps"] >= 5
    assert out["progress"].startswith("0 / ") and out["progress"].endswith(" done")


def test_checklist_tick_persists_and_completes_phase(tmp_path):
    out = _run(tmp_path, r"""
    const alert = { id: 77, rule_id: 'host_posture', severity: 'medium' };  // confirm has 1 step
    const ck = A.checklistFor(alert);
    const confirm = ck.querySelectorAll('checklist__phase')[0];
    const boxes = confirm.querySelectorAll('checklist__box');
    out.confirmSteps = boxes.length;
    boxes.forEach((b) => { b.checked = true; b.fire('change'); });
    out.phaseComplete = confirm.classList.contains('is-complete');
    out.stored = JSON.parse(window.__store['hearth.ck.77'] || '[]').length;
    out.progressAfter = ck.querySelector('checklist__count').textContent;
    // A fresh render reads the saved state back.
    const ck2 = A.checklistFor(alert);
    out.restored = ck2.querySelectorAll('checklist__step').filter((n) => n.classList.contains('is-done')).length;
    """)
    assert out["confirmSteps"] == 1
    assert out["phaseComplete"] is True
    assert out["stored"] == 1
    assert out["progressAfter"].startswith("1 / ")
    assert out["restored"] == 1


def test_alert_row_masks_identifiers(tmp_path):
    # Every identifier in a row goes through el(), so the privacy mask applies
    # to the alert queue exactly as it does to the log. A title carrying an IP
    # and a MAC is the case that would leak through a textContent shortcut.
    body = r"""
    const a = { id: 3, severity: 'high', rule_id: 'arp_spoof', status: 'open', last_seen: Date.now()/1000,
                title: 'gateway 192.168.0.1 answered by aa:bb:cc:dd:ee:ff' };
    out.text = A.alertRow(a, () => {}, null, 1).textContent;
    """
    on = _run(tmp_path, body, mask="1")
    assert "192.168.0.1" not in on["text"] and "aa:bb:cc:dd:ee:ff" not in on["text"]
    off = _run(tmp_path, body, mask="0")
    assert "192.168.0.1" in off["text"] and "aa:bb:cc:dd:ee:ff" in off["text"]
