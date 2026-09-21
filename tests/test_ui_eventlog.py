"""The eventLog component, under node with a minimal DOM.

What the drawer's Investigation log and the Logs tab both rely on:

* consecutive identical agent rows fold into one row with a count;
* the "alert raised" marker lands in sequence, not at an end;
* the kind chips and the agent toggle filter in place;
* every identifier in a row goes through el(), so the privacy mask applies
  to log rows exactly as it does to the rest of the page. Raw log rows are
  the densest source of MACs and IPs on the dashboard, which makes this the
  one place a textContent shortcut would leak.
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from pnma.api import app as api

NODE = shutil.which("node")

HARNESS = r"""
// A DOM just big enough for el()/clear() and the component's own reads.
class Node {
  constructor(tag) { this.tagName = tag.toUpperCase(); this.attrs = {}; this.children = []; this._text = ''; this.listeners = {}; this.dataset = {}; this.style = {}; this.hidden = false; }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'class') this.className = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  appendChild(c) { if (c == null) return c; if (typeof c === 'string') c = document.createTextNode(c); c.parentNode = this; this.children.push(c); return c; }
  removeChild(c) { this.children = this.children.filter((x) => x !== c); }
  get firstChild() { return this.children[0] || null; }
  get lastChild() { return this.children[this.children.length - 1] || null; }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
  set textContent(v) { this._text = String(v); this.children = []; }
  addEventListener(t, fn) { (this.listeners[t] = this.listeners[t] || []).push(fn); }
  click() { (this.listeners.click || []).forEach((fn) => fn({ target: this, preventDefault() {} })); }
  get classList() { const self = this; return { add(c) { self.className = ((self.className || '') + ' ' + c).trim(); }, remove(c) { self.className = (self.className || '').split(' ').filter((x) => x !== c).join(' '); }, toggle() {}, contains(c) { return (self.className || '').split(' ').includes(c); } }; }
  all() { return [this].concat(...this.children.filter((c) => c instanceof Node).map((c) => c.all())); }
  querySelectorAll(sel) { const cls = sel.replace(/^\./, ''); return this.all().filter((n) => n !== this && (n.className || '').split(' ').includes(cls)); }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
}
class Text { constructor(t) { this.textContent = String(t); } }
globalThis.window = globalThis;
globalThis.localStorage = { getItem: (k) => k === 'pnma.privacy' ? process.env.MASK : null, setItem: () => {} };
globalThis.location = { hash: '', reload: () => {} };
globalThis.history = { replaceState: () => {} };
globalThis.document = {
  addEventListener: () => {}, getElementById: () => null, querySelectorAll: () => [], querySelector: () => null,
  createElement: (t) => new Node(t), createTextNode: (t) => new Text(t),
  createElementNS: () => ({ setAttribute() {}, appendChild() {} }), hidden: false,
  body: new Node('body'), documentElement: new Node('html'), dispatchEvent() {},
};
globalThis.CustomEvent = class {};
globalThis.requestAnimationFrame = (fn) => fn();
globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => ({}) });
globalThis.setInterval = () => 0; globalThis.setTimeout = (fn) => 0; globalThis.clearTimeout = () => {};
require(process.argv[2]); require(process.argv[3]);
const now = Date.now() / 1000;
const rows = [];
for (let i = 0; i < 25; i++) rows.push({ ts: now - 3000 + i * 60, kind: 'scan', source: 'arp_table_read', summary: 'arp table read 10.20.30.0/24: 12 devices', agent_generated: true, detail: {} });
rows.push({ ts: now - 3100, kind: 'observation', source: 'passive_arp', summary: '10.20.30.1 is 98:03:8e:e9:a2:11 (passive_arp)', entity: '10.20.30.1', agent_generated: false, detail: { mac: '98:03:8e:e9:a2:11', ip: '10.20.30.1' } });
rows.push({ ts: now - 1000, kind: 'alert', source: 'arp_spoof', summary: 'critical: GATEWAY IP 10.20.30.1 claimed', entity: 'x', agent_generated: false, detail: { alert_id: 7, severity: 'critical' } });
const log = window.PNMA.eventLog(rows, { markerTs: now - 2000, markerText: 'RAISED' });
const rowsOf = () => log.querySelectorAll('evlog__row');
const out = {};
out.rendered = rowsOf().length;                                  // 25 fold to 1, +2
out.folded = rowsOf()[1].querySelector('evlog__count') ? rowsOf()[1].querySelector('evlog__count').textContent : null;
const seq = log.querySelector('evlog__rows').children.map((c) => (c.className || '').includes('evlog__marker') ? 'MARKER' : c.className.split(' ')[1]);
out.sequence = seq;
out.text = log.textContent;
out.sevClass = rowsOf()[2].className;
const chips = log.querySelectorAll('evlog__chip');
out.chipNames = chips.map((c) => c.textContent);
chips.find((c) => c.textContent.startsWith('hide')).click();     // hide agent rows
out.afterHide = rowsOf().length;
chips.find((c) => c.textContent.startsWith('alert')).click();    // only alerts
out.afterKind = rowsOf().length;
log.refresh(rows.slice(25));                                     // live refresh keeps filters
out.afterRefresh = rowsOf().length;
console.log(JSON.stringify(out));
"""


def _run(tmp_path, mask: str):
    harness = tmp_path / "h.js"
    harness.write_text(HARNESS, encoding="utf-8")
    import os
    env = dict(os.environ, MASK=mask)
    r = subprocess.run([NODE, str(harness), str(api.WEB_DIR / "viz.js"), str(api.WEB_DIR / "app.js")],
                       capture_output=True, text=True, encoding="utf-8", timeout=30, check=False, env=env)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


@pytest.mark.skipif(NODE is None, reason="node not installed")
def test_eventlog_folds_marks_and_filters(tmp_path):
    out = _run(tmp_path, "0")
    assert out["rendered"] == 3
    assert out["folded"] == "\u00d725"
    assert out["sequence"] == ["evlog__row--observation", "evlog__row--scan", "MARKER", "evlog__row--alert"]
    assert "evlog__row--sev-critical" in out["sevClass"]
    assert out["chipNames"][:3] == ["seen1", "agent25", "alert1"] and out["chipNames"][-1].startswith("hide")
    assert out["afterHide"] == 2
    assert out["afterKind"] == 1
    assert out["afterRefresh"] == 1
    assert "98:03:8e:e9:a2:11" in out["text"]           # unmasked: the real identifier is shown


@pytest.mark.skipif(NODE is None, reason="node not installed")
def test_eventlog_rows_are_masked_when_privacy_is_on(tmp_path):
    out = _run(tmp_path, "1")
    assert "98:03:8e:e9:a2:11" not in out["text"]
    assert "98:03:8e:\u00b7\u00b7:\u00b7\u00b7:11" in out["text"]
    assert "10.20.30.1 " not in out["text"] and "\u00b7.\u00b7.\u00b7.1" in out["text"]
