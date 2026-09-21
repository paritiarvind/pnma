/* PNMA dashboard: navigation, privacy mask, and the graphical panels.
 *
 * Loaded before app.js. Owns the things that span panels -- the tab bar, the
 * bearer-token gate, the privacy mask that every string on the page passes
 * through -- and the panels that draw rather than list: posture rings, the
 * network map, the activity swimlane, the attack-surface bars, the ATT&CK
 * matrix, identity attestation and the agent's self-report.
 *
 * All drawing is inline SVG built with createElementNS. No chart library:
 * the page must render on a host with no route to the internet, and every
 * label on these charts is data read off a network the agent does not
 * control, so nothing is ever assembled as markup.
 *
 * Colour rules are inherited from style.css and are load-bearing: the three
 * posture states (--ok / --finding / --unknown) are the only encoding of a
 * check's outcome, severity is a separate axis, and neither is reused for
 * anything decorative. Series that are neither state nor severity (kinds of
 * collection run, device classes) use the categorical slots below, assigned
 * in a fixed order and never cycled past the list.
 */

(() => {
  'use strict';

  const NS = 'http://www.w3.org/2000/svg';
  const PNMA = (window.PNMA = window.PNMA || {});

  /* ================================================================ privacy */

  /* Privacy mode masks the identifying parts of every string that reaches
   * the DOM, so the page can be looked at on a phone in public, or
   * screenshotted, without publishing the household. What survives the mask
   * is chosen so the operator can still tell devices apart: the OUI (vendor)
   * and last octet of a MAC, the last octet of an IPv4, the first letter of
   * a hostname or email local-part. Labels the operator assigned are left
   * alone -- they are the names chosen to be safe.
   *
   * Applied in app.js's `el()` and this file's `svgText()`, i.e. at the point
   * of rendering, never to the data. Toggling it re-renders everything. */
  const PRIV_KEY = 'pnma.privacy';
  // Off unless switched on. The mask exists for screenshots and write-ups;
  // the person triaging an alert needs the real address and MAC in front of
  // them to check it against the router, and a dashboard that hid those by
  // default was making its own alerts unverifiable.
  let privacy = false;
  try { privacy = localStorage.getItem(PRIV_KEY) === '1'; } catch (e) { /* private mode */ }

  const MAC_RE = /\b([0-9a-f]{2})[:-]([0-9a-f]{2})[:-]([0-9a-f]{2})[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-]([0-9a-f]{2})\b/gi;
  const IP_RE = /\b(?:\d{1,3}\.){3}(\d{1,3})\b/g;
  const EMAIL_RE = /\b([a-z0-9._%+-])[a-z0-9._%+-]*@([a-z0-9.-]+\.[a-z]{2,})\b/gi;
  const knownNames = new Set(); // hostnames learned from payloads
  // Hostnames that are a role, not an identity. Learning "gateway" from the
  // router's DHCP name and then masking every occurrence of the word turned
  // the Agent tab's own "Gateway fingerprint enforced" into "G··· fingerprint
  // enforced" -- the mask eating the operator's copy, not the reader's data.
  const GENERIC_NAMES = new Set(['gateway', 'router', 'localhost', 'unknown', 'iphone', 'ipad', 'android',
                                 'printer', 'laptop', 'desktop', 'phone', 'home', 'lan', 'wifi', 'default']);

  function maskNames(s) {
    for (const name of knownNames) {
      if (name.length < 3 || GENERIC_NAMES.has(name.toLowerCase())) continue;
      const re = new RegExp('\\b' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'gi');
      s = s.replace(re, (m) => m[0] + '···');
    }
    return s;
  }

  PNMA.mask = (s) => {
    if (!privacy || typeof s !== 'string') return s;
    return maskNames(
      s.replace(MAC_RE, '$1:$2:$3:··:··:$4')
       .replace(IP_RE, '·.·.·.$1')
       .replace(EMAIL_RE, '$1···@$2')
    );
  };
  PNMA.privacy = () => privacy;
  PNMA.learnName = (n) => { if (n && typeof n === 'string') knownNames.add(n); };
  /* Resolved once every hostname the mask needs to know about has been
   * learned. app.js's panels await this before their first paint: an alert
   * description quotes hostnames in prose ("hostname 'cam-frontdoor'
   * matches camera"), and on a cold load the alerts fetch can finish before
   * the devices fetch that teaches the mask those names. The panel then
   * paints the name raw -- and because every panel skips re-rendering an
   * unchanged payload, it stays raw until the data happens to change. The
   * promise is assigned at startup (below), after the fetch wrapper exists. */
  PNMA.namesReady = Promise.resolve();

  function setPrivacy(on) {
    privacy = on;
    try { localStorage.setItem(PRIV_KEY, on ? '1' : '0'); } catch (e) { /* ignore */ }
    // Every panel caches its last payload and skips identical re-renders, and
    // the mask lives outside the payload. A reload is the honest way to
    // re-render everything through it.
    location.reload();
  }

  /* ================================================================== token */

  /* When the server was started with a dashboard token, every /api call
   * needs it. It is kept in localStorage on the device (the tailnet already
   * authenticated the device; the token authenticates the person) and added
   * to every fetch here so the panels in app.js never know about it. A 401
   * raises the gate, which is the whole login UI. */
  const TOKEN_KEY = 'pnma.token';
  const realFetch = window.fetch.bind(window);
  function token() { try { return localStorage.getItem(TOKEN_KEY) || ''; } catch (e) { return ''; } }

  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : input.url;
    const opts = Object.assign({}, init || {});
    if (url.startsWith('/api') || url === '/metrics') {
      const t = token();
      if (t) opts.headers = Object.assign({}, opts.headers || {}, { Authorization: 'Bearer ' + t });
    }
    const resp = await realFetch(input, opts);
    if (resp.status === 401) showGate();
    return resp;
  };

  function showGate() {
    const gate = document.getElementById('token-gate');
    if (!gate || !gate.hidden) return;
    gate.hidden = false;
    clear(gate);
    const input = el('input', { type: 'password', autocomplete: 'current-password',
                                placeholder: 'dashboard token', class: 'gate__input' });
    const form = el('form', { class: 'gate__card' }, [
      el('h2', { text: 'PNMA' }),
      el('p', { text: 'This dashboard is bound off loopback and requires the token you set with pnma secrets set dashboard_token.' }),
      input,
      el('button', { type: 'submit', class: 'btn btn--primary', text: 'Unlock' }),
    ]);
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      try { localStorage.setItem(TOKEN_KEY, input.value.trim()); } catch (e) { /* ignore */ }
      location.reload();
    });
    gate.appendChild(form);
    input.focus();
    // Two frames, not one: `hidden = false` and adding `.is-open` in the same
    // tick gives the browser nothing to transition *from* -- it can coalesce
    // both style changes into one layout pass and skip straight to the end
    // state. A rAF forces the "closed" styles (opacity: 0, scale: 0.98) to
    // actually paint first.
    requestAnimationFrame(() => requestAnimationFrame(() => gate.classList.add('is-open')));
  }

  /* ================================================================ helpers */

  function el(tag, attrs, children) { return PNMA.el(tag, attrs, children); }
  function clear(node) { PNMA.clear(node); }
  function relativeTime(ts) { return PNMA.relativeTime(ts); }
  function plural(n, s, p) { return PNMA.plural(n, s, p); }

  function svg(tag, attrs, children) {
    const node = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      node.setAttribute(k, v);
    }
    for (const c of children || []) {
      if (c === null || c === undefined || c === false) continue;
      node.appendChild(typeof c === 'string' ? document.createTextNode(PNMA.mask(c)) : c);
    }
    return node;
  }
  function svgText(x, y, text, attrs) {
    return svg('text', Object.assign({ x, y }, attrs || {}), [String(text)]);
  }
  function title(text) { return svg('title', {}, [text]); }

  async function getJSON(path) {
    const resp = await fetch(path);
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    return resp.json();
  }

  /**
   * Same fetch, but keeps the raw text alongside the parsed body so a caller
   * can compare bytes across polls the way app.js's `loadPanel` already does
   * for the host/alerts/devices/availability panels.
   */
  async function getRaw(path) {
    const resp = await fetch(path);
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const text = await resp.text();
    return { text, json: JSON.parse(text) };
  }

  /* Last combined payload per polled panel, so an unchanged tick is a no-op
   * in the DOM here too.
   *
   * Every panel below rebuilds its section from scratch on every poll --
   * `clear(body)` followed by a full re-append -- because nothing short of
   * that can safely reconcile an SVG network map or a re-sorted device list.
   * app.js's four panels already guard that rebuild behind a byte-for-byte
   * comparison of the last response, specifically because rebuilding closes
   * every open `<details>` the reader had open. This file's panels never got
   * that guard, which is a real gap and not merely a missed optimisation:
   * the Agent tab's 11 detection-rule disclosures and the Host tab's ATT&CK
   * link both live under a viz.js loader, and both silently collapsed
   * whatever the reader had open every 60-120 seconds. A dashboard meant to
   * "sit open on a second screen for hours" (style.css's own token comment)
   * cannot also be quietly resetting itself that often.
   *
   * `unchanged(key, signature)` returns true (and does nothing else) when
   * this poll's signature matches the last one recorded under `key`; a
   * caller returns immediately on `true` rather than re-rendering. */
  const lastSignature = {};
  function unchanged(key, signature, hasContent) {
    const same = lastSignature[key] === signature && hasContent;
    lastSignature[key] = signature;
    return same;
  }

  function fail(container, label, err) {
    clear(container);
    container.appendChild(el('div', { class: 'error' }, [
      el('strong', { text: label + ' unavailable' }),
      el('p', { text: (err && err.message ? err.message : String(err)) +
        '. Nothing is shown rather than a stale result.' }),
    ]));
  }

  function fmtPct(n) { return n === null || n === undefined ? '—' : Math.round(n) + '%'; }
  function fmtMs(n) { return n === null || n === undefined ? '—' : Math.round(n) + ' ms'; }
  function hhmm(ts) {
    const d = new Date(ts * 1000);
    return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
  }

  /* Categorical slots for series that carry identity rather than state.
   * Fixed order; a ninth series folds into the last slot's "other". */
  const CAT = ['#3987e5', '#d95926', '#199e70', '#c98500', '#d55181', '#9085e9', '#e66767', '#8b949e'];
  const STATE_COLOR = { ok: 'var(--ok)', finding: 'var(--finding)', unknown: 'var(--unknown)' };
  const SEV_COLOR = { critical: 'var(--sev-critical)', high: 'var(--sev-high)',
                      medium: 'var(--sev-medium)', low: 'var(--sev-low)', info: 'var(--fg-dim)' };
  const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

  /* =================================================================== tabs */

  const TABS = [
    ['overview', 'Overview'], ['network', 'Network'], ['host', 'Host'],
    ['alerts', 'Alerts'], ['identity', 'Identity'], ['agent', 'Agent'],
  ];
  const badges = {}; // tab -> count element
  let tabIndicator = null;
  // True once the sidebar layout (style.css's `min-width: 900px` block) has
  // turned `.tabs` into a vertical rail -- the indicator has to measure and
  // animate along a different axis in that mode. A MediaQueryList rather
  // than a one-off `matchMedia().matches` read because it has to stay right
  // across a resize, not just at load. Built lazily rather than at module
  // scope: this IIFE runs the moment the script loads, before there is
  // necessarily a real `window.matchMedia` to call -- the repo's own
  // Node-based privacy-mask test loads this file against a minimal stub
  // `window`/`document` with neither a real DOM nor `matchMedia`, precisely
  // so it can check `PNMA.mask` in isolation without a browser. Calling
  // `matchMedia` eagerly here would throw before that test ever reaches the
  // one function it actually wants.
  let sidebarMQ = null;
  function getSidebarMQ() {
    if (!sidebarMQ && typeof window.matchMedia === 'function') {
      sidebarMQ = window.matchMedia('(min-width: 900px)');
    }
    return sidebarMQ;
  }

  /* Slides the indicator to the newly active tab instead of just recolouring
   * it in place -- an underline sliding under a horizontal bar, or a rail
   * sliding down a vertical one, depending on `sidebarMQ`. Desktop-bar-or-
   * sidebar only: style.css hides the indicator entirely on the phone
   * bottom bar, where each tab already gets its own top-border highlight and
   * a second moving element would just be visual noise on five cramped
   * icons. Measured in real pixels off the button rather than done in pure
   * CSS because the tab list is a variable-size flex row with a badge in
   * some of them; there is no selector for "the size of whichever button has
   * .is-active" without measuring it. Colour comes from the button's own
   * `--nav-color` custom property (set in style.css by `data-tab`) read back
   * with getComputedStyle, so the six hues stay defined in exactly one file. */
  function moveIndicator(btn) {
    if (!tabIndicator || !btn) return;
    const color = getComputedStyle(btn).getPropertyValue('--nav-color').trim();
    if (color) tabIndicator.style.background = color;
    const mq = getSidebarMQ();
    if (mq && mq.matches) {
      tabIndicator.style.transform = 'translateY(' + btn.offsetTop + 'px)';
      tabIndicator.style.height = btn.offsetHeight + 'px';
      tabIndicator.style.width = '';
    } else {
      tabIndicator.style.transform = 'translateX(' + btn.offsetLeft + 'px)';
      tabIndicator.style.width = btn.offsetWidth + 'px';
      tabIndicator.style.height = '';
    }
  }

  /* `anchor`, when given, is the `data-anchor` of a row inside the target
   * tab: the row is scrolled into view and flashed, so a gap on the overview
   * lands on the control it names rather than at the top of a 21-row list.
   * Retries briefly because the target panel may still be rendering. */
  function showTab(name, anchor) {
    if (!TABS.some(([k]) => k === name)) name = 'overview';
    document.querySelectorAll('section[data-tab]').forEach((s) => {
      s.classList.toggle('is-active', s.dataset.tab === name);
    });
    let activeBtn = null;
    document.querySelectorAll('.tabs__tab').forEach((b) => {
      const active = b.dataset.tab === name;
      b.classList.toggle('is-active', active);
      b.setAttribute('aria-selected', active ? 'true' : 'false');
      if (active) activeBtn = b;
    });
    moveIndicator(activeBtn);
    if (location.hash !== '#' + name) history.replaceState(null, '', '#' + name);
    if (anchor) revealAnchor(name, anchor, 10);
    else window.scrollTo({ top: 0 });
  }

  function revealAnchor(tab, anchor, tries) {
    const rows = document.querySelectorAll('section[data-tab="' + tab + '"] [data-anchor]');
    const row = Array.from(rows).find((r) => r.dataset.anchor === anchor);
    if (!row) { if (tries > 0) setTimeout(() => revealAnchor(tab, anchor, tries - 1), 150); return; }
    // Open the disclosure it lives in, if any, so the scroll has a target.
    for (let d = row.closest('details'); d; d = d.parentElement && d.parentElement.closest('details')) d.open = true;
    row.scrollIntoView({ block: 'center' });
    row.classList.remove('is-target');
    void row.offsetWidth; // restart the flash animation on a repeat visit
    row.classList.add('is-target');
    row.addEventListener('animationend', () => row.classList.remove('is-target'), { once: true });
  }

  // Escape dismisses whichever sheet is open. Each sheet's own close logic
  // runs on a click whose target is the backdrop, so that is what we send.
  document.addEventListener('keydown', (ev) => {
    if (ev.key !== 'Escape') return;
    document.querySelectorAll('.sheet.is-open').forEach((sh) => sh.dispatchEvent(new MouseEvent('click', { bubbles: true })));
  });

  function buildTabs() {
    const nav = document.getElementById('tabs');
    tabIndicator = el('div', { class: 'tabs__indicator', 'aria-hidden': 'true' });
    nav.appendChild(tabIndicator);
    // The indicator has to land on the right button before first paint, and
    // on a resize (rotating a phone into a width where the desktop tab bar
    // takes over, or crossing the 900px sidebar line) it has to re-measure --
    // a stale transform left over from a different layout's axis would put
    // it nowhere near the tab. `resize` covers most of that; the MQ's own
    // `change` event covers a window resized slowly enough, or a devtools
    // responsive-mode jump, that never fires `resize` on this frame.
    const reflow = () => moveIndicator(document.querySelector('.tabs__tab.is-active'));
    window.addEventListener('resize', reflow);
    const mq = getSidebarMQ();
    if (mq) mq.addEventListener('change', reflow);
    for (const [key, label] of TABS) {
      const badge = el('span', { class: 'tabs__badge', hidden: true });
      badges[key] = badge;
      const b = el('button', { class: 'tabs__tab', 'data-tab': key, role: 'tab', type: 'button' },
                   [el('span', { class: 'tabs__glyph' }, [TAB_ICON[key]()]),
                    el('span', { class: 'tabs__label', text: label }), badge]);
      b.addEventListener('click', () => showTab(key));
      nav.appendChild(b);
    }
    window.addEventListener('hashchange', () => showTab(location.hash.slice(1)));
    showTab(location.hash.slice(1));
  }

  /* Hand-drawn, not a font glyph or an emoji: a 20x20 stroke icon per tab,
   * built the same way everything else on this page is built -- createElementNS,
   * no markup string, nothing that could be reinterpreted as HTML. Identity's
   * old glyph was a Unicode smiley (☺), which read as a joke on a page about
   * account compromise; the rest were Unicode dingbats standing in for shapes
   * (a gear, a house, a warning sign) that are worth just drawing properly.
   * Colour is not set here -- `.tabs__icon` in style.css reads it from each
   * button's `--nav-color`, via `stroke="currentColor"` / `fill="currentColor"`. */
  function navIcon(children) {
    return svg('svg', { viewBox: '0 0 20 20', class: 'tabs__icon', 'aria-hidden': 'true', focusable: 'false' }, children);
  }
  const STROKE = { fill: 'none', stroke: 'currentColor', 'stroke-width': 1.6,
                   'stroke-linecap': 'round', 'stroke-linejoin': 'round' };
  const TAB_ICON = {
    // Overview: a gauge -- track, needle, hub. Echoes the posture rings this
    // tab is actually made of.
    overview: () => navIcon([
      svg('circle', Object.assign({ cx: 10, cy: 10, r: 7 }, STROKE)),
      svg('line', Object.assign({ x1: 10, y1: 10, x2: 10, y2: 4.7, transform: 'rotate(-40 10 10)' }, STROKE)),
      svg('circle', { cx: 10, cy: 10, r: 1.3, fill: 'currentColor' }),
    ]),
    // Network: hub and spokes -- a miniature of the network-map panel itself.
    network: () => navIcon([
      ...[[10, 3.4], [16, 7], [16, 13], [4, 13], [4, 7]].map(([x, y]) =>
        svg('line', Object.assign({ x1: 10, y1: 10, x2: x, y2: y }, STROKE))),
      ...[[10, 3.4], [16, 7], [16, 13], [4, 13], [4, 7]].map(([x, y]) =>
        svg('circle', { cx: x, cy: y, r: 1.5, fill: 'var(--bg-raised)', stroke: 'currentColor', 'stroke-width': 1.4 })),
      svg('circle', { cx: 10, cy: 10, r: 1.8, fill: 'currentColor' }),
    ]),
    // Host: a monitor on a stand, for checks run against this machine.
    host: () => navIcon([
      svg('rect', Object.assign({ x: 3, y: 4, width: 14, height: 9.4, rx: 1.6 }, STROKE)),
      svg('line', Object.assign({ x1: 10, y1: 13.4, x2: 10, y2: 16 }, STROKE)),
      svg('line', Object.assign({ x1: 6.5, y1: 16.6, x2: 13.5, y2: 16.6 }, STROKE)),
    ]),
    // Alerts: warning triangle with an exclamation mark, drawn rather than
    // borrowed from a font so the corners join the same way every other icon
    // here does.
    alerts: () => navIcon([
      svg('path', Object.assign({ d: 'M10 3.1 L17.4 16.5 H2.6 Z' }, STROKE)),
      svg('line', Object.assign({ x1: 10, y1: 8.2, x2: 10, y2: 12 }, STROKE)),
      svg('circle', { cx: 10, cy: 14.3, r: 0.9, fill: 'currentColor' }),
    ]),
    // Identity: a person, replacing the smiley -- this tab is about account
    // compromise, not a mood.
    identity: () => navIcon([
      svg('circle', Object.assign({ cx: 10, cy: 6.5, r: 3.1 }, STROKE)),
      svg('path', Object.assign({ d: 'M3.7 17c0-4.3 3-6.7 6.3-6.7s6.3 2.4 6.3 6.7' }, STROKE)),
    ]),
    // Agent: a shield with a check -- its own safety posture, self-reported.
    agent: () => navIcon([
      svg('path', Object.assign({ d: 'M10 2.6 L16.8 5.1 V9.9 C16.8 14.5 13.8 17.1 10 17.9 ' +
                                       'C6.2 17.1 3.2 14.5 3.2 9.9 V5.1 Z' }, STROKE)),
      svg('path', Object.assign({ d: 'M7.1 10 L9.1 12 L13 8' }, STROKE)),
    ]),
  };

  function setBadge(tab, n, cls) {
    const b = badges[tab];
    if (!b) return;
    b.hidden = !n;
    b.textContent = n;
    b.className = 'tabs__badge' + (cls ? ' tabs__badge--' + cls : '');
  }

  function buildTools() {
    const tools = document.getElementById('masthead-tools');
    const priv = el('button', {
      class: 'tool' + (privacy ? ' tool--on' : ''), type: 'button',
      title: privacy ? 'Identifiers are masked for screenshots. Tap to show real addresses, MACs and names.'
                     : 'Real identifiers shown. Tap to mask them for a screenshot or write-up.',
      text: privacy ? '◐ masked' : '○ mask',
    });
    priv.addEventListener('click', () => setPrivacy(!privacy));
    tools.appendChild(priv);
    tools.appendChild(el('span', { class: 'tool tool--mode', id: 'mode-pill', text: '…' }));
    tools.appendChild(el('span', { class: 'tool tool--stream', id: 'stream-pill', text: '⇅ connecting',
      title: 'How this page learns about changes. Streaming: the API holds a request open and answers the moment the collector writes, so the page moves within about a second. Polling: the stream is down and every panel refreshes on its own timer instead.' }));
  }

  /* ================================================================= live */

  /* The page used to learn about the world on six independent timers, 60 to
   * 120 seconds apart -- on top of whatever the detection cadence added. Now
   * one long-poll against /api/changes holds a request open for up to 25s
   * and returns the moment SQLite's change counter moves (a collector wrote,
   * or an operator acted through the API). Every panel then refreshes at
   * once; each one's own unchanged() guard keeps the DOM still if its slice
   * did not move. The timers stay as the fallback when the stream is down.
   * Hidden tabs pause the stream and resume on return, so a phone in a
   * pocket costs nothing. */
  const live = { streaming: false, cursor: null, lastChange: 0, lastAck: 0, backoff: 1000, refreshers: [], paused: false };
  PNMA.live = live;
  PNMA.onChange = (fn) => { live.refreshers.push(fn); };
  PNMA.refreshAll = (why) => {
    live.lastChange = Date.now();
    const fns = [loadOverview, loadMap, loadActivity, loadAttack, loadIdentity, loadAgent,
                 PNMA.loadAlerts, PNMA.loadDevices, PNMA.loadHostPosture, PNMA.loadAvailability].concat(live.refreshers);
    for (const fn of fns) { if (typeof fn === 'function') { try { const r = fn(why); if (r && r.catch) r.catch(() => {}); } catch (e) { /* a panel reports its own failure */ } } }
    document.dispatchEvent(new CustomEvent('pnma:change', { detail: { why } }));
    paintStream();
  };
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  function paintStream() {
    const pill = document.getElementById('stream-pill');
    if (!pill) return;
    if (live.paused) { pill.textContent = '⇅ paused'; pill.className = 'tool tool--stream'; return; }
    if (live.streaming) {
      const ago = live.lastChange ? relativeTime(live.lastChange / 1000) : null;
      pill.textContent = '⇅ streaming' + (ago ? ' · ' + (ago === 'just now' ? 'moved just now' : 'moved ' + ago) : '');
      pill.className = 'tool tool--stream tool--streaming';
    } else {
      pill.textContent = '⇅ polling';
      pill.className = 'tool tool--stream tool--polling';
    }
  }
  async function streamLoop() {
    for (;;) {
      if (document.hidden) { live.paused = true; live.streaming = false; paintStream(); await sleep(1000); continue; }
      if (live.paused) { live.paused = false; PNMA.refreshAll('resume'); }
      try {
        const q = live.cursor == null ? '/api/changes' : '/api/changes?cursor=' + encodeURIComponent(live.cursor) + '&wait=25';
        const r = await getJSON(q);
        live.cursor = r.cursor; live.lastAck = Date.now(); live.backoff = 1000;
        if (!live.streaming) { live.streaming = true; paintStream(); }
        if (r.changed) PNMA.refreshAll('change');
      } catch (e) {
        live.streaming = false; paintStream();
        await sleep(live.backoff);
        live.backoff = Math.min(live.backoff * 2, 30000);
      }
    }
  }
  /* Fallback timers: run only while the stream is down. */
  function every(fn, ms) { setInterval(() => { if (!live.streaming) fn(); }, ms); }
  PNMA.every = every;
  setInterval(paintStream, 15000);

  /* =============================================================== overview */

  /* A posture ring. Three arcs in state colours, proportional to counts, on
   * a recessive track. The number in the middle is "measured and ok" as a
   * percentage of *everything*, so unknown costs exactly what a finding
   * costs -- that is the gamification rule of this page, and it is the same
   * rule the host module was built on. */
  function ring(label, counts, sub, opts) {
    opts = opts || {};
    const total = counts.ok + counts.finding + counts.unknown;
    const r = 44, c = 2 * Math.PI * r, cx = 60, cy = 60;
    const g = svg('svg', { viewBox: '0 0 120 120', class: 'ring', role: 'img' }, [
      title(label + ': ' + counts.ok + ' ok, ' + counts.finding + ' finding, ' + counts.unknown + ' unknown'),
      svg('circle', { cx, cy, r, class: 'ring__track' }),
    ]);
    let offset = 0;
    for (const state of ['ok', 'finding', 'unknown']) {
      const n = counts[state];
      if (!n || !total) continue;
      const len = (n / total) * c - 2; // 2px surface gap between arcs
      g.appendChild(svg('circle', {
        cx, cy, r, class: 'ring__arc', stroke: STATE_COLOR[state],
        'stroke-dasharray': Math.max(len, 0) + ' ' + c,
        'stroke-dashoffset': -offset, transform: 'rotate(-90 60 60)',
      }));
      offset += (n / total) * c;
    }
    const score = total ? Math.round((counts.ok / total) * 100) : null;
    // "83" over "of 12" read as an impossible fraction (the 83 is a percentage,
    // the 12 a device count). The score carries its own unit now, and the
    // line under it says what the denominator is made of.
    g.appendChild(svgText(cx, cy + 2, score === null ? '—' : score + '%', { class: 'ring__score', 'text-anchor': 'middle' }));
    g.appendChild(svgText(cx, cy + 18, score === null ? 'no data' : total + ' ' + plural(total, opts.unit || 'item'),
                          { class: 'ring__of', 'text-anchor': 'middle' }));

    const legend = el('div', { class: 'ring__legend' }, ['ok', 'finding', 'unknown'].map((s) =>
      el('span', { class: 'ring__key' }, [
        el('i', { class: 'swatch', style: 'background:' + STATE_COLOR[s] }),
        String(counts[s]) + ' ' + s,
      ])));
    const card = el(opts.tab ? 'button' : 'div', { class: 'ringcard', type: opts.tab ? 'button' : null,
                                                    title: opts.tab ? 'Open the ' + label + ' panel' : null }, [
      g, el('div', { class: 'ringcard__label', text: label }),
      el('div', { class: 'ringcard__sub', text: sub }), legend,
    ]);
    if (opts.tab) card.addEventListener('click', () => showTab(opts.tab));
    return card;
  }

  function tile(value, label, opts) {
    opts = opts || {};
    const t = el(opts.tab ? 'button' : 'div', {
      class: 'tile' + (opts.cls ? ' ' + opts.cls : '') + (opts.tab ? ' tile--link' : ''),
      type: opts.tab ? 'button' : null, title: opts.title || null,
    }, [
      el('div', { class: 'tile__value', text: value }),
      el('div', { class: 'tile__label', text: label }),
      opts.foot ? el('div', { class: 'tile__foot', text: opts.foot }) : null,
      opts.child || null,
    ]);
    if (opts.tab) t.addEventListener('click', () => showTab(opts.tab));
    return t;
  }

  /* Severity bar: one thin stacked bar, severity colours, direct-labelled. */
  function severityBar(bySev) {
    const total = SEV_ORDER.reduce((a, s) => a + (bySev[s] || 0), 0);
    const bar = el('div', { class: 'sevbar' });
    for (const s of SEV_ORDER) {
      const n = bySev[s] || 0;
      if (!n) continue;
      bar.appendChild(el('span', {
        class: 'sevbar__seg', style: 'flex:' + n + ';background:' + SEV_COLOR[s],
        title: n + ' ' + s,
      }));
    }
    const keys = el('div', { class: 'sevbar__keys' }, SEV_ORDER.filter((s) => bySev[s]).map((s) =>
      el('span', {}, [el('i', { class: 'swatch', style: 'background:' + SEV_COLOR[s] }), bySev[s] + ' ' + s])));
    return el('div', {}, [total ? bar : el('div', { class: 'tile__foot', text: 'no open alerts' }), keys]);
  }

  function networkCounts(devices) {
    // Network domain, three-valued: trusted = ok; untrusted but seen in the
    // last day = finding (a decision is owed); not seen for a day = unknown
    // (whatever it is now, the agent has not looked recently).
    const now = Date.now() / 1000;
    const c = { ok: 0, finding: 0, unknown: 0 };
    for (const d of devices) {
      if (now - d.last_seen > 86400) c.unknown++;
      else if (d.trusted) c.ok++;
      else c.finding++;
    }
    return c;
  }

  /* Executive posture banner: the one-glance verdict both SOC-dashboard
   * playbooks put at the very top -- an overall status, the numbers behind
   * it, and the most severe open alerts as chips that jump straight into the
   * drawer. Verdict is by icon + word + colour, never colour alone, so it
   * survives a colour-blind reader and a greyscale screenshot. */
  function postureVerdict(counts, gaps) {
    if (counts.critical) return { key: 'critical', word: 'Action needed now', icon: '!' };
    if (counts.high) return { key: 'high', word: 'Needs attention', icon: '!' };
    if (gaps) return { key: 'warn', word: 'Review recommended', icon: '~' };
    return { key: 'ok', word: 'Healthy', icon: '✓' };
  }

  function postureBanner(summary, openAlerts, gaps, devices) {
    const counts = summary.alerts.by_severity || {};
    const v = postureVerdict(counts, gaps);
    const online = devices.filter((d) => d.online).length;
    const bits = [];
    for (const s of ['critical', 'high', 'medium', 'low']) if (counts[s]) bits.push(counts[s] + ' ' + s);
    const summaryLine = (bits.length ? bits.join(', ') + ' open' : 'no open alerts')
      + ' · ' + gaps + ' ' + plural(gaps, 'gap') + ' to close'
      + ' · ' + devices.length + ' ' + plural(devices.length, 'device') + ', ' + online + ' online';

    // The most severe open alerts, as chips into the drawer.
    const top = openAlerts
      .filter((a) => a.severity === 'critical' || a.severity === 'high')
      .sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))
      .slice(0, 4);
    const chips = top.map((a) => {
      const c = el('button', { class: 'pb__chip pb__chip--' + a.severity, type: 'button',
                               title: 'Open this alert' },
        [el('span', { class: 'pb__chipsev', text: a.severity }), a.title || a.rule_id]);
      c.addEventListener('click', () => { if (PNMA.openAlert) PNMA.openAlert(a.id); });
      return c;
    });

    const head = el('div', { class: 'pb__head' }, [
      el('div', { class: 'pb__badge', text: v.icon }),
      el('div', {}, [
        el('div', { class: 'pb__verdict', text: v.word }),
        el('div', { class: 'pb__summary', text: summaryLine }),
      ]),
      el('div', { class: 'pb__meta' }, [
        el('span', { class: 'pb__updated', text: 'updated ' + relativeTime(summary.generated_at || Date.now() / 1000) }),
        (counts.critical || counts.high)
          ? (() => { const b = el('button', { class: 'pb__all', type: 'button', text: 'All alerts →' });
                     b.addEventListener('click', () => showTab('alerts')); return b; })()
          : null,
      ]),
    ]);
    const card = el('div', { class: 'pb pb--' + v.key }, [head]);
    if (chips.length) card.appendChild(el('div', { class: 'pb__chips' }, chips));
    return card;
  }

  async function loadOverview() {
    const body = document.getElementById('overview-body');
    try {
      const raw = await Promise.all([
        getRaw('/api/summary'), getRaw('/api/host'), getRaw('/api/identity'),
        getRaw('/api/devices'), getRaw('/api/sensors'), getRaw('/api/alerts?status=open&limit=100'),
      ]);
      if (unchanged('overview', raw.map((r) => r.text).join('\u0000'), body.firstChild)) return;
      const [summary, host, identity, devices, sensors, alertList] = raw.map((r) => r.json);
      for (const d of devices.devices) PNMA.learnName(d.hostname);
      for (const s of sensors.sensors) PNMA.learnName(s.hostname);

      const net = networkCounts(devices.devices);
      const hs = host.summary, is = identity.summary;
      const openPorts = devices.devices.reduce((a, d) => a + (d.open_ports || []).length, 0);
      const risky = devices.devices.reduce((a, d) => a + (d.open_ports || []).filter((p) => p.risk && p.risk !== 'none').length, 0);

      const onlineN = devices.devices.filter((d) => d.online).length;
      const rings = el('div', { class: 'rings' }, [
        ring('Network', net, onlineN + ' online now', { unit: 'device', tab: 'network' }),
        ring('Host', { ok: hs.ok, finding: hs.finding, unknown: hs.unknown },
             hs.elevated ? 'collected elevated' : hs.blocked_by_privilege + ' blocked by privilege', { unit: 'check', tab: 'host' }),
        ring('Identity', { ok: is.ok, finding: is.finding, unknown: is.unknown },
             is.accounts ? is.accounts + ' ' + plural(is.accounts, 'account') + ', ' + is.stale + ' stale' : 'no accounts registered',
             { unit: 'control', tab: 'identity' }),
      ]);

      const alerts = summary.alerts;
      const tiles = el('div', { class: 'tiles' }, [
        tile(onlineN + ' / ' + summary.devices.total, 'devices online',
             { foot: summary.devices.untrusted_online + ' untrusted online', cls: summary.devices.untrusted_online ? 'tile--warn' : '', tab: 'network' }),
        tile(alerts.open, plural(alerts.open, 'open alert'), { child: severityBar(alerts.by_severity || {}),
             cls: (alerts.by_severity || {}).critical || (alerts.by_severity || {}).high ? 'tile--bad' : '', tab: 'alerts' }),
        tile(openPorts, plural(openPorts, 'open port'), { foot: risky ? risky + ' flagged risky' : 'none flagged risky', cls: risky ? 'tile--warn' : '', tab: 'network' }),
        tile(fmtPct(summary.availability_24h_pct), 'reachable, 24h', { foot: summary.availability_24h_pct === null ? 'no samples yet' : 'across all devices', tab: 'network' }),
        tile(fmtMs(summary.latency_1h.avg_ms), 'avg round-trip, 1h', { foot: summary.latency_1h.samples + ' samples, max ' + fmtMs(summary.latency_1h.max_ms), tab: 'network' }),
        tile(hs.unknown + is.unknown + net.unknown, 'unmeasured controls', { foot: 'each one is a point you can win back', cls: 'tile--unknown', tab: 'host' }),
      ]);

      // Gaps to close: the gamification loop. Sorted so the cheapest wins
      // come first -- attesting an identity control is a tap, elevating the
      // collector is a restart, trusting a device is a decision.
      const gaps = [];
      // One row per account, not one per control: seven "Everyday banking:
      // <control> -- never attested" rows in a row is a wall, and every one
      // of them is the same tap on the same panel. A single finding on an
      // account still gets its own row, because a finding is a different
      // kind of thing from "not looked at yet" and deserves its own line.
      for (const acc of identity.accounts) {
        const findings = acc.controls.filter((c) => c.state === 'finding');
        const unknown = acc.controls.filter((c) => c.state === 'unknown');
        for (const c of findings)
          gaps.push({ tab: 'identity', anchor: acc.account_id + ':' + c.control, text: acc.label + ': ' + c.title,
                      why: c.reason || 'finding', state: 'finding' });
        if (unknown.length) {
          const stale = unknown.filter((c) => c.stale).length;
          gaps.push({ tab: 'identity', anchor: acc.account_id + ':' + unknown[0].control,
                      text: acc.label + ': ' + unknown.length + ' ' + plural(unknown.length, 'control') + ' to attest',
                      why: stale ? stale + ' stale, ' + (unknown.length - stale) + ' never attested' : 'never attested', state: 'unknown' });
        }
      }
      for (const d of devices.devices) if (!d.trusted && Date.now() / 1000 - d.last_seen < 86400)
        gaps.push({ tab: 'network', anchor: 'device:' + d.device_id, text: 'Decide trust for ' + (d.label || d.hostname || d.ip || d.mac), why: 'untrusted and seen today', state: 'finding' });
      for (const f of host.facts) if (f.state !== 'ok')
        gaps.push({ tab: 'host', anchor: 'fact:' + f.fact_key, text: f.title, why: f.reason || (f.state === 'unknown' ? 'could not run' : 'finding'), state: f.state });
      const SHOW = 8;
      const list = el('ul', { class: 'gaps__list' }, gaps.map((g, i) => {
        const li = el('li', { class: 'gap gap--' + g.state, hidden: i >= SHOW }, [
          PNMA.stateChip(g.state), el('span', { class: 'gap__text', text: g.text }),
          el('span', { class: 'gap__why', text: g.why }),
        ]);
        li.addEventListener('click', () => showTab(g.tab, g.anchor));
        return li;
      }));
      let more = null;
      if (gaps.length > SHOW) {
        more = el('button', { class: 'btn gaps__more', type: 'button', text: 'Show all ' + gaps.length });
        more.addEventListener('click', () => {
          list.querySelectorAll('[hidden]').forEach((li) => { li.hidden = false; });
          more.remove();
        });
      }
      const gapList = el('div', { class: 'gaps' }, [
        el('h3', { class: 'gaps__title', text: gaps.length ? gaps.length + ' ' + plural(gaps.length, 'gap') + ' to close' : 'No gaps. Every control measured and passing.' }),
        list, more,
      ]);

      clear(body);
      body.appendChild(postureBanner(summary, alertList.alerts || [], gaps.length, devices.devices));
      body.appendChild(rings);
      body.appendChild(tiles);
      body.appendChild(gapList);

      setBadge('alerts', alerts.open, (alerts.by_severity || {}).critical || (alerts.by_severity || {}).high ? 'bad' : 'warn');
      setBadge('host', hs.finding + hs.unknown, hs.finding ? 'bad' : 'unknown');
      setBadge('identity', is.finding + is.unknown, is.finding ? 'bad' : 'unknown');
      setBadge('network', summary.devices.untrusted_online, 'warn');
    } catch (err) {
      fail(body, 'Overview', err);
    }
  }

  /* ============================================================ network map */

  let mapDevices = [];

  function renderMap(devices) {
    const body = document.getElementById('netmap-body');
    clear(body);
    if (!devices.length) {
      body.appendChild(el('div', { class: 'empty' }, [
        el('strong', { text: 'No devices discovered yet.' }),
        el('p', { text: 'The map is drawn from discovery. Until the collector has run, this is not an empty network -- it is an unmeasured one.' }),
      ]));
      return;
    }
    const gw = devices.find((d) => d.device_class === 'gateway' || d.device_class === 'router') ||
               devices.reduce((a, d) => (d.open_ports || []).length > (a.open_ports || []).length ? d : a, devices[0]);
    const others = devices.filter((d) => d !== gw);

    // Single ring is legible up to about eight spokes -- past that, the arc
    // length per device shrinks faster than the labels below each node do,
    // and names start overlapping their neighbours' before the ring is even
    // half full. Two concentric rings roughly double how many devices fit
    // before that happens, at the cost of a taller canvas; below the
    // threshold the outer ring is simply everyone, same as before.
    const TWO_RING_AT = 9;
    const twoRings = others.length >= TWO_RING_AT;
    const W = 640;
    // Extra headroom per ring "row" so labels on a crowded outer ring have
    // somewhere to go without being clipped by the viewBox.
    const H = twoRings ? 560 : 480;
    const cx = W / 2, cy = H / 2;
    const Router = Math.min(W, H) / 2 - 76;
    const Rinner = Router * 0.56;

    // Interleaved, not split into two contiguous halves: alternating
    // assignment spreads related devices (adjacent in the API's own
    // ordering, usually by recency) across both rings instead of bunching
    // them on one, which is what made a full inner ring and a nearly-empty
    // outer one possible before.
    const outer = twoRings ? others.filter((_, i) => i % 2 === 0) : others;
    const inner = twoRings ? others.filter((_, i) => i % 2 === 1) : [];

    const root = svg('svg', { viewBox: '0 0 ' + W + ' ' + H, class: 'netmap', role: 'img' }, [
      title('Network map: ' + devices.length + ' devices'),
    ]);
    // Orbit ring(s), hairline, one shade off the surface.
    root.appendChild(svg('circle', { cx, cy, r: Router, class: 'netmap__orbit' }));
    if (twoRings) root.appendChild(svg('circle', { cx, cy, r: Rinner, class: 'netmap__orbit' }));

    const now = Date.now() / 1000;
    function place(list, R, angleOffset) {
      list.forEach((d, i) => {
        const a = (i / list.length) * 2 * Math.PI - Math.PI / 2 + angleOffset;
        const x = cx + R * Math.cos(a), y = cy + R * Math.sin(a);
        const online = now - d.last_seen < 900;
        root.appendChild(svg('line', {
          x1: cx, y1: cy, x2: x, y2: y,
          class: 'netmap__edge' + (online ? '' : ' netmap__edge--dim'),
        }));
        root.appendChild(node(d, x, y, online, false));
      });
    }
    // The inner ring is rotated a half-step relative to the outer one so a
    // spoke on one ring falls in the gap between two spokes on the other,
    // rather than lining up behind them from the gateway's point of view.
    place(outer, Router, 0);
    if (inner.length) place(inner, Rinner, Math.PI / outer.length);

    root.appendChild(node(gw, cx, cy, now - gw.last_seen < 900, true));
    body.appendChild(root);
    body.appendChild(el('div', { class: 'netmap__legend' }, [
      // Trust reuses the ok/finding tokens rather than accent/warn: those two
      // are the only vocabulary this dashboard has for "this passed" versus
      // "this needs a decision", and a third colour pairing for the same
      // idea on one panel is exactly the "parallel colours" style.css's own
      // token comment warns against.
      key('ring: trusted', 'var(--ok)'), key('ring: untrusted', 'var(--finding)'),
      key('fill: online', 'var(--bg-inset)'), key('badge: open ports', 'var(--fg-muted)'),
      el('span', { text: 'dashed edge: not seen in 15 min' }),
    ]));

    function key(text, color) {
      return el('span', {}, [el('i', { class: 'swatch swatch--ring', style: 'border-color:' + color }), text]);
    }
  }

  function node(d, x, y, online, isGw) {
    const ports = (d.open_ports || []).length;
    const alerts = d.open_alerts || 0;
    const r = isGw ? 30 : 22;
    const name = d.label || d.hostname || d.vendor || d.ip || d.mac || '?';
    const g = svg('g', { class: 'netnode' + (online ? '' : ' netnode--offline'), tabindex: 0, role: 'button' }, [
      title(name + ' — ' + (d.ip || 'no ip') + ' — ' + (d.vendor || 'vendor unknown') +
            ' — ' + ports + ' open ' + plural(ports, 'port') + (alerts ? ' — ' + alerts + ' open alerts' : '')),
      svg('circle', { cx: x, cy: y, r: r + 6, class: 'netnode__halo' + (alerts ? ' netnode__halo--alert' : '') }),
      svg('circle', { cx: x, cy: y, r, class: 'netnode__body', stroke: d.trusted ? 'var(--ok)' : 'var(--finding)' }),
      svgText(x, y + 5, isGw ? '⌂' : glyphFor(d.device_class), { class: 'netnode__glyph', 'text-anchor': 'middle' }),
      svgText(x, y + r + 16, truncate(name, 16), { class: 'netnode__name', 'text-anchor': 'middle' }),
      svgText(x, y + r + 29, d.ip ? d.ip : (d.mac_type === 'local' ? 'randomised MAC' : ''), { class: 'netnode__addr', 'text-anchor': 'middle' }),
    ]);
    if (ports) {
      g.appendChild(svg('circle', { cx: x + r - 4, cy: y - r + 4, r: 10, class: 'netnode__badge' }));
      g.appendChild(svgText(x + r - 4, y - r + 8, ports, { class: 'netnode__badgetext', 'text-anchor': 'middle' }));
    }
    if (alerts) {
      g.appendChild(svg('circle', { cx: x - r + 4, cy: y - r + 4, r: 6, fill: 'var(--sev-high)' }));
    }
    const open = () => openSheet(d.device_id);
    g.addEventListener('click', open);
    g.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); open(); } });
    return g;
  }

  function glyphFor(cls) {
    return { phone: '☎', laptop: '⌸', workstation: '⌸', printer: '⎙', tv: '▣',
             iot: '⚙', camera: '◉', speaker: '♫', console: '▶', gateway: '⌂' }[cls] || '●';
  }
  function truncate(s, n) { return s.length > n ? s.slice(0, n - 1) + '…' : s; }

  async function loadMap() {
    const body = document.getElementById('netmap-body');
    const statsBody = document.getElementById('netstats-body');
    try {
      const raw = await getRaw('/api/devices');
      if (unchanged('map', raw.text, body.firstChild && statsBody.firstChild)) return;
      const payload = raw.json;
      mapDevices = payload.devices;
      for (const d of mapDevices) PNMA.learnName(d.hostname);
      renderMap(mapDevices);
      renderNetStats(mapDevices);
    } catch (err) {
      fail(body, 'Network map', err);
    }
  }

  /* ---------------------------------------------------------- device sheet */

  // Guards the close animation's timer against a re-open that lands inside
  // it: tapping one device, then a second before the first sheet finished
  // closing, would otherwise let the first close's stale timeout fire *after*
  // the second sheet has opened and hide the wrong content.
  let sheetCloseTimer = null;

  async function openSheet(deviceId) {
    const sheet = document.getElementById('device-sheet');
    clearTimeout(sheetCloseTimer);
    sheet.hidden = false;
    clear(sheet);
    const card = el('div', { class: 'sheet__card' }, [el('div', { class: 'placeholder', text: 'Loading device…' })]);
    sheet.appendChild(card);
    // Same two-frame trick as the token gate: let `hidden` removal paint
    // once at the closed position before adding the class that transitions
    // it to open, or the browser has nothing to animate from.
    requestAnimationFrame(() => requestAnimationFrame(() => sheet.classList.add('is-open')));
    // Play the close transition out instead of just vanishing, but don't
    // block the actual close on it -- a `transitionend` listener here would
    // never fire at all for a reduced-motion visitor (the transition is
    // `none`), which would leave the sheet permanently un-closeable for
    // exactly the audience most likely to have that setting on for a
    // reason. A timer that matches the CSS duration, capped, is honest about
    // being an approximation rather than pretending to synchronise with it.
    const close = () => {
      sheet.classList.remove('is-open');
      sheetCloseTimer = setTimeout(() => { sheet.hidden = true; clear(sheet); }, 180);
    };
    sheet.addEventListener('click', (ev) => { if (ev.target === sheet) close(); });
    try {
      const d = await getJSON('/api/devices/' + encodeURIComponent(deviceId));
      clear(card);
      const name = d.label || d.hostname || d.vendor || d.ip || d.mac;
      card.appendChild(el('div', { class: 'sheet__head' }, [
        el('h3', { text: name }),
        el('button', { class: 'btn', type: 'button', text: 'close' }),
      ]));
      card.lastChild.lastChild.addEventListener('click', close);
      card.appendChild(el('dl', { class: 'kv' }, [
        kv('address', d.ip || '—'), kv('mac', (d.mac || '—') + (d.mac_type === 'local' ? ' (randomised)' : '')),
        kv('vendor', d.vendor || 'unknown'), kv('class', d.device_class ? d.device_class + ' (' + (d.class_confidence || '?') + ')' : 'unclassified'),
        kv('trust', d.trusted ? 'trusted' : 'untrusted'), kv('first seen', relativeTime(d.first_seen)),
        kv('last seen', relativeTime(d.last_seen)),
      ]));
      const ports = (d.ports || []).filter((p) => !p.closed_at);
      card.appendChild(el('h4', { text: ports.length + ' open ' + plural(ports.length, 'port') }));
      card.appendChild(el('div', { class: 'dev__ports' }, ports.length ? ports.map((p) =>
        el('span', { class: 'port-pill' + (p.risk && p.risk !== 'none' ? ' port-pill--risky' : ''),
                     text: p.port + '/' + (p.proto || 'tcp') + (p.service ? ' ' + p.service : '') })) :
        [el('span', { class: 'dev__class', text: 'none recorded -- either nothing listens, or it was never scanned' })]));
      card.appendChild(el('h4', { text: 'Reachability, 24h' }));
      card.appendChild(sparkline(d.availability || []));
      if ((d.alerts || []).length) {
        card.appendChild(el('h4', { text: d.alerts.length + ' ' + plural(d.alerts.length, 'alert') }));
        card.appendChild(el('ul', { class: 'sheet__alerts' }, d.alerts.slice(0, 8).map((a) =>
          el('li', {}, [PNMA.severityChip(a.severity), el('span', { text: ' ' + a.title + ' (' + a.status + ')' })]))));
      }
      const trustBtn = el('button', { class: 'btn btn--primary', type: 'button',
                                      text: d.trusted ? 'Mark untrusted' : 'Mark trusted' });
      trustBtn.addEventListener('click', async () => {
        trustBtn.disabled = true;
        await fetch('/api/devices/' + encodeURIComponent(deviceId) + '/trust', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ trusted: !d.trusted, label: d.label || null }),
        });
        close(); loadMap(); loadOverview(); PNMA.loadDevices(); PNMA.loadAlerts(true);
      });
      card.appendChild(el('div', { class: 'sheet__actions' }, [trustBtn]));
    } catch (err) {
      clear(card);
      card.appendChild(el('p', { class: 'error', text: 'Could not load device: ' + err.message }));
    }
  }
  function kv(k, v) { return el('div', {}, [el('dt', { text: k }), el('dd', { text: v })]); }

  /* Reachability sparkline: one 2px line for rtt, gaps for missing samples,
   * red ticks along the baseline where a probe got no answer. */
  function sparkline(samples) {
    const W = 320, H = 60, pad = 4;
    const root = svg('svg', { viewBox: '0 0 ' + W + ' ' + H, class: 'spark' });
    if (!samples.length) {
      root.appendChild(svgText(W / 2, H / 2 + 4, 'no samples in 24h', { class: 'spark__empty', 'text-anchor': 'middle' }));
      return root;
    }
    const t0 = samples[0].ts, t1 = samples[samples.length - 1].ts || t0 + 1;
    const maxRtt = Math.max(1, ...samples.map((s) => s.rtt_ms || 0));
    const X = (t) => pad + ((t - t0) / Math.max(1, t1 - t0)) * (W - 2 * pad);
    const Y = (v) => H - pad - (v / maxRtt) * (H - 2 * pad - 10);
    let dpath = '', pen = false;
    for (const s of samples) {
      if (s.reachable && s.rtt_ms !== null) {
        dpath += (pen ? 'L' : 'M') + X(s.ts).toFixed(1) + ' ' + Y(s.rtt_ms).toFixed(1);
        pen = true;
      } else {
        pen = false;
        root.appendChild(svg('line', { x1: X(s.ts), x2: X(s.ts), y1: H - pad - 6, y2: H - pad, stroke: 'var(--finding)', 'stroke-width': 2 }));
      }
    }
    root.appendChild(svg('path', { d: dpath, class: 'spark__line' }));
    root.appendChild(svgText(W - pad, 10, 'max ' + Math.round(maxRtt) + ' ms', { class: 'spark__label', 'text-anchor': 'end' }));
    return root;
  }

  /* ========================================================= attack surface */

  function renderNetStats(devices) {
    const body = document.getElementById('netstats-body');
    clear(body);
    if (!devices.length) { body.appendChild(el('div', { class: 'placeholder', text: 'No devices yet.' })); return; }

    // Ports per device: one series, one colour, sorted by count, direct labels.
    const rows = devices.map((d) => ({
      name: d.label || d.hostname || d.vendor || d.ip || d.mac,
      ports: d.open_ports || [],
    })).sort((a, b) => b.ports.length - a.ports.length);
    const max = Math.max(1, ...rows.map((r) => r.ports.length));
    const bars = el('div', { class: 'hbars' }, rows.map((r) => {
      const risky = r.ports.filter((p) => p.risk && p.risk !== 'none').length;
      return el('div', { class: 'hbar', title: r.ports.map((p) => p.port + '/' + (p.proto || 'tcp') + (p.service ? ' ' + p.service : '')).join(', ') || 'no open ports recorded' }, [
        el('span', { class: 'hbar__label', text: truncate(r.name, 22) }),
        el('span', { class: 'hbar__track' }, [
          el('span', { class: 'hbar__fill', style: 'width:' + (r.ports.length / max) * 100 + '%' }),
          risky ? el('span', { class: 'hbar__fill hbar__fill--risky', style: 'width:' + (risky / max) * 100 + '%' }) : null,
        ]),
        el('span', { class: 'hbar__value', text: r.ports.length + (risky ? ' (' + risky + ' risky)' : '') }),
      ]);
    }));

    // Classification breakdown: what discovery thinks lives here. IoT and
    // unclassified are the two to watch; both get the same scan.
    const classes = {};
    for (const d of devices) {
      const k = d.device_class || 'unclassified';
      classes[k] = (classes[k] || 0) + 1;
    }
    const entries = Object.entries(classes).sort((a, b) => b[1] - a[1]);
    const total = devices.length;
    const strip = el('div', { class: 'classbar' }, entries.map(([k, n], i) =>
      el('span', { class: 'classbar__seg', style: 'flex:' + n + ';background:' + CAT[Math.min(i, CAT.length - 1)], title: n + ' ' + k })));
    const keys = el('div', { class: 'sevbar__keys' }, entries.map(([k, n], i) =>
      el('span', {}, [el('i', { class: 'swatch', style: 'background:' + CAT[Math.min(i, CAT.length - 1)] }), n + ' ' + k + ' (' + Math.round((n / total) * 100) + '%)'])));

    body.appendChild(el('div', { class: 'twocol' }, [
      el('div', {}, [el('h3', { class: 'sub', text: 'Open ports by device' }), bars]),
      el('div', {}, [el('h3', { class: 'sub', text: 'Device classes' }), strip, keys,
        el('p', { class: 'section__note', text: 'Classification comes from DHCP fingerprint, vendor and open services. It is a guess with a confidence, shown per device below.' })]),
    ]));
  }

  /* =============================================================== activity */

  const KIND_LABEL = { discovery_sweep: 'discovery', arp_table_read: 'arp cache', ping: 'ping',
                       port_scan: 'port scan', host_posture: 'host posture', passive: 'passive', detect: 'detect' };

  async function loadActivity() {
    const body = document.getElementById('activity-body');
    try {
      const raw = await getRaw('/api/timeline?hours=24');
      if (unchanged('activity', raw.text, body.firstChild)) return;
      const payload = raw.json;
      const events = payload.events || [];
      clear(body);
      if (!events.length) {
        body.appendChild(el('div', { class: 'empty' }, [
          el('strong', { text: 'No collection runs in the last 24 hours.' }),
          el('p', { text: 'Every other panel is downstream of a collector that has not run. Start it: pnma collect' }),
        ]));
        return;
      }
      const kinds = [];
      for (const e of events) if (!kinds.includes(e.kind)) kinds.push(e.kind);
      const now = Date.now() / 1000, start = now - 86400;
      const W = 720, rowH = 26, left = 96, H = kinds.length * rowH + 28;
      const X = (t) => left + ((t - start) / 86400) * (W - left - 8);
      const root = svg('svg', { viewBox: '0 0 ' + W + ' ' + H, class: 'swim', role: 'img' }, [title('Collection runs, 24h')]);
      // Hour ticks, hairline.
      for (let h = 0; h <= 24; h += 6) {
        const x = X(start + h * 3600);
        root.appendChild(svg('line', { x1: x, x2: x, y1: 0, y2: H - 20, class: 'swim__grid' }));
        root.appendChild(svgText(x, H - 6, h === 24 ? 'now' : '-' + (24 - h) + 'h', { class: 'swim__tick', 'text-anchor': 'middle' }));
      }
      kinds.forEach((k, i) => {
        const y = i * rowH + rowH / 2;
        root.appendChild(svgText(left - 8, y + 4, KIND_LABEL[k] || k, { class: 'swim__label', 'text-anchor': 'end' }));
        root.appendChild(svg('line', { x1: left, x2: W - 8, y1: y, y2: y, class: 'swim__lane' }));
        for (const e of events.filter((ev) => ev.kind === k)) {
          const x = X(e.ts);
          const failed = !!e.error;
          const refused = /refus|denied|scope/i.test(e.error || '');
          const w = Math.max(3, ((e.duration_s || 0) / 86400) * (W - left - 8));
          const mark = svg('rect', {
            x: x - w / 2, y: y - 6, width: w, height: 12, rx: 2,
            class: 'swim__run' + (failed ? (refused ? ' swim__run--refused' : ' swim__run--failed') : ''),
            fill: failed ? null : CAT[Math.min(i, CAT.length - 1)],
          }, [title(hhmm(e.ts) + ' ' + (KIND_LABEL[k] || k) + ' — ' + (e.result || '') + (e.error ? ' — ERROR: ' + e.error : '') +
                    (e.duration_s ? ' (' + Math.round(e.duration_s) + 's)' : ''))]);
          root.appendChild(mark);
        }
      });
      body.appendChild(root);
      // Same split as the tiles above: a run the scope guard refused is the
      // guard working, not the collector failing, and counting it under
      // "failed" here while the tiles said "0 failed" contradicted the page.
      const isRefused = (e) => /refus|denied|scope/i.test(e.error || '');
      const failed = events.filter((e) => e.error && !isRefused(e)).length;
      const refused = events.filter((e) => e.error && isRefused(e)).length;
      body.appendChild(el('div', { class: 'netmap__legend' }, [
        el('span', { text: events.length + ' runs' }),
        el('span', {}, [el('i', { class: 'swatch', style: 'background:var(--finding)' }), failed + ' failed']),
        el('span', {}, [el('i', { class: 'swatch swatch--hatch' }), refused + ' refused by scope guard']),
        el('span', { text: 'width = duration' }),
      ]));
      const lastErr = events.find((e) => e.error);
      if (lastErr) body.appendChild(el('p', { class: 'section__note', text: 'Most recent ' + (isRefused(lastErr) ? 'refusal' : 'failure') + ': ' + hhmm(lastErr.ts) + ' ' + (KIND_LABEL[lastErr.kind] || lastErr.kind) + ' — ' + lastErr.error }));
    } catch (err) {
      fail(body, 'Activity', err);
    }
  }

  /* ================================================================ ATT&CK */

  async function loadAttack() {
    const body = document.getElementById('attack-body');
    try {
      const raw = await getRaw('/api/attack');
      if (unchanged('attack', raw.text, body.firstChild)) return;
      const payload = raw.json;
      clear(body);
      const bySev = {};
      for (const t of payload.techniques || []) {
        const cur = bySev[t.id || t.mitre_id];
        if (!cur || SEV_ORDER.indexOf(t.severity) < SEV_ORDER.indexOf(cur.severity)) bySev[t.id || t.mitre_id] = t;
      }
      const matrix = el('div', { class: 'matrix' }, (payload.coverage || []).map((tac) => {
        const col = el('div', { class: 'matrix__col' + (tac.count ? '' : ' matrix__col--empty') }, [
          el('div', { class: 'matrix__head', text: tac.name }),
        ]);
        if (!tac.techniques.length) {
          col.appendChild(el('div', { class: 'matrix__none', text: 'no evidence' }));
        }
        for (const id of tac.techniques) {
          const t = bySev[id] || {};
          const covered = !!t.count;
          const cell = el(covered ? 'button' : 'div', {
            class: 'matrix__cell' + (covered ? ' matrix__cell--live' : ''),
            type: covered ? 'button' : null,
            style: t.severity ? 'border-left-color:' + SEV_COLOR[t.severity] : null,
            title: (t.name || id) + (covered ? ' — ' + t.count + ' open ' + plural(t.count, 'alert') + '. Click to filter the queue to this technique.' : ' — no open alert maps here'),
          }, [el('span', { class: 'matrix__id', text: id }), el('span', { class: 'matrix__name', text: t.name || '' })]);
          if (covered && window.PNMA.filterAlertsByTechnique) {
            cell.addEventListener('click', () => window.PNMA.filterAlertsByTechnique(id));
          }
          col.appendChild(cell);
        }
        return col;
      }));
      const covered = (payload.coverage || []).filter((t) => t.count).length;
      body.appendChild(el('p', { class: 'section__note' }, [
        el('strong', { text: covered + ' of ' + (payload.coverage || []).length + ' tactics' }),
        ' have at least one open alert mapped to them. Cell edge colour is the highest open severity. ',
        navigatorLink(), '.',
      ]));
      body.appendChild(matrix);
    } catch (err) {
      fail(body, 'ATT&CK coverage', err);
    }
  }

  /* A plain <a href> would navigate without the bearer header and get a
   * 401 behind the token gate, so the layer is fetched like any API call
   * and handed to the viewer as a file. */
  function navigatorLink() {
    const a = el('a', { href: '#', text: 'Download as an ATT&CK Navigator layer' });
    a.addEventListener('click', async (ev) => {
      ev.preventDefault();
      const resp = await fetch('/api/attack/navigator');
      if (!resp.ok) return;
      const blob = new Blob([await resp.text()], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const tmp = el('a', { href: url, download: 'pnma-attack-layer.json' });
      document.body.appendChild(tmp); tmp.click(); tmp.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
    return a;
  }

  /* =============================================================== identity */

  const PROVIDER_GLYPH = { google: 'G', apple: '', microsoft: 'M', meta: 'f', x: 'X', github: '⎇', bank: '¤', other: '●' };

  async function loadIdentity() {
    const body = document.getElementById('identity-body');
    try {
      const raw = await getRaw('/api/identity');
      if (unchanged('identity', raw.text, body.firstChild)) return;
      const payload = raw.json;
      clear(body);
      const s = payload.summary;
      if (!payload.accounts.length) {
        body.appendChild(el('div', { class: 'empty' }, [
          el('strong', { text: 'No accounts registered.' }),
          el('p', { text: 'Register the accounts you own and start attesting. Every control begins as unknown -- which is the truthful state of an account nobody has reviewed.' }),
          el('pre', { text: 'pnma identity add gmail-main --provider google --category email --label "Main mailbox"\npnma identity attest gmail-main mfa ok --value "passkey"' }),
        ]));
        return;
      }
      // The ring for this domain already sits on the overview; repeating it
      // here said nothing new. What this panel can add is the two numbers
      // that tell the reader what to do next.
      const total = s.ok + s.finding + s.unknown;
      body.appendChild(el('div', { class: 'idsummary' }, [
        el('div', { class: 'idsummary__counts' }, ['ok', 'finding', 'unknown'].map((st) => {
          const chip = PNMA.stateChip(st);
          chip.appendChild(el('span', { text: ' ' + s[st] }));
          return chip;
        }).concat([el('span', { class: 'idsummary__of', text: 'of ' + total + ' ' + plural(total, 'control') + ' across ' + s.accounts + ' ' + plural(s.accounts, 'account') })])),
        el('div', { class: 'idsummary__text' }, [
          el('p', {}, [el('strong', { text: s.stale + ' stale' }), ' ' + plural(s.stale, 'attestation') + ' rotted back to unknown. ',
                       el('strong', { text: s.never + ' never attested' }), '.']),
          el('p', { class: 'section__note', text: 'Tap a state to attest it. The review clock restarts on every attestation, even an unchanged one.' }),
        ]),
      ]));
      for (const acc of payload.accounts) {
        const head = el('div', { class: 'idacc__head' }, [
          el('span', { class: 'idacc__glyph', text: PROVIDER_GLYPH[acc.provider] || '●' }),
          el('div', {}, [
            el('div', { class: 'idacc__label', text: acc.label }),
            el('div', { class: 'idacc__meta', text: acc.provider + ' · ' + acc.category + (acc.handle ? ' · ' + acc.handle : '') + ' · review every ' + acc.review_days + ' days' }),
          ]),
          el('div', { class: 'idacc__counts' }, ['ok', 'finding', 'unknown'].map((st) => PNMA.stateChip(st)).map((chip, i) => {
            chip.appendChild(el('span', { text: ' ' + acc.counts[['ok', 'finding', 'unknown'][i]] }));
            return chip;
          })),
        ]);
        const rows = el('div', { class: 'idctl' }, acc.controls.map((c) => controlRow(acc, c)));
        body.appendChild(el('div', { class: 'idacc', 'data-anchor': 'account:' + acc.account_id }, [head, rows]));
      }
    } catch (err) {
      fail(body, 'Identity posture', err);
    }
  }

  function controlRow(acc, c) {
    const row = el('div', { class: 'idctl__row idctl__row--' + c.state, 'data-anchor': acc.account_id + ':' + c.control }, [
      PNMA.stateChip(c.state),
      el('div', { class: 'idctl__text' }, [
        el('div', { class: 'idctl__title', text: c.title }),
        el('div', { class: 'idctl__why', text: (c.stale ? 'STALE — ' : '') + (c.reason || c.value || ('expected: ' + c.expected)) +
          (c.attested_at ? ' · attested ' + relativeTime(c.attested_at) : '') }),
      ]),
    ]);
    if (c.source === 'hibp' && c.attested_state === null) {
      row.appendChild(el('span', { class: 'idctl__cli', text: 'pnma identity breaches ' + acc.account_id }));
    } else {
      const btns = el('div', { class: 'idctl__btns' }, ['ok', 'finding', 'unknown'].map((st) => {
        const b = el('button', { type: 'button', class: 'btn btn--' + st + (c.state === st && !c.stale ? ' is-current' : ''), text: st });
        b.addEventListener('click', async () => {
          b.disabled = true;
          const resp = await fetch('/api/identity/' + encodeURIComponent(acc.account_id) + '/' + encodeURIComponent(c.control), {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ state: st, value: c.value || null, reason: st === 'unknown' ? 'marked unknown from the dashboard' : null }),
          });
          if (resp.ok) { loadIdentity(); loadOverview(); }
          else { b.disabled = false; }
        });
        return b;
      }));
      row.appendChild(btns);
    }
    return row;
  }

  /* ================================================================== agent */

  async function loadAgent() {
    const body = document.getElementById('agent-body');
    try {
      // The live/idle pill is read every tick regardless of whether the rest
      // of this panel changed -- it is the one piece of this page with a
      // freshness clock of its own (10 minutes), independent of whatever the
      // audit/detections/sensors payloads say.
      const pill = document.getElementById('mode-pill');
      if (pill) {
        const runs = (await getJSON('/api/timeline?hours=2')).events || [];
        const ls = runs.length ? Math.max(...runs.map((e) => e.ts)) : 0;
        const fresh = ls && Date.now() / 1000 - ls < 600;
        pill.textContent = fresh ? '● live' : '○ idle' + (ls ? ' · ' + relativeTime(ls) : '');
        pill.title = fresh ? 'The collector ran within the last 10 minutes.' : 'No collection run in the last 10 minutes. Is pnma collect running?';
        pill.className = 'tool tool--mode ' + (fresh ? 'tool--live' : 'tool--idle');
      }

      const raw = await Promise.all([getRaw('/api/audit?hours=24'), getRaw('/api/detections'), getRaw('/api/sensors')]);
      // The 11 rule disclosures below are the panel's own <details> elements
      // -- exactly what a poll-driven full rebuild must not close out from
      // under a reader partway through one. Skip the rebuild when nothing
      // in the underlying data actually changed.
      if (unchanged('agent', raw.map((r) => r.text).join('\u0000'), body.firstChild)) return;
      const [audit, det, sensors] = raw.map((r) => r.json);
      for (const s of sensors.sensors) PNMA.learnName(s.hostname);
      clear(body);
      const a = audit.authorisation || {};
      body.appendChild(el('div', { class: 'agent__auth ' + (a.currently_allowed ? 'agent__auth--ok' : 'agent__auth--no') }, [
        el('strong', { text: a.currently_allowed ? 'Authorised' : 'NOT authorised' }),
        el('span', { text: ' for ' + (a.authorised_cidr || '?') + (a.gateway_pinned ? ', gateway fingerprint pinned. ' : ', gateway NOT pinned. ') + (a.reason || '') }),
      ]));

      const posture = audit.posture || [];
      const okN = posture.filter((p) => p.ok).length;
      body.appendChild(el('h3', { class: 'sub', text: 'Own safety posture: ' + okN + ' of ' + posture.length }));
      body.appendChild(el('div', { class: 'checks' }, posture.map((p) =>
        el('div', { class: 'check check--' + (p.ok ? 'ok' : 'finding') }, [
          PNMA.stateChip(p.ok ? 'ok' : 'finding'),
          el('div', {}, [el('div', { class: 'check__title', text: p.check }), el('div', { class: 'check__detail', text: p.detail })]),
        ]))));

      const nb = audit.noise_budget || {};
      const act = audit.activity || [];
      body.appendChild(el('h3', { class: 'sub', text: 'Activity, 24h' }));
      body.appendChild(el('div', { class: 'tiles tiles--compact' }, [
        tile(act.reduce((n, r) => n + r.n, 0), 'collection runs', { foot: act.map((r) => r.n + ' ' + (KIND_LABEL[r.kind] || r.kind)).join(', ') }),
        tile(act.reduce((n, r) => n + r.failed, 0), 'failed', { cls: act.some((r) => r.failed) ? 'tile--bad' : '' }),
        tile(act.reduce((n, r) => n + r.refused, 0) + ((audit.refusals || {}).scope || 0), 'refused by scope guard', { foot: 'targets outside the authorised network are never touched' }),
        tile(nb.capacity ? Math.round((nb.available / nb.capacity) * 100) + '%' : '—', 'noise budget left',
             { foot: nb.granted_total + ' probes granted, ' + nb.denied_total + ' denied', cls: nb.denied_total ? 'tile--warn' : '' }),
      ]));

      body.appendChild(el('h3', { class: 'sub', text: (det.rules || []).length + ' detection rules, each with its blind spot' }));
      body.appendChild(el('div', { class: 'rules' }, (det.rules || []).map((r) =>
        el('details', { class: 'rule' }, [
          el('summary', {}, [PNMA.severityChip(r.severity), el('span', { class: 'rule__name', text: ' ' + r.name }),
                             r.mitre_id ? el('span', { class: 'rule__mitre', text: r.mitre_id }) : null]),
          el('p', { class: 'rule__blind' }, [el('strong', { text: 'Blind spot: ' }), r.blind_spots || 'none stated']),
        ]))));

      body.appendChild(el('h3', { class: 'sub', text: 'Sensors' }));
      body.appendChild(el('div', { class: 'checks' }, (sensors.sensors || []).map((s) =>
        el('div', { class: 'check' }, [
          el('div', {}, [el('div', { class: 'check__title', text: s.kind + ' · ' + s.hostname + ' · v' + s.version }),
                         el('div', { class: 'check__detail', text: 'last seen ' + relativeTime(s.last_seen) })]),
        ]))));
    } catch (err) {
      fail(body, 'Agent report', err);
    }
  }

  /* =================================================================== boot */

  PNMA.showTab = showTab;
  PNMA.openDeviceSheet = openSheet;
  document.addEventListener('DOMContentLoaded', () => {
    buildTabs();
    buildTools();
    PNMA.namesReady = Promise.all([getJSON('/api/devices'), getJSON('/api/sensors')]).then(([d, s]) => {
      for (const x of d.devices || []) PNMA.learnName(x.hostname);
      for (const x of s.sensors || []) PNMA.learnName(x.hostname);
    }).catch(() => { /* the gate or a dead API; the panels report that themselves */ });
    loadOverview(); loadMap(); loadActivity(); loadAttack(); loadIdentity(); loadAgent();
    every(loadOverview, 60000);
    every(loadMap, 60000);
    every(loadActivity, 60000);
    every(loadAttack, 120000);
    every(loadIdentity, 120000);
    every(loadAgent, 120000);
    document.addEventListener('visibilitychange', paintStream);
    streamLoop();
  });
})();
