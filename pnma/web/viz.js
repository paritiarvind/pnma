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
  let privacy = true;
  try { privacy = localStorage.getItem(PRIV_KEY) !== '0'; } catch (e) { /* private mode */ }

  const MAC_RE = /\b([0-9a-f]{2})[:-]([0-9a-f]{2})[:-]([0-9a-f]{2})[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-]([0-9a-f]{2})\b/gi;
  const IP_RE = /\b(?:\d{1,3}\.){3}(\d{1,3})\b/g;
  const EMAIL_RE = /\b([a-z0-9._%+-])[a-z0-9._%+-]*@([a-z0-9.-]+\.[a-z]{2,})\b/gi;
  const knownNames = new Set(); // hostnames learned from payloads

  function maskNames(s) {
    for (const name of knownNames) {
      if (name.length < 3) continue;
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

  function showTab(name) {
    if (!TABS.some(([k]) => k === name)) name = 'overview';
    document.querySelectorAll('section[data-tab]').forEach((s) => {
      s.classList.toggle('is-active', s.dataset.tab === name);
    });
    document.querySelectorAll('.tabs__tab').forEach((b) => {
      b.classList.toggle('is-active', b.dataset.tab === name);
      b.setAttribute('aria-selected', b.dataset.tab === name ? 'true' : 'false');
    });
    if (location.hash !== '#' + name) history.replaceState(null, '', '#' + name);
    window.scrollTo({ top: 0 });
  }

  function buildTabs() {
    const nav = document.getElementById('tabs');
    for (const [key, label] of TABS) {
      const badge = el('span', { class: 'tabs__badge', hidden: true });
      badges[key] = badge;
      const b = el('button', { class: 'tabs__tab', 'data-tab': key, role: 'tab', type: 'button' },
                   [el('span', { class: 'tabs__glyph', text: TAB_GLYPH[key] }),
                    el('span', { class: 'tabs__label', text: label }), badge]);
      b.addEventListener('click', () => showTab(key));
      nav.appendChild(b);
    }
    window.addEventListener('hashchange', () => showTab(location.hash.slice(1)));
    showTab(location.hash.slice(1));
  }
  const TAB_GLYPH = { overview: '◎', network: '⌘', host: '⌂', alerts: '⚠',
                      identity: '☺', agent: '⚙' };

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
      title: privacy ? 'Privacy mode on: identifiers are masked. Tap to reveal.'
                     : 'Privacy mode off: full identifiers shown. Tap to mask.',
      text: privacy ? '◐ masked' : '● revealed',
    });
    priv.addEventListener('click', () => setPrivacy(!privacy));
    tools.appendChild(priv);
    tools.appendChild(el('span', { class: 'tool tool--mode', id: 'mode-pill', text: '…' }));
  }

  /* =============================================================== overview */

  /* A posture ring. Three arcs in state colours, proportional to counts, on
   * a recessive track. The number in the middle is "measured and ok" as a
   * percentage of *everything*, so unknown costs exactly what a finding
   * costs -- that is the gamification rule of this page, and it is the same
   * rule the host module was built on. */
  function ring(label, counts, sub) {
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
    g.appendChild(svgText(cx, cy + 2, score === null ? '—' : score, { class: 'ring__score', 'text-anchor': 'middle' }));
    g.appendChild(svgText(cx, cy + 18, score === null ? 'no data' : 'of ' + total, { class: 'ring__of', 'text-anchor': 'middle' }));

    const legend = el('div', { class: 'ring__legend' }, ['ok', 'finding', 'unknown'].map((s) =>
      el('span', { class: 'ring__key' }, [
        el('i', { class: 'swatch', style: 'background:' + STATE_COLOR[s] }),
        String(counts[s]) + ' ' + s,
      ])));
    return el('div', { class: 'ringcard' }, [
      g, el('div', { class: 'ringcard__label', text: label }),
      el('div', { class: 'ringcard__sub', text: sub }), legend,
    ]);
  }

  function tile(value, label, opts) {
    opts = opts || {};
    return el('div', { class: 'tile' + (opts.cls ? ' ' + opts.cls : ''), title: opts.title || null }, [
      el('div', { class: 'tile__value', text: value }),
      el('div', { class: 'tile__label', text: label }),
      opts.foot ? el('div', { class: 'tile__foot', text: opts.foot }) : null,
      opts.child || null,
    ]);
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

  async function loadOverview() {
    const body = document.getElementById('overview-body');
    try {
      const [summary, host, identity, devices, sensors] = await Promise.all([
        getJSON('/api/summary'), getJSON('/api/host'), getJSON('/api/identity'),
        getJSON('/api/devices'), getJSON('/api/sensors'),
      ]);
      for (const d of devices.devices) PNMA.learnName(d.hostname);
      for (const s of sensors.sensors) PNMA.learnName(s.hostname);

      const net = networkCounts(devices.devices);
      const hs = host.summary, is = identity.summary;
      const openPorts = devices.devices.reduce((a, d) => a + (d.open_ports || []).length, 0);
      const risky = devices.devices.reduce((a, d) => a + (d.open_ports || []).filter((p) => p.risk && p.risk !== 'none').length, 0);

      const rings = el('div', { class: 'rings' }, [
        ring('Network', net, devices.devices.length + ' ' + plural(devices.devices.length, 'device')),
        ring('Host', { ok: hs.ok, finding: hs.finding, unknown: hs.unknown },
             hs.elevated ? 'collected elevated' : hs.blocked_by_privilege + ' blocked by privilege'),
        ring('Identity', { ok: is.ok, finding: is.finding, unknown: is.unknown },
             is.accounts ? is.accounts + ' ' + plural(is.accounts, 'account') + ', ' + is.stale + ' stale' : 'no accounts registered'),
      ]);

      const alerts = summary.alerts;
      const tiles = el('div', { class: 'tiles' }, [
        tile(devices.devices.filter((d) => d.online).length + ' / ' + summary.devices.total, 'devices online',
             { foot: summary.devices.untrusted_online + ' untrusted online', cls: summary.devices.untrusted_online ? 'tile--warn' : '' }),
        tile(alerts.open, plural(alerts.open, 'open alert'), { child: severityBar(alerts.by_severity || {}),
             cls: (alerts.by_severity || {}).critical || (alerts.by_severity || {}).high ? 'tile--bad' : '' }),
        tile(openPorts, plural(openPorts, 'open port'), { foot: risky ? risky + ' flagged risky' : 'none flagged risky', cls: risky ? 'tile--warn' : '' }),
        tile(fmtPct(summary.availability_24h_pct), 'reachable, 24h', { foot: summary.availability_24h_pct === null ? 'no samples yet' : 'across all devices' }),
        tile(fmtMs(summary.latency_1h.avg_ms), 'avg round-trip, 1h', { foot: summary.latency_1h.samples + ' samples, max ' + fmtMs(summary.latency_1h.max_ms) }),
        tile(hs.unknown + is.unknown + net.unknown, 'unmeasured controls', { foot: 'each one is a point you can win back', cls: 'tile--unknown' }),
      ]);

      // Gaps to close: the gamification loop. Sorted so the cheapest wins
      // come first -- attesting an identity control is a tap, elevating the
      // collector is a restart, trusting a device is a decision.
      const gaps = [];
      for (const acc of identity.accounts) for (const c of acc.controls) if (c.state !== 'ok')
        gaps.push({ tab: 'identity', text: acc.label + ': ' + c.title, why: c.reason || 'finding', state: c.state });
      for (const d of devices.devices) if (!d.trusted && Date.now() / 1000 - d.last_seen < 86400)
        gaps.push({ tab: 'network', text: 'Decide trust for ' + (d.label || d.hostname || d.ip || d.mac), why: 'untrusted and seen today', state: 'finding' });
      for (const f of host.facts) if (f.state !== 'ok')
        gaps.push({ tab: 'host', text: f.title, why: f.reason || (f.state === 'unknown' ? 'could not run' : 'finding'), state: f.state });
      const gapList = el('div', { class: 'gaps' }, [
        el('h3', { class: 'gaps__title', text: gaps.length ? gaps.length + ' ' + plural(gaps.length, 'gap') + ' to close' : 'No gaps. Every control measured and passing.' }),
        el('ul', { class: 'gaps__list' }, gaps.slice(0, 12).map((g) => {
          const li = el('li', { class: 'gap gap--' + g.state }, [
            PNMA.stateChip(g.state), el('span', { class: 'gap__text', text: g.text }),
            el('span', { class: 'gap__why', text: g.why }),
          ]);
          li.addEventListener('click', () => showTab(g.tab));
          return li;
        })),
        gaps.length > 12 ? el('p', { class: 'section__note', text: 'and ' + (gaps.length - 12) + ' more in their panels' }) : null,
      ]);

      clear(body);
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
    const W = 640, H = 480, cx = W / 2, cy = H / 2;
    const gw = devices.find((d) => d.device_class === 'gateway' || d.device_class === 'router') ||
               devices.reduce((a, d) => (d.open_ports || []).length > (a.open_ports || []).length ? d : a, devices[0]);
    const others = devices.filter((d) => d !== gw);
    const R = Math.min(W, H) / 2 - 70;
    const root = svg('svg', { viewBox: '0 0 ' + W + ' ' + H, class: 'netmap', role: 'img' }, [
      title('Network map: ' + devices.length + ' devices'),
    ]);
    // Orbit ring, hairline, one shade off the surface.
    root.appendChild(svg('circle', { cx, cy, r: R, class: 'netmap__orbit' }));

    const now = Date.now() / 1000;
    others.forEach((d, i) => {
      const a = (i / others.length) * 2 * Math.PI - Math.PI / 2;
      const x = cx + R * Math.cos(a), y = cy + R * Math.sin(a);
      const online = now - d.last_seen < 900;
      root.appendChild(svg('line', {
        x1: cx, y1: cy, x2: x, y2: y,
        class: 'netmap__edge' + (online ? '' : ' netmap__edge--dim'),
      }));
      root.appendChild(node(d, x, y, online, false));
    });
    root.appendChild(node(gw, cx, cy, now - gw.last_seen < 900, true));
    body.appendChild(root);
    body.appendChild(el('div', { class: 'netmap__legend' }, [
      key('ring: trusted', 'var(--accent)'), key('ring: untrusted', 'var(--warn)'),
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
      svg('circle', { cx: x, cy: y, r, class: 'netnode__body', stroke: d.trusted ? 'var(--accent)' : 'var(--warn)' }),
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
    try {
      const payload = await getJSON('/api/devices');
      mapDevices = payload.devices;
      for (const d of mapDevices) PNMA.learnName(d.hostname);
      renderMap(mapDevices);
      renderNetStats(mapDevices);
    } catch (err) {
      fail(body, 'Network map', err);
    }
  }

  /* ---------------------------------------------------------- device sheet */

  async function openSheet(deviceId) {
    const sheet = document.getElementById('device-sheet');
    sheet.hidden = false;
    clear(sheet);
    const card = el('div', { class: 'sheet__card' }, [el('div', { class: 'placeholder', text: 'Loading device…' })]);
    sheet.appendChild(card);
    const close = () => { sheet.hidden = true; clear(sheet); };
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
      const payload = await getJSON('/api/timeline?hours=24');
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
      const failed = events.filter((e) => e.error).length;
      body.appendChild(el('div', { class: 'netmap__legend' }, [
        el('span', { text: events.length + ' runs' }),
        el('span', {}, [el('i', { class: 'swatch', style: 'background:var(--finding)' }), failed + ' failed']),
        el('span', {}, [el('i', { class: 'swatch swatch--hatch' }), 'refused by scope guard']),
        el('span', { text: 'width = duration' }),
      ]));
      const lastErr = events.find((e) => e.error);
      if (lastErr) body.appendChild(el('p', { class: 'section__note', text: 'Most recent failure: ' + hhmm(lastErr.ts) + ' ' + (KIND_LABEL[lastErr.kind] || lastErr.kind) + ' — ' + lastErr.error }));
    } catch (err) {
      fail(body, 'Activity', err);
    }
  }

  /* ================================================================ ATT&CK */

  async function loadAttack() {
    const body = document.getElementById('attack-body');
    try {
      const payload = await getJSON('/api/attack');
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
          col.appendChild(el('div', {
            class: 'matrix__cell', style: t.severity ? 'border-left-color:' + SEV_COLOR[t.severity] : null,
            title: (t.name || id) + (t.count ? ' — ' + t.count + ' open ' + plural(t.count, 'alert') : ''),
          }, [el('span', { class: 'matrix__id', text: id }), el('span', { class: 'matrix__name', text: t.name || '' })]));
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
      const payload = await getJSON('/api/identity');
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
      body.appendChild(el('div', { class: 'idsummary' }, [
        ring('Identity', { ok: s.ok, finding: s.finding, unknown: s.unknown }, s.accounts + ' ' + plural(s.accounts, 'account')),
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
        body.appendChild(el('div', { class: 'idacc' }, [head, rows]));
      }
    } catch (err) {
      fail(body, 'Identity posture', err);
    }
  }

  function controlRow(acc, c) {
    const row = el('div', { class: 'idctl__row idctl__row--' + c.state }, [
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
      const [audit, det, sensors] = await Promise.all([getJSON('/api/audit?hours=24'), getJSON('/api/detections'), getJSON('/api/sensors')]);
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
      // Liveness comes from the most recent collection run, not the sensor
      // row: the sensor heartbeat is written at startup, and a collector that
      // has been running for an hour would otherwise read as idle.
      const pill = document.getElementById('mode-pill');
      if (pill) {
        const runs = (await getJSON('/api/timeline?hours=2')).events || [];
        const ls = runs.length ? Math.max(...runs.map((e) => e.ts)) : 0;
        const fresh = ls && Date.now() / 1000 - ls < 600;
        pill.textContent = fresh ? '● live' : '○ idle' + (ls ? ' · ' + relativeTime(ls) : '');
        pill.title = fresh ? 'The collector ran within the last 10 minutes.' : 'No collection run in the last 10 minutes. Is pnma collect running?';
        pill.className = 'tool tool--mode ' + (fresh ? 'tool--live' : 'tool--idle');
      }
    } catch (err) {
      fail(body, 'Agent report', err);
    }
  }

  /* =================================================================== boot */

  PNMA.showTab = showTab;
  document.addEventListener('DOMContentLoaded', () => {
    buildTabs();
    buildTools();
    loadOverview(); loadMap(); loadActivity(); loadAttack(); loadIdentity(); loadAgent();
    setInterval(loadOverview, 60000);
    setInterval(loadMap, 60000);
    setInterval(loadActivity, 60000);
    setInterval(loadAttack, 120000);
    setInterval(loadIdentity, 120000);
    setInterval(loadAgent, 120000);
  });
})();
