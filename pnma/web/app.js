/* PNMA dashboard client.
 *
 * Vanilla ES2020, no build step, no dependencies. `pnma/api/app.py` serves
 * static files from an explicit allowlist (`STATIC_FILES`) and there is no
 * static mount behind it, so a new file first needs a route. This file owns
 * the four original panels; `viz.js` (loaded before it) owns navigation, the
 * privacy mask, the overview, ATT&CK, identity and agent panels, and the
 * shared helpers below are exported on `window.PNMA` for it.
 *
 * Everything renders through `el()` and textContent rather than innerHTML. That
 * is not ceremony: this dashboard displays scheduled task names, driver paths
 * and service descriptions read off a possibly-compromised host. Those strings
 * are attacker-influenced, and a monitoring tool that executes what it monitors
 * is a delivery mechanism. The only markup on the page is markup this file
 * constructs.
 */

/* ------------------------------------------------------------------ states */

/* The three outcomes, and how each is drawn.
 *
 * `unknown` is the reason this module exists. It means the check could not run
 * -- most often because the collector was not elevated -- and it is NOT a pass.
 * A dashboard that folds `unknown` into `ok`, or renders it in a polite grey
 * next to the green ones, manufactures confidence that the data does not
 * support. So each state gets a colour, a glyph and a spelled-out word, and
 * `unknown` additionally gets a hatched rail in the stylesheet so it stays
 * distinguishable from both `ok` and `finding` in greyscale.
 */
const STATES = {
  ok:      { glyph: '✓', label: 'OK',      order: 2 }, // check mark
  finding: { glyph: '!',      label: 'FINDING', order: 0 },
  unknown: { glyph: '?',      label: 'UNKNOWN', order: 1 },
};

const STATE_KEYS = ['ok', 'finding', 'unknown'];

/* Preferred group order, roughly "most likely to matter first". Categories the
 * payload does not contain are never rendered -- the Windows collector emits
 * `network` facts, but a run where those checks all failed to register produces
 * a payload with four categories, and an empty fifth group would read as a
 * clean fifth category. Anything unrecognised sorts to the end rather than
 * being dropped, so a new collector category shows up without a UI change. */
const CATEGORY_ORDER = ['defender', 'audit', 'persistence', 'network', 'drivers'];

const CATEGORY_LABELS = {
  defender:    'Defender',
  audit:       'Audit & logging',
  persistence: 'Persistence',
  network:     'Network',
  drivers:     'Drivers',
};

/* ------------------------------------------------------------- DOM helpers */

/**
 * Build an element. `attrs.text` sets textContent; children may be nodes,
 * strings, or null (skipped) so callers can inline conditionals without
 * assembling arrays by hand.
 */
function el(tag, attrs, children) {
  const node = document.createElement(tag);
  // Privacy mode is applied at the one place every string on this page passes
  // through, so a MAC inside an alert description or an evidence blob is
  // masked the same way as one in a device row. `viz.js` defines the mask; it
  // is an identity function when privacy mode is off or viz.js is absent.
  const mask = (window.PNMA && window.PNMA.mask) || ((x) => x);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'text') node.textContent = mask(String(v));
      else if (k === 'class') node.className = v;
      else if (k === 'title') node.setAttribute(k, mask(String(v)));
      else node.setAttribute(k, v);
    }
  }
  for (const child of children || []) {
    if (child === null || child === undefined || child === false) continue;
    node.appendChild(typeof child === 'string' ? document.createTextNode(mask(child)) : child);
  }
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

/** Plural helper: `n === 1 ? "check" : "checks"`, without the noise at callsites. */
function plural(n, singular, pluralForm) {
  return n === 1 ? singular : (pluralForm || singular + 's');
}

/**
 * Format a unix timestamp as a coarse relative age.
 *
 * Coarse on purpose. The collector runs on a schedule measured in minutes, so
 * second-level precision here would imply a freshness the data does not have.
 */
function relativeTime(ts) {
  if (!ts) return null;
  const secs = Math.max(0, Date.now() / 1000 - ts);
  if (secs < 90) return 'just now';
  const mins = Math.round(secs / 60);
  if (mins < 60) return mins + ' ' + plural(mins, 'minute') + ' ago';
  const hours = Math.round(mins / 60);
  if (hours < 48) return hours + ' ' + plural(hours, 'hour') + ' ago';
  const days = Math.round(hours / 24);
  return days + ' ' + plural(days, 'day') + ' ago';
}

/* ------------------------------------------------------- host inventory */

const CLASS_LABEL = {
  remote_access: 'remote access', activation_tooling: 'activation / crack', tor: 'Tor', tunnel: 'tunnel',
  security_tooling: 'security tooling', no_publisher: 'no publisher', user_writable_path: 'user-writable path',
  recent: 'installed this week', trusted_publisher: 'known vendor', script_host: 'script host',
  obfuscated_or_downloader: 'encoded / downloader', unsigned: 'unsigned', pnma_own: 'PNMA itself',
};
const FLAG_CLASSES = new Set(['remote_access', 'activation_tooling', 'tor', 'tunnel', 'security_tooling', 'script_host', 'obfuscated_or_downloader', 'unsigned']);

function classChips(tags) {
  return el('span', { class: 'classchips' }, (tags || []).map((t) =>
    el('span', { class: 'classchip' + (FLAG_CLASSES.has(t) ? ' classchip--flag' : ''), text: CLASS_LABEL[t] || t })));
}

/* Installed software and autoruns from /api/host/software and
 * /api/host/autoruns. "Flagged only" is the default view: on a real machine
 * the full list is 130 rows and the analyst wants the six that matter, but
 * the six are only credible next to the count of the rest. */
let inventoryShowAll = false;
async function loadHostInventory() {
  const body = document.getElementById('host-inventory-body');
  if (!body) return;
  try {
    const [sw, ar] = await Promise.all([
      fetch('/api/host/software').then((r) => { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); }),
      fetch('/api/host/autoruns').then((r) => { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); }),
    ]);
    const software = sw.software || [];
    const autoruns = ar.autoruns || [];
    const sig = JSON.stringify([software, autoruns, inventoryShowAll]);
    if (body.dataset.sig === sig) return;
    body.dataset.sig = sig;
    clear(body);
    if (!software.length && !autoruns.length) {
      body.appendChild(el('div', { class: 'placeholder' }, [
        el('strong', { text: 'No inventory yet' }),
        el('p', { text: 'The host-events collector has not run on this machine (Windows only; it runs with the collector every five minutes).' }),
      ]));
      return;
    }
    const flagged = (rows) => rows.filter((r) => (r.tags || []).some((t) => FLAG_CLASSES.has(t)));
    const swShown = inventoryShowAll ? software : flagged(software);
    const arShown = inventoryShowAll ? autoruns : flagged(autoruns);
    const toggle = el('button', { class: 'btn', type: 'button', text: inventoryShowAll ? 'Show flagged only' : 'Show all ' + software.length + ' programs and ' + autoruns.length + ' autoruns' });
    toggle.addEventListener('click', () => { inventoryShowAll = !inventoryShowAll; loadHostInventory(); });
    body.appendChild(el('div', { class: 'inventory__head' }, [
      el('p', { class: 'alert__desc', text: software.length + ' installed ' + plural(software.length, 'program') + ', ' + flagged(software).length + ' flagged \u00b7 ' + autoruns.length + ' ' + plural(autoruns.length, 'autorun') + ', ' + flagged(autoruns).length + ' flagged' }),
      toggle,
    ]));
    const row = (cells, cls) => el('div', { class: 'inv__row ' + (cls || '') }, cells.map((c, i) => el('div', { class: 'inv__cell inv__cell--' + i }, Array.isArray(c) ? c : [c])));
    body.appendChild(el('h3', { class: 'sub', text: 'Software' + (inventoryShowAll ? '' : ' (flagged)') }));
    body.appendChild(el('div', { class: 'inv', role: 'table' }, swShown.length ? swShown.map((s) => row([
      el('strong', { text: s.name }),
      s.publisher || '\u2014',
      (s.version || '') + (s.installed_at ? ' \u00b7 ' + relativeTime(s.installed_at) : ''),
      classChips(s.tags),
      el('span', { class: 'inv__path', text: s.location || '' }),
    ], (s.tags || []).some((t) => FLAG_CLASSES.has(t)) ? 'inv__row--flag' : '')) : [el('p', { class: 'alert__desc', text: 'Nothing flagged.' })]));
    body.appendChild(el('h3', { class: 'sub', text: 'Autoruns' + (inventoryShowAll ? '' : ' (flagged)') }));
    body.appendChild(el('div', { class: 'inv', role: 'table' }, arShown.length ? arShown.map((a) => row([
      el('strong', { text: a.name }),
      el('span', { class: 'inv__path', text: a.location }),
      a.signed === 1 ? 'signed' : a.signed === 0 ? 'UNSIGNED' : 'not checked',
      classChips(a.tags),
      el('span', { class: 'inv__path', title: a.sha256 ? 'sha256 ' + a.sha256 : '' }, [a.command || '', a.sha256 ? el('code', { class: 'inv__hash', text: ' ' + a.sha256.slice(0, 12) }) : null]),
    ], (a.tags || []).some((t) => FLAG_CLASSES.has(t)) ? 'inv__row--flag' : '')) : [el('p', { class: 'alert__desc', text: 'Nothing flagged.' })]));
  } catch (err) {
    clear(body);
    body.appendChild(el('div', { class: 'error' }, [el('strong', { text: 'Could not load the inventory' }), el('p', { text: String(err.message || err) })]));
  }
}

/* The host event stream, newest first, through the same eventLog component
 * as the drawer and the Logs tab. */
async function loadHostEvents() {
  const body = document.getElementById('host-events-body');
  if (!body) return;
  try {
    const r = await fetch('/api/events?kinds=host_event&hours=168&limit=300');
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const data = await r.json();
    const events = data.events || [];
    const sig = JSON.stringify(events.map((e) => e.ref));
    if (body.dataset.sig === sig) return;
    body.dataset.sig = sig;
    clear(body);
    if (!events.length) {
      body.appendChild(el('div', { class: 'placeholder' }, [
        el('strong', { text: 'No host events in the last 7 days' }),
        el('p', { text: 'Either nothing notable happened, or the host-events collector is not running here. The Agent tab lists what each rule reads.' }),
      ]));
      return;
    }
    const flagged = events.filter((e) => e.detail && e.detail.severity && !e.agent_generated).length;
    body.appendChild(el('p', { class: 'alert__desc', text: events.length + ' ' + plural(events.length, 'event') + ' in 7 days, ' + flagged + ' carrying a severity (those become alerts). Open a row for the fields; the SHA-256, where present, is what you look up by hand.' }));
    body.appendChild(eventLog(events, { order: 'desc' }));
  } catch (err) {
    clear(body);
    body.appendChild(el('div', { class: 'error' }, [el('strong', { text: 'Could not load host events' }), el('p', { text: String(err.message || err) })]));
  }
}

/* ------------------------------------------------------- state indicators */

/** The state chip: glyph + word + colour. Used on every fact card. */
function stateChip(state) {
  const meta = STATES[state] || { glyph: '·', label: String(state || 'unknown').toUpperCase() };
  return el('span', { class: 'state-chip is-' + state }, [
    el('span', { class: 'state-chip__glyph', text: meta.glyph, 'aria-hidden': 'true' }),
    el('span', { text: meta.label }),
  ]);
}

/**
 * Per-group tally: `[glyph] N`.
 *
 * Zeroes are dimmed rather than omitted. "0 unknown" in the Defender group is a
 * statement about coverage and deserves to be readable; silently dropping it
 * would make a group with full coverage look identical to one where the count
 * simply was not rendered.
 */
function tally(state, count) {
  const meta = STATES[state];
  return el('span', {
    class: 'tally tally--' + state + (count === 0 ? ' is-zero' : ''),
    title: count + ' ' + state,
  }, [
    el('span', { class: 'tally__glyph', text: meta.glyph, 'aria-hidden': 'true' }),
    el('span', { text: String(count) }),
    el('span', { class: 'tally__word', text: meta.label.toLowerCase() }),
  ]);
}

/* ---------------------------------------------------------------- banners */

/**
 * The coverage banner: how much of the host we failed to measure, and why.
 *
 * The split between "blocked by privilege" and "unknown for another reason" is
 * the part that has to stay correct. Not every `unknown` is an elevation
 * problem -- a collector that raises inside a check group also lands here with
 * `needs_admin` false -- and telling an operator to re-run elevated when the
 * real cause was a TypeError in the collector sends them to fix the wrong
 * thing. Being wrong about *why* a measurement is missing is the same class of
 * error this whole feature exists to prevent, so the two are counted and
 * described separately.
 */
function coverageBanner(summary, facts) {
  const unknowns = facts.filter((f) => f.state === 'unknown');
  const blocked = unknowns.filter((f) => !!f.needs_admin);
  const otherwise = unknowns.filter((f) => !f.needs_admin);
  const elevated = !!summary.elevated;

  // Nothing unmeasured and running elevated: no banner, and the stats strip
  // still shows the unknown count as zero.
  if (unknowns.length === 0 && elevated) return null;

  const body = el('div', { class: 'coverage-banner__body' }, []);
  let title;

  if (blocked.length > 0 && !elevated) {
    // Deliberately phrased as "these checks came back unmeasured", not "PNMA is
    // running unelevated". The API derives `elevated` from this very set --
    // `elevated = not blocked` -- so the flag cannot independently confirm the
    // process's privilege level. A genuinely elevated run where an admin-only
    // check fails for some other cause (WMI down, a policy blocking the query,
    // a timeout) still arrives here as `elevated: false`, and copy that asserted
    // "you are not elevated" would send the operator to fix the wrong thing --
    // the same substitution of an assumed cause for a measured one that this
    // panel exists to prevent. Re-running elevated is offered as the first thing
    // to try, which is true either way.
    title = blocked.length + ' ' + plural(blocked.length, 'check') +
            ' needing Administrator came back unmeasured';
    body.appendChild(el('p', {
      text: blocked.length + ' ' + plural(blocked.length, 'check') +
            ' that require Administrator returned no result, so ' +
            (blocked.length === 1 ? 'its' : 'their') + ' state is unmeasured — ' +
            'which is not the same as passing. The usual cause is a collector ' +
            'run without elevation.',
    }));
    body.appendChild(el('p', {}, [
      'Re-run the collector from an elevated terminal: ',
      el('code', { class: 'coverage-banner__cmd', text: 'pnma collect' }),
      '. If ' + (blocked.length === 1 ? 'it stays' : 'they stay') +
      ' unknown after that, the reason on each card is the place to look.',
    ]));
  } else if (blocked.length > 0 && elevated) {
    // Elevated and still blind. Worth saying plainly rather than staying silent:
    // silence here reproduces the false-clean result the feature exists to stop.
    title = blocked.length + ' ' + plural(blocked.length, 'check') +
            ' reported needing Administrator despite an elevated run';
    body.appendChild(el('p', {
      text: 'The collector reports itself as elevated, yet ' + blocked.length + ' ' +
            plural(blocked.length, 'check') + ' still could not read what ' +
            (blocked.length === 1 ? 'it needs' : 'they need') +
            '. That is a different problem from a privilege gap — read the ' +
            'reason on each card before assuming coverage.',
    }));
  } else if (unknowns.length > 0) {
    title = unknowns.length + ' ' + plural(unknowns.length, 'check') + ' could not run';
  } else {
    // Unelevated, nothing reported blocked. Still worth a line: a control that
    // is only visible to an elevated caller cannot always report that it was
    // hidden -- which is exactly how the original false negative happened.
    title = 'Running without Administrator';
    body.appendChild(el('p', {
      text: 'No check reported being blocked, but an unelevated run cannot ' +
            'confirm that nothing was hidden from it. Treat this as full ' +
            'coverage only after an elevated run agrees.',
    }));
  }

  if (otherwise.length > 0) {
    body.appendChild(el('p', {
      text: otherwise.length + ' further ' + plural(otherwise.length, 'check') +
            ' returned unknown for reasons other than privilege — a collector ' +
            'error, or a data source that was not available. Elevation will not ' +
            'fix ' + (otherwise.length === 1 ? 'that one' : 'those') +
            '; the reason on each card says what happened.',
    }));
  }

  return el('div', { class: 'coverage-banner', role: 'status' }, [
    el('div', { class: 'coverage-banner__glyph', text: '?', 'aria-hidden': 'true' }),
    el('div', {}, [
      el('div', { class: 'coverage-banner__title', text: title }),
      body,
    ]),
  ]);
}

/* ------------------------------------------------------------------ facts */

/**
 * One fact card.
 *
 * Which rows appear depends on the state, because the fields are genuinely
 * absent rather than empty for some of them: an `ok` fact carries no `reason`,
 * and an `unknown` fact has neither `value` nor `expected` -- there was no
 * measurement to record. Rendering "Value: null" or a blank labelled row would
 * imply the collector returned something when it did not.
 */
function factCard(fact) {
  const state = STATES[fact.state] ? fact.state : 'unknown';

  const head = el('div', { class: 'fact__head' }, [
    stateChip(state),
    el('span', { class: 'fact__title', text: fact.title || fact.fact_key, title: fact.fact_key }),
  ]);

  // Needs-admin badge. Present on facts that require elevation regardless of
  // their state: a check that needed admin and got it is worth flagging too,
  // because it tells the reader this result disappears on an unelevated run.
  if (fact.needs_admin) {
    head.appendChild(el('span', {
      class: 'badge badge--admin',
      title: 'This check reads something only an elevated process can see.',
      text: 'needs admin',
    }));
  }

  // A control being switched off is an event, not a status. The API gives us
  // `changed_at` but no previous state, so the copy says when the state last
  // changed and refuses to assert a direction it cannot derive.
  if (fact.changed_at) {
    const when = relativeTime(fact.changed_at);
    head.appendChild(el('span', {
      class: 'badge badge--changed',
      title: 'State last differed from the previous run at ' +
             new Date(fact.changed_at * 1000).toLocaleString(),
      text: 'changed ' + when,
    }));
  }

  const card = el('div', { class: 'fact fact--' + state, 'data-anchor': 'fact:' + fact.fact_key }, [head]);

  const measures = [];
  if (fact.value !== null && fact.value !== undefined && fact.value !== '') {
    measures.push(el('div', {}, [
      el('span', { class: 'fact__label', text: 'Measured' }),
      el('span', { class: 'fact__value', text: String(fact.value) }),
    ]));
  }
  if (fact.expected !== null && fact.expected !== undefined && fact.expected !== '') {
    measures.push(el('div', {}, [
      el('span', { class: 'fact__label', text: 'Expected' }),
      el('span', { class: 'fact__value fact__value--expected', text: String(fact.expected) }),
    ]));
  }
  if (measures.length) {
    card.appendChild(el('div', { class: 'fact__measure' }, measures));
  } else if (state === 'unknown') {
    // Say it outright. An unknown fact with no value row would otherwise look
    // like a rendering bug rather than a deliberate absence of data.
    card.appendChild(el('div', { class: 'fact__measure' }, [
      el('div', {}, [
        el('span', { class: 'fact__label', text: 'Measured' }),
        el('span', { class: 'fact__value fact__value--expected', text: 'nothing — the check did not complete' }),
      ]),
    ]));
  }

  // `reason` is the payload's most valuable field: it is where "Tamper
  // Protection is off" becomes "and here is what an attacker does with that".
  // Full text, no clamp -- truncating it to a tidy single line would throw away
  // the only part that tells the reader what to do next.
  if (fact.reason) {
    card.appendChild(el('p', { class: 'fact__reason', text: fact.reason }));
  }

  // Evidence is the specific detail behind a count -- *which* two scheduled
  // tasks, *which* drivers. Collapsed by default so a card stays scannable.
  //
  // `evidence` arrives decoded when it parsed as JSON and as the raw string
  // when it did not -- app.py's `_rows()` swallows the ValueError and passes
  // the original text through. Rendering only the object case would silently
  // drop the string case, and a panel whose whole argument is "never hide what
  // you could not show" cannot quietly discard evidence because it failed to
  // parse. Malformed evidence is shown as-is; the reader can judge it.
  const ev = fact.evidence;
  const evText = (ev && typeof ev === 'object')
    ? (Object.keys(ev).length ? JSON.stringify(ev, null, 2) : null)
    : (typeof ev === 'string' && ev.trim() ? ev : null);
  if (evText) {
    card.appendChild(el('details', { class: 'fact__evidence' }, [
      el('summary', { text: typeof ev === 'string' ? 'evidence (unparsed)' : 'evidence' }),
      el('pre', { text: evText }),
    ]));
  }

  return card;
}

/**
 * Group facts by category.
 *
 * Findings first, then unknowns, then passes, within each group. The ordering
 * is deliberate: unknowns rank above passes because an unmeasured control is
 * closer to a problem than to a clean result, and burying them under a run of
 * green is how they get missed.
 */
function categoryGroup(category, facts) {
  const counts = {};
  for (const key of STATE_KEYS) counts[key] = 0;
  for (const f of facts) {
    if (counts[f.state] === undefined) counts.unknown += 1;
    else counts[f.state] += 1;
  }

  const sorted = facts.slice().sort((a, b) => {
    const oa = (STATES[a.state] || STATES.unknown).order;
    const ob = (STATES[b.state] || STATES.unknown).order;
    if (oa !== ob) return oa - ob;
    return String(a.fact_key).localeCompare(String(b.fact_key));
  });

  // A group is one line until it needs to be more. Findings and unknowns
  // are shown as cards; the checks that passed fold into a single sentence
  // -- "8 passing: Real-time protection, Tamper protection, ..." -- because a
  // wall of green cards is the opposite of a wall the reader can scan.
  const attention = sorted.filter((f) => f.state !== 'ok');
  const passing = sorted.filter((f) => f.state === 'ok');
  const verdict = counts.finding ? counts.finding + ' ' + plural(counts.finding, 'finding')
    : counts.unknown ? counts.unknown + ' unmeasured' : 'all ' + counts.ok + ' passing';
  const head = el('summary', { class: 'cat-group__head' }, [
    el('span', { class: 'cat-group__chev', text: '\u203a' }),
    el('span', { class: 'cat-group__name', text: CATEGORY_LABELS[category] || category }),
    el('span', { class: 'cat-group__verdict cat-group__verdict--' + (counts.finding ? 'finding' : counts.unknown ? 'unknown' : 'ok'), text: verdict }),
    el('span', { class: 'cat-group__counts' }, [
      tally('finding', counts.finding),
      tally('unknown', counts.unknown),
      tally('ok', counts.ok),
    ]),
  ]);
  const body = attention.map(factCard);
  if (passing.length) {
    body.push(el('details', { class: 'fact fact--ok fact--passing' }, [
      el('summary', { class: 'fact__passing' }, [
        stateChip('ok'),
        el('span', { text: passing.length + ' passing: ' + passing.map((f) => f.title || f.fact_key).join(', ') }),
      ]),
      el('div', { class: 'fact__passinglist' }, passing.map(factCard)),
    ]));
  }
  return el('details', { class: 'cat-group', open: attention.length ? 'open' : null, 'data-category': category }, [head].concat(body));
}

/* ---------------------------------------------------------------- summary */

function statsStrip(summary, facts) {
  // Trust the payload's summary when it is present, but fall back to counting
  // the facts. The two should agree; if the API ever ships a summary computed
  // over a different filter than the fact list, counting locally is the answer
  // that matches what the reader can actually see on screen.
  const counted = { ok: 0, finding: 0, unknown: 0 };
  for (const f of facts) {
    if (counted[f.state] === undefined) counted.unknown += 1;
    else counted[f.state] += 1;
  }
  const total = facts.length || summary.total || 0;

  function stat(kind, label, n) {
    return el('div', { class: 'stat stat--' + kind }, [
      el('div', { class: 'stat__n', text: String(n) }),
      el('div', { class: 'stat__label', text: label }),
    ]);
  }

  const strip = el('div', { class: 'posture-stats' }, [
    stat('total', plural(total, 'check'), total),
    stat('finding', plural(counted.finding, 'finding'), counted.finding),
    // Always rendered, including at zero. The unknown count is the honesty
    // metric for this whole panel; hiding it when it happens to be zero would
    // make its absence ambiguous on the runs where it is not.
    stat('unknown', 'could not run', counted.unknown),
    stat('ok', 'passing', counted.ok),
  ]);

  return strip;
}

/* ----------------------------------------------------------- empty states */

/**
 * No facts at all. Almost always a non-Windows host: the posture collector is
 * Windows-only, so on Linux or macOS it declines to run and stores nothing.
 *
 * This has to read as "not measured" and never as "all clear" -- an empty green
 * panel here would be the same lie as an `unknown` rendered in green.
 */
function emptyState(summary) {
  const kids = [
    el('div', { class: 'placeholder__title', text: 'No host posture data' }),
    el('p', {
      text: 'The posture collector is Windows-only. On any other platform it ' +
            'declines to run rather than guessing, so this panel has nothing ' +
            'to show — which is not the same as this host being clean. ' +
            'Nothing about it has been checked.',
    }),
  ];
  if (summary && summary.last_run) {
    kids.push(el('p', {
      text: 'A collection did run ' + relativeTime(summary.last_run) +
            ' and produced no facts. If this is a Windows host, check the ' +
            'collector log — an empty result there is a failure, not a pass.',
    }));
  } else {
    kids.push(el('p', {}, [
      'No collection has been recorded yet. Run ',
      el('code', { class: 'coverage-banner__cmd', text: 'pnma collect' }),
      ' on this host to populate it.',
    ]));
  }
  return el('div', { class: 'placeholder' }, kids);
}

function errorState(err) {
  return el('div', { class: 'placeholder placeholder--error' }, [
    el('div', { class: 'placeholder__title', text: 'Host posture unavailable' }),
    el('p', {
      text: 'The dashboard could not read /api/host: ' + err +
            '. This panel shows nothing rather than the last good result, ' +
            'because a stale posture reading is worse than none.',
    }),
  ]);
}

/* --------------------------------------------------------------- normalise */

/**
 * Coerce every fact's `state` into the three-value vocabulary, once, before
 * anything counts or renders it.
 *
 * The vocabulary is `ok|finding|unknown` today, but the detection rules feeding
 * this table are still being written and a fourth value is a plausible future.
 * Without a single normalisation point the failure is silent and specific: a
 * fact with an unrecognised state would fall into the `unknown` bucket in the
 * stats strip and the group tallies (both of which treat "not one of the three"
 * as unknown) while a strict `state === 'unknown'` filter in the banner skipped
 * it -- so the strip would say five could not run and the banner would explain
 * four. The banner is the honesty metric for this panel; it disagreeing with
 * the count beside it is the one bug that discredits the whole feature.
 *
 * Anything unrecognised becomes `unknown` rather than being dropped or shown as
 * `ok`. An unmapped state is by definition something this build cannot vouch
 * for, which is what `unknown` means.
 */
function normaliseFacts(facts) {
  return facts.map((f) => (
    STATES[f.state] ? f : Object.assign({}, f, { state: 'unknown' })
  ));
}

/* ------------------------------------------------------------------ render */

/**
 * Render the whole Host posture panel from an `/api/host` payload.
 *
 * Exported on `window` so the panel can be driven from a fixture during
 * development without standing up the API.
 */
function renderHostPosture(payload, container) {
  const summary = (payload && payload.summary) || {};
  const facts = normaliseFacts((payload && payload.facts) || []);

  clear(container);

  if (!facts.length) {
    container.appendChild(emptyState(summary));
    return;
  }

  container.appendChild(statsStrip(summary, facts));

  const banner = coverageBanner(summary, facts);
  if (banner) container.appendChild(banner);

  // Group by whatever categories the payload actually contains. A category with
  // no facts is never rendered -- an empty "Network" group would read as a
  // category that passed, which is precisely the wrong inference.
  const byCategory = new Map();
  for (const f of facts) {
    const cat = f.category || 'uncategorised';
    if (!byCategory.has(cat)) byCategory.set(cat, []);
    byCategory.get(cat).push(f);
  }

  const cats = Array.from(byCategory.keys()).sort((a, b) => {
    const ia = CATEGORY_ORDER.indexOf(a);
    const ib = CATEGORY_ORDER.indexOf(b);
    // Unrecognised categories sort after the known ones instead of vanishing,
    // so a new collector category appears without a change here.
    return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib) || a.localeCompare(b);
  });

  for (const cat of cats) {
    container.appendChild(categoryGroup(cat, byCategory.get(cat)));
  }

  if (summary.last_run) {
    container.appendChild(el('p', {
      class: 'section__note',
      style: 'margin-top: 16px',
      text: 'Collected ' + relativeTime(summary.last_run) + '.',
    }));
  }
}

/* The last payload rendered, serialised. The poll below rebuilds the panel from
 * scratch, which would otherwise close every <details> the reader had open --
 * and on this panel the open one is usually the evidence list naming *which*
 * tasks run as SYSTEM, opened precisely because it is being read slowly.
 * Posture changes once per collector run, so nearly every poll is a no-op;
 * comparing the payload makes it a no-op in the DOM too. */
let lastPayload = null;

async function loadHostPosture() {
  const container = document.getElementById('host-posture-body');
  if (!container) return;
  try {
    const resp = await fetch('/api/host');
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const body = await resp.text();
    if (body === lastPayload && container.querySelector('.fact, .placeholder')) return;
    lastPayload = body;
    renderHostPosture(JSON.parse(body), container);
  } catch (err) {
    lastPayload = null;
    clear(container);
    container.appendChild(errorState(err && err.message ? err.message : String(err)));
  }
}

/* ================================================================== alerts */

/* Severity vocabulary.
 *
 * A separate axis from STATES above, and kept separate deliberately -- see the
 * token comment in style.css. `order` drives sorting; the API already sorts by
 * severity, but the panel re-sorts locally so a payload from a future endpoint
 * that forgets to cannot quietly present a low above a critical.
 */
const SEVERITIES = {
  critical: { label: 'critical', order: 0 },
  high:     { label: 'high',     order: 1 },
  medium:   { label: 'medium',   order: 2 },
  low:      { label: 'low',      order: 3 },
};

/**
 * Coerce every alert's severity into the four-value vocabulary, once.
 *
 * The sibling of `normaliseFacts`, and for the same reason. The alerts SQL
 * already sorts unrecognised severities last with `ELSE 4`, which means the
 * API will happily return a severity this file has no colour, no rail and no
 * sort order for. Unmapped values become `low` rather than being dropped:
 * dropping an alert is the one outcome a monitoring panel may never produce,
 * and inventing a `critical` for a value we cannot interpret would be the
 * opposite error. The raw value is preserved on `severity_raw` and shown on the
 * card, so an unrecognised severity is visible rather than silently flattened.
 */
function normaliseAlerts(alerts) {
  return alerts.map((a) => (
    SEVERITIES[a.severity]
      ? a
      : Object.assign({}, a, { severity: 'low', severity_raw: a.severity })
  ));
}

/* Which transitions each status offers, and the order statuses are listed in.
 *
 * `resolved` keeps a Reopen rather than disappearing: resolving is a judgement,
 * and a judgement you cannot revisit is one the operator has to be sure about
 * before making, which is how alerts stop being acknowledged at all. */
const ALERT_ACTIONS = {
  open:         [['acknowledge', 'Acknowledge'], ['resolve', 'Resolve']],
  acknowledged: [['resolve', 'Resolve'], ['reopen', 'Reopen']],
  resolved:     [['reopen', 'Reopen']],
};

const STATUS_ORDER = { open: 0, acknowledged: 1, resolved: 2 };

function severityChip(sev, raw) {
  return el('span', {
    class: 'sev-chip sev-chip--' + sev,
    title: raw ? 'Unrecognised severity "' + raw + '", shown as low' : null,
    text: raw ? String(raw) : SEVERITIES[sev].label,
  });
}

/**
 * Pull the folded-away rules out of an alert's evidence.
 *
 * This is the correlation engine's receipt. `_correlate` keeps the most severe
 * finding for a given dedup key and files the losers under
 * `evidence.corroborating_rules`, so an alert with three entries there is one
 * alert that replaced four. Surfacing it is the panel's best argument for
 * itself -- without it, correlation is invisible work and the reader has no way
 * to tell a quiet dashboard from an under-reporting one.
 *
 * `evidence` arrives decoded when it parsed as JSON and as the raw string when
 * it did not (`_rows()` in app.py swallows the ValueError), exactly as on the
 * posture cards. A string cannot be walked for folded rules, so this returns
 * nothing for that case rather than guessing -- the raw text is still shown in
 * the evidence disclosure below.
 */
function foldedRules(alert) {
  const ev = alert.evidence;
  if (!ev || typeof ev !== 'object') return [];
  const folded = ev.corroborating_rules;
  return Array.isArray(folded) ? folded : [];
}

/* ---- reading a rule's prose ------------------------------------------------
 *
 * Every rule writes its description as paragraphs, most of them headed by a
 * shouted label: WHY THIS MATTERS:, BENIGN EXPLANATION:, MALICIOUS
 * EXPLANATION:, NEXT STEP:, CORROBORATION: and so on. That is the right
 * structure for an operator and the wrong presentation for one -- eighteen
 * of them inline is a wall, and the labels vary rule by rule. The drawer
 * below reads the labels and files each paragraph under one of five fixed
 * headings, so every alert answers the same five questions in the same
 * order: what was seen, why it matters, what would make it harmless, what
 * would make it an attack, what to do. Nothing is dropped -- a label that
 * fits no heading is kept under its own name in the "how sure is this"
 * group -- and nothing is rewritten. The detection code is untouched.
 */
const DESC_GROUPS = [
  { key: 'why',        title: 'Why it matters',            re: /WHY|MATTERS|CONTEXT|COMPROMISE|GATEWAY|RISK|CHANGED|FOOTNOTE/ },
  { key: 'benign',     title: 'Could be harmless if…', re: /BENIGN|^EXPLANATION$/ },
  { key: 'malicious',  title: 'Could be an attack if…', re: /MALICIOUS/ },
  { key: 'steps',      title: 'What to do',                re: /NEXT STEP|WHAT TO DO|ACTION|RESOLUTION/ },
  { key: 'confidence', title: 'How sure is this',          re: /./ },
];

/* One plain sentence per severity, so the chip is never the only thing
 * telling a non-specialist how urgently to act. */
const SEVERITY_MEANING = {
  critical: 'Act today. This is either a compromise in progress or the exact setup for one.',
  high:     'Act this week. Exploitable from your own network by anyone who gets onto it.',
  medium:   'Worth fixing. Not exploitable on its own, but it is the foothold something else needs.',
  low:      'Hygiene. Fix when convenient; it lowers the noise around everything above it.',
};

function parseDescription(text) {
  // Blank lines either side are stripped; a paragraph's own indentation is
  // kept, because evidence lists are indented on purpose.
  const paras = String(text || '').split(/\n[ \t]*\n/).map((s) => s.replace(/^\s*\n|\s+$/g, '')).filter((s) => s.trim());
  const out = { lead: [], groups: {} };
  for (const g of DESC_GROUPS) out.groups[g.key] = [];
  for (const p of paras) {
    let label = null, body = p;
    let m = p.match(/^([A-Z][A-Z0-9 ,'\/()-]{2,60}?):\s*([\s\S]*)$/);
    if (m) { label = m[1].trim(); body = m[2].trim(); }
    else {
      // "THIS IS THE DEFAULT GATEWAY. If an attacker..." -- a shouted first
      // sentence without a colon is a label too.
      m = p.match(/^((?:[A-Z][A-Z0-9'-]*\s+){2,}[A-Z][A-Z0-9'-]*)\.\s+([\s\S]*)$/);
      if (m) { label = m[1].trim(); body = m[2].trim(); }
    }
    if (!label) {
      if (Object.values(out.groups).every((g) => !g.length)) out.lead.push(p);
      else out.groups.confidence.push({ label: null, body: p });
      continue;
    }
    const group = DESC_GROUPS.find((g) => g.re.test(label)) || DESC_GROUPS[DESC_GROUPS.length - 1];
    out.groups[group.key].push({ label, body });
  }
  return out;
}

/* "isolate this device, then investigate. Do not simply close the port --
 * ..." reads as a checklist once each sentence gets its own line. */
function stepsList(body) {
  const steps = body.split(/(?<=[.!?])\s+(?=[A-Z])/).map((s) => s.trim()).filter(Boolean);
  if (steps.length < 2) return el('p', { class: 'alert__desc', text: body });
  return el('ol', { class: 'alert__steps' }, steps.map((s) => el('li', { text: s })));
}

function deviceLabelFor(deviceId) {
  const devs = (lastDevicesPayload && JSON.parse(lastDevicesPayload).devices) || [];
  const d = devs.find((x) => x.device_id === deviceId);
  return d ? (d.label || d.hostname || d.ip || d.mac || deviceId) : null;
}

/**
 * One queue row. Everything a triage pass needs to rank the alert without
 * opening it: severity, what, where, how old, what state it is in.
 */
/* Same status, same rule, two or more alerts: one story row with the alerts
 * inside. A single alert stays a plain row -- a group of one is just noise.
 * Order is preserved (open first, severity inside), so a story sits where
 * its worst alert would have. */
/* Which thing an alert is about, as the reader names it. A device; this
 * computer for host findings; an account for identity findings; the
 * gateway for the binding rules; otherwise the rule itself. */
const HOST_RULES = new Set(['host_posture', 'control_disabled', 'unmeasured_control', 'suspicious_powershell',
  'service_installed', 'autorun_changed', 'software_flagged', 'hidden_dir_created', 'notable_connection',
  'log_cleared', 'upload_spike', 'collector_heartbeat']);
const IDENTITY_RULES = new Set(['identity_posture', 'identity_unreviewed']);
function storySubject(alert) {
  if (alert.device_id) {
    // Rule titles lead with the device's name ("Smart Plug: ..."), which is
    // the right fallback when the device list has not arrived yet.
    const fromTitle = /^([^:]{2,40}):\s/.exec(alert.title || '');
    const label = deviceLabelFor(alert.device_id) || (fromTitle ? fromTitle[1] : null);
    return { key: 'device:' + alert.device_id, name: label || 'a device', kind: 'device', device_id: alert.device_id };
  }
  if (HOST_RULES.has(alert.rule_id)) return { key: 'host', name: 'This computer', kind: 'host' };
  if (IDENTITY_RULES.has(alert.rule_id)) {
    const acct = (alert.evidence && (alert.evidence.account_label || alert.evidence.account_id)) || 'an account';
    const label = (alert.title || '').split(':')[0] || acct;
    return { key: 'account:' + acct, name: label, kind: 'account' };
  }
  if (alert.rule_id === 'arp_spoof') return { key: 'gateway', name: 'The gateway', kind: 'device' };
  if (alert.rule_id === 'honeypot_hit') return { key: 'honeypot', name: 'The honeypot', kind: 'sensor' };
  return { key: 'rule:' + alert.rule_id, name: RULE_STORY[alert.rule_id] || (alert.rule_id || '').replace(/_/g, ' '), kind: 'rule' };
}

/* Same status, same subject, two or more alerts: one story row with the
 * alerts inside -- "what is wrong with the TV", not "which rule fired". A
 * story sits where its worst alert would have; a group of one stays a row. */
function storyRows(sorted, onOpen) {
  const groups = new Map();
  for (const a of sorted) {
    const subj = storySubject(a);
    const key = a.status + '|' + subj.key;
    if (!groups.has(key)) groups.set(key, { subj, run: [] });
    groups.get(key).run.push(a);
  }
  const out = [];
  const done = new Set();
  for (const a of sorted) {
    const key = a.status + '|' + storySubject(a).key;
    if (done.has(key)) continue;
    done.add(key);
    const { subj, run } = groups.get(key);
    if (run.length < 2) { out.push(alertRow(a, onOpen, subj)); continue; }
    const worst = run[0].severity;
    const sevs = {};
    run.forEach((x) => { sevs[x.severity] = (sevs[x.severity] || 0) + 1; });
    const mix = Object.keys(sevs).length > 1 ? Object.keys(sevs).map((k) => sevs[k] + ' ' + k).join(', ') : null;
    const rules = Array.from(new Set(run.map((x) => x.rule_id)));
    out.push(el('details', {
      class: 'story story--' + worst + ' story--' + subj.kind, 'data-subject': subj.key,
      open: (worst === 'critical' || worst === 'high') && a.status === 'open' ? 'open' : null,
    }, [
      el('summary', {}, [
        el('span', { class: 'story__count', text: String(run.length) }),
        el('span', {}, [
          el('span', { class: 'story__name', text: subj.name }),
          el('span', { class: 'story__meta' }, [
            severityChip(worst),
            mix ? el('span', { text: mix }) : null,
            el('span', { text: rules.length === 1 ? (RULE_STORY[rules[0]] || rules[0].replace(/_/g, ' ')) : rules.length + ' different rules' }),
            a.status !== 'open' ? el('span', { class: 'badge', text: a.status }) : null,
          ]),
        ]),
        el('span', { class: 'story__chev', text: '\u203a' }),
      ]),
      el('div', { class: 'story__rows' }, run.map((x) => alertRow(x, onOpen, subj))),
    ]));
  }
  return out;
}

/* Rule ids as the reader should see them. Falls back to the id with the
 * underscores removed, so an unlisted rule still reads. */
const RULE_STORY = {
  cve_exposure: 'Exposed to a known exploited weakness',
  suspicious_powershell: 'Suspicious PowerShell on this host',
  service_installed: 'New service, task or account on this host',
  autorun_changed: 'Startup entry added or changed',
  software_flagged: 'Notable software installed',
  hidden_dir_created: 'Hidden directory created',
  notable_connection: 'Outbound connection worth a look',
  host_posture: 'Host security control misconfigured',
  control_disabled: 'A host control changed state',
  unmeasured_control: 'Controls PNMA could not measure',
  identity_unreviewed: 'Accounts with unreviewed controls',
  identity_posture: 'Account control in the wrong state',
  availability: 'Devices that stopped answering',
  new_device: 'New devices',
  service_drift: 'A device started listening on a new port',
  profile_deviation: 'A device behaving unlike its kind',
  c2_indicator: 'Possible command-and-control',
  arp_spoof: 'Gateway claimed by two addresses',
  arp_sweep_seen: 'Network scan seen',
  honeypot_hit: 'Honeypot attacked',
  upload_spike: 'Unusual upload volume',
  log_cleared: 'Event log cleared',
  collector_heartbeat: 'The collector stopped reporting',
};

function alertRow(alert, onOpen, subj) {
  const sev = SEVERITIES[alert.severity] ? alert.severity : 'low';
  const folded = foldedRules(alert);
  const device = alert.device_id && !(subj && subj.kind === 'device') ? deviceLabelFor(alert.device_id) : null;
  const row = el('button', {
    class: 'alertrow alertrow--' + sev + (alert.status !== 'open' ? ' alertrow--' + alert.status : ''),
    type: 'button', 'data-anchor': 'alert:' + alert.id, 'data-status': alert.status, 'data-severity': sev, 'data-mitre': alert.mitre_id || '',
  }, [
    severityChip(sev, alert.severity_raw),
    el('span', { class: 'alertrow__main' }, [
      el('span', { class: 'alertrow__title', text: alert.title || alert.rule_id }),
      el('span', { class: 'alertrow__meta' }, [
        device ? el('span', { text: device }) : null,
        el('span', { text: RULE_STORY[alert.rule_id] || (alert.rule_id || '').replace(/_/g, ' ') }),
        folded.length ? el('span', { text: '+' + folded.length + ' ' + plural(folded.length, 'rule') }) : null,
        alert.count > 1 ? el('span', { text: 'seen x' + alert.count }) : null,
      ]),
    ]),
    el('span', { class: 'alertrow__side' }, [
      alert.status !== 'open' ? el('span', { class: 'badge', text: alert.status }) : null,
      el('span', { class: 'alertrow__age', text: alert.last_seen ? relativeTime(alert.last_seen) : '' }),
    ]),
  ]);
  row.addEventListener('click', () => onOpen(alert));
  return row;
}

/* Every top-level scalar or list in the evidence, as a key/value grid --
 * the IPs, MACs, ports, vendors and counts an investigator wants to copy
 * out without reading JSON. Nested objects stay in the raw disclosure. */
function evidenceGrid(ev) {
  if (!ev || typeof ev !== 'object') return null;
  const rows = [];
  for (const [k, v] of Object.entries(ev)) {
    if (k === 'corroborating_rules') continue;
    let text;
    if (v === null || v === undefined) text = '\u2014';
    else if (Array.isArray(v)) { if (!v.length || v.some((x) => x && typeof x === 'object')) continue; text = v.join(', '); }
    else if (typeof v === 'object') {
      const flat = Object.entries(v);
      if (!flat.length || flat.some(([, x]) => x && typeof x === 'object')) continue;
      text = flat.map(([a, b]) => a + ' \u2192 ' + b).join('\n');
    }
    else if (typeof v === 'boolean') text = v ? 'yes' : 'no';
    else text = String(v);
    rows.push(el('div', {}, [el('dt', { text: k.replace(/_/g, ' ') }), el('dd', { text: text })]));
  }
  return rows.length ? el('dl', { class: 'kv kv--evidence' }, rows) : null;
}

/* ------------------------------------------------------ investigation log */

/* One kind, one label. Load-bearing colours (severity) stay with alerts; the
 * rest are wayfinding so a reader can skim "what kind of row is this". */
const EVENT_KIND_LABEL = {
  observation: 'seen', scan: 'agent', delivery: 'delivered', alert: 'alert',
  alert_change: 'changed', availability: 'ping', host_fact: 'control', host_event: 'host', router: 'router', port: 'port', banner: 'banner',
};

function clockTime(ts) {
  if (!ts) return '';
  const d = new Date(ts * 1000);
  const sameDay = d.toDateString() === new Date().toDateString();
  const hms = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  return sameDay ? hms : d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + hms;
}

/**
 * A time-ordered log of normalised events (see pnma.events). Used by the
 * alert drawer (the window around one alert) and the Logs tab (everything).
 * Every string reaches the DOM through el(), so the privacy mask applies.
 *
 * opts: { markerTs, markerText, order: 'asc'|'desc', emptyText, bar (false hides the filter chips) }
 */
function eventLog(events, opts) {
  opts = opts || {};
  const order = opts.order || 'asc';
  const sortRows = (arr) => arr.slice().sort((a, b) => order === 'asc' ? a.ts - b.ts : b.ts - a.ts);
  const rows = sortRows(events);
  const wrap = el('div', { class: 'evlog' });
  const state = { hideAgent: false, kinds: new Set() };
  const bar = el('div', { class: 'evlog__bar' });
  const list = el('div', { class: 'evlog__rows', role: 'list' });
  if (opts.bar !== false) wrap.appendChild(bar);
  wrap.appendChild(list);

  function buildBar() {
    clear(bar);
    const counts = {};
    rows.forEach((e) => { counts[e.kind] = (counts[e.kind] || 0) + 1; });
    Object.keys(counts).forEach((k) => {
      const chip = el('button', { class: 'evlog__chip evlog__chip--' + k, type: 'button', 'aria-pressed': state.kinds.has(k) ? 'true' : 'false' }, [
        el('span', { class: 'evlog__chipname', text: EVENT_KIND_LABEL[k] || k }),
        el('span', { class: 'evlog__chipcount', text: String(counts[k]) }),
      ]);
      chip.addEventListener('click', () => {
        if (state.kinds.has(k)) state.kinds.delete(k); else state.kinds.add(k);
        chip.setAttribute('aria-pressed', state.kinds.has(k) ? 'true' : 'false');
        render();
      });
      bar.appendChild(chip);
    });
    const agentRows = rows.filter((e) => e.agent_generated).length;
    if (agentRows) {
      const t = el('button', { class: 'evlog__chip evlog__chip--toggle', type: 'button', 'aria-pressed': state.hideAgent ? 'true' : 'false',
        text: 'hide PNMA’s own probes (' + agentRows + ')',
        title: 'Rows the agent caused itself: its scans answering, its pings, its deliveries. Hiding them leaves what the network did on its own.' });
      t.addEventListener('click', () => { state.hideAgent = !state.hideAgent; t.setAttribute('aria-pressed', state.hideAgent ? 'true' : 'false'); render(); });
      bar.appendChild(t);
    }
  }

  function row(e) {
    const sev = (e.kind === 'alert' || e.kind === 'host_event') && e.detail ? e.detail.severity : null;
    const r = el('details', { class: 'evlog__row evlog__row--' + e.kind + (e.agent_generated ? ' is-agent' : '') + (sev ? ' evlog__row--sev-' + sev : ''), role: 'listitem' });
    const folded = (e.count || 1) > 1;
    r.appendChild(el('summary', { class: 'evlog__head' }, [
      el('span', { class: 'evlog__time', text: clockTime(e.ts), title: relativeTime(e.ts) || '' }),
      el('span', { class: 'evlog__kind', text: EVENT_KIND_LABEL[e.kind] || e.kind }),
      el('span', { class: 'evlog__src', text: e.source || '' }),
      el('span', { class: 'evlog__sum' }, [
        e.summary || '',
        folded ? el('span', { class: 'evlog__count', text: '×' + e.count, title: 'identical rows from ' + clockTime(e.span_from) + ' to ' + clockTime(e.span_to) }) : null,
      ]),
    ]));
    const kv = [];
    if (folded) kv.push(['repeated', e.count + ' identical rows, ' + clockTime(e.span_from) + ' → ' + clockTime(e.span_to)]);
    if (e.entity) kv.push(['entity', e.entity]);
    if (e.device_id) kv.push(['device', deviceLabelFor(e.device_id) || e.device_id]);
    kv.push(['recorded', new Date(e.ts * 1000).toLocaleString()]);
    if (e.ref) kv.push(['row', e.ref]);
    if (e.detail && typeof e.detail === 'object') {
      Object.keys(e.detail).forEach((k) => {
        if (k === 'count' || k === 'span_from' || k === 'span_to') return;
        const v = e.detail[k];
        if (v === null || v === undefined || v === '') return;
        kv.push([k, typeof v === 'object' ? JSON.stringify(v) : String(v)]);
      });
    }
    r.appendChild(el('dl', { class: 'kv evlog__detail' }, kv.map(([k, v]) => el('div', {}, [el('dt', { text: k }), el('dd', { text: v })]))));
    if (e.kind === 'alert' && e.detail && e.detail.alert_id && window.PNMA.openAlert) {
      const b = el('button', { class: 'btn', type: 'button', text: 'open this alert' });
      b.addEventListener('click', () => window.PNMA.openAlert(e.detail.alert_id));
      r.appendChild(b);
    }
    return r;
  }

  /* Consecutive agent rows that say the same thing (thirty identical "arp
   * table read: 12 devices" ticks) fold into one row with a count and span.
   * Only the agent's own repetition folds; anything the network did is
   * shown as it happened. */
  function fold(arr) {
    const out = [];
    arr.forEach((e) => {
      const last = out[out.length - 1];
      if (last && e.agent_generated && last.agent_generated && last.kind === e.kind && last.source === e.source && last.summary === e.summary) {
        last.count = (last.count || 1) + 1;
        last.span_from = Math.min(last.span_from, e.ts);
        last.span_to = Math.max(last.span_to, e.ts);
      } else {
        out.push(Object.assign({}, e, { count: 1, span_from: e.ts, span_to: e.ts }));
      }
    });
    return out;
  }

  function render() {
    clear(list);
    const shown = fold(rows.filter((e) => !(state.hideAgent && e.agent_generated) && (!state.kinds.size || state.kinds.has(e.kind))));
    if (!shown.length) {
      list.appendChild(el('p', { class: 'evlog__empty', text: rows.length ? 'Every row is filtered out.' : (opts.emptyText || 'Nothing recorded in this window.') }));
      return;
    }
    let markerDone = opts.markerTs == null;
    const marker = () => el('div', { class: 'evlog__marker', text: opts.markerText || 'alert raised' });
    shown.forEach((e) => {
      const after = order === 'asc' ? e.ts >= opts.markerTs : e.ts <= opts.markerTs;
      if (!markerDone && after) { list.appendChild(marker()); markerDone = true; }
      list.appendChild(row(e));
    });
    if (!markerDone) list.appendChild(marker());
  }
  buildBar();
  render();
  wrap.refresh = (next) => { rows.splice(0, rows.length, ...sortRows(next)); wrap.events = rows.slice(); buildBar(); render(); };
  wrap.events = rows.slice();
  return wrap;
}

/* The window around one alert, read from /api/alerts/{id}/investigate: every
 * observation of its device (and any address its evidence names), every
 * scan that touched it, its ping transitions, port changes, banners, the
 * alert's own history, and the other alerts that fired alongside it. The
 * alert's evidence is a snapshot; this is the record it was cut from. */
async function enrichWithInvestigation(card, alert) {
  const slot = card.querySelector('.alertdetail__investigate');
  if (!slot) return;
  try {
    const resp = await fetch('/api/alerts/' + encodeURIComponent(alert.id) + '/investigate');
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const b = await resp.json();
    clear(slot);
    const w = b.window || {};
    const idents = b.identifiers || {};
    const scope = [].concat(idents.ips || [], idents.macs || []);
    slot.appendChild(el('p', { class: 'alert__desc evlog__scope' }, [
      'Window ' + clockTime(w.since) + ' → ' + clockTime(w.until) + '. ',
      scope.length ? 'Matched on ' + scope.join(', ') + '. ' : 'No device is attached to this alert, so only the agent’s own runs are shown. ',
      b.truncated ? 'Capped at ' + b.events.length + ' rows; the Logs tab has the rest.' : '',
    ]));
    const total = b.events.length;
    const own = b.events.filter((e) => e.agent_generated).length;
    if (total && own === total) {
      slot.appendChild(el('p', { class: 'alert__desc evlog__note', text: 'Everything in this window came from PNMA’s own probes -- nothing was seen passively. That is information: the device only spoke when asked.' }));
    }
    slot.appendChild(eventLog(b.events, {
      markerTs: alert.first_seen, markerText: 'this alert was raised',
      emptyText: 'Nothing else was recorded in this window. Either the device was quiet, or the sensor that would have seen it was not running -- the Agent tab shows coverage.',
    }));
    if ((b.related_alerts || []).length) {
      slot.appendChild(el('p', { class: 'alert__desc', text: b.related_alerts.length + ' other ' + plural(b.related_alerts.length, 'alert') + ' on the same device in this window -- each is a row above and opens from there.' }));
    }
  } catch (err) {
    clear(slot);
    slot.appendChild(el('p', { class: 'alert__desc', text: 'Could not load the investigation log (' + err.message + ').' }));
  }
}

/* The device the alert is about, read live from /api/devices/{id}: address,
 * hardware, class, trust, every open port, and what else is open on it. An
 * alert's own evidence is a snapshot from the moment the rule fired; this is
 * the entity as it stands now, which is what an investigation starts from. */
async function enrichWithDevice(card, deviceId) {
  const slot = card.querySelector('.alertdetail__entity');
  if (!slot) return;
  try {
    const resp = await fetch('/api/devices/' + encodeURIComponent(deviceId));
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const d = await resp.json();
    const ports = (d.ports || []).filter((p) => !p.closed_at);
    const risky = ports.filter((p) => p.risk && p.risk !== 'none');
    const others = (d.alerts || []).filter((a) => a.status === 'open');
    clear(slot);
    slot.appendChild(el('dl', { class: 'kv' }, [
      el('div', {}, [el('dt', { text: 'device' }), el('dd', { text: d.label || d.hostname || '\u2014' })]),
      el('div', {}, [el('dt', { text: 'hostname' }), el('dd', { text: d.hostname || '\u2014' })]),
      el('div', {}, [el('dt', { text: 'ip' }), el('dd', { text: d.ip || '\u2014' })]),
      el('div', {}, [el('dt', { text: 'mac' }), el('dd', { text: (d.mac || '\u2014') + (d.mac_type === 'local' ? ' (randomised)' : '') })]),
      el('div', {}, [el('dt', { text: 'vendor' }), el('dd', { text: d.vendor || 'unknown' })]),
      el('div', {}, [el('dt', { text: 'class' }), el('dd', { text: d.device_class ? d.device_class + ' (' + (d.class_confidence || '?') + ' confidence)' : 'unclassified' })]),
      el('div', {}, [el('dt', { text: 'trust' }), el('dd', { text: d.trusted ? 'trusted' : 'untrusted' })]),
      el('div', {}, [el('dt', { text: 'online' }), el('dd', { text: d.online ? 'yes' : 'no' })]),
      el('div', {}, [el('dt', { text: 'first seen' }), el('dd', { text: relativeTime(d.first_seen) })]),
      el('div', {}, [el('dt', { text: 'last seen' }), el('dd', { text: relativeTime(d.last_seen) })]),
      el('div', {}, [el('dt', { text: 'open ports' }), el('dd', { text: ports.length + (risky.length ? ' (' + risky.length + ' risky)' : '') })]),
      el('div', {}, [el('dt', { text: 'open alerts on it' }), el('dd', { text: String(others.length) })]),
    ]));
    if (ports.length) {
      slot.appendChild(el('div', { class: 'dev__ports' }, ports.map((p) =>
        el('span', { class: 'port-pill' + (p.risk && p.risk !== 'none' ? ' port-pill--risky' : ''),
                     title: p.product || p.service || '', text: p.port + '/' + (p.proto || 'tcp') + (p.service ? ' ' + p.service : '') }))));
    }
  } catch (err) {
    clear(slot);
    slot.appendChild(el('p', { class: 'alert__desc', text: 'Device record unavailable: ' + (err && err.message ? err.message : err) }));
  }
}

/* What each lifecycle button does, in one line, because two of the three
 * looked interchangeable without it. */
const ACTION_HELP = {
  acknowledge: 'I have seen this and I am on it. Keeps it listed, stops it counting as untriaged.',
  resolve:     'Dealt with, or judged benign. Drops out of the open count; the record stays.',
  reopen:      'Undo: back to open. For an acknowledged or resolved alert that turned out not to be done.',
};


/* ---- playbooks --------------------------------------------------------
 *
 * The rule's own NEXT STEP says *what* ("isolate this device"); this says
 * *how*, on the equipment this household actually has. Router paths are for
 * a TP-Link Archer (web UI at the gateway address, or the Tether app) --
 * the menu names differ on other brands but the controls exist everywhere.
 * Each step is a plain instruction; the verification step is deliberate,
 * because "I blocked it" and "it is blocked" are different claims.
 */
/* The router's admin address comes from the device list (the row classed
 * "router"), never from a literal: this file is published with the repo. */
function gatewayAddress() {
  try {
    const devs = (lastDevicesPayload && JSON.parse(lastDevicesPayload).devices) || [];
    const gw = devs.find((d) => d.device_class === 'router' || d.device_class === 'gateway');
    return gw && gw.ip ? 'http://' + gw.ip : null;
  } catch (e) { return null; }
}
function routerUI() {
  const gw = gatewayAddress();
  return 'the router\'s admin page (' + (gw ? gw + ', ' : '') + 'TP-Link Archer: web UI or the Tether app)';
}
const PLAYBOOKS = {
  isolate_device: {
    title: 'Isolate this device',
    steps: [
      () => 'Identify it physically first: match the MAC and vendor above against the router\'s client list (' + routerUI() + ' → Network Map → Clients). On this network: "Apple" is a Mac or iPhone, "Microsoft" the Xbox, "HP" the printer, "TP-Link" the router itself, "Hui Zhou Gaoshengda" is the Wi-Fi module inside the smart TV. A randomised MAC with no vendor is a phone or laptop with private addressing on. The smart bulb and the robot vacuum will show up under a module maker you may not recognise (Tuya, Espressif, Broadlink, Roborock/Ecovacs) -- if a vendor here is one you cannot place, that is the device to pick up first.',
      'Cut it off at the router: Advanced → Security → Access Control → turn Access Control on, mode Blacklist, add the device by MAC. This survives the device rebooting or changing IP.',
      'If it is wired (the Xbox, the printer), unplug the Ethernet cable; the TV, bulb and vacuum come off at the power switch or the plug. Physical isolation beats every setting.',
      'Verify: within 15 minutes its node on the Network tab should go dashed (not seen) and "online" in the Telemetry above should read "no". `ping <its ip>` from this machine should time out.',
      'Then investigate, not before: open the device\'s own app (the TV\'s settings, the vacuum\'s or bulb\'s phone app), look for the service named in the alert, install any firmware update, and factory-reset it if you cannot explain the listener.',
      'Re-admit only once a fresh scan no longer shows the port, then mark this alert Resolved. Move the TV, bulb and vacuum onto the router\'s IoT network from then on (Advanced → Wireless → IoT Network on this firmware; Guest Network with "allow guests to see each other" off is the fallback) so they can reach the internet but not your laptops.',
    ],
  },
  arp_spoof: {
    title: 'Check the gateway binding',
    steps: [
      'On this machine run `arp -a` and read the MAC next to the gateway IP. It must be the router\'s own MAC (the one PNMA pinned in config/pnma.toml as gateway_mac). Anything else means something is answering for the router.',
      () => 'Look up the second MAC in the router\'s client list (' + routerUI() + ' → Network Map → Clients). A laptop with both Wi-Fi and Ethernet, or a mesh satellite, is the benign case.',
      'If you cannot name it: change the Wi-Fi password (Wireless → WPA2/WPA3-Personal, AES), reboot the router, and re-check `arp -a` after two minutes.',
      () => 'Stop-gap on this PC while you investigate, from an Administrator prompt: `netsh interface ipv4 add neighbors "Wi-Fi" ' + (gatewayAddress() || 'http://<gateway-ip>').replace('http://', '') + ' <router-mac>` pins the correct binding so traffic cannot be redirected. Undo later with `delete neighbors`.',
      'Verify: the alert stops recurring on later runs (the "seen on N runs" badge stops climbing) and `arp -a` shows one stable MAC.',
    ],
  },
  new_device: {
    title: 'Decide whether this device is yours',
    steps: [
      () => 'Read vendor, hostname and first-seen time above. Then check what joined the Wi-Fi at that moment: ' + routerUI() + ' → Network Map → Clients shows the SSID and band it is on. This household expects: Mac and Windows laptops, two iPhones, one Android, an Xbox, an HP printer, a smart TV, a smart bulb and a robot vacuum. Anything that is not one of those needs a name or a block.',
      'Yours: open it on the Network tab and mark it trusted with a name. That is the whole fix; the alert clears on the next run.',
      'Not yours: block it (Advanced → Security → Access Control → Blacklist by MAC) and change the Wi-Fi password, because it had that password.',
      'If it keeps returning under new randomised MACs, the password has leaked further than one device: rotate it and re-join only what you can name.',
    ],
  },
  host: {
    title: 'Fix the setting on this machine',
    steps: [
      'Open the Host tab: the card for this control shows what was measured, what was expected, and why it matters, with the exact setting name.',
      'Defender controls live in Windows Security → Virus & threat protection → Manage settings (Tamper Protection, real-time, PUA under "Reputation-based protection" in App & browser control).',
      'Audit and PowerShell logging are Group Policy or registry settings; the card names the key. Change it from an Administrator prompt or gpedit.msc.',
      'Verify by re-running the collector; the card turns green and this alert resolves itself on the next detection pass.',
    ],
  },
  unmeasured: {
    title: 'Get a real answer',
    steps: [
      '"Could not be measured" is not "fine". The check needed Administrator and did not have it.',
      'From an elevated terminal run `pnma collect` once; the Host tab updates within a minute and this alert resolves if the controls pass.',
      'If it stays unknown after an elevated run, the reason on the card is a collector failure, not a permission problem -- that reason is the thing to chase.',
    ],
  },
  identity: {
    title: 'Review the account, then attest',
    steps: [
      'Open the provider\'s security page (Google: myaccount.google.com/security; Microsoft: account.microsoft.com/security; Apple: appleid.apple.com; banks: their app\'s security or devices page).',
      'Check the control named in this alert -- MFA method, recovery email and phone, signed-in devices and connected apps, new-login alerts. Remove anything you do not recognise.',
      'Go to the Identity tab and tap the state you actually found: ok, finding, or unknown. Attest what you verified, not what you hope.',
      'A finding on a mailbox is urgent: every password reset for every other account flows through it.',
    ],
  },
  availability: {
    title: 'Find out why it dropped',
    steps: [
      'Check the obvious: power, Wi-Fi range, a device that was simply taken out of the house.',
      'If it is a security camera, NAS, or anything that should always be up, look at its own status light and reboot it once.',
      'Repeated drops on one device with everything else steady point at the device; drops across many devices at once point at the router or the Wi-Fi channel.',
    ],
  },
  honeypot: {
    title: 'Triage a honeypot hit',
    steps: [
      'This is traffic against your decoy, not your real network -- so first confirm the honeypot is still isolated: it must sit on a segment with no route to your laptops, phones or the router’s main LAN.',
      'Read the source IP and the credentials it tried (in the evidence above). If any password it guessed is one you actually use anywhere, rotate that password now -- treat it as known to attackers.',
      'If the source IP is one of YOUR devices, that is the real finding: something on your network is attacking the decoy, which means it is likely compromised. Isolate that device (see the network playbooks).',
      'Otherwise this is intelligence, not an incident: note the commands the attacker ran to learn current tactics, then leave the honeypot to keep collecting. Nothing on your real network needs action.',
      'Mark the alert Resolved once you have checked isolation and rotated any matching password.',
    ],
  },
  cve: {
    title: 'Close a known-exploited exposure',
    steps: [
      'Read the advisory above: it names the exposure class and links the emblematic CVE. This is matched on the open port/service, not a version-exact test, so first confirm the device really runs that service (the Telemetry section shows its open ports).',
      () => 'If it is a laptop or the Xbox, fix it on the device: turn the service off (Remote Desktop, file sharing) or patch the OS. If it is the TV, bulb or vacuum, update its firmware from its own app and turn off any remote/debug feature you do not use.',
      () => 'If you cannot fix it now, contain it: block the device by MAC at ' + routerUI() + ' (Advanced -> Security -> Access Control), or move it onto the IoT network so a compromise cannot reach your laptops.',
      'Never leave the port forwarded to the internet -- check Advanced -> NAT Forwarding -> Port Forwarding / DMZ on the router and remove any entry for this device.',
      'To actually learn the attack, do it in a sandbox against a target built to be attacked, never against this device. The FOR LEARNING note above and docs/PENTEST_LAB.md say how.',
      'Verify: re-run a scan (or wait for the next collector pass); when the port no longer answers, the advisory clears. Then mark the alert Resolved.',
    ],
  },
};
const RULE_PLAYBOOK = {
  c2_indicator: 'isolate_device', profile_deviation: 'isolate_device', service_drift: 'isolate_device',
  arp_spoof: 'arp_spoof', new_device: 'new_device', cve_exposure: 'cve', honeypot_hit: 'honeypot',
  host_posture: 'host', control_disabled: 'host', unmeasured_control: 'unmeasured',
  identity_posture: 'identity', identity_unreviewed: 'identity', availability: 'availability',
};
function playbookFor(alert) {
  const pb = PLAYBOOKS[RULE_PLAYBOOK[alert.rule_id]];
  if (!pb) return null;
  return el('div', { class: 'playbook' }, [
    el('div', { class: 'alertdetail__label', text: 'how, step by step: ' + pb.title }),
    el('ol', { class: 'alert__steps' }, pb.steps.map((st) => el('li', {}, inlineCode(typeof st === 'function' ? st() : st)))),
  ]);
}
/* `backticks` in a step become <code>, so a command reads as a command. */
function inlineCode(text) {
  return text.split(/(`[^`]+`)/).filter(Boolean).map((part) =>
    part.startsWith('`') ? el('code', { text: part.slice(1, -1) }) : part);
}

/**
 * The drawer body: the SOC-analyst view of one alert, in plain language.
 */
function alertDetail(alert, onAction) {
  const sev = SEVERITIES[alert.severity] ? alert.severity : 'low';
  const parsed = parseDescription(alert.description);
  const card = el('div', { class: 'alertdetail' });

  card.appendChild(el('div', { class: 'sheet__head' }, [
    el('div', { class: 'alertdetail__head' }, [
      el('div', { class: 'alert__head' }, [
        severityChip(sev, alert.severity_raw),
        alert.status !== 'open' ? el('span', { class: 'badge', text: alert.status }) : null,
        alert.count > 1 ? el('span', { class: 'badge', text: 'seen on ' + alert.count + ' runs' }) : null,
      ]),
      el('h3', { class: 'alertdetail__title', text: alert.title || alert.rule_id }),
      el('p', { class: 'alertdetail__urgency', text: SEVERITY_MEANING[sev] }),
      (window.PNMA.privacy && window.PNMA.privacy())
        ? el('p', { class: 'alertdetail__masked', text: 'Addresses and names are masked for screenshots. Tap "masked" in the sidebar to show the real ones before you verify anything.' })
        : null,
    ]),
    el('button', { class: 'btn', type: 'button', text: 'close', 'data-close': '1' }),
  ]));

  const section = (title, children, cls) => el('section', { class: 'alertdetail__sec ' + (cls || '') }, [
    el('h4', { text: title }), ...children,
  ]);
  const paras = (items) => items.map((it) => el('div', { class: 'alertdetail__para' }, [
    it.label && !/^(WHY THIS MATTERS( HERE)?|BENIGN EXPLANATION|MALICIOUS EXPLANATION|NEXT STEP|EXPLANATION)$/.test(it.label)
      ? el('div', { class: 'alertdetail__label', text: it.label.toLowerCase() }) : null,
    el('p', { class: 'alert__desc', text: it.body }),
  ]));

  if (parsed.lead.length) card.appendChild(section('What was seen', [el('p', { class: 'alert__desc', text: parsed.lead.join('\n\n') })]));
  // Telemetry: the evidence as a grid, then the live device record.
  const grid = evidenceGrid(alert.evidence);
  const tele = [];
  if (grid) tele.push(grid);
  if (alert.device_id) tele.push(el('div', { class: 'alertdetail__entity' }, [el('p', { class: 'alert__desc', text: 'Loading device record\u2026' })]));
  if (tele.length) card.appendChild(section('Telemetry', tele, 'alertdetail__sec--tele'));
  card.appendChild(section('Investigation log', [el('div', { class: 'alertdetail__investigate' }, [el('p', { class: 'alert__desc', text: 'Loading the record around this alert\u2026' })])], 'alertdetail__sec--investigate'));
  if (parsed.groups.why.length) card.appendChild(section('Why it matters', paras(parsed.groups.why), 'alertdetail__sec--why'));
  const bm = [];
  if (parsed.groups.benign.length) bm.push(section('Could be harmless if…', paras(parsed.groups.benign), 'alertdetail__sec--benign'));
  if (parsed.groups.malicious.length) bm.push(section('Could be an attack if…', paras(parsed.groups.malicious), 'alertdetail__sec--malicious'));
  if (bm.length) card.appendChild(el('div', { class: 'alertdetail__pair' }, bm));
  const todo = parsed.groups.steps.map((it) => stepsList(it.body));
  const pb = playbookFor(alert);
  if (pb) todo.push(pb);
  if (todo.length) card.appendChild(section('What to do', todo, 'alertdetail__sec--steps'));

  // How sure is this: corroboration, classification signals, coverage
  // caveats, the technique, then the raw evidence for the reader who wants
  // to check the working.
  const sure = paras(parsed.groups.confidence);
  const folded = foldedRules(alert);
  if (folded.length) {
    sure.push(el('div', { class: 'alertdetail__para' }, [
      el('div', { class: 'alertdetail__label', text: folded.length + ' other ' + plural(folded.length, 'rule') + ' fired on this and ' + (folded.length === 1 ? 'was' : 'were') + ' folded in' }),
      el('ul', { class: 'alertdetail__folded' }, folded.map((r) => el('li', {
        text: (r.rule_id || 'unknown rule').replace(/_/g, ' ') + (r.severity ? ' (' + r.severity + ')' : '') + (r.title ? ' - ' + r.title : ''),
      }))),
    ]));
  }
  const ev = alert.evidence;
  const evText = (ev && typeof ev === 'object')
    ? (Object.keys(ev).length ? JSON.stringify(ev, null, 2) : null)
    : (typeof ev === 'string' && ev.trim() ? ev : null);
  if (evText) {
    sure.push(el('details', { class: 'fact__evidence' }, [
      el('summary', { text: typeof ev === 'string' ? 'raw evidence (unparsed)' : 'raw evidence' }),
      el('pre', { text: evText }),
    ]));
  }
  if (sure.length) card.appendChild(section('How sure is this', sure));

  const device = alert.device_id ? deviceLabelFor(alert.device_id) : null;
  card.appendChild(el('div', { class: 'alert__meta' }, [
    el('span', { text: 'rule: ' + (alert.rule_id || '-') }),
    alert.mitre_id ? el('span', { text: 'ATT&CK ' + alert.mitre_id + (alert.mitre_name ? ' ' + alert.mitre_name : '') }) : null,
    alert.first_seen ? el('span', { text: 'first seen ' + relativeTime(alert.first_seen) }) : null,
    alert.last_seen ? el('span', { text: 'last seen ' + relativeTime(alert.last_seen) }) : null,
  ]));

  const available = ALERT_ACTIONS[alert.status] || [];
  const buttons = available.map(([action, label]) => el('button', { class: 'btn', type: 'button', text: label, title: ACTION_HELP[action] }));
  buttons.forEach((btn, i) => btn.addEventListener('click', () => onAction(alert.id, available[i][0], buttons)));
  if (available.length) {
    card.appendChild(el('ul', { class: 'alertdetail__help' }, available.map(([action, label]) =>
      el('li', {}, [el('strong', { text: label + ': ' }), ACTION_HELP[action]]))));
  }
  if (alert.device_id && window.PNMA.openDeviceSheet) {
    const b = el('button', { class: 'btn btn--primary', type: 'button', text: 'Open ' + (device || 'device') });
    b.addEventListener('click', () => { closeAlertSheet(); window.PNMA.openDeviceSheet(alert.device_id); });
    buttons.push(b);
  }
  if (buttons.length) card.appendChild(el('div', { class: 'sheet__actions' }, buttons));
  // Two columns on a wide screen: the story (what/why/what to do) on the
  // left, the record (telemetry, investigation log) on the right. Grouped
  // here rather than by CSS grid placement so the columns flow naturally.
  const head = card.querySelector('.sheet__head');
  const main = el('div', { class: 'alertdetail__main' });
  const aside = el('div', { class: 'alertdetail__aside' });
  const tail = [];
  Array.from(card.children).forEach((c) => {
    if (c === head) return;
    if (c.classList.contains('alertdetail__sec--tele') || c.classList.contains('alertdetail__sec--investigate')) aside.appendChild(c);
    else if (c.classList.contains('alert__meta') || c.classList.contains('alertdetail__help') || c.classList.contains('sheet__actions')) tail.push(c);
    else main.appendChild(c);
  });
  card.appendChild(el('div', { class: 'alertdetail__cols' }, [main, aside]));
  tail.forEach((c) => card.appendChild(c));
  return card;
}

let openAlertId = null;
let openAlertSignature = null;
let alertSheetCloseTimer = null;

function closeAlertSheet() {
  const sheet = document.getElementById('alert-sheet');
  if (!sheet || sheet.hidden) return;
  openAlertId = null;
  openAlertSignature = null;
  sheet.classList.remove('is-open');
  alertSheetCloseTimer = setTimeout(() => { sheet.hidden = true; clear(sheet); }, 180);
}

function openAlertSheet(alert, onAction) {
  const sheet = document.getElementById('alert-sheet');
  if (!sheet) return;
  clearTimeout(alertSheetCloseTimer);
  const wasOpen = !sheet.hidden;
  // A poll that changed nothing about *this* alert must not touch the
  // drawer: a re-firing rule bumps last_seen every detection pass, and
  // rebuilding on each one would throw the reader back to the top of a
  // six-step playbook once a minute. Same invariant as viz.js's
  // `unchanged()`, applied to the one element that outlives a re-render.
  const signature = JSON.stringify(alert);
  if (wasOpen && openAlertId === alert.id && openAlertSignature === signature) return;
  // When it does rebuild (an action changed the status), keep the reader's
  // place: scroll offset and whichever disclosures they had open.
  const prev = sheet.querySelector('.sheet__card');
  const scrollTop = prev && openAlertId === alert.id ? prev.scrollTop : 0;
  const openDetails = prev && openAlertId === alert.id
    ? Array.from(prev.querySelectorAll('details[open]')).map((d) => d.querySelector('summary') && d.querySelector('summary').textContent) : [];
  openAlertId = alert.id;
  openAlertSignature = signature;
  sheet.hidden = false;
  clear(sheet);
  const card = el('div', { class: 'sheet__card sheet__card--wide' }, [alertDetail(alert, onAction)]);
  sheet.appendChild(card);
  card.querySelectorAll('details').forEach((d) => {
    const s = d.querySelector('summary');
    if (s && openDetails.includes(s.textContent)) d.open = true;
  });
  card.scrollTop = scrollTop;
  if (alert.device_id) enrichWithDevice(card, alert.device_id);
  enrichWithInvestigation(card, alert);
  card.querySelector('[data-close]').addEventListener('click', closeAlertSheet);
  if (!sheet.dataset.wired) {
    sheet.dataset.wired = '1';
    sheet.addEventListener('click', (ev) => { if (ev.target === sheet) closeAlertSheet(); });
  }
  if (wasOpen) sheet.classList.add('is-open');
  else requestAnimationFrame(() => requestAnimationFrame(() => sheet.classList.add('is-open')));
}

/**
 * No open alerts.
 *
 * The dangerous empty state on this page. "No alerts" reads as "you are fine",
 * and it is only ever evidence of the weaker claim that no rule fired -- which
 * is also exactly what a detection engine that never ran looks like.
 */
function alertsEmpty() {
  return el('div', { class: 'placeholder' }, [
    el('div', { class: 'placeholder__title', text: 'No alerts recorded' }),
    el('p', {
      text: 'No rule is currently firing. That is not the same as the network ' +
            'being clean: it means nothing matched the rules that ran. A ' +
            'detection engine that never ran produces this same empty list.',
    }),
    el('p', {}, [
      'What the rules do and do not cover is listed by ',
      el('code', { class: 'coverage-banner__cmd', text: 'pnma detections' }),
      ', including their stated blind spots.',
    ]),
  ]);
}

/* Triage filters survive a re-render (the panel rebuilds on every changed
 * poll) but not a reload -- a filter is a working position, not a setting. */
const alertFilter = { severity: null, status: null, mitre: null };

function applyAlertFilter(container) {
  let shown = 0;
  container.querySelectorAll('.alertrow').forEach((row) => {
    const hide = (alertFilter.severity && row.dataset.severity !== alertFilter.severity) ||
                 (alertFilter.status && row.dataset.status !== alertFilter.status) ||
                 (alertFilter.mitre && row.dataset.mitre !== alertFilter.mitre);
    row.hidden = hide;
    if (!hide) shown += 1;
  });
  container.querySelectorAll('.story').forEach((story) => {
    const rows = Array.from(story.querySelectorAll('.alertrow'));
    story.hidden = rows.length > 0 && rows.every((r) => r.hidden);
  });
  container.querySelectorAll('.triage__chip').forEach((c) => {
    c.classList.toggle('is-on', (c.dataset.severity && c.dataset.severity === alertFilter.severity) ||
                                 (c.dataset.status && c.dataset.status === alertFilter.status));
  });
  // A MITRE filter (arrived here from a click on the ATT&CK matrix) shows a
  // removable banner, since there is no chip for it in the triage strip.
  let banner = container.querySelector('.triage__mitre');
  if (alertFilter.mitre) {
    if (!banner) {
      banner = el('button', { class: 'triage__mitre', type: 'button', title: 'Clear this technique filter' });
      const strip = container.querySelector('.triage');
      if (strip) strip.appendChild(banner);
    }
    clear(banner);
    banner.appendChild(el('span', { text: 'technique ' + alertFilter.mitre + ' ✕' }));
    banner.onclick = () => { alertFilter.mitre = null; applyAlertFilter(container); };
  } else if (banner) {
    banner.remove();
  }
  const none = container.querySelector('.alertqueue__none');
  if (none) none.hidden = shown > 0;
}

/* Called from the ATT&CK matrix (viz.js): filter the queue to one technique
 * and bring it into view. The matrix and the queue live on the same tab, so
 * this is a scroll, not a tab switch. */
function filterAlertsByTechnique(mitreId) {
  alertFilter.mitre = mitreId;
  alertFilter.severity = null;
  alertFilter.status = null;
  const container = document.getElementById('alerts-body');
  if (container) {
    applyAlertFilter(container);
    const q = container.querySelector('.alertqueue');
    if (q) q.scrollIntoView({ block: 'start', behavior: 'smooth' });
  }
}

/* Browser notifications for a new critical/high alert while the page is
 * open. Opt-in, local to this browser, no egress: the one delivery channel
 * that costs the agent nothing on its own safety posture. */
const NOTIFY_KEY = 'pnma.notify';
let seenAlertIds = null;
function notifyOn() { try { return localStorage.getItem(NOTIFY_KEY) === '1'; } catch (e) { return false; } }
function notifyNew(alerts) {
  const urgent = alerts.filter((a) => a.status === 'open' && (a.severity === 'critical' || a.severity === 'high'));
  const ids = new Set(urgent.map((a) => a.id));
  if (seenAlertIds === null) { seenAlertIds = ids; return; }
  const fresh = urgent.filter((a) => !seenAlertIds.has(a.id));
  seenAlertIds = ids;
  if (!fresh.length || !notifyOn() || typeof Notification === 'undefined' || Notification.permission !== 'granted') return;
  const n = new Notification('PNMA: ' + fresh.length + ' new ' + plural(fresh.length, 'alert'), {
    body: fresh.map((a) => a.severity.toUpperCase() + ' ' + (a.title || a.rule_id)).join('\n'), tag: 'pnma-alerts',
  });
  n.addEventListener('click', () => { window.focus(); if (window.PNMA.showTab) window.PNMA.showTab('alerts', 'alert:' + fresh[0].id); });
}
function buildNotifyPill() {
  const tools = document.getElementById('masthead-tools');
  if (!tools || typeof Notification === 'undefined') return;
  const pill = el('button', { class: 'tool', type: 'button' });
  const paint = () => {
    const on = notifyOn() && Notification.permission === 'granted';
    pill.textContent = on ? '◉ notify' : '○ notify';
    pill.className = 'tool' + (on ? ' tool--on' : '');
    pill.title = on ? 'A browser notification is raised for every new critical or high alert while this page is open. Tap to turn off.'
                    : 'Tap to get a browser notification for new critical or high alerts while this page is open.';
  };
  pill.addEventListener('click', async () => {
    if (notifyOn()) { try { localStorage.setItem(NOTIFY_KEY, '0'); } catch (e) { /* */ } paint(); return; }
    const perm = Notification.permission === 'granted' ? 'granted' : await Notification.requestPermission();
    try { localStorage.setItem(NOTIFY_KEY, perm === 'granted' ? '1' : '0'); } catch (e) { /* */ }
    paint();
  });
  paint();
  tools.appendChild(pill);
}

function renderAlerts(payload, container, onAction) {
  const alerts = normaliseAlerts((payload && payload.alerts) || []);
  // Preserve what the reader had going when a real change forces a rebuild:
  // which device stories were expanded, and the scroll position. Without this
  // a rebuild snaps every open story shut and jumps to the top.
  const openStories = new Set(Array.from(container.querySelectorAll('.story[open]')).map((d) => d.dataset.subject));
  const scrollY = window.scrollY;
  clear(container);
  notifyNew(alerts);

  if (!alerts.length) {
    container.appendChild(alertsEmpty());
    return;
  }

  // The headline counts describe OPEN alerts only. The list below also carries
  // acknowledged and resolved ones so the lifecycle stays visible, but counting
  // those in "3 critical or high" would inflate the number every time somebody
  // triaged something -- the opposite of what triage is for.
  const open = alerts.filter((a) => a.status === 'open');
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const a of open) counts[a.severity] += 1;
  const byStatus = { open: open.length, acknowledged: 0, resolved: 0 };
  for (const a of alerts) if (a.status !== 'open') byStatus[a.status] = (byStatus[a.status] || 0) + 1;
  let foldedTotal = 0;
  for (const a of alerts) foldedTotal += foldedRules(a).length;

  // Triage strip: every count is also the filter for it. Tap a severity to
  // see only that, tap again to clear.
  const chip = (kind, value, n, label) => {
    const c = el('button', { class: 'triage__chip triage__chip--' + value, type: 'button', ['data-' + kind]: value }, [
      el('span', { class: 'triage__n', text: String(n) }), el('span', { class: 'triage__label', text: label }),
    ]);
    c.addEventListener('click', () => {
      alertFilter[kind] = alertFilter[kind] === value ? null : value;
      applyAlertFilter(container);
    });
    return c;
  };
  container.appendChild(el('div', { class: 'triage' }, [
    el('div', { class: 'triage__group' }, [
      chip('severity', 'critical', counts.critical, 'critical'), chip('severity', 'high', counts.high, 'high'),
      chip('severity', 'medium', counts.medium, 'medium'), chip('severity', 'low', counts.low, 'low'),
    ]),
    el('div', { class: 'triage__group' }, [
      chip('status', 'open', byStatus.open, 'open'), chip('status', 'acknowledged', byStatus.acknowledged, 'acknowledged'),
      chip('status', 'resolved', byStatus.resolved, 'resolved'),
    ]),
    el('span', { class: 'triage__note', text: foldedTotal + ' ' + plural(foldedTotal, 'finding') + ' folded by correlation' }),
  ]));

  // Open first, then acknowledged, then resolved; severity inside each. Sorting
  // by severity alone would file a resolved critical above an open high, which
  // reverses what the reader is looking for.
  const sorted = alerts.slice().sort((a, b) => {
    const sa = STATUS_ORDER[a.status] === undefined ? 0 : STATUS_ORDER[a.status];
    const sb = STATUS_ORDER[b.status] === undefined ? 0 : STATUS_ORDER[b.status];
    if (sa !== sb) return sa - sb;
    const d = SEVERITIES[a.severity].order - SEVERITIES[b.severity].order;
    return d || (b.last_seen || 0) - (a.last_seen || 0);
  });

  const openOne = (a) => openAlertSheet(a, onAction);
  container.appendChild(el('div', { class: 'alertqueue' }, storyRows(sorted, openOne).concat([
    el('p', { class: 'placeholder alertqueue__none', text: 'Nothing matches this filter.', hidden: true }),
  ])));
  applyAlertFilter(container);
  // Re-open the stories the reader had open, and keep their scroll position.
  if (openStories.size) {
    container.querySelectorAll('.story').forEach((d) => { if (openStories.has(d.dataset.subject)) d.open = true; });
    if (scrollY) window.scrollTo(0, scrollY);
  }

  // An action taken inside the drawer forces this re-render; keep the drawer
  // on the same alert, now in its new state, instead of snapping it shut.
  if (openAlertId !== null) {
    const cur = alerts.find((a) => a.id === openAlertId);
    if (cur) openAlertSheet(cur, onAction); else closeAlertSheet();
  }
}

/* ================================================================= devices */

/**
 * Decode a column that the API hands over as raw JSON text.
 *
 * `_rows()` in app.py decodes `evidence` and nothing else, and the devices
 * endpoint does not even call it -- it builds `dict(row)` by hand. So
 * `class_signals` arrives as the literal string '["is the default gateway"]'
 * while an alert's `evidence` on the same page arrives as an object. Rather
 * than teach every callsite that asymmetry, decode here and return an empty
 * list on anything unparseable: a signal list is explanatory colour, and a
 * malformed one is not worth failing a device row over.
 */
function jsonList(raw) {
  if (Array.isArray(raw)) return raw;
  if (typeof raw !== 'string' || !raw.trim()) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    return [];
  }
}

/** The name to lead with, in descending order of how much a human chose it. */
function deviceName(d) {
  return d.label || d.hostname || d.ip || d.mac || d.device_id;
}

/**
 * One device row.
 *
 * Ports carry their own `risk` from the ports table. This panel does not
 * re-derive risk from the port number: the detection rules already made that
 * judgement, and a second opinion computed here could disagree with the alert
 * sitting directly above it on the same page.
 */
function deviceRow(d) {
  const online = !!d.online;
  const trusted = !!d.trusted;
  const ports = d.open_ports || [];

  // Untrusted *and* currently online is the row worth finding in a list of
  // twelve. Untrusted and long gone is history rather than a live question, so
  // it does not get the treatment.
  const attention = !trusted && online;

  const signals = jsonList(d.class_signals);
  const identity = el('div', {}, [
    el('div', { class: 'dev__name', text: deviceName(d) }),
    d.device_class
      ? el('div', {
          class: 'dev__class',
          title: signals.length ? 'Classified from: ' + signals.join('; ') : null,
          text: d.device_class +
                (d.class_confidence ? ' (' + d.class_confidence + ' confidence)' : ''),
        })
      : null,
  ]);

  const addr = el('div', { class: 'dev__addr' }, [
    el('div', { text: d.ip || 'no address' }),
    // A randomised MAC has no vendor and `oui.lookup` returns None for it
    // rather than guessing. Say which case this is instead of leaving the
    // vendor line blank, which reads as a lookup that simply failed.
    el('div', { text: d.mac || '-' }),
    el('div', {
      class: 'dev__vendor',
      text: d.vendor || (d.mac_type === 'local' ? 'randomised MAC, no vendor' : 'vendor unknown'),
    }),
  ]);

  const portEls = ports.length
    ? ports.map((p) => el('span', {
        class: 'port-pill' + (p.risk && p.risk !== 'none' ? ' port-pill--risky' : ''),
        title: [p.service, p.product, p.risk ? 'risk: ' + p.risk : null]
          .filter(Boolean).join(' - ') || null,
        text: p.port + '/' + (p.proto || 'tcp') + (p.service ? ' ' + p.service : ''),
      }))
    // No open ports is ambiguous and the ambiguity matters: it is either a
    // device with nothing listening or a device that was never scanned. The
    // devices payload cannot tell them apart, so neither does this.
    : [el('span', { class: 'dev__class', text: 'no open ports recorded' })];

  const badges = el('div', { class: 'dev__badges' }, [
    el('span', {
      class: 'dot ' + (online ? 'dot--online' : 'dot--offline'),
      title: d.last_seen ? 'Last seen ' + relativeTime(d.last_seen) : null,
      text: online ? 'online' : (d.last_seen ? relativeTime(d.last_seen) : 'never seen'),
    }),
    el('span', {
      class: 'badge' + (trusted ? '' : ' badge--admin'),
      text: trusted ? 'trusted' : 'untrusted',
    }),
    d.open_alerts
      ? el('span', {
          class: 'badge badge--changed',
          text: d.open_alerts + ' ' + plural(d.open_alerts, 'alert'),
        })
      : null,
  ]);

  return el('div', { class: 'dev' + (attention ? ' dev--attention' : ''), 'data-anchor': 'device:' + d.device_id }, [
    identity, addr, el('div', { class: 'dev__ports' }, portEls), badges,
  ]);
}

/**
 * No devices at all.
 *
 * Means no discovery has run. It emphatically does not mean the network is
 * empty -- this host is on it, and so is whatever answered its DHCP.
 */
function devicesEmpty() {
  return el('div', { class: 'placeholder' }, [
    el('div', { class: 'placeholder__title', text: 'No devices recorded' }),
    el('p', {
      text: 'Nothing has been discovered yet, which means no collection has ' +
            'run rather than that the network is empty. At minimum this host ' +
            'and its gateway are on it.',
    }),
    el('p', {}, [
      'Run ',
      el('code', { class: 'coverage-banner__cmd', text: 'pnma collect' }),
      ' to populate the inventory, or ',
      el('code', { class: 'coverage-banner__cmd', text: 'pnma seed' }),
      ' for a synthetic network to look at.',
    ]),
  ]);
}

function renderDevices(payload, container) {
  const devices = (payload && payload.devices) || [];
  clear(container);

  if (!devices.length) {
    container.appendChild(devicesEmpty());
    return;
  }

  const online = devices.filter((d) => d.online);
  const untrustedOnline = online.filter((d) => !d.trusted);

  // One line, not three tiles: the overview's "devices online" tile already
  // carries these numbers and links here. Repeating them as a second row of
  // stat cards was the first thing the reader saw on this tab.
  container.appendChild(el('p', { class: 'devices__caption' }, [
    el('strong', { text: String(devices.length) }), ' ' + plural(devices.length, 'device') + ' \u00b7 ',
    el('strong', { text: String(online.length) }), ' online now \u00b7 ',
    el('strong', { class: untrustedOnline.length ? 'is-finding' : '', text: String(untrustedOnline.length) }), ' untrusted and online',
  ]));

  // Attention first, then online, then by recency. The API already sorts by
  // last_seen; this re-sorts so that the row a reader needs is at the top
  // rather than wherever its last packet happened to put it.
  const sorted = devices.slice().sort((a, b) => {
    const aa = (!a.trusted && a.online) ? 0 : 1;
    const bb = (!b.trusted && b.online) ? 0 : 1;
    if (aa !== bb) return aa - bb;
    if (!!a.online !== !!b.online) return a.online ? -1 : 1;
    return (b.last_seen || 0) - (a.last_seen || 0);
  });

  for (const d of sorted) container.appendChild(deviceRow(d));
}
/* ============================================================ availability */

const AVAIL_HOURS = 24;
const AVAIL_BUCKETS = 96;

/* Reachability bands, as percentages.
 *
 * Bands rather than an exact-100 test, because `up_pct` is AVG(reachable) over
 * every device in the bucket, not the state of one thing. On a twelve-device
 * network a single phone going out for a walk reads as 91.7%, and colouring
 * that amber paints the ordinary churn of a home network as degradation --
 * which leaves no colour free to mean "something is actually wrong". Amber is
 * reserved for a bucket where a real share of the network was unreachable, red
 * for one where most of it was.
 *
 * These are display thresholds only. The exact percentage is on every bar's
 * tooltip, and the alert rules make their own judgements without consulting
 * these numbers.
 */
const AVAIL_OK_PCT = 90;
const AVAIL_DOWN_PCT = 50;

/**
 * Expand the API's sparse bucket list into a dense one.
 *
 * This is the correctness centre of the panel. `/api/latency` GROUPs BY bucket,
 * so a bucket with no availability rows produces no row and simply is not in
 * `points`. Rendering `points` directly would draw 91 bars where 96 were asked
 * for, and -- worse -- the five missing ones would close up silently, so four
 * hours during which the agent was not running would render as an unbroken
 * green run. A monitoring gap displayed as uptime is the same false-clean
 * failure the posture panel exists to prevent, arriving through the chart.
 *
 * Index is derived from each point's own `t` rather than from its position in
 * the array, because position only equals bucket index when nothing is missing,
 * which is exactly the case this function exists for.
 */
function densify(payload) {
  const start = payload.start;
  const width = payload.bucket_width_s;
  const slots = new Array(AVAIL_BUCKETS).fill(null);
  if (!width) return slots;
  for (const p of payload.points || []) {
    const i = Math.round((p.t - start) / width);
    if (i >= 0 && i < AVAIL_BUCKETS) slots[i] = p;
  }
  return slots;
}

/**
 * The uptime strip.
 *
 * Divs, not SVG. `el()` builds nodes with `document.createElement`, which
 * returns an inert HTMLUnknownElement for <svg> and <path> -- an SVG chart here
 * would render nothing and raise nothing, failing in the one way that is hard
 * to notice. Flex divs also hold the no-build, no-dependency line the rest of
 * this file keeps.
 *
 * Height encodes round-trip time and colour encodes reachability. They are
 * separate channels on purpose: a bucket can be fast and half-unreachable, and
 * folding both into bar height would hide one of them.
 */
function uptimeStrip(slots) {
  const rtts = slots.filter((s) => s && s.rtt !== null && s.rtt !== undefined).map((s) => s.rtt);
  const maxRtt = rtts.length ? Math.max.apply(null, rtts) : 1;

  const bars = slots.map((s, i) => {
    if (!s) {
      return el('div', {
        class: 'uptime__bar uptime__bar--gap',
        title: 'No samples in this bucket - the agent was not collecting',
      }, []);
    }
    const up = s.up_pct === null || s.up_pct === undefined ? null : s.up_pct;
    let cls = 'uptime__bar';
    if (up !== null && up < AVAIL_DOWN_PCT) cls += ' uptime__bar--down';
    else if (up !== null && up < AVAIL_OK_PCT) cls += ' uptime__bar--degraded';

    // A fully-unreachable bucket has no round-trip time to draw, so it is drawn
    // at full height in red rather than as a zero-height bar that would be
    // indistinguishable from the axis.
    const pct = (s.rtt === null || s.rtt === undefined)
      ? 100
      : Math.max(4, Math.round((s.rtt / maxRtt) * 100));

    const label = [
      up === null ? 'reachability unknown' : up + '% reachable',
      (s.rtt === null || s.rtt === undefined) ? 'no RTT' : s.rtt + ' ms',
    ].join(', ');

    return el('div', { class: cls, style: 'height: ' + pct + '%', title: label }, []);
  });

  return el('div', { class: 'uptime' }, [
    el('div', { class: 'uptime__bars' }, bars),
    el('div', { class: 'uptime__axis' }, [
      el('span', { text: AVAIL_HOURS + ' hours ago' }),
      el('span', { text: 'bar height = round-trip time; taller is slower' }),
      el('span', { text: 'now' }),
    ]),
    el('div', { class: 'uptime__legend' }, [
      el('span', {}, [
        el('span', { class: 'uptime__key', style: 'background: var(--ok)' }, []),
        AVAIL_OK_PCT + '%+ reachable',
      ]),
      el('span', {}, [
        el('span', { class: 'uptime__key', style: 'background: var(--warn)' }, []),
        AVAIL_DOWN_PCT + '-' + AVAIL_OK_PCT + '% reachable',
      ]),
      el('span', {}, [
        el('span', { class: 'uptime__key', style: 'background: var(--finding)' }, []),
        'under ' + AVAIL_DOWN_PCT + '% reachable',
      ]),
      el('span', {}, [
        el('span', { class: 'uptime__key', style: 'border: 1px dashed var(--line-strong)' }, []),
        'no samples collected',
      ]),
    ]),
  ]);
}

function availabilityEmpty() {
  return el('div', { class: 'placeholder' }, [
    el('div', { class: 'placeholder__title', text: 'No availability samples' }),
    el('p', {
      text: 'Nothing has been pinged in the last ' + AVAIL_HOURS + ' hours, so ' +
            'there is no reachability history to draw. An empty chart here ' +
            'means the agent was not measuring, not that everything was up.',
    }),
  ]);
}

function renderAvailability(payload, container) {
  clear(container);

  const points = (payload && payload.points) || [];
  if (!points.length) {
    container.appendChild(availabilityEmpty());
    return;
  }

  const slots = densify(payload);
  const measured = slots.filter(Boolean);
  const gaps = slots.length - measured.length;

  const upVals = measured
    .map((s) => s.up_pct)
    .filter((v) => v !== null && v !== undefined);
  const rttVals = measured
    .map((s) => s.rtt)
    .filter((v) => v !== null && v !== undefined);

  const avgUp = upVals.length
    ? Math.round((upVals.reduce((a, b) => a + b, 0) / upVals.length) * 10) / 10
    : null;
  const avgRtt = rttVals.length
    ? Math.round((rttVals.reduce((a, b) => a + b, 0) / rttVals.length) * 10) / 10
    : null;
  const maxRtt = rttVals.length ? Math.max.apply(null, rttVals) : null;

  container.appendChild(el('div', { class: 'metrics' }, [
    el('div', { class: 'stat stat--ok' }, [
      el('div', { class: 'stat__n', text: avgUp === null ? '-' : avgUp + '%' }),
      el('div', { class: 'stat__label', text: 'reachable, measured buckets' }),
    ]),
    el('div', { class: 'stat stat--total' }, [
      el('div', { class: 'stat__n', text: avgRtt === null ? '-' : String(avgRtt) }),
      el('div', { class: 'stat__label', text: 'mean RTT (ms)' }),
    ]),
    el('div', { class: 'stat stat--total' }, [
      el('div', { class: 'stat__n', text: maxRtt === null ? '-' : String(maxRtt) }),
      el('div', { class: 'stat__label', text: 'worst RTT (ms)' }),
    ]),
    // The honesty metric for this panel, and the reason the percentage above is
    // labelled "measured buckets" rather than presented as 24-hour uptime.
    // Averaging over the buckets that happen to exist and calling it uptime is
    // how a collector outage becomes a good number.
    el('div', { class: 'stat stat--unknown' }, [
      el('div', { class: 'stat__n', text: String(gaps) }),
      el('div', { class: 'stat__label', text: 'buckets with no samples' }),
    ]),
  ]));

  if (gaps > 0) {
    container.appendChild(el('div', { class: 'coverage-banner', role: 'status' }, [
      el('div', { class: 'coverage-banner__glyph', text: '?', 'aria-hidden': 'true' }),
      el('div', {}, [
        el('div', {
          class: 'coverage-banner__title',
          text: gaps + ' of ' + AVAIL_BUCKETS + ' ' + plural(gaps, 'bucket') +
                ' has no samples',
        }),
        el('div', { class: 'coverage-banner__body' }, [
          el('p', {
            text: 'The percentage above is an average over the buckets that ' +
                  'were measured, not over the last ' + AVAIL_HOURS + ' hours. ' +
                  'Roughly ' + Math.round((gaps / AVAIL_BUCKETS) * 100) + '% of ' +
                  'the window has no data behind it, and the hatched bars mark ' +
                  'where.',
          }),
        ]),
      ]),
    ]));
  }

  container.appendChild(uptimeStrip(slots));
}
/* =============================================================== transport */

/**
 * Panel-level error state.
 *
 * The generalisation of `errorState` above, which stays as-is because its copy
 * is specific to why a stale posture reading is worse than none. Every panel
 * follows the same rule: on a failed read, show nothing and say so. None of
 * them fall back to the last good payload, because a dashboard that keeps
 * displaying a result after it stops being able to confirm it is asserting
 * something it no longer knows.
 */
function panelError(label, path, err) {
  return el('div', { class: 'placeholder placeholder--error' }, [
    el('div', { class: 'placeholder__title', text: label + ' unavailable' }),
    el('p', {
      text: 'The dashboard could not read ' + path + ': ' + err +
            '. Nothing is shown rather than the last good result — a reading ' +
            'the agent can no longer confirm is worse than an absent one.',
    }),
  ]);
}

/* Last payload per panel, serialised, so an unchanged poll is a no-op in the
 * DOM as well as on the wire. The posture panel's comment explains the reason
 * this matters -- rebuilding closes every <details> the reader had open -- and
 * it applies at least as strongly here: on the alerts panel the open one is
 * usually the folded-rules list or a raw evidence blob, both opened precisely
 * because they are being read slowly. */
let lastAlertsPayload = null;
let lastDevicesPayload = null;
let lastAvailPayload = null;

/**
 * Fetch, compare, render. The shared body of all three loaders.
 *
 * `force` skips the unchanged-payload check, which an action handler needs: a
 * resolve that leaves the response byte-identical (because the server rejected
 * it, say) must still repaint the buttons it disabled.
 */
async function loadPanel(opts, force) {
  const container = document.getElementById(opts.elementId);
  if (!container) return;
  try {
    const resp = await fetch(opts.path);
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const body = await resp.text();
    // Compare a structural signature when the panel provides one, so churn in
    // volatile fields (an alert's last_seen or count bumping) does not trigger
    // a full rebuild -- that was the Alerts page "visibly reloading". The
    // relative-time labels going a little stale between real changes is a fair
    // trade for a queue that does not flash every few seconds.
    const cur = opts.signature ? opts.signature(body) : body;
    if (!force && cur === opts.getLast() && container.firstChild) return;
    // The privacy mask can only hide a hostname it has been told about, and
    // alert prose quotes hostnames. Wait for viz.js's name preload so the
    // first paint is already masked (see PNMA.namesReady).
    if (window.PNMA && window.PNMA.namesReady) await window.PNMA.namesReady;
    opts.setLast(cur);
    opts.render(JSON.parse(body), container);
  } catch (err) {
    opts.setLast(null);
    clear(container);
    container.appendChild(
      panelError(opts.label, opts.path, err && err.message ? err.message : String(err))
    );
  }
}

/**
 * Acknowledge or resolve one alert.
 *
 * The only writes this dashboard performs. Both are reversible through
 * `/api/alerts/{id}/reopen`, and neither deletes anything -- the API exposes no
 * destructive action and this panel does not synthesise one out of the two it
 * has.
 *
 * The buttons are disabled for the duration and re-enabled only on failure,
 * because on success the card is about to be replaced by the reload anyway.
 * Leaving them live during the request invites a double-POST that would return
 * a second 200 and look, from here, exactly like the first.
 */
async function alertAction(id, action, buttons) {
  for (const b of buttons) b.disabled = true;
  try {
    const resp = await fetch('/api/alerts/' + id + '/' + action, { method: 'POST' });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    await loadAlerts(true);
  } catch (err) {
    for (const b of buttons) b.disabled = false;
    const card = buttons[0] && buttons[0].closest('.alertdetail');
    if (card && !card.querySelector('.alert__error')) {
      card.appendChild(el('p', {
        class: 'alert__desc alert__error',
        text: 'Could not ' + action + ' this alert: ' +
              (err && err.message ? err.message : String(err)) +
              '. It is unchanged on the server.',
      }));
    }
  }
}

async function loadAlerts(force) {
  // Stories are named after devices; make sure the device list is here
  // before the first alert render, or the story reads as a raw device id.
  if (!lastDevicesPayload) { try { await loadDevices(); } catch (e) { /* the panel reports it */ } }
  return loadPanel({
    elementId: 'alerts-body',
    // Every status, not just open: see the action table in `alertCard`. The
    // limit is the endpoint's own default made explicit.
    path: '/api/alerts?status=all&limit=100',
    label: 'Alerts',
    getLast: () => lastAlertsPayload,
    setLast: (v) => { lastAlertsPayload = v; },
    signature: (body) => {
      try {
        const a = JSON.parse(body).alerts || [];
        // Only the fields that shape the DOM: which alerts, their severity,
        // status, title and grouping -- not last_seen, count or evidence.
        return a.map((x) => x.id + '|' + x.severity + '|' + x.status + '|' + x.rule_id + '|' + (x.device_id || '') + '|' + (x.title || '')).join(String.fromCharCode(10)); } catch (e) { return body; }
    },
    render: (payload, container) => renderAlerts(payload, container, alertAction),
  }, force);
}

function loadDevices() {
  return loadPanel({
    elementId: 'devices-body',
    path: '/api/devices',
    label: 'Devices',
    getLast: () => lastDevicesPayload,
    setLast: (v) => { lastDevicesPayload = v; },
    render: renderDevices,
  });
}

function loadAvailability() {
  return loadPanel({
    elementId: 'availability-body',
    path: '/api/latency?hours=' + AVAIL_HOURS + '&buckets=' + AVAIL_BUCKETS,
    label: 'Availability',
    getLast: () => lastAvailPayload,
    setLast: (v) => { lastAvailPayload = v; },
    render: renderAvailability,
  });
}

/* ------------------------------------------------------------------- boot */

window.PNMA = window.PNMA || {};
window.PNMA.renderHostPosture = renderHostPosture;
Object.assign(window.PNMA, { el, clear, plural, relativeTime, stateChip, severityChip, eventLog, clockTime,
                             loadAlerts, loadDevices, loadAvailability, loadHostPosture });
// Exported for the same reason as the posture renderer: each panel can be
// driven from a fixture during development without standing up the API.
window.PNMA.renderAlerts = renderAlerts;
window.PNMA.filterAlertsByTechnique = filterAlertsByTechnique;

/* Open one alert's drawer from anywhere (the Overview posture banner uses
 * this). Switches to the Alerts tab, then opens the drawer for that id from
 * the last loaded payload -- loading it first if the tab has not yet. */
function openAlertById(id) {
  if (window.PNMA.showTab) window.PNMA.showTab('alerts');
  const open = () => {
    const alerts = lastAlertsPayload ? (JSON.parse(lastAlertsPayload).alerts || []) : [];
    const a = alerts.find((x) => String(x.id) === String(id));
    if (a) openAlertSheet(normaliseAlerts([a])[0], alertAction);
    else if (window.PNMA.showTab) window.PNMA.showTab('alerts', 'alert:' + id);
  };
  if (lastAlertsPayload) open();
  else loadAlerts(true).then(open);
}
window.PNMA.openAlert = openAlertById;
window.PNMA.renderDevices = renderDevices;
window.PNMA.renderAvailability = renderAvailability;

document.addEventListener('DOMContentLoaded', () => {
  buildNotifyPill();
  loadHostPosture();
  loadDevices();
  loadAlerts();
  loadAvailability();

  /* Every panel on this page is downstream of the same collector run, so none
   * of them can change faster than the collector schedule -- polling any of
   * them at a few seconds would just re-read the database to be told the same
   * thing. Sixty seconds keeps them current at roughly the cadence the data
   * actually moves.
   *
   * Availability is the exception in the other direction: its buckets are
   * fifteen minutes wide, so a bar cannot change more than four times an hour
   * and five minutes is already generous.
   *
   * Acknowledging or resolving an alert does not wait for the next tick -- it
   * forces its own reload, because a UI that leaves a button you just pressed
   * looking unpressed for up to a minute teaches people to press it twice. */
  // Fallback cadence only: while viz.js's change stream is up, every panel
  // refreshes the moment the collector writes instead (PNMA.refreshAll).
  const every = window.PNMA.every || ((fn, ms) => setInterval(fn, ms));
  loadHostInventory(); loadHostEvents();
  every(loadHostInventory, 300000);
  every(loadHostEvents, 120000);
  if (window.PNMA.onChange) { window.PNMA.onChange(loadHostEvents); window.PNMA.onChange(loadHostInventory); }
  every(loadHostPosture, 60000);
  every(loadDevices, 60000);
  every(loadAlerts, 60000);
  every(loadAvailability, 300000);
});
