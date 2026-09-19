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
    el('span', { class: 'fact__title', text: fact.title || fact.fact_key }),
    el('code', { class: 'fact__key', text: fact.fact_key }),
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

  const card = el('div', { class: 'fact fact--' + state }, [head]);

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

  const head = el('div', { class: 'cat-group__head' }, [
    el('span', { class: 'cat-group__name', text: CATEGORY_LABELS[category] || category }),
    el('span', { class: 'cat-group__counts' }, [
      tally('finding', counts.finding),
      tally('unknown', counts.unknown),
      tally('ok', counts.ok),
    ]),
  ]);

  return el('section', { class: 'cat-group' }, [head].concat(sorted.map(factCard)));
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

/**
 * One alert card.
 *
 * `onAction` is invoked with (alertId, action, buttons) and owns the POST and
 * the refresh. Passing it in rather than reaching for a module-level function
 * keeps the card renderable from a fixture with no API behind it.
 */
function alertCard(alert, onAction) {
  const sev = SEVERITIES[alert.severity] ? alert.severity : 'low';

  const head = el('div', { class: 'alert__head' }, [
    severityChip(sev, alert.severity_raw),
    el('span', { class: 'alert__title', text: alert.title || alert.rule_id }),
  ]);

  // A repeat count is a different fact from a single occurrence: it says the
  // condition kept being true across runs, not that it was seen once and aged.
  if (alert.count > 1) {
    head.appendChild(el('span', {
      class: 'badge',
      title: 'Seen on ' + alert.count + ' collection runs',
      text: 'x' + alert.count,
    }));
  }

  if (alert.status && alert.status !== 'open') {
    head.appendChild(el('span', { class: 'badge', text: alert.status }));
  }

  const card = el('div', {
    class: 'alert alert--' + sev + (alert.status === 'resolved' ? ' alert--muted' : ''),
  }, [head]);

  if (alert.description) {
    card.appendChild(el('p', { class: 'alert__desc', text: alert.description }));
  }

  // The folded rules. Rendered as a disclosure rather than inline: the headline
  // is one alert, and the point of correlation is that the reader does not have
  // to read four. It is there for the reader who asks "what did it merge?".
  const folded = foldedRules(alert);
  if (folded.length) {
    card.appendChild(el('details', { class: 'alert__folded' }, [
      el('summary', {
        text: folded.length + ' other ' + plural(folded.length, 'rule') +
              ' fired on this and ' + (folded.length === 1 ? 'was' : 'were') +
              ' folded in',
      }),
      el('ul', {}, folded.map((r) => el('li', {
        text: (r.rule_id || 'unknown rule') +
              (r.severity ? ' (' + r.severity + ')' : '') +
              (r.title ? ' - ' + r.title : ''),
      }))),
    ]));
  }

  // Raw evidence, same both-shapes handling as `factCard`.
  const ev = alert.evidence;
  const evText = (ev && typeof ev === 'object')
    ? (Object.keys(ev).length ? JSON.stringify(ev, null, 2) : null)
    : (typeof ev === 'string' && ev.trim() ? ev : null);
  if (evText) {
    card.appendChild(el('details', { class: 'fact__evidence' }, [
      el('summary', { text: typeof ev === 'string' ? 'evidence (unparsed)' : 'evidence' }),
      el('pre', { text: evText }),
    ]));
  }

  card.appendChild(el('div', { class: 'alert__meta' }, [
    el('span', { text: 'rule: ' + (alert.rule_id || '-') }),
    alert.mitre_id
      ? el('span', {
          text: 'ATT&CK: ' + alert.mitre_id +
                (alert.mitre_name ? ' ' + alert.mitre_name : ''),
        })
      : null,
    alert.device_id ? el('span', { text: 'device: ' + alert.device_id }) : null,
    alert.last_seen ? el('span', { text: 'last seen ' + relativeTime(alert.last_seen) }) : null,
  ]));

  // Actions follow the alert's place in its lifecycle, and the panel reads every
  // status so each transition stays visible and reversible.
  //
  // An earlier draft read only open alerts. That made Acknowledge and Resolve
  // indistinguishable -- both simply removed the row -- and left `reopen`
  // unreachable from the UI even though the API implements it. Two buttons that
  // appear to do different things and observably do the same one are worse than
  // either alone, and an acknowledged alert you cannot see is an alert you have
  // silently dropped.
  //
  // Nothing here deletes. The API exposes no destructive action and this panel
  // does not synthesise one out of the three it has.
  const available = ALERT_ACTIONS[alert.status] || [];
  if (onAction && alert.id !== undefined && available.length) {
    const buttons = available.map(([, label]) =>
      el('button', { class: 'btn', type: 'button', text: label }));
    buttons.forEach((btn, i) => {
      btn.addEventListener('click', () => onAction(alert.id, available[i][0], buttons));
    });
    card.appendChild(el('div', { class: 'alert__actions' }, buttons));
  }

  return card;
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

function renderAlerts(payload, container, onAction) {
  const alerts = normaliseAlerts((payload && payload.alerts) || []);
  clear(container);

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

  // How much correlation actually did, across everything shown. This is the
  // number that says whether the feature is earning its place.
  let foldedTotal = 0;
  for (const a of alerts) foldedTotal += foldedRules(a).length;

  const triaged = alerts.length - open.length;

  container.appendChild(el('div', { class: 'metrics' }, [
    el('div', { class: 'stat stat--total' }, [
      el('div', { class: 'stat__n', text: String(open.length) }),
      el('div', { class: 'stat__label', text: plural(open.length, 'open alert') }),
    ]),
    el('div', { class: 'stat stat--finding' }, [
      el('div', { class: 'stat__n', text: String(counts.critical + counts.high) }),
      el('div', { class: 'stat__label', text: 'open, critical or high' }),
    ]),
    el('div', { class: 'stat' }, [
      el('div', { class: 'stat__n', text: String(foldedTotal) }),
      el('div', { class: 'stat__label', text: 'folded by correlation' }),
    ]),
    el('div', { class: 'stat' }, [
      el('div', { class: 'stat__n', text: String(triaged) }),
      el('div', { class: 'stat__label', text: 'acknowledged or resolved' }),
    ]),
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

  for (const a of sorted) container.appendChild(alertCard(a, onAction));
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

  return el('div', { class: 'dev' + (attention ? ' dev--attention' : '') }, [
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

  container.appendChild(el('div', { class: 'metrics' }, [
    el('div', { class: 'stat stat--total' }, [
      el('div', { class: 'stat__n', text: String(devices.length) }),
      el('div', { class: 'stat__label', text: plural(devices.length, 'device') }),
    ]),
    el('div', { class: 'stat stat--ok' }, [
      el('div', { class: 'stat__n', text: String(online.length) }),
      el('div', { class: 'stat__label', text: 'online now' }),
    ]),
    // Always rendered, including at zero, for the same reason the posture panel
    // always renders its unknown count: the absence of untrusted devices is a
    // result, and it should not be indistinguishable from an unrendered one.
    el('div', { class: 'stat stat--finding' }, [
      el('div', { class: 'stat__n', text: String(untrustedOnline.length) }),
      el('div', { class: 'stat__label', text: 'untrusted, online' }),
    ]),
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
    if (!force && body === opts.getLast() && container.firstChild) return;
    opts.setLast(body);
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
    const card = buttons[0] && buttons[0].closest('.alert');
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

function loadAlerts(force) {
  return loadPanel({
    elementId: 'alerts-body',
    // Every status, not just open: see the action table in `alertCard`. The
    // limit is the endpoint's own default made explicit.
    path: '/api/alerts?status=all&limit=100',
    label: 'Alerts',
    getLast: () => lastAlertsPayload,
    setLast: (v) => { lastAlertsPayload = v; },
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
Object.assign(window.PNMA, { el, clear, plural, relativeTime, stateChip, severityChip,
                             loadAlerts, loadDevices, loadAvailability, loadHostPosture });
// Exported for the same reason as the posture renderer: each panel can be
// driven from a fixture during development without standing up the API.
window.PNMA.renderAlerts = renderAlerts;
window.PNMA.renderDevices = renderDevices;
window.PNMA.renderAvailability = renderAvailability;

document.addEventListener('DOMContentLoaded', () => {
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
  setInterval(loadHostPosture, 60000);
  setInterval(loadDevices, 60000);
  setInterval(loadAlerts, 60000);
  setInterval(loadAvailability, 300000);
});
