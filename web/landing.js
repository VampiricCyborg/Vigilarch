// Vigilarch landing page.
//
// Four jobs, and none of them is computing anything about a ledger:
//
//   1. Drive one short, fixed scenario through `vigil-ledger` compiled to
//      wasm32-unknown-unknown, and print what comes back — into the hero card,
//      into the pipeline's artifact slots, and into the five LIVE figures in
//      the capabilities section.
//   2. Some reveal animation on numbers that are already in the DOM.
//   3. Presentation: which section the header should point at, a fade for each
//      section as it comes into view, the architecture diagram's hover model,
//      and the copy buttons. All attached from here rather than written into
//      the markup, so the page without JavaScript is the whole page, plainly
//      visible, rather than a screen of nothing.
//   4. Nothing else.
//
// The header bar's own behaviour — the narrow-screen menu, the stuck state —
// lives in nav.js, because demo.html carries the same bar.
//
// ---------------------------------------------------------------------------
// The rule this file is held to
// ---------------------------------------------------------------------------
//
// Every verdict, bound, witness depth, content address, sequence number and
// fork proof this file renders is a value the wasm module returned. There is no
// chain walk, no DAG construction and no bracketing rule here, and there must
// never be one — a second implementation in JavaScript is exactly the
// divergence invariant I2 exists to prevent. The same rule governs app.js on
// the demo page.
//
// That extends to the *edges* drawn in the chain and DAG figures. A chain edge
// is drawn because the entry's returned `prev` field names the entry it comes
// from. A sealing edge is drawn because `bracket()` returned that attestation
// as the record's `upper_bound`. Neither is worked out here. If a relation is
// not a field on something the module handed back, this file does not draw it.
//
// If you want to check that the figures are live rather than JSON literals that
// merely look live: change a string in SCENARIO below and reload. Every content
// address on the page changes, because they are BLAKE3 addresses of the objects
// the ledger actually built.
//
// If the module cannot be loaded at all, every live surface says so and stays
// empty. None of them falls back to plausible-looking values.

// ---------------------------------------------------------------------------
// The canned run
// ---------------------------------------------------------------------------

/** The six mutating calls the page makes, in order. This mirrors the shape of
 *  `vigil-sim`'s `minimal` and `equivocation` scenarios — an honest partition
 *  that gets sealed by one meeting, then an equivocation that gets convicted —
 *  which is the same ground `crates/vigil-wasm`'s native tests cover. It
 *  invents no new scenario. */
const SCENARIO = {
  a0: 'shoring on grid B4 is out of plumb',
  b0: 'night shift headcount logged',
  a1: 'gas monitor alarmed at portal, crew withdrawn',
  a2: 'temporary works permit expired, work stopped',
  eq: 'tag-out never applied, crew still on it',
};

// ---------------------------------------------------------------------------
// Small DOM helpers
// ---------------------------------------------------------------------------

const $ = (id) => document.getElementById(id);

const SVGNS = 'http://www.w3.org/2000/svg';

/** An element with an optional class and text. Text is always set as text and
 *  never parsed as markup. */
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
}

/** The SVG counterpart, with attributes, because every figure below is drawn
 *  rather than laid out. */
function svg(tag, attrs, text) {
  const n = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, String(v));
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
}

/** Content addresses are 64 hex characters; 12 is enough to read and to match
 *  the short ids `vigil-sim`'s run reports print. The full value is always put
 *  on `title` where there is room for it, so nothing is truncated away. */
const shortId = (hex) => (hex ? hex.slice(0, 12) : '—');
const shortKey = (hex) => (hex ? hex.slice(0, 8) + '…' : '—');

// ---------------------------------------------------------------------------
// Reading the ledger's answers
// ---------------------------------------------------------------------------

/** The three verdicts the ledger returns, decided exactly the way app.js
 *  decides them on the demo page: from the flags on the bracket, never from
 *  which call produced it. If the scenario above is edited and a claim comes
 *  back with a different verdict, the page shows the different verdict. */
function verdictOf(br) {
  if (br.disputed) return { key: 'disputed', label: 'UNWITNESSED · DISPUTED', glyph: '✕' };
  if (br.sealed) return { key: 'sealed', label: 'SEALED', glyph: '●' };
  return { key: 'unwitnessed', label: 'UNWITNESSED', glyph: '○' };
}

/** The short badge form of the same thing. */
function badgeOf(br) {
  if (br.disputed) return { key: 'disputed', label: 'disputed' };
  if (br.sealed) return { key: 'sealed', label: `sealed ×${br.witness_depth}` };
  return { key: 'unwitnessed', label: 'unwitnessed' };
}

/** The bracket exactly as the module returned it, in the field order of the
 *  `BracketSummary` struct in `crates/vigil-wasm/src/lib.rs`.
 *
 *  One normalisation, and only one: serde_wasm_bindgen serialises a Rust `None`
 *  as `undefined`, and `JSON.stringify` drops an undefined-valued key entirely.
 *  An absent bound is the most load-bearing value on this page — it is what an
 *  open window edge means — so it is rendered as an explicit `null` rather than
 *  vanishing. No other value is touched. */
function bracketJson(br) {
  return JSON.stringify(
    {
      observation: br.observation,
      sealed: br.sealed,
      unwitnessed: br.unwitnessed,
      upper_bound: br.upper_bound ?? null,
      lower_bound: br.lower_bound ?? null,
      witness_depth: br.witness_depth,
      disputed: br.disputed,
      window: br.window,
    },
    null,
    2,
  );
}

/** Maps a `WindowEdge` (spec/02 §5.1, serialised by vigil-wasm) to its label.
 *  The three kinds are the spec's own; this file invents no fourth. */
function edgeInfo(edge, which) {
  switch (edge.kind) {
    case 'genesis':
      return { open: true, label: 'open — genesis', what: 'nothing proves it did not exist earlier' };
    case 'verification_moment':
      return { open: true, label: 'open — now', what: 'no witness has ever sealed this record' };
    case 'attestation':
      return {
        open: false,
        label: which === 'lower' ? 'bounded — L' : 'bounded — U',
        what: shortId(edge.id),
      };
    default:
      return { open: true, label: 'unknown edge', what: String(edge.kind) };
  }
}

/** The unwitnessed window, drawn so an open edge cannot be mistaken for a
 *  bounded one: bounded edges are solid caps, open edges are dashed and the
 *  fill fades out towards them. Same treatment as the demo page.
 *
 *  The axis this sits on is causal order, not a clock, and carries no times for
 *  that reason (spec/02 §5.3: the lower bound is an ordering fact, and becomes
 *  a wall-clock bound only with an external anchor, which v1 does not have). */
function windowBlock(br) {
  const lower = edgeInfo(br.window.lower, 'lower');
  const upper = edgeInfo(br.window.upper, 'upper');

  const block = el('div', 'lw');
  block.appendChild(el('p', 'lw-h', 'unwitnessed window — the span the system cannot vouch for'));

  const bar = el('div', 'lw-bar');
  if (lower.open) bar.classList.add('open-left');
  if (upper.open) bar.classList.add('open-right');
  bar.appendChild(el('span', `lw-cap left ${lower.open ? 'open' : 'bounded'}`));
  bar.appendChild(el('span', 'lw-track'));
  bar.appendChild(el('span', `lw-cap right ${upper.open ? 'open' : 'bounded'}`));
  bar.setAttribute('role', 'img');
  bar.setAttribute('aria-label', `window ${lower.label}: ${lower.what}, to ${upper.label}: ${upper.what}`);
  block.appendChild(bar);

  const edges = el('div', 'lw-edges');
  for (const [side, info] of [['left', lower], ['right', upper]]) {
    const d = el('div', `lw-edge ${side} ${info.open ? 'open' : 'bounded'}`);
    d.appendChild(el('span', 'k', info.label));
    d.appendChild(el('span', 'v', info.what));
    edges.appendChild(d);
  }
  block.appendChild(edges);
  return block;
}

/** A plain reading of the verdict, derived from the returned flags — the same
 *  three explanations the demo page gives, shortened. */
function explain(br) {
  if (br.disputed) {
    return (
      'The author is quarantined by a fork proof and no witness ever sealed this entry, so it is ' +
      'disputed — retained, never deleted, because the dispute is itself evidence. An attacker’s ' +
      'withheld branch lands exactly here (spec/02 §6.4).'
    );
  }
  if (br.sealed) {
    return (
      'A witness signed a statement about this key’s chain head at or past this record’s seq, so the ' +
      'record existed no later than that meeting. Upper bound only: the window stays open below, ' +
      'because nothing proves the record did not exist earlier (spec/02 §5.2, §8).'
    );
  }
  return (
    'No attestation covers this record, so the system will not claim when it was written. The window ' +
    'runs to the moment of verification. This is the honest answer, not a detection (spec/02 §8).'
  );
}

// ---------------------------------------------------------------------------
// The hero card
// ---------------------------------------------------------------------------

function setStatus(state, text) {
  const wrap = $('lc-status');
  if (!wrap) return;
  wrap.dataset.state = state;
  $('lc-status-text').textContent = text;
}

/** Rendered when the wasm module is not there. `web/pkg/` is generated and not
 *  tracked in git, so this is the state a fresh clone gets — and inventing
 *  plausible numbers to fill the card would be exactly the kind of claim this
 *  project exists to refuse. Every other live surface is told the same thing. */
function renderUnavailable(err) {
  setStatus('error', 'module not built');
  const body = $('lc-body');
  if (body) {
    body.replaceChildren();
    body.appendChild(
      el(
        'p',
        'lc-boot',
        'This card runs the real ledger, so it needs the WebAssembly module, and web/pkg/ is ' +
          'generated rather than committed. Build it and serve this directory over HTTP — file:// ' +
          'cannot load an ES module or instantiate WASM.',
      ),
    );
    const pre = el('pre', 'lc-json');
    pre.appendChild(el('code', null, './web/build.sh\npython -m http.server -d web 8080'));
    body.appendChild(pre);
    if (err) body.appendChild(el('p', 'lc-err', String(err && err.message ? err.message : err)));
  }
  markLiveSurfacesUnavailable();
}

/** The pipeline slots and the five LIVE figures, when there is nothing to put
 *  in them. They say so; they do not improvise. */
function markLiveSurfacesUnavailable() {
  for (const slot of document.querySelectorAll('.pl-art[data-live]')) {
    slot.textContent = 'module not built';
    slot.classList.add('is-const');
  }
  for (const fig of document.querySelectorAll('.fig-live')) {
    fig.classList.add('is-err');
    fig.replaceChildren(
      el(
        'p',
        null,
        'This figure is drawn from values the ledger returns, and the WebAssembly module is not ' +
          'built. Rather than show something that looks right, it shows nothing.',
      ),
    );
  }
}

function renderCard(run) {
  const body = $('lc-body');
  if (!body) return;
  body.replaceChildren();

  // --- the call log: what each mutating call returned ----------------------
  const log = el('div', 'lc-log');
  for (const [call, result] of run.log) {
    const line = el('div', 'lc-line');
    line.appendChild(el('span', 'call', call));
    line.appendChild(el('span', 'res', result));
    log.appendChild(line);
  }
  body.appendChild(log);

  // A live cross-check rather than an assertion in prose: re-bracketing the
  // sealed record after its author is convicted must not change its upper bound
  // (spec/02 §6.5). Whatever the comparison says is what gets printed.
  body.appendChild(el('p', `lc-check ${run.recheck.ok ? 'ok' : 'bad'}`, run.recheck.text));

  // --- one chip per claim, verdict decided by the ledger -------------------
  const chips = el('div', 'lc-chips');
  chips.setAttribute('role', 'group');
  chips.setAttribute('aria-label', 'claims from this run');
  run.claims.forEach((claim, i) => {
    const v = verdictOf(claim.br);
    const b = el('button', `lc-chip v-${v.key}`);
    b.type = 'button';
    b.setAttribute('aria-pressed', String(i === run.selected));
    b.appendChild(el('span', 'g', v.glyph));
    b.appendChild(el('span', 'l', v.label));
    b.appendChild(el('span', 'w', claim.label));
    b.addEventListener('click', () => {
      run.selected = i;
      renderCard(run);
    });
    chips.appendChild(b);
  });
  body.appendChild(chips);

  // --- the selected claim, as the module returned it -----------------------
  const claim = run.claims[run.selected];
  const panel = el('div', 'lc-panel');

  panel.appendChild(el('p', 'lc-call', `demo.bracket("a", "${shortId(claim.br.observation)}…")`));
  panel.appendChild(el('p', 'lc-when', claim.when));

  const pre = el('pre', 'lc-json');
  pre.appendChild(el('code', null, bracketJson(claim.br)));
  panel.appendChild(pre);

  panel.appendChild(windowBlock(claim.br));
  panel.appendChild(el('p', 'lc-read', explain(claim.br)));

  body.appendChild(panel);
}

// ---------------------------------------------------------------------------
// The pipeline's artifact slots
// ---------------------------------------------------------------------------

/** Eight stages, five of which can show something the run actually produced.
 *  `SIGN` is not among them: the domain-separation tag is a constant in
 *  crates/vigil-core/src/sign.rs, and it is printed as a constant in the markup
 *  and labelled as one rather than dressed up as a computed value. */
function fillPipeline(run) {
  const put = (id, value, note) => {
    const slot = $(id);
    if (!slot) return;
    slot.replaceChildren(el('code', null, value));
    if (note) slot.appendChild(el('b', null, note));
  };

  put('pl-observe', run.st.a.chain[0].text, 'the body, as state() returned it');
  put('pl-hash', shortId(run.a0.id) + '…', 'BLAKE3 over the canonical encoding');
  put('pl-append', `seq ${run.a0.seq} · prev ${run.a0.prev ? shortId(run.a0.prev) : '∅ genesis'}`, 'from the store, not the writer');
  put('pl-meet', shortId(run.ex.b_witnesses_a.id) + '…', 'the attestation B signed about A');
  put(
    'pl-attest',
    `B witnesses A @ seq ${run.ex.b_witnesses_a.subject_seq}`,
    `head ${shortId(run.ex.b_witnesses_a.subject_head)}…`,
  );
  put(
    'pl-entangle',
    `${run.stPre.a.chain.length + run.stPre.b.chain.length} observations · ${run.stPre.attestations.length} attestations`,
    'vertices held after the meeting, before the fork',
  );
  const v = verdictOf(run.claims[0].br);
  put('pl-verify', `O0 → ${v.label} ×${run.claims[0].br.witness_depth}`, 'returned by bracket()');
}

// ---------------------------------------------------------------------------
// Figure B — the chain
// ---------------------------------------------------------------------------

/** Node A's chain as a run of blocks. Every value on a block — `seq`, the
 *  content address, the body, `prev` — is a field on an entry `state()`
 *  returned, and the verdict badge is a `bracket()` result. The connector
 *  between two blocks is the `prev` link: it exists because the lower block's
 *  returned `prev` is the upper block's returned id. */
function renderChainFigure(run) {
  const host = $('fig-chain');
  if (!host) return;

  const wrap = el('div', 'chainfig');
  const list = el('ol', 'cf-list');

  run.stPre.a.chain.forEach((entry, i) => {
    const br = run.preBrackets[i];
    const b = badgeOf(br);

    const li = el('li', 'cf-block');
    li.dataset.state = b.key;
    li.title = entry.id;

    li.appendChild(el('span', 'cf-seq', `seq ${entry.seq}`));
    const badge = el('span', 'cf-badge', b.label);
    badge.dataset.state = b.key;
    li.appendChild(badge);
    li.appendChild(el('span', 'cf-id', shortId(entry.id) + '…'));
    li.appendChild(el('span', 'cf-text', entry.text));
    li.appendChild(el('span', 'cf-prev', `prev ${entry.prev ? shortId(entry.prev) + '…' : '∅ genesis'}`));
    list.appendChild(li);
  });

  wrap.appendChild(list);
  wrap.appendChild(
    el(
      'p',
      'dag-cap',
      'Node A, bracketed before the equivocation in call 6. Only the entry the meeting covers is ' +
        'sealed; the two written after it are unwitnessed, and the window stays open rather than ' +
        'being guessed at.',
    ),
  );
  host.replaceChildren(wrap);
}

// ---------------------------------------------------------------------------
// Figure C — the exchange
// ---------------------------------------------------------------------------

function renderAttestFigure(run) {
  const host = $('fig-attest');
  if (!host) return;

  const wrap = el('div', 'atfig');

  const heads = el('div', 'at-heads');
  const dev = (label, key) => {
    const d = el('div', 'at-dev');
    const s = svg('svg', { class: 'ic', 'aria-hidden': 'true' });
    s.appendChild(svg('use', { href: '#i-node' }));
    d.appendChild(s);
    d.appendChild(el('b', null, label));
    d.appendChild(el('span', 'at-key', shortKey(key)));
    return d;
  };
  heads.appendChild(dev('Node A', run.st.a.pubkey));
  const mid = el('div', 'at-mid');
  const ms = svg('svg', { class: 'ic', 'aria-hidden': 'true' });
  ms.appendChild(svg('use', { href: '#i-meet' }));
  mid.appendChild(ms);
  mid.appendChild(el('span', null, 'meeting'));
  heads.appendChild(mid);
  heads.appendChild(dev('Node B', run.st.b.pubkey));
  wrap.appendChild(heads);

  const row = (att, dir, label) => {
    const d = el('div', `at-x dir-${dir}`);
    d.appendChild(el('span', 'at-lbl', label));
    d.appendChild(el('span', 'at-line'));
    const id = el('code', 'at-id', shortId(att.id) + '…');
    id.title = att.id;
    d.appendChild(id);
    d.appendChild(el('span', 'at-meta', `subject_head ${shortId(att.subject_head)}…`));
    return d;
  };
  wrap.appendChild(
    row(run.ex.b_witnesses_a, 'l', `B witnesses A @ seq ${run.ex.b_witnesses_a.subject_seq}`),
  );
  wrap.appendChild(
    row(run.ex.a_witnesses_b, 'r', `A witnesses B @ seq ${run.ex.a_witnesses_b.subject_seq}`),
  );
  wrap.appendChild(
    el(
      'p',
      'dag-cap',
      'Both ids are content addresses of attestations exchangeAttestation() produced. Neither ' +
        'attestation says anything in wall-clock terms.',
    ),
  );

  host.replaceChildren(wrap);
}

// ---------------------------------------------------------------------------
// Figure D — the DAG
// ---------------------------------------------------------------------------

/** Three lanes: node A's chain, the attestations, node B's chain.
 *
 *  Two kinds of edge, and both are returned relations rather than inferences:
 *
 *    chain edge   drawn from entry n−1 to entry n because entry n's returned
 *                 `prev` is entry n−1's returned id.
 *    sealing edge drawn from an observation to an attestation because
 *                 `bracket()` returned that attestation as the observation's
 *                 `upper_bound`.
 *
 *  Nothing else is drawn. Working out a third edge type here would be a second
 *  implementation of the DAG, which invariant I2 forbids. */
function renderDagFigure(run) {
  const host = $('fig-dag');
  if (!host) return;

  const W = 580;
  const LANE_A = 46;
  const LANE_T = 122;
  const LANE_B = 198;
  const BOXH = 34;
  const H = 286;

  const s = svg('svg', {
    class: 'dagfig',
    viewBox: `0 0 ${W} ${H}`,
    fill: 'none',
    role: 'img',
    'aria-label':
      'The attestation DAG after one meeting: node A and node B each hold their own chain, and ' +
      'two attestations join them.',
  });

  const edges = svg('g', {});
  const nodes = svg('g', {});
  s.appendChild(edges);
  s.appendChild(nodes);

  // --- geometry -----------------------------------------------------------
  // The gap between boxes in a lane has to be wide enough for the chain edge
  // between them to read as an edge rather than as a join.
  const spread = (n, width) => {
    const gap = 34;
    const total = n * width + (n - 1) * gap;
    const left = Math.max(20, (W - total) / 2);
    return (i) => left + i * (width + gap);
  };

  const aW = 112;
  const tW = 150;
  const bW = 112;
  const aX = spread(run.stPre.a.chain.length, aW);
  const tX = spread(run.stPre.attestations.length, tW);
  const bX = spread(run.stPre.b.chain.length, bW);

  /** id -> { x, y, w } for every vertex actually drawn. */
  const at = new Map();

  const box = (x, y, w, cls, title, sub, id) => {
    const g = svg('g', { class: `dg-v ${cls}` });
    g.appendChild(svg('rect', { x, y, width: w, height: BOXH, rx: 4 }));
    g.appendChild(svg('text', { class: 'dg-t', x: x + 9, y: y + 15 }, title));
    g.appendChild(svg('text', { class: 'dg-s', x: x + 9, y: y + 27 }, sub));
    const t = svg('title', {}, id);
    g.appendChild(t);
    nodes.appendChild(g);
    at.set(id, { x, y, w });
  };

  const lane = (y, text) => nodes.appendChild(svg('text', { class: 'dg-lane', x: 8, y }, text));
  lane(LANE_A - 10, 'node A · chain');
  lane(LANE_T - 10, 'attestations');
  lane(LANE_B - 10, 'node B · chain');

  run.stPre.a.chain.forEach((e, i) => {
    const br = run.preBrackets[i];
    box(aX(i), LANE_A, aW, 'st-' + badgeOf(br).key, `O${e.seq}`, shortId(e.id), e.id);
  });
  run.stPre.attestations.forEach((a, i) => {
    const w = a.witness === run.stPre.a.pubkey ? 'A' : 'B';
    const sub = a.subject === run.stPre.a.pubkey ? 'A' : 'B';
    box(tX(i), LANE_T, tW, 'is-att', `${w} attests ${sub}@${a.subject_seq}`, shortId(a.id), a.id);
  });
  run.stPre.b.chain.forEach((e, i) => {
    const br = run.preBracketsB[i];
    box(bX(i), LANE_B, bW, 'st-' + badgeOf(br).key, `B${e.seq}`, shortId(e.id), e.id);
  });

  // --- edges --------------------------------------------------------------
  const link = (fromId, toId, cls) => {
    const f = at.get(fromId);
    const t = at.get(toId);
    if (!f || !t) return;
    let d;
    if (f.y === t.y) {
      // same lane: a chain edge, drawn along the lane
      d = `M${f.x + f.w} ${f.y + BOXH / 2}H${t.x}`;
      const head = `M${t.x - 6} ${f.y + BOXH / 2 - 4.5}L${t.x} ${f.y + BOXH / 2}L${t.x - 6} ${f.y + BOXH / 2 + 4.5}`;
      edges.appendChild(svg('path', { class: `dg-e ${cls}`, d: head }));
    } else {
      // between lanes: a sealing edge, dropping from one lane to the next
      const fy = f.y < t.y ? f.y + BOXH : f.y;
      const ty = f.y < t.y ? t.y : t.y + BOXH;
      const fx = f.x + f.w / 2;
      const tx = t.x + t.w / 2;
      const my = (fy + ty) / 2;
      d = `M${fx} ${fy}C${fx} ${my} ${tx} ${my} ${tx} ${ty}`;
      const dir = f.y < t.y ? 1 : -1;
      const head = `M${tx - 4.5} ${ty - 6 * dir}L${tx} ${ty}L${tx + 4.5} ${ty - 6 * dir}`;
      edges.appendChild(svg('path', { class: `dg-e ${cls}`, d: head }));
    }
    edges.appendChild(svg('path', { class: `dg-e ${cls}`, d }));
  };

  // chain edges — from each entry's returned `prev`
  for (const node of [run.stPre.a, run.stPre.b]) {
    for (const e of node.chain) if (e.prev) link(e.prev, e.id, '');
  }
  // sealing edges — from each bracket's returned `upper_bound`
  run.stPre.a.chain.forEach((e, i) => {
    const u = run.preBrackets[i].upper_bound;
    if (u) link(e.id, u, 'is-seal');
  });
  run.stPre.b.chain.forEach((e, i) => {
    const u = run.preBracketsB[i].upper_bound;
    if (u) link(e.id, u, 'is-seal');
  });

  // --- legend -------------------------------------------------------------
  const lg = svg('g', {});
  lg.appendChild(svg('path', { class: 'dg-e', d: `M20 ${H - 30}h22` }));
  lg.appendChild(svg('text', { class: 'dg-legend', x: 48, y: H - 26 }, 'chain edge · from the returned prev'));
  lg.appendChild(svg('path', { class: 'dg-e is-seal', d: `M20 ${H - 12}h22` }));
  lg.appendChild(
    svg('text', { class: 'dg-legend', x: 48, y: H - 8 }, 'sealing edge · from the returned upper_bound'),
  );
  s.appendChild(lg);

  const wrap = el('div');
  wrap.appendChild(s);
  wrap.appendChild(
    el(
      'p',
      'dag-cap',
      'Before the meeting the two chains have no relation to one another at all. After it, an ' +
        'attestation sits in the causal past of everything either node writes next — which is what ' +
        'makes a fact about one chain constrain the other.',
    ),
  );
  host.replaceChildren(wrap);
}

// ---------------------------------------------------------------------------
// Figure E — the bracket
// ---------------------------------------------------------------------------

/** Three claims from the run, one tab each, and the bracket the module returned
 *  for whichever is selected. The axis is causal order and carries no times:
 *  an attestation is an upper bound, and a lower bound is an ordering fact, not
 *  a wall-clock instant (spec/02 §5.2, §5.3). */
function renderBracketFigure(run, selected = 0) {
  const host = $('fig-bracket');
  if (!host) return;

  const claim = run.claims[selected];
  const br = claim.br;
  const v = verdictOf(br);

  const wrap = el('div', 'bkfig');

  const tabs = el('div', 'bk-tabs');
  tabs.setAttribute('role', 'group');
  tabs.setAttribute('aria-label', 'claims from this run');
  run.claims.forEach((c, i) => {
    const b = el('button', 'bk-tab', c.short);
    b.type = 'button';
    b.dataset.state = verdictOf(c.br).key;
    b.setAttribute('aria-pressed', String(i === selected));
    b.addEventListener('click', () => renderBracketFigure(run, i));
    tabs.appendChild(b);
  });
  wrap.appendChild(tabs);

  const verdict = el('div', 'bk-verdict');
  verdict.dataset.state = v.key;
  verdict.appendChild(el('span', null, v.glyph));
  verdict.appendChild(el('span', null, v.label));
  wrap.appendChild(verdict);

  const axis = el('div', 'bk-axis');
  const lbl = el('div', 'bk-axis-l');
  lbl.appendChild(el('span', null, '← earlier in causal order'));
  lbl.appendChild(el('span', null, 'later →'));
  axis.appendChild(lbl);
  axis.appendChild(windowBlock(br));
  wrap.appendChild(axis);

  const kv = el('dl', 'bk-kv');
  const pair = (k, value, none) => {
    kv.appendChild(el('dt', null, k));
    kv.appendChild(el('dd', none ? 'none' : null, value));
  };
  pair('observation', shortId(br.observation) + '…');
  pair('upper bound U', br.upper_bound ? shortId(br.upper_bound) + '…' : 'none — nothing has sealed this record', !br.upper_bound);
  pair('lower bound L', br.lower_bound ? shortId(br.lower_bound) + '…' : 'none — open to this key’s genesis', !br.lower_bound);
  pair('witness depth', `${br.witness_depth} distinct witness key${br.witness_depth === 1 ? '' : 's'}`, br.witness_depth === 0);
  wrap.appendChild(kv);

  wrap.appendChild(el('p', 'bk-note', explain(br)));
  wrap.appendChild(
    el(
      'p',
      'bk-note',
      'Every record in this run has an open lower edge, and that is not a rendering choice: no ' +
        'observation the demo writes carries an acks field, so no attestation provably precedes any ' +
        'of them, and the honest lower bound is none.',
    ),
  );

  host.replaceChildren(wrap);
}

// ---------------------------------------------------------------------------
// Figure F — the fork
// ---------------------------------------------------------------------------

/** One key, two entries at one `seq`. The two colliding addresses are the
 *  `entry_a` and `entry_b` the `ForkProof` itself names; the collision label,
 *  the proof id and the convicted key are the proof's own fields. */
function renderForkFigure(run) {
  const host = $('fig-fork');
  if (!host || !run.eq.fork) return;

  const f = run.eq.fork;
  const wrap = el('div', 'fkfig');

  const W = 620;
  const H = 176;
  const s = svg('svg', {
    class: 'fk',
    viewBox: `0 0 ${W} ${H}`,
    fill: 'none',
    role: 'img',
    'aria-label': 'One chain position holding two entries: a fork, attributed to the author key.',
  });

  const node = (x, y, w, cls, title, sub, full) => {
    const g = svg('g', { class: `fk-node ${cls}` });
    g.appendChild(svg('rect', { x, y, width: w, height: 40, rx: 4 }));
    g.appendChild(svg('text', { class: 'fk-t', x: x + 10, y: y + 17 }, title));
    g.appendChild(svg('text', { class: 'fk-s', x: x + 10, y: y + 31 }, sub));
    if (full) g.appendChild(svg('title', {}, full));
    s.appendChild(g);
  };

  const seq = run.eq.sibling.seq;
  const prevLabel = run.eq.sibling.prev ? shortId(run.eq.sibling.prev) : '∅ genesis';

  s.appendChild(svg('path', { class: 'fk-e', d: 'M170 68H214' }));
  s.appendChild(svg('path', { class: 'fk-e is-split', d: 'M214 68H236C248 68 248 56 248 44V34' }));
  s.appendChild(svg('path', { class: 'fk-e is-split', d: 'M214 68H236C248 68 248 80 248 92V102' }));
  s.appendChild(svg('path', { class: 'fk-e is-split', d: 'M243.5 40 248 34 252.5 40' }));
  s.appendChild(svg('path', { class: 'fk-e is-split', d: 'M243.5 96 248 102 252.5 96' }));

  node(30, 48, 140, '', `prev`, prevLabel, run.eq.sibling.prev || 'genesis');
  node(268, 14, 172, 'is-a', `seq ${seq}`, shortId(f.entry_a), f.entry_a);
  node(268, 102, 172, 'is-b', `seq ${seq} · withheld`, shortId(f.entry_b), f.entry_b);

  s.appendChild(svg('path', { class: 'fk-e is-split', d: 'M440 34H482' }));
  s.appendChild(svg('path', { class: 'fk-e is-split', d: 'M440 122H482' }));
  s.appendChild(svg('path', { class: 'fk-e is-split', d: 'M482 34V122' }));
  s.appendChild(svg('path', { class: 'fk-e is-split', d: 'M482 78H512' }));
  s.appendChild(svg('text', { class: 'fk-mark', x: 518, y: 74 }, 'FORK'));
  s.appendChild(svg('text', { class: 'fk-mark', x: 518, y: 88 }, 'DETECTED'));
  s.appendChild(svg('text', { class: 'fk-s', x: 30, y: 160 }, `collision ${f.collision} — one key, one position, two entries`));

  wrap.appendChild(s);

  const proof = el('div', 'fk-proof');
  const row = (k, value, full) => {
    const d = el('div', 'fk-row');
    d.appendChild(el('span', null, k));
    const c = el('code', null, value);
    if (full) c.title = full;
    d.appendChild(c);
    proof.appendChild(d);
  };
  row('ForkProof', shortId(f.proof_id) + '…', f.proof_id);
  row('collision', f.collision);
  row('convicted key', shortKey(f.convicted_key), f.convicted_key);
  row('quarantine', f.newly_quarantined ? 'key quarantined by this proof' : 'key was already quarantined');
  row(`entry at seq ${seq}`, `${shortId(f.entry_a)}… → ${verdictOf(run.forkVerdicts.a).label}`, f.entry_a);
  row('withheld sibling', `${shortId(f.entry_b)}… → ${verdictOf(run.forkVerdicts.b).label}`, f.entry_b);
  wrap.appendChild(proof);

  wrap.appendChild(
    el(
      'p',
      'fk-note',
      'The proof is self-verifying: it carries both signed entries, so anyone holding it can check ' +
        'the conviction without trusting the node that raised it. The record the meeting had already ' +
        'sealed keeps its upper bound — quarantine disputes what was never witnessed, and does not ' +
        'retract what was.',
    ),
  );

  host.replaceChildren(wrap);
}

// ---------------------------------------------------------------------------
// Driving the ledger
// ---------------------------------------------------------------------------

async function runLedger() {
  let mod;
  try {
    // Dynamic, not a top-level import: web/pkg/ is generated, and a missing
    // module must degrade to an honest empty state instead of killing the
    // ticker, the counters and the accordion along with it.
    mod = await import('./pkg/vigil_wasm.js');
    await mod.default();
  } catch (e) {
    renderUnavailable(e);
    return;
  }

  try {
    const demo = new mod.Demo();

    // --- the six mutating calls, in order --------------------------------
    const a0 = demo.append('a', SCENARIO.a0);
    const b0 = demo.append('b', SCENARIO.b0);
    const ex = demo.exchangeAttestation();
    const a1 = demo.append('a', SCENARIO.a1);
    const a2 = demo.append('a', SCENARIO.a2);

    // Everything from here is a query. Snapshot the honest state first: the
    // chain and DAG figures show the fleet before anyone equivocates, which is
    // the state those two figures are about.
    const stPre = demo.state();
    const preBrackets = stPre.a.chain.map((e) => demo.bracket('a', e.id));
    const preBracketsB = stPre.b.chain.map((e) => demo.bracket('b', e.id));

    // Then the same key signs a second entry at a seq it has already committed.
    const eq = demo.equivocate('a', SCENARIO.eq);
    const st = demo.state();

    const disputed = demo.bracket('a', eq.sibling.id);
    const sealedAfter = demo.bracket('a', a0.id);
    const sealedBefore = preBrackets[0];
    const forkVerdicts = eq.fork
      ? { a: demo.bracket('a', eq.fork.entry_a), b: demo.bracket('a', eq.fork.entry_b) }
      : { a: disputed, b: disputed };

    const unchanged =
      sealedBefore.sealed === sealedAfter.sealed &&
      (sealedBefore.upper_bound ?? null) === (sealedAfter.upper_bound ?? null) &&
      sealedBefore.witness_depth === sealedAfter.witness_depth;

    const run = {
      a0,
      b0,
      a1,
      a2,
      ex,
      eq,
      st,
      stPre,
      preBrackets,
      preBracketsB,
      forkVerdicts,
      selected: 0,
      log: [
        ['append a', `seq ${a0.seq} · id ${shortId(a0.id)} · prev ∅ genesis`],
        ['append b', `seq ${b0.seq} · id ${shortId(b0.id)} · prev ∅ genesis`],
        [
          'exchangeAttestation',
          `B attests A@${ex.b_witnesses_a.subject_seq} → U ${shortId(ex.b_witnesses_a.id)}`,
        ],
        ['append a', `seq ${a1.seq} · id ${shortId(a1.id)} · prev ${shortId(a1.prev)}`],
        ['append a', `seq ${a2.seq} · id ${shortId(a2.id)} · prev ${shortId(a2.prev)}`],
        [
          'equivocate a',
          eq.fork_detected
            ? `sibling seq ${eq.sibling.seq} · ForkProof ${shortId(eq.fork.proof_id)} convicts ${shortKey(eq.fork.convicted_key)}`
            : `sibling seq ${eq.sibling.seq} · no fork proof`,
        ],
      ],
      recheck: {
        ok: unchanged,
        text: unchanged
          ? 're-bracketed O0 after its author was convicted → sealed, upper bound and witness depth unchanged (spec/02 §6.5)'
          : `re-bracketed O0 after its author was convicted → CHANGED: sealed ${sealedBefore.sealed}→${sealedAfter.sealed}, ` +
            `upper ${shortId(sealedBefore.upper_bound)}→${shortId(sealedAfter.upper_bound)}, ` +
            `depth ${sealedBefore.witness_depth}→${sealedAfter.witness_depth}`,
      },
      claims: [
        {
          label: `O${a0.seq} · node A · seq ${a0.seq}`,
          short: `O${a0.seq} · sealed by the meeting`,
          br: sealedAfter,
          when: 'bracketed from node A’s own store after the fork was detected and its author quarantined.',
        },
        {
          label: `O${a1.seq} · node A · seq ${a1.seq}`,
          short: `O${a1.seq} · written after the meeting`,
          br: preBrackets[1],
          when: 'bracketed before the equivocation — the record was appended after the meeting, so no attestation reaches it.',
        },
        {
          label: `O${eq.sibling.seq}′ · node A · seq ${eq.sibling.seq} · withheld sibling`,
          short: `O${eq.sibling.seq}′ · the withheld sibling`,
          br: disputed,
          when: 'the second entry at a seq the chain had already committed. No witness ever saw it.',
        },
      ],
    };

    setStatus('live', 'live · computed in-browser');
    renderCard(run);
    fillPipeline(run);
    renderChainFigure(run);
    renderAttestFigure(run);
    renderDagFigure(run);
    renderBracketFigure(run);
    renderForkFigure(run);
  } catch (e) {
    setStatus('error', 'ledger call failed');
    const body = $('lc-body');
    if (body) body.replaceChildren(el('p', 'lc-err', String(e && e.message ? e.message : e)));
    markLiveSurfacesUnavailable();
  }
}

// ---------------------------------------------------------------------------
// The architecture diagram
// ---------------------------------------------------------------------------

/** Which edges and which neighbouring nodes belong to each node's path. This is
 *  a presentation map for a static picture — the diagram computes nothing — so
 *  it lives here rather than being derived from anything. */
const ARCH_PATH = {
  a:       { edges: ['ed-a', 'ed-meet'], nodes: ['a', 'meeting', 'ledger'] },
  b:       { edges: ['ed-b', 'ed-meet'], nodes: ['b', 'meeting', 'ledger'] },
  c:       { edges: ['ed-c'], nodes: ['c', 'ledger'] },
  meeting: { edges: ['ed-meet'], nodes: ['meeting', 'a', 'b'] },
  ledger:  { edges: ['ed-a', 'ed-b', 'ed-c', 'ed-ledger'], nodes: ['ledger', 'a', 'b', 'c', 'dag'] },
  dag:     { edges: ['ed-ledger', 'ed-dag'], nodes: ['dag', 'ledger', 'bracket'] },
  bracket: { edges: ['ed-dag', 'ed-pack'], nodes: ['bracket', 'dag', 'verify'] },
  verify:  { edges: ['ed-pack'], nodes: ['verify', 'bracket'] },
};

/** The meeting is the default: it is the one event in the picture that creates
 *  time evidence, so it is what the diagram should be pointing at when a reader
 *  first arrives — lit, but without dimming the rest of the diagram, which at
 *  rest should still read as a whole system rather than as one lit box among
 *  seven faded ones. Dimming starts on the first hover and ends with it. */
const ARCH_DEFAULT = 'meeting';

function architecture() {
  const s = $('archsvg');
  const info = $('arch-info');
  if (!s || !info) return;

  const nodes = Array.from(s.querySelectorAll('.anode[data-node]'));
  const edges = Array.from(s.querySelectorAll('.ed'));
  const panels = Array.from(info.querySelectorAll('.ai[data-for]'));
  if (!nodes.length || !panels.length) return;

  // Only now do the panels collapse to one at a time. Without this file they
  // all remain visible, which is the same content in an accessible form.
  info.classList.add('is-live');

  const show = (name, dim = true) => {
    const path = ARCH_PATH[name];
    if (!path) return;
    if (dim) s.dataset.hot = name;
    else delete s.dataset.hot;
    for (const n of nodes) n.classList.toggle('is-hot', path.nodes.includes(n.dataset.node));
    for (const e of edges) {
      e.classList.toggle('is-hot', path.edges.some((c) => e.classList.contains(c)));
    }
    for (const p of panels) p.classList.toggle('is-shown', p.dataset.for === name);
  };

  for (const n of nodes) {
    const name = n.dataset.node;
    n.addEventListener('mouseenter', () => show(name));
    n.addEventListener('focus', () => show(name));
    n.addEventListener('click', () => show(name));
    n.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' || ev.key === ' ') {
        ev.preventDefault();
        show(name);
      }
    });
  }
  s.addEventListener('mouseleave', () => show(ARCH_DEFAULT, false));

  show(ARCH_DEFAULT, false);
}

// ---------------------------------------------------------------------------
// Copy buttons
// ---------------------------------------------------------------------------

/** Copies the text of the element a button names in `data-copy`. The button is
 *  added in the markup and does nothing without this file, which is correct:
 *  the text it copies is on the page and selectable either way. */
function copyButtons() {
  const write = async (text) => {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return;
    }
    // http://localhost is a secure context, but a plain http:// host is not,
    // and this page is meant to be servable from anywhere.
    const ta = el('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  };

  for (const btn of document.querySelectorAll('.cb-copy[data-copy]')) {
    const target = $(btn.dataset.copy);
    if (!target) continue;
    const label = btn.querySelector('.cb-copy-t');
    btn.addEventListener('click', async () => {
      try {
        await write(target.textContent);
        btn.classList.add('is-done');
        if (label) label.textContent = 'copied';
      } catch {
        if (label) label.textContent = 'select it';
      }
      setTimeout(() => {
        btn.classList.remove('is-done');
        if (label) label.textContent = 'copy';
      }, 1600);
    });
  }
}

// ---------------------------------------------------------------------------
// Stat count-up
// ---------------------------------------------------------------------------

/** The numbers are already in the DOM and correct at rest; this only animates
 *  the reveal, and only when the section is scrolled to and the visitor has not
 *  asked for reduced motion. */
function countUp() {
  const stats = document.querySelectorAll('.stat [data-count]');
  if (!stats.length) return;
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  if (!('IntersectionObserver' in window)) return;

  const animate = (node) => {
    const target = Number(node.dataset.count);
    if (!Number.isFinite(target) || target === 0) return;
    const started = performance.now();
    const ms = 900;
    const step = (now) => {
      const t = Math.min(1, (now - started) / ms);
      // easeOutCubic: fast, then settles on the real value.
      const eased = 1 - Math.pow(1 - t, 3);
      node.textContent = String(Math.round(target * eased));
      if (t < 1) requestAnimationFrame(step);
      else node.textContent = String(target);
    };
    requestAnimationFrame(step);
  };

  const io = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        io.unobserve(entry.target);
        animate(entry.target);
      }
    },
    { threshold: 0.6 },
  );
  stats.forEach((s) => io.observe(s));
}

// ---------------------------------------------------------------------------
// Ticker
// ---------------------------------------------------------------------------

/** A seamless marquee needs the badges twice, so the track can translate by half
 *  its width and land where it started. The duplicates are decorative repeats of
 *  content a screen reader has already been given, so they are hidden from it.
 *
 *  Without this — no JS, or reduced motion — the track keeps its default
 *  `flex-wrap: wrap` and the badges simply sit still and legible. The animation
 *  is the enhancement; the strip is not. */
function ticker() {
  const track = document.querySelector('.ticker-track');
  if (!track) return;
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  const clone = document.createElement('div');
  clone.style.display = 'contents';
  clone.setAttribute('aria-hidden', 'true');
  for (const item of Array.from(track.children)) clone.appendChild(item.cloneNode(true));
  track.appendChild(clone);
  track.classList.add('is-animated');
}

// ---------------------------------------------------------------------------
// Where am I — the header's active section
// ---------------------------------------------------------------------------

/** The nav marks the section the reading position is currently inside. Driven
 *  off the scroll offset rather than an IntersectionObserver: sections here run
 *  from a screenful to several screenfuls, so "which one is visible" has no
 *  single answer, while "which one has the reading line passed into" has
 *  exactly one and never flickers between two.
 *
 *  Above the first section nothing is marked, which is correct — the hero is
 *  not in the nav. */
function scrollSpy() {
  const nav = document.querySelector('.sitenav');
  const links = Array.from(document.querySelectorAll('.navlinks a[href^="#"]'));
  const marks = links
    .map((a) => ({ a, el: document.getElementById(a.getAttribute('href').slice(1)) }))
    .filter((m) => m.el);
  if (!marks.length) return;

  let queued = false;

  const update = () => {
    queued = false;
    // The reading line: just below the bar, a little into the viewport.
    const line = window.scrollY + (nav ? nav.offsetHeight : 52) + 120;
    let active = null;
    for (const m of marks) {
      const top = m.el.getBoundingClientRect().top + window.scrollY;
      if (top <= line) active = m;
    }
    for (const m of marks) m.a.classList.toggle('is-active', m === active);
  };

  const onScroll = () => {
    if (queued) return;
    queued = true;
    requestAnimationFrame(update);
  };

  window.addEventListener('scroll', onScroll, { passive: true });
  window.addEventListener('resize', onScroll);
  update();
}

// ---------------------------------------------------------------------------
// Section reveal
// ---------------------------------------------------------------------------

/** Each section fades and lifts once, the first time it enters the viewport,
 *  and is then left alone — it does not replay on the way back up, which is
 *  what makes a long page feel restless rather than considered.
 *
 *  The classes are added here and not in index.html on purpose. If this file
 *  never runs, or the visitor has asked for reduced motion, no element is ever
 *  given `opacity: 0` and the page is simply the page. */
function reveal() {
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  if (!('IntersectionObserver' in window)) return;

  const blocks = document.querySelectorAll('main > section:not(.hero) > .measure');
  if (!blocks.length) return;

  // Rows inside a revealed block slide in behind it, a few tens of ms apart, so
  // a grid arrives as a grid rather than as one rectangle.
  const ROWS = [
    '.stat-grid > .stat',
    '.prob-grid > .prob',
    '.pipe > .pl',
    '.steps > li',
    '.caps > .cap',
    '.grid-6 > .card',
    '.split > .col',
    '.checklist > li',
    '.closing-cmds > .cmdrow',
    '.faq',
  ].join(', ');

  const io = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        io.unobserve(entry.target);
        entry.target.classList.add('is-in');
      }
    },
    { rootMargin: '0px 0px -12% 0px', threshold: 0.06 },
  );

  for (const block of blocks) {
    block.classList.add('reveal');
    block.querySelectorAll(ROWS).forEach((row, i) => {
      row.classList.add('r-item');
      // Capped so a ten-row checklist does not end on a half-second delay.
      row.style.setProperty('--i', String(Math.min(i, 7)));
    });
    io.observe(block);
  }
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

ticker();
countUp();
scrollSpy();
reveal();
architecture();
copyButtons();
runLedger();
