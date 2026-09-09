// Vigilarch demo frontend.
//
// This file is a renderer and nothing else. Every verdict it displays — sealed or
// unwitnessed, the bounds, the witness depth, the fork conviction — comes back from
// `vigil-ledger` compiled to wasm32 through the `Demo` class in `crates/vigil-wasm`.
// There is no chain walk, no DAG, no bracketing rule here, and there must never be
// one: a second implementation in JavaScript is exactly the divergence invariant I2
// exists to prevent.
//
// The wasm module is a bundler-free ES module produced by `wasm-bindgen --target web`
// (see ./build.sh). No npm, no framework, no build step for this file.

import init, { Demo } from './pkg/vigil_wasm.js';

// ---------------------------------------------------------------------------
// DOM helpers
// ---------------------------------------------------------------------------

const $ = (id) => document.getElementById(id);

/** An element with an optional class and text. Text is always set as text, never
 *  parsed as markup — observation bodies are free-form input. */
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
}

/** Content addresses are 64 hex characters; 12 is enough to read and to match the
 *  short ids `vigil-sim`'s run reports print. */
const shortId = (hex) => (hex ? hex.slice(0, 12) : '—');
const shortKey = (hex) => (hex ? hex.slice(0, 8) + '…' : '—');

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

let demo = null;
/** `{ node, id }` of the observation whose bracket is in the detail panel. */
let selected = null;

/** Sample bodies, so the buttons are usable without typing. Deliberately the kind
 *  of line the ledger exists for. */
const SAMPLES = [
  'grid B4 shoring is out of plumb',
  'tag-out re-checked, crew clear',
  'night shift headcount logged',
  'gas monitor alarmed at portal, crew withdrawn',
  'temporary works permit expired, work stopped',
  'spoil conveyor guard found removed',
];
const EQUIVOCATION_SAMPLE = 'tag-out never applied, crew still on it';
let sampleAt = 0;

function nextText(fallback) {
  const typed = $('note-text').value.trim();
  if (typed) {
    $('note-text').value = '';
    return typed;
  }
  if (fallback) return fallback;
  const s = SAMPLES[sampleAt % SAMPLES.length];
  sampleAt += 1;
  return s;
}

// ---------------------------------------------------------------------------
// Transcript
// ---------------------------------------------------------------------------

/** Append one line. `parts` is a list of `[className, text]`; className '' is plain. */
function log(parts) {
  const line = document.createElement('span');
  for (const [cls, text] of parts) {
    if (cls) line.appendChild(el('span', cls, text));
    else line.appendChild(document.createTextNode(text));
  }
  line.appendChild(document.createTextNode('\n'));
  const box = $('log');
  box.appendChild(line);
  box.scrollTop = box.scrollHeight;
}

const logCmd = (text) => log([['cmd', '$ ' + text]]);
const logOut = (text) => log([['', '  ' + text]]);
const logOk = (text) => log([['', '  '], ['ok', text]]);
const logWarn = (text) => log([['', '  '], ['warn', text]]);
const logErr = (text) => log([['err', '! ' + text]]);

// ---------------------------------------------------------------------------
// Actions — each one calls into wasm, then re-renders from state()
// ---------------------------------------------------------------------------

/** Run a wasm call, reporting any thrown `DemoError` into the transcript rather
 *  than the console. The ledger's refusals are results, not crashes. */
function guard(fn) {
  let after = null;
  try {
    after = fn() || null;
  } catch (e) {
    logErr(e && e.message ? e.message : String(e));
  }
  render();
  if (after) after();
}

// ---------------------------------------------------------------------------
// Flashes -- presentation only
// ---------------------------------------------------------------------------

/** Plays a one-shot animation on an element by adding a class and dropping it
 *  when the animation ends.
 *
 *  Nothing here decides anything. Every element it touches was already put into
 *  its state by `render()` from a verdict the ledger returned; this only draws
 *  the eye to the change. The three kinds map to the palette's three meanings --
 *  the accent for a system event, sealed for a sealing, disputed for a
 *  violation -- so a flash can never say something the colour does not. */
function flash(node, kind) {
  if (!node) return;
  const cls = 'fx-' + kind;
  node.classList.remove(cls);
  // Reading offsetWidth restarts the animation when the same row is flashed
  // twice in quick succession.
  void node.offsetWidth;
  node.classList.add(cls);
  node.addEventListener('animationend', () => node.classList.remove(cls), { once: true });
}

const flashAll = (selector, kind) =>
  document.querySelectorAll(selector).forEach((n) => flash(n, kind));

function doAppend(node) {
  guard(() => {
    const text = nextText();
    const r = demo.append(node, text);
    logCmd(`append ${node} ${JSON.stringify(text)}`);
    logOut(`seq=${r.seq} id=${shortId(r.id)} prev=${r.prev ? shortId(r.prev) : '∅ (genesis)'}`);
    selected = { node, id: r.id };
    return () => flash(document.querySelector(`#chain-${node} li[aria-selected="true"]`), 'append');
  });
}

function doExchange() {
  guard(() => {
    const r = demo.exchangeAttestation();
    logCmd('exchange-attestation');
    const ab = r.a_witnesses_b;
    const ba = r.b_witnesses_a;
    logOut(`A attests B@${ab.subject_seq} head=${shortId(ab.subject_head)} -> ${shortId(ab.id)}`);
    logOut(`B attests A@${ba.subject_seq} head=${shortId(ba.subject_head)} -> ${shortId(ba.id)}`);
    logOk('each node now holds an attestation over the other\'s chain (spec/02 §3)');
    return () => {
      flash($('att-table'), 'append');
      // Whatever the ledger has just decided is sealed, and only that.
      flashAll('.chain li.st-sealed', 'sealed');
    };
  });
}

function doEquivocate() {
  guard(() => {
    const node = $('equiv-node').value;
    const text = nextText(EQUIVOCATION_SAMPLE);
    const r = demo.equivocate(node, text);
    logCmd(`equivocate ${node} ${JSON.stringify(text)}`);
    logOut(`sibling seq=${r.sibling.seq} id=${shortId(r.sibling.id)} — same seq, same prev, different body`);
    if (r.fork_detected && r.fork) {
      logWarn(
        `ForkProof ${shortId(r.fork.proof_id)} collision=${r.fork.collision} ` +
          `key=${shortKey(r.fork.convicted_key)}`,
      );
      logWarn(
        r.fork.newly_quarantined
          ? `key ${shortKey(r.fork.convicted_key)} quarantined (spec/02 §6.4)`
          : 'key was already quarantined',
      );
    } else {
      logOut('no fork proof — the entries do not collide');
    }
    // The withheld sibling is the interesting one: no witness ever saw it.
    selected = { node, id: r.sibling.id };
    return () => {
      flashAll('.quarantine-banner:not([hidden])', 'fork');
      flashAll('.chain li.st-disputed, .row-head .badge.fork', 'fork');
    };
  });
}

function doReset() {
  demo = new Demo();
  selected = null;
  sampleAt = 0;
  $('log').replaceChildren();
  logCmd('reset');
  logOut('two empty chains, empty quarantine, keys re-derived from the fixed demo seed');
  render();
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

function render() {
  const state = demo.state();
  const quarantined = new Set(state.quarantine);

  renderNode('a', state.a, quarantined);
  renderNode('b', state.b, quarantined);
  renderAttestations(state, quarantined);
  renderDetail(state);

  $('btn-exchange').disabled = state.a.chain.length === 0 || state.b.chain.length === 0;
  const equivNode = $('equiv-node').value;
  $('btn-equivocate').disabled = state[equivNode].chain.length === 0;
}

function renderNode(side, node, quarantined) {
  $('pubkey-' + side).textContent = shortKey(node.pubkey);
  $('quarantine-' + side).hidden = !quarantined.has(node.pubkey);
  $('empty-' + side).hidden = node.chain.length > 0;

  // A seq holding more than one entry is a fork in that key's own chain
  // (spec/02 §6.1) — both siblings are retained and both are marked.
  const perSeq = new Map();
  for (const e of node.chain) perSeq.set(e.seq, (perSeq.get(e.seq) ?? 0) + 1);

  const list = $('chain-' + side);
  list.replaceChildren();
  for (const entry of node.chain) {
    list.appendChild(chainRow(side, entry, perSeq.get(entry.seq) > 1));
  }
}

function chainRow(side, entry, isForkSibling) {
  // The row's state comes from the ledger, not from anything this file infers.
  let br = null;
  try {
    br = demo.bracket(side, entry.id);
  } catch {
    // Cannot happen for an id state() just handed us; a missing badge is the
    // honest fallback if it ever did.
  }

  const li = el('li');
  li.tabIndex = 0;
  li.setAttribute('role', 'button');
  if (br) li.classList.add(br.disputed ? 'st-disputed' : br.sealed ? 'st-sealed' : 'st-unwitnessed');
  if (selected && selected.node === side && selected.id === entry.id) {
    li.setAttribute('aria-selected', 'true');
  }

  const head = el('div', 'row-head');
  head.appendChild(el('span', 'seq', `seq ${entry.seq}`));
  head.appendChild(el('span', 'id', shortId(entry.id)));
  if (isForkSibling) head.appendChild(el('span', 'badge fork', '⑂ fork'));
  if (br) {
    head.appendChild(
      br.disputed
        ? el('span', 'badge disputed', 'disputed')
        : br.sealed
          ? el('span', 'badge sealed', `sealed ×${br.witness_depth}`)
          : el('span', 'badge unwitnessed', 'unwitnessed'),
    );
  }
  li.appendChild(head);
  li.appendChild(el('div', 'row-text', entry.text));
  li.appendChild(el('div', 'row-prev', `prev ${entry.prev ? shortId(entry.prev) : '∅ genesis'}`));

  const select = () => {
    selected = { node: side, id: entry.id };
    render();
  };
  li.addEventListener('click', select);
  li.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter' || ev.key === ' ') {
      ev.preventDefault();
      select();
    }
  });
  return li;
}

function renderAttestations(state, quarantined) {
  const label = (pubkeyHex) =>
    pubkeyHex === state.a.pubkey ? 'A' : pubkeyHex === state.b.pubkey ? 'B' : shortKey(pubkeyHex);

  const body = $('att-body');
  body.replaceChildren();
  for (const a of state.attestations) {
    const tr = el('tr');
    tr.appendChild(el('td', null, shortId(a.id)));
    const w = el('td', 'who', label(a.witness));
    if (quarantined.has(a.witness)) {
      w.classList.add('quarantined');
      w.title = 'witness quarantined — its attestations no longer seal (spec/02 §6.5)';
      w.textContent += ' ⚑';
    }
    tr.appendChild(w);
    tr.appendChild(el('td', 'who', label(a.subject)));
    tr.appendChild(el('td', null, a.subject_seq));
    tr.appendChild(el('td', null, shortId(a.subject_head)));
    body.appendChild(tr);
  }
  $('att-count').textContent = state.attestations.length
    ? `(${state.attestations.length})`
    : '';
  $('att-empty').hidden = state.attestations.length > 0;
  $('att-table').hidden = state.attestations.length === 0;
}

// --- the detail panel: one observation's bracket ---------------------------

function renderDetail(state) {
  const panel = $('detail-body');

  if (!selected) {
    panel.replaceChildren(el('p', 'empty', 'Click an observation in either chain to bracket it.'));
    return;
  }

  let br;
  try {
    br = demo.bracket(selected.node, selected.id);
  } catch (e) {
    selected = null;
    panel.replaceChildren(el('p', 'empty', e && e.message ? e.message : String(e)));
    return;
  }

  const nodeState = state[selected.node];
  const entry = nodeState.chain.find((c) => c.id === selected.id);
  const kind = br.disputed ? 'disputed' : br.sealed ? 'sealed' : 'unwitnessed';

  const out = document.createDocumentFragment();

  const verdict = el('div', 'verdict ' + kind);
  verdict.appendChild(el('span', 'glyph', br.disputed ? '✕' : br.sealed ? '●' : '○'));
  verdict.appendChild(
    el('span', null, br.sealed ? 'SEALED' : br.disputed ? 'UNWITNESSED · DISPUTED' : 'UNWITNESSED'),
  );
  out.appendChild(verdict);

  const kv = el('dl', 'kv');
  const pair = (k, v, none) => {
    kv.appendChild(el('dt', null, k));
    kv.appendChild(el('dd', none ? 'none' : null, v));
  };
  pair('node', selected.node.toUpperCase() + (entry ? ` · seq ${entry.seq}` : ''));
  pair('observation', br.observation);
  if (entry) pair('body', entry.text);
  pair(
    'upper bound U',
    br.upper_bound ? shortId(br.upper_bound) : 'none — nothing has sealed this record',
    !br.upper_bound,
  );
  pair(
    'lower bound L',
    br.lower_bound ? shortId(br.lower_bound) : 'none — open to this key\'s genesis',
    !br.lower_bound,
  );
  pair(
    'witness depth',
    br.witness_depth + (br.witness_depth === 1 ? ' distinct witness key' : ' distinct witness keys'),
    br.witness_depth === 0,
  );
  out.appendChild(kv);

  out.appendChild(windowBlock(br));
  out.appendChild(el('p', 'detail-note', explain(br)));

  panel.replaceChildren(out);
}

/** The unwitnessed window, drawn so an open edge cannot be mistaken for a bounded
 *  one: bounded edges are solid caps, open edges are dashed and the fill fades out
 *  towards them. `spec/02` §5.1. */
function windowBlock(br) {
  const lower = edgeInfo(br.window.lower, 'lower');
  const upper = edgeInfo(br.window.upper, 'upper');

  const block = el('section', 'window');
  block.appendChild(el('h3', null, 'unwitnessed window — the span the system cannot vouch for'));

  const bar = el('div', 'window-bar');
  if (lower.open) bar.classList.add('open-left');
  if (upper.open) bar.classList.add('open-right');
  bar.appendChild(el('div', `cap left ${lower.open ? 'open' : 'bounded'}`));
  bar.appendChild(el('div', 'track'));
  bar.appendChild(el('div', `cap right ${upper.open ? 'open' : 'bounded'}`));
  bar.setAttribute('role', 'img');
  bar.setAttribute('aria-label', `window ${lower.label}: ${lower.what} to ${upper.label}: ${upper.what}`);
  block.appendChild(bar);

  const edges = el('div', 'edges');
  for (const [side, info] of [['left', lower], ['right', upper]]) {
    const d = el('div', `edge ${side} ${info.open ? 'open' : 'bounded'}`);
    d.appendChild(el('span', 'kind', info.label));
    d.appendChild(el('span', 'what', info.what));
    edges.appendChild(d);
  }
  block.appendChild(edges);
  return block;
}

/** Maps a `WindowEdge` (spec/02 §5.1, serialised by vigil-wasm) to its label. The
 *  three kinds are the spec's own; this file invents no fourth. */
function edgeInfo(edge, which) {
  switch (edge.kind) {
    case 'genesis':
      return {
        open: true,
        label: '◀ open — genesis',
        what: 'nothing proves the record did not exist earlier',
      };
    case 'verification_moment':
      return {
        open: true,
        label: 'open — now ▶',
        what: 'no witness has ever sealed this record',
      };
    case 'attestation':
      return {
        open: false,
        label: which === 'lower' ? '├ bounded — L' : 'bounded — U ┤',
        what: shortId(edge.id),
      };
    default:
      return { open: true, label: 'unknown edge', what: String(edge.kind) };
  }
}

function explain(br) {
  if (br.disputed) {
    return (
      'The author of this record is quarantined by a fork proof and no witness ever sealed it, ' +
      'so it is disputed — retained, never deleted, because it may still be true and the dispute ' +
      'is itself evidence (spec/02 §6.4). An attacker\'s withheld branch lands exactly here.'
    );
  }
  if (br.sealed) {
    return (
      'A witness signed a statement about this key\'s chain head at or past this record\'s seq, so ' +
      'the record existed no later than that meeting. That is an upper bound only: the window stays ' +
      'open below because nothing proves the record did not exist earlier (spec/02 §5.2, §8).'
    );
  }
  return (
    'No attestation covers this record, so the system will not claim when it was written. The window ' +
    'runs to the moment of verification. This is the honest answer for an isolated node, not a ' +
    'detection and not an alarm (spec/02 §8) — exchange attestations to close it from above.'
  );
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

async function main() {
  try {
    await init();
  } catch (e) {
    document.body.prepend(
      el(
        'p',
        'empty',
        'Could not load the WebAssembly module. Build it with ./build.sh and serve this ' +
          'directory over HTTP (file:// will not work). ' +
          (e && e.message ? e.message : String(e)),
      ),
    );
    return;
  }

  demo = new Demo();

  $('btn-append-a').addEventListener('click', () => doAppend('a'));
  $('btn-append-b').addEventListener('click', () => doAppend('b'));
  $('btn-exchange').addEventListener('click', doExchange);
  $('btn-equivocate').addEventListener('click', doEquivocate);
  $('btn-reset').addEventListener('click', doReset);
  $('equiv-node').addEventListener('change', render);
  $('note-text').addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') doAppend('a');
  });

  logOut('vigil-ledger loaded under wasm32 — two nodes, empty chains, empty quarantine');
  logOut('keys are derived from a fixed seed, so ids here reproduce across machines');
  render();
}

main();
