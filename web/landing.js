// Vigilarch landing page.
//
// Three jobs, and none of them is computing anything about a ledger:
//
//   1. Drive a short, fixed scenario through `vigil-ledger` compiled to
//      wasm32-unknown-unknown, and print what comes back.
//   2. Some reveal animation on numbers that are already in the DOM.
//   3. Presentation: which section the header should point at, and a fade for
//      each section as it comes into view. Both are attached from here rather
//      than written into the markup, so the page without JavaScript is the
//      whole page, plainly visible, rather than a screen of nothing.
//
// The header bar's own behaviour — the narrow-screen menu, the stuck state —
// lives in nav.js, because demo.html carries the same bar.
//
// Every verdict, bound, witness depth, content address and fork proof on this
// page is a value returned by the wasm module. There is no chain walk, no DAG,
// no bracketing rule here, and there must never be one — a second implementation
// in JavaScript is exactly the divergence invariant I2 exists to prevent. The
// same rule governs app.js on the demo page.
//
// If you want to check that the card is live rather than a JSON literal that
// merely looks live: change a string in SCENARIO below and reload. Every content
// address on the card changes, because they are BLAKE3 addresses of the objects
// the ledger actually built.

// ---------------------------------------------------------------------------
// The canned run
// ---------------------------------------------------------------------------

/** The five calls the hero card makes, in order. This mirrors the shape of
 *  `vigil-sim`'s `minimal` and `equivocation` scenarios — an honest partition
 *  that gets sealed by one meeting, then an equivocation that gets convicted —
 *  which is the same ground `crates/vigil-wasm`'s native tests cover. It invents
 *  no new scenario. */
const SCENARIO = {
  a0: 'shoring on grid B4 is out of plumb',
  b0: 'night shift headcount logged',
  a1: 'gas monitor alarmed at portal, crew withdrawn',
  eq: 'tag-out never applied, crew still on it',
};

// ---------------------------------------------------------------------------
// Small DOM helpers
// ---------------------------------------------------------------------------

const $ = (id) => document.getElementById(id);

/** An element with an optional class and text. Text is always set as text and
 *  never parsed as markup. */
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
}

/** Content addresses are 64 hex characters; 12 is enough to read and to match
 *  the short ids `vigil-sim`'s run reports print. */
const shortId = (hex) => (hex ? hex.slice(0, 12) : '—');
const shortKey = (hex) => (hex ? hex.slice(0, 8) + '…' : '—');

// ---------------------------------------------------------------------------
// Rendering the ledger's answers
// ---------------------------------------------------------------------------

/** The three verdicts the ledger returns, decided exactly the way app.js decides
 *  them on the demo page: from the flags on the bracket, never from which call
 *  produced it. If the scenario above is edited and a claim comes back with a
 *  different verdict, this card shows the different verdict. */
function verdictOf(br) {
  if (br.disputed) return { key: 'disputed', label: 'UNWITNESSED · DISPUTED', glyph: '✕' };
  if (br.sealed) return { key: 'sealed', label: 'SEALED', glyph: '●' };
  return { key: 'unwitnessed', label: 'UNWITNESSED', glyph: '○' };
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
 *  bounded one: bounded edges are solid caps, open edges are dashed and the fill
 *  fades out towards them. Same treatment as the demo page. */
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
      "The author is quarantined by a fork proof and no witness ever sealed this entry, so it is " +
      'disputed — retained, never deleted, because the dispute is itself evidence. An attacker’s ' +
      'withheld branch lands exactly here (spec/02 §6.4).'
    );
  }
  if (br.sealed) {
    return (
      "A witness signed a statement about this key’s chain head at or past this record’s seq, so the " +
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
// The card
// ---------------------------------------------------------------------------

function setStatus(state, text) {
  const wrap = $('lc-status');
  wrap.dataset.state = state;
  $('lc-status-text').textContent = text;
}

/** Rendered when the wasm module is not there. `web/pkg/` is generated and not
 *  tracked in git, so this is the state a fresh clone gets — and inventing
 *  plausible numbers to fill the card would be exactly the kind of claim this
 *  project exists to refuse. */
function renderUnavailable(err) {
  setStatus('error', 'module not built');
  const body = $('lc-body');
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

function renderCard(run) {
  const body = $('lc-body');
  body.replaceChildren();

  // --- the call log: five calls, and what each one returned ----------------
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

    // Five calls. Everything after this point is a returned value.
    const a0 = demo.append('a', SCENARIO.a0);
    const b0 = demo.append('b', SCENARIO.b0);
    const ex = demo.exchangeAttestation();
    const a1 = demo.append('a', SCENARIO.a1);

    // Bracket the two honest records while the author is still unconvicted.
    const sealedBefore = demo.bracket('a', a0.id);
    const unwitnessed = demo.bracket('a', a1.id);

    // Then the same key signs a second entry at a seq it has already committed.
    const eq = demo.equivocate('a', SCENARIO.eq);
    const disputed = demo.bracket('a', eq.sibling.id);
    const sealedAfter = demo.bracket('a', a0.id);

    const unchanged =
      sealedBefore.sealed === sealedAfter.sealed &&
      (sealedBefore.upper_bound ?? null) === (sealedAfter.upper_bound ?? null) &&
      sealedBefore.witness_depth === sealedAfter.witness_depth;

    const run = {
      selected: 0,
      log: [
        ['append a', `seq ${a0.seq} · id ${shortId(a0.id)} · prev ∅ genesis`],
        ['append b', `seq ${b0.seq} · id ${shortId(b0.id)} · prev ∅ genesis`],
        [
          'exchangeAttestation',
          `B attests A@${ex.b_witnesses_a.subject_seq} → U ${shortId(ex.b_witnesses_a.id)}`,
        ],
        ['append a', `seq ${a1.seq} · id ${shortId(a1.id)} · prev ${shortId(a1.prev)}`],
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
          label: 'O0 · node A · seq 0',
          br: sealedAfter,
          when: 'bracketed from node A’s own store after the fork was detected and its author quarantined.',
        },
        {
          label: 'O1 · node A · seq 1',
          br: unwitnessed,
          when: 'bracketed at call 4, before the equivocation — the record was appended after the meeting, so no attestation reaches it.',
        },
        {
          label: 'O1′ · node A · seq 1 · withheld sibling',
          br: disputed,
          when: 'the second entry at a seq the chain had already committed. No witness ever saw it.',
        },
      ],
    };

    setStatus('live', 'live · computed in-browser');
    renderCard(run);
  } catch (e) {
    setStatus('error', 'ledger call failed');
    const body = $('lc-body');
    body.replaceChildren(el('p', 'lc-err', String(e && e.message ? e.message : e)));
  }
}

// ---------------------------------------------------------------------------
// Stat count-up
// ---------------------------------------------------------------------------

/** The numbers are already in the DOM and correct at rest; this only animates
 *  the reveal, and only when the section is scrolled to and the visitor has not
 *  asked for reduced motion. */
function countUp() {
  const stats = document.querySelectorAll('.stat .num[data-count]');
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
  const ROWS = '.stat-grid > .stat, .steps > li, .grid-6 > .card, .checklist > li, .faq';

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
runLedger();
