# ADR-0005 — `vigil-verify` links only `vigil-core`

**Status:** accepted.
**Date:** 2026-09-07.
**Affects:** `spec/03-export-pack.md` §5, §8; `README.md`; `crates/vigil-verify`
(implemented); `crates/vigil-ledger/examples/gen_pack_verdicts.rs` (new);
`testdata/packs/expected/` (new fixtures); `.github/workflows/ci.yml`.
**Builds on:** ADR-0004 (export pack format), `spec/02-entanglement.md` §7.

---

## Context

`spec/03-export-pack.md` §5, as written under ADR-0004, opened with a
self-contradiction:

> `vigil-verify` performs exactly these steps, in order, with its own code — not
> by calling `vigil-ledger`. `vigil-verify` depends only on `vigil-core` **and
> the verification path of `vigil-ledger`**.

The first sentence forbids what the second sentence permits. `spec/02` §7 is
unambiguous on the same point — "`vigil-verify` rebuilds the DAG with its **own**
traversal — not `vigil-ledger`'s" — and the crate's own module documentation
(`crates/vigil-verify/src/lib.rs`, present since the scaffold) states the strict
rule and the reason for it.

The reason is not stylistic. `vigil-verify` exists to give a third party a verdict
that does not depend on trusting the code that produced the pack. A verifier that
reuses `vigil-ledger`'s chain check, DAG construction, sealing or fork-detection
code cannot detect a bug in any of them: it reproduces the same wrong answer and
reports agreement. The duplicated traversal is the product, not an inefficiency to
factor away.

## Decision

`vigil-verify` links **only `vigil-core`**, and nothing else in the workspace —
not as a normal dependency and not as a dev-dependency.

- `crates/vigil-verify/src/pack.rs`, `chain.rs`, `dag.rs` and `bracket.rs` are
  second implementations of logic that also exists in `vigil-ledger`, written from
  the text of `spec/01` §6.6 and `spec/02` §4–§6.
- Sharing `vigil-core` is the one deliberate exception. Invariant I2 requires
  exactly one implementation of the canonical encoding and content addressing; a
  second one here is the thing that invariant exists to forbid, and the golden
  vectors in `testdata/vectors/` are what hold the single implementation honest.

### The `spec/03` §8 cross-check, without the link

`spec/03` §8 requires a property test that `vigil-verify`'s recomputed bracket
equals `vigil-ledger`'s `bracket()` over the same object set on honest input —
"the two independent traversals agree." That test may not call `vigil-ledger`
either.

Resolution: `vigil-ledger`'s side of the equality is computed ahead of time by
`cargo run -p vigil-ledger --example gen_pack_verdicts`, which parses each fixture
pack, rebuilds a store from its surviving objects, applies any carried fork proof
as a quarantine, and writes the resulting `bracket()` and `verify_chain()`
outcomes to `testdata/packs/expected/*.json`. CI regenerates and diffs these the
same way it does the `.vgl` fixtures — a drift is a `bracket()` behaviour change
and must not pass silently. `vigil-verify`'s `tests/property.rs` loads the JSON
and asserts its own independent traversal reproduces it field for field.

### Where the two enums differ, deliberately

`vigil-verify::bracket::WindowEdge` has a fourth variant `EarliestHeld(seq)` that
`vigil-ledger::WindowEdge` does not. `spec/03` §5 step 6 requires the lower window
edge to read `genesis` **only when `seq` 0 is held**, and otherwise "open below to
the earliest held entry (`seq` n)" — the §3.5 marker. The ledger's `bracket()`
never needs this because its chain segments always start at genesis; the verifier,
handed a partial segment in a pack, does. The `earliest-held` fixture asserts the
verifier reports `EarliestHeld`, not `Genesis`, so the cross-check fixtures under
`testdata/packs/expected/` cover only the packs where the two enums coincide
(`honest`, `t3-dropped-anchor`, `fork-witness`).

## Alternatives rejected

- **Keep the `vigil-ledger` dependency and call its verification path.** Defeats
  the crate's purpose (above). Rejected.
- **Move the shared traversal into a third crate both depend on.** Same failure
  mode with an extra crate: a bug in the shared traversal is invisible to both
  sides. The traversal must be written twice by different code to be a check.
- **Drop the `spec/03` §8 cross-check.** It is the single most direct evidence
  that the duplication is faithful. Kept, via the checked-in fixture.

## Consequences

- `spec/03` §5 and §8, `README.md`, and the deliverable-6 status line are
  corrected to state the strict rule.
- CI gains a `gen_pack_verdicts` regenerate-and-diff step alongside `gen_packs`.
- Any future change to `vigil-ledger::bracket` or `verify_chain` that changes a
  fixture verdict now fails CI in two places — the ledger's own tests and the
  `testdata/packs/expected/` diff — and the `vigil-verify` cross-check test then
  has to be re-examined rather than silently re-baselined.
