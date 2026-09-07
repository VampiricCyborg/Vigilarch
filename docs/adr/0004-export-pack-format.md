# ADR-0004 — Export pack format

**Status:** accepted.
**Date:** 2026-09-07.
**Affects:** `spec/03-export-pack.md` (new); `testdata/vectors/` and `testdata/packs/`
(new fixtures); unblocks `crates/vigil-verify`.
**Builds on:** ADR-0002 (entanglement, which deferred this), ADR-0003 (DAG edge scope).

---

## Context

`spec/02-entanglement.md` §7 says what an export pack must *contain* — for every bracket
claim: the observation, its author's chain segment, the reachable attestation closure,
the witness chains needed to anchor seal edges, and any touching `ForkProof` — but
explicitly defers the byte framing: "fixed alongside the `vigil-verify` implementation
rather than here." ADR-0002's "Not decided here" section records the same deferral.

`vigil-verify` is a v1 deliverable (`CLAUDE.md` §Deliverables 5) and the highest
persuasion-per-line artifact in the project. It cannot be implemented against an
unspecified input. The `spec/` discipline is that the format — including its failure
modes — is worked out on paper first, the same way `spec/01` §10 and `spec/02` §5 were,
and the implementation is then checked against a hand-reproducible worked example.

This ADR records the decision to fix the format now, and the load-bearing choices in
`spec/03`.

## Decision

Write `spec/03-export-pack.md` now, before any `vigil-verify` code, defining the pack as
a single self-contained file.

### The pack reuses `spec/01`'s CBOR profile; it invents no second encoding

Every object in a pack — observation, attestation, fork proof — is carried in the exact
canonical form `spec/01` §6 already defines. Observations and attestations are carried as
`[preimage, sig]` pairs, the same self-contained carriage `ForkProof` already uses for
its two entries (`spec/01` §6.7): the full domain-separated preimage plus the detached
signature, so a reader holding no chain can still recompute the id and check the
signature. The envelope that wraps them is a CBOR map under the same `spec/01` §2.1
profile (definite lengths, sorted keys, shortest form, no floats, no tags, no null).

*Rejected: a bespoke pack encoding, or a framing borrowed from `ciborium`/`serde`.* The
whole point of `spec/01` §2.4 is that the canonical path is built by hand from the field
tables and is byte-reproducible across native and WASM. A pack that used a different
encoder would reintroduce exactly the divergence risk `spec/01` exists to remove, and
would need its own golden-vector cross-check. Reusing the profile means the pack decoder
*is* the `spec/01` §8 decoder.

*Rejected: JSON (like the golden-vector files).* The vector files are test fixtures
describing bytes; a pack *is* the bytes, and must be canonical and hashable-in-principle
with the same rules as everything else.

### The envelope is never hashed and never signed

The objects inside a pack are already self-certifying through their own content addresses
and signatures (`spec/01` §3–§4). Adding a signature over the envelope would invent a
second trust root — whose key? the org's? a per-export key? — and imply the envelope
authenticates its contents, which it does not need to: a tampered object fails its own
check. The envelope carries a file marker (`vigilarch/1/pack\x00`, the `spec/01` §3.1
lexical convention used purely for file-type recognition and an explicit wire version)
and a container. Nothing more.

*Rejected: signing the envelope with the org key.* Key issuance is stubbed in v1 (README;
`spec/04`). An org signature would be a checkable-looking artifact backed by no
verification path, which is worse than no signature. `org` is carried as a label the
verifier compares to its out-of-band `<org-pubkey>` argument and nothing else, and
`spec/03` §2.4 / §7.5 say so plainly.

### "Far enough to anchor seal edges" is defined against the reference implementation

`spec/02` §7's phrase "the chains of every witness far enough to anchor their seal edges"
is imprecise as written — it names the witness's chain, but `crates/vigil-ledger/src/dag.rs`
anchors a seal edge on the **subject's** entry (`observations[X.subject_head]`, with
`author == X.subject` and `seq == X.subject_seq`), then walks `prev` back through the
subject's chain (ADR-0003 Part 1). And in wire version 1 the DAG has **no cross-author
edge** (ADR-0003 Part 2), so the only chain a claim's closure touches is the claimed
observation's own author's chain.

`spec/03` §3.2 therefore defines "far enough" concretely: the author's chain segment runs
from genesis (or earliest held, marked) to `max(claimed seq, greatest subject_seq among
carried attestations)` — past the claimed record when a witness saw the chain further
along. A v1 pack carries **no witness-chain entries**, and `spec/03` says why, and notes
that `spec/02` §7's wording becomes literally correct only when the wire-version-2
witness-order edge (ADR-0003 Part 2) lets a witness's own chain enter a closure.

This is a clarification of `spec/02` §7, not a change to it: the set of objects a correct
pack contains is unchanged; `spec/03` just states it in terms that match what the code
already does. A follow-up edit to `spec/02` §7's prose to cross-reference `spec/03` §3.2
is worth doing but is not required for this ADR to stand.

*Rejected: requiring witness-chain genesis segments "for completeness".* They are not
reachable from any claim in v1 (§3.3), so including them would violate the minimisation
property (§4) — a pack would leak a witness's unrelated history to prove a bracket that
does not depend on it.

### The pack is a minimisation, and minimisation is bounded below by soundness

`spec/03` §4 states pack minimisation as a first-class privacy property: a pack proves
ordering for a named set of claims and is *not* required to be a full ledger. A verifier
of a bracket about one incident learns the chain and meeting structure around that
incident and nothing about the site's other activity.

The bound (§3.3, §3.4, §7.2): the exporter MUST include every reachable attestation and
every held `ForkProof` touching any key in the pack, because those can only widen a
bracket or invalidate it. Omitting a fork proof against the pack's own witness is the one
omission that lets a pack overstate, so it makes the pack invalid rather than merely
incomplete.

### The failure modes are specified before the verifier, with a hand-worked example

`spec/03` §6 works a three-object scenario end to end with exact bytes (reusing the
`spec/01` §10 genesis note as `A@0`), then corrupts the honest pack one way at a time to
pin three *distinct* verifier verdicts:

| Tamper | Mechanism | Verdict |
|---|---|---|
| Flip a byte in the claimed observation | recomputed id ≠ claimed id; signature fails | claim unverifiable — claimed observation absent; chain `Incomplete` |
| Substitute a validly re-signed genesis | objects individually valid; `prev` link does not close | chain `Violated` — `BrokenLink`, attributable to the author's key |
| Drop the anchor entry | attestation valid but `subject_head` not held | `unwitnessed` — no seal edge (`spec/02` §4.5), window open above |

These three are the taxonomy `vigil-verify` is tested against. Getting them exact on
paper, with reproducible bytes, is the point of doing the spec first.

## Consequences

- **`vigil-verify` is unblocked.** Its implementation prompt comes next and will be
  checked against `spec/03` §6: the honest pack must produce the §6.4 result, and the
  T1/T2/T3 packs must produce the three §6.5 verdicts, distinctly named.
- **`vigil-verify` stays thin.** It depends only on `vigil-core` and `vigil-ledger`'s
  verification path (`CLAUDE.md` §Deliverables 5). It rebuilds the DAG with its own
  traversal (`spec/02` §7) rather than calling `vigil-ledger`'s builder, and a property
  test asserts the two agree on honest input.
- **New golden vector** `pack/worked-example` under `testdata/vectors/`, generated by
  hand from the tables (the ADR-0001 discipline), cross-checked native vs. WASM, byte for
  byte. Changing it needs an ADR.
- **New fixtures** under `testdata/packs/`: the honest pack and the tampered variants,
  each asserting its exact verdict.
- **`spec/01` §3.1** gains, as a follow-up, a note that `vigilarch/1/pack` is a
  file-type marker using the tag convention but is not a hash preimage. Not blocking.
- The pack file marker is additive (`spec/01` §11): it changes no existing content
  address, so no wire version bump — only this ADR and the new vector.
- **Doc `03` is reassigned** from the (unwritten) sync spec to the export pack. The sync
  spec becomes `06-sync.md` when it is written (v2). `spec/README.md` and `spec/01` §6.1
  are updated. Two stale references to `spec/03-sync.md` remain in
  `crates/vigil-core/src/object.rs` (a doc comment and the `Heartbeat` rejection
  message); they point at the same unwritten document under its old number and are
  corrected the next time that file is touched — harmless until then, since the variant
  is rejected regardless.

## Not decided here

- **`.pack` vs. another file extension**, and whether a pack may be gzip-framed for
  transport. Cosmetic; left to `vigil-verify`.
- **Multi-claim packs across different authors.** `spec/03` is written so one pack can
  carry several claims, but every worked example and fixture in v1 is single-author,
  because v1 has no cross-author DAG edge (ADR-0003 Part 2). The cross-author case gets
  its own fixtures when `witness_seq` lands.
- **Streaming verification** of a pack too large for memory. v1 packs are small (the
  worked example is 775 bytes); not a concern until it is.
