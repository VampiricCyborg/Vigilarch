# ADR-0002 — Entanglement protocol v1

**Status:** accepted. **Date:** 2026-09-06. **Affects:** `spec/02-entanglement.md` (new),
`spec/01-wire-format.md` §6.1 / §6.7 / §11 (additive), `testdata/vectors/`.

## Context

`spec/02-entanglement.md` specifies the M1 protocol: checkpoint and attestation exchange,
the attestation DAG, the bracketing rule, and fork detection. `spec/` requires an ADR for
every specification change; this records the load-bearing decisions and the alternatives
that were rejected. ADR-0001 covers the base wire format this builds on.

## Decisions

### Attestations bind into the chain through a new `Observation` field, `acks`

`docs/VIGILARCH.md` §8.3 says a node "embeds the received attestation into its own next
chain entry" without saying how. It is now `Observation` field 8: an ascending,
duplicate-free list of attestation ids, covered by the entry's content address.

The binding **must** be in the signed, content-addressed preimage. That is the only thing
that stops a node from later presenting a history in which the meeting never happened. A
node that merely stored the attestation locally could "forget" it and backdate freely.

*Rejected: a dedicated chain-entry type / body variant for "contact".* Forces a whole
entry per meeting and does not match "its own next chain entry, whatever that is". A list
field also lets a node ack several attestations at once when it met several peers before
writing again.

*Rejected: binding via the HLC merge.* Merging a number is not a cryptographic commitment
to an object, and the HLC is not evidence (I4).

### The lower bound is a relative ordering fact, not a timestamp

The bracketing rule gives a robust **upper** bound (the sealing theorem, `spec/02` §5.2)
and a weak **lower** bound (§5.3): "R is after this meeting", which becomes a wall-clock
lower bound only with an external anchor, and v1 has none. Its use in v1 is
contradiction detection — a record placed before an event it provably followed is
provably false — not the production of an earliest time.

This is stated as a first-class non-guarantee (`spec/02` §8.1, §8.2, §8.4) rather than
buried, because overstating a lower bound is exactly the defect I5/I6 forbid, and because
a genesis-isolated node's correct output is a wide window and **no detection**.

*Rejected: pairing the two attestations from a meeting to tighten the lower bound
normatively.* The two attestations share no structural link a verifier can prove (their
nonces are independent, their HLCs untrusted). Same-meeting pairing is left as an
informative heuristic the simulator may measure, not a normative edge.

### `ForkProof` is self-contained: two full preimages plus signatures

`spec/01` §6.7. It carries each conflicting entry's full domain-separated preimage and
detached signature, so a node that holds neither entry can still validate it and act. It
is ordered by recomputed id (smaller is `a`) so two nodes building a proof of the same
fork get the same content address.

*Rejected: referencing the two entries by id.* A fork proof that requires you to already
hold both entries is useless for gossip to a node that holds neither — and gossip to
exactly those nodes is the point.

Consequence: a `ForkProof` is ~350–450 bytes, larger than the ~150 bytes
`docs/VIGILARCH.md` §9.2 pencils in for class 0. It stays class 0 regardless and is
fragmented on a link that cannot carry it whole.

### Additive wire changes do not bump the wire version

`spec/01` §11 now distinguishes additive changes — a new optional field with a fresh
number, a new object type with a fresh tag — from changes to existing encodings. Additive
changes leave every existing content address untouched, so they take an ADR and new
golden vectors but not a version bump (which would rewrite every id in history via the
§3.1 tags). `acks` and `ForkProof` are additive.

*Rejected: bumping to wire version 2 for M1.* Catastrophic for an additive change — it
would invalidate every M0 golden vector and every id already computed, to add an optional
field.

### Checkpoints are the offer, attestations are the evidence; `frontier` is ignored in v1

A checkpoint is self-signed and proves nothing about time; only `node`/`head`/`seq` drive
entanglement. `frontier` is for range reconciliation (v2) and a v1 verifier ignores it
for any temporal claim. Checkpoints are not DAG vertices.

## Consequences

- `vigil-core`'s `Observation` decoder must accept field 8 and a `ForkProof` type must be
  added; both land with the M1 code, against new golden vectors written first by hand
  from the §6.1 / §6.7 tables (the ADR-0001 discipline).
- `vigil-ledger` builds the DAG and computes brackets against the `Store` trait; the
  logic is written once and `vigil-verify` re-implements the traversal independently.
- `vigil-sim` grows the four §9 scenarios alongside M1, each with its ablation.
- The non-guarantees (`spec/02` §8) are contract text and may not be weakened without an
  ADR that argues the weaker statement is still honest.

## Not decided here

The export-pack byte framing (a file format, fixed with `vigil-verify`, not a negotiated
wire protocol). External anchoring (`docs/VIGILARCH.md` §8.7) stays out of v1 — it is one
paragraph in `spec/04-threat-model.md`, which is deliberately deferred until after M1.
