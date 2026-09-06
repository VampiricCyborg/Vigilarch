# ADR-0003 — Entanglement DAG refinements: seal-edge scope and cross-author ordering

**Status:** accepted.
**Date:** 2026-09-06.
**Affects:** `spec/02-entanglement.md` §4.2, §4.6; `crates/vigil-ledger/src/dag.rs`.
**Commits:** 97e8bc8 (DAG build), 6dff471 (bracketing queries).

---

## Part 1 — Seal-edge scope: spec correction

### Finding

`spec/02-entanglement.md` §4.2 defines the seal edge as:

> observation S@m → attestation X, for every held observation of S at
> **seq m ≤ X.subject_seq**, when the held observation at X.subject_seq
> recomputes to X.subject_head and X.witness ≠ S.

The italicised phrase is a sequence-number comparison. Under equivocation — two
observations by the same author at the same `seq` — it would seal both entries
with any attestation that anchors either one of them, including the fork-branch
sibling the witness never saw.

That is wrong. The sealing theorem (§5.2) proves:

> Because that id recomputes from A's held entry, the entry — and, **by the chain
> rule** (`spec/01` §6.6), **every entry before it** — existed in the form W saw
> at the moment W signed.

"Every entry before it by the chain rule" means every entry reachable by walking
`prev` from the anchored head — chain ancestors, not all entries at a lower seq.
The proof never mentions seq comparison; it relies on the hash-linked `prev`
pointer. The seq-comparison wording in §4.2 is an imprecise shorthand that happens
to be equivalent on any unforked chain and is wrong under exactly the adversarial
condition entanglement exists to catch.

### Resolution

The implementation in `dag.rs` (97e8bc8) uses the `prev`-walk rule, matching the
proof rather than the imprecise §4.2 wording. §4.2 is corrected in this commit to
state the `prev`-walk rule directly.

The two rules agree on every unforked chain. They diverge only when the same author
has two entries at the same `seq` — equivocation — which is a fork and is handled
by §6. The correction therefore changes no behaviour on honest chains and closes a
logical gap on dishonest ones.

### Golden case

Author A equivocates at seq 3: two entries, `A@3a` and `A@3b`, both with `prev`
pointing to `A@2`. Witness W attests A's chain at seq 3, anchoring `A@3a`
(`X.subject_head = id(A@3a)`, `X.subject_seq = 3`).

Under the **old seq-comparison rule**: both `A@3a` and `A@3b` receive a seal edge
from X, because both have `seq 3 ≤ X.subject_seq = 3`. W's attestation would seal
a branch W never saw.

Under the **corrected prev-walk rule**: `dag.rs` walks `prev` from `id(A@3a)`:
`A@3a → A@2 → A@1 → A@0`. Only those entries receive a seal edge. `A@3b` is not
reachable from `id(A@3a)` by `prev` — it is a sibling, not an ancestor — so it
receives **no seal edge** from X. W's attestation seals only what W actually saw.

This is the correct outcome. `A@3b` is unwitnessed by X. If a separate witness
attests `A@3b`, that attestation seals `A@3b`'s ancestors independently. The fork
is detectable the moment any node holds both `A@3a` and `A@3b` (§6.1).

### Spec edit

§4.2's seal-edge definition is reworded from the seq-comparison form to the
prev-walk form. See the diff to `spec/02-entanglement.md` in this commit.

---

## Part 2 — No cross-author DAG edges: design decision, deferred

### Finding

An `Attestation` carries `subject_head` and `subject_seq` — the subject's position
— but nothing about the witness's own chain position. As a result, every seal edge
in the DAG arrives from the subject's observations and every ack edge leaves to the
subject's chain. The DAG has no edge between two different authors' chains.

This is documented in `dag.rs` (97e8bc8):

> An `Attestation` carries the *subject's* head, never the witness's. So its seal
> edges arrive only from the subject's observations, and its one ack edge leaves
> only to the subject's chain. A consequence worth stating: this graph has **no
> edge between two different authors' chains**.

The self-referential case — author A embeds, via `acks`, an attestation that W made
about A — works correctly and is what the two-node scenario in `vigil-sim` tests.
A's chain reaches W's attestation via the ack edge; W's attestation seals A's prior
entries via seal edges. That is the intended path.

The mule case described in §4.6 does not work with the current three edge types.
§4.6 states:

> A path `Site A ⟶ mule ⟶ Site B` through the mule's own chain is what gives two
> never-connected sites an ordering relationship.

For that path to exist, the DAG would need an edge from the mule's attestation
about A to the mule's attestation about B, or from one of those attestations into
the mule's own observation chain. None of the three current edge types produces
that. The mule issues two attestations — one about A, one about B — but nothing in
the current wire format records the order in which the mule issued them, so no edge
can be drawn between them.

### Proposed fix (not implemented in v1)

Add a `witness_seq` field to `Attestation`: a counter the witness increments per
attestation it issues, independent of its observation chain. Add a fourth edge type:

- **witness-order** — attestation X → attestation Y, when `X.witness == Y.witness`
  and `Y.witness_seq == X.witness_seq + 1`.

This gives the mule's two attestations a defined order and lets the DAG connect
`Site A ⟶ mule-att-about-A ⟶ mule-att-about-B ⟶ Site B`.

### Why this is not implemented now

`witness_seq` is a new field on `Attestation`. Under `spec/01` §11, adding a field
to an existing object type requires:

1. a new ADR (this one records the gap; the implementation needs its own);
2. a new golden vector for `Attestation` with the field present;
3. a wire version bump only if an existing content address changes — a new optional
   field with a fresh permanent number does not change existing ids, but the ADR
   must argue this explicitly.

The mule-relay scenario in `spec/02` §9 and `vigil-sim` is therefore **out of
scope until `witness_seq` is built**. This matches what `dag.rs` already documents.
Nothing in the current sealing or bracketing guarantees depends on cross-author
ordering — those guarantees are stated in terms of a single author's chain and its
witnesses, and they hold exactly as specified. The limitation is that certain
topologies (two sites connected only through a mule) produce `incomparable` records
where a future implementation would produce an ordering. That is the honest,
conservative outcome (invariant I5), not a correctness defect.

### Consequences

- `mule-relay` stays out of the `vigil-sim` scenario suite until `witness_seq`
  lands. The scenario file is not written; the §9 test obligation for it is
  deferred.
- §4.6 of `spec/02` is annotated to record this limitation explicitly, so a reader
  does not infer that the mule path works today.
- When `witness_seq` is implemented, it gets its own ADR under `spec/01` §11's
  process, new golden vectors, and a `vigil-sim` scenario asserting the ordering
  relationship.

---

## Not decided here

The `witness_seq` counter's reset policy (per session vs. monotone across the
device's lifetime), its interaction with the `nonce` field, and whether it should
be optional or required are left to the ADR that implements it. Making it optional
preserves backward compatibility with v1 attestations; making it required is a
cleaner invariant. That tradeoff is not resolved here.
