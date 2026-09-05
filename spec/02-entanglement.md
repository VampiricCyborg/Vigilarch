# 02 — Entanglement

**Status:** draft. **Wire version:** `1`. **Milestone:** M1.

This document defines how two nodes co-sign each other's chain heads on contact, how the
resulting attestations form a DAG, how a record's creation time is bracketed from that
DAG, and how equivocation is proven and contained. It is the protocol `docs/VIGILARCH.md`
§8 sketches; where the two disagree, this document wins.

It is normative. It depends on `spec/01-wire-format.md` for every encoding, for the
canonical CBOR profile, for domain separation, and for the chain-integrity rules of §6.6;
it introduces no new encoding rules of its own, only two additive objects recorded in
`01` (the `acks` field of `Observation`, §6.1, and `ForkProof`, §6.7). The key words
**MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are used as in RFC 2119.

Changing the exchange, the DAG edge rules (§4), or the bracketing rule (§5) requires an
ADR in `docs/adr/` and, if it changes an existing content address, a wire version bump
(`spec/01` §11). The non-guarantees in §8 are part of the contract and are held to the
same review as the guarantees.

---

## 1. What entanglement is for

A device clock is a settable field. Per-node hash chains (`spec/01` §6.6) stop a node
inserting into its own past — it can only append or fork, and a fork is attributable
misconduct — but a node that has been alone since genesis can still fabricate a complete,
internally consistent chain with any clock values it likes. Nothing in the bytes betrays
it, because nothing external has ever constrained it.

Entanglement supplies the external constraint, and it uses the one resource field
operations produce for free: **contact**. When node A meets node W, each signs a short
statement about the other's current chain head and embeds the statement it received into
its own next entry. A's subsequent history is now cryptographically dependent on that
meeting, and W's signature is independent evidence of where A's chain stood at the time.

Proof of time becomes a property of a meeting rather than of a clock. The forensic
resolution of the whole system is the contact frequency of the network: sites meeting
hourly get hour-tight brackets, a site alone for three weeks gets a three-week bracket,
and the correct behaviour is to **report that width, not conceal it**.

> **What this does not do.** An attestation bounds a record's creation from **above** —
> "no later than this meeting" — and never from below. A node isolated since genesis has
> no meeting in its past and the honest output for its records is a wide unwitnessed
> window, **not a detection and not an alarm**. Entanglement orders records; it cannot
> make a real-time false report false, and it cannot force a withholder to sync. The full
> list is §8, and it is not an appendix — it is half the specification.

---

## 2. Checkpoints

### 2.1 What a checkpoint is

A `Checkpoint` (`spec/01` §6.4) is a node's signed claim about its own current position:
`node`, `head` (the id of its latest observation), `seq`, an `hlc`, and a `frontier`
version vector. It is the *offer* in the exchange — "here is my head; attest it" — and it
is self-signed, so on its own it proves nothing about time.

### 2.2 When it is sent

Both nodes MUST exchange checkpoints at the start of every session, immediately after the
`hello` version negotiation (`spec/01` §7) and before any other object transfer. A
sneakernet bundle carries the exporter's checkpoint in its header.

A node MAY decline to send a checkpoint. The consequence is simply that no entanglement
occurs on that link and that peer contributes no sealing — the records stay unwitnessed.
There is no penalty and no way to compel it.

### 2.3 What is load-bearing in v1

Only `node`, `head` and `seq` drive entanglement. `hlc` is untrusted input and MUST NOT
be read as evidence of anything (`spec/01` §5.1, invariant I4). `frontier` exists for
range reconciliation, which is a v2 concern; in v1 a verifier MUST ignore it entirely for
any temporal or ordering claim.

Checkpoints MAY be retained for diagnostics. They are **not** vertices in the attestation
DAG (§4) — only attestations are.

---

## 3. The attestation exchange

### 3.1 The exchange, step by step

For a session between A and W, after `hello`:

```
A → W:  Checkpoint { node: A, head: H_a, seq: s_a, hlc, frontier, sig_A }
W → A:  Checkpoint { node: W, head: H_w, seq: s_w, hlc, frontier, sig_W }
A → W:  Attestation { witness: A, subject: W, subject_head: H_w, subject_seq: s_w,
                      witness_hlc, nonce, sig_A }
W → A:  Attestation { witness: W, subject: A, subject_head: H_a, subject_seq: s_a,
                      witness_hlc, nonce, sig_W }
```

Each node then embeds the attestation **in which it is the subject** into its own next
chain entry, via the `acks` field (§3.4). A embeds W's attestation about A; W embeds A's
attestation about W.

The exchange is symmetric and independent per direction: if one node sends its
attestation and the other does not, the half that arrived is still valid and still used.

### 3.2 What the witness signs

An attestation is signed by `witness` over its own id (`spec/01` §4). It asserts exactly
one thing: *at some point I, the witness, saw the subject presenting this head at this
seq.* `subject_head` and `subject_seq` are copied from the checkpoint the subject
presented; the witness does not need to hold the subject's chain to make the attestation,
and MUST NOT invent a head the subject did not present.

`witness_hlc` is the witness's own clock reading at signing. It is untrusted and carries
no authority (`spec/01` §6.5). It MAY be used as a tie-break hint when ordering a node's
own received attestations; it MUST NOT appear in any bound.

### 3.3 Accepting an attestation

On receipt of an attestation X, a node MUST:

- verify `sig` under `X.witness` (`spec/01` §4); a failure means the frame is discarded
  and contributes nothing (`spec/01` §8);
- treat `(X.witness, X.nonce)` as the deduplication key — a second attestation with the
  same pair and the same content is the same object; the same pair with different content
  is an integrity finding against `X.witness` and is retained, not dropped;
- make no inference about wall-clock time, and none about the subject's chain beyond "the
  subject claimed this head to this witness".

### 3.4 Embedding: the `acks` field

`Observation` field 8, `acks` (`spec/01` §6.1), is an ascending, duplicate-free list of
attestation ids. An entry's content address commits to its `acks`, which is what makes
the binding cryptographic: once A has published an entry E that acks X, A cannot present
a history in which E — or anything after E — exists without X, except by forking.

A verifier MUST treat an `acks` entry as an integrity finding against the observation's
`author` (attributable, retained — `spec/01` §6.6) when:

- the referenced attestation's `subject` is not equal to the observation's `author`, or
- the referenced attestation's `subject_seq` is not strictly less than the observation's
  `seq`.

A node SHOULD ack every not-yet-acked attestation of its own head at its next entry. It
MAY ack several at once (it met several peers before writing again). Acking is the only
mechanism by which an attestation comes to *precede a record in that record's own chain*,
which is what §5 needs for a lower-bound.

### 3.5 Propagation

Attestations are content-addressed objects and propagate like any other — priority class
1, ~150 bytes, fitting any link. An attestation W made about A is useful to any third
party C, because it lets C place A's chain relative to W's. A verifier builds its DAG
(§4) from whatever set of attestations it holds; a larger set yields tighter brackets, a
smaller set yields honestly wider ones. In v1 there is no sync layer; `vigil-sim` moves
attestations between nodes over scripted links.

---

## 4. The attestation DAG

### 4.1 Vertices

Given a set of held objects, the DAG has one vertex per **valid observation** and one per
**valid attestation**. "Valid" means: the id recomputes from the preimage (`spec/01`
§3.2), the signature verifies, and — for observations — the entry is not itself a decode
failure. Integrity findings (§6.6 of `spec/01`: a `seq`/`prev` mismatch, a bad `acks`)
are retained and reported but their observation still enters the DAG; fork branches enter
the DAG and are marked (§6.4).

### 4.2 Edges

Every edge means *the tail is in the causal past of the head* — "the tail happened before
the head". There are exactly three edge types:

- **chain** — for author A, the observation at `seq` n−1 → the observation at `seq` n,
  when both are held and n's `prev` recomputes to n−1's id.
- **ack** — attestation X → observation E, when `X.id ∈ E.acks`, X is held and valid,
  `X.subject == E.author`, and `X.subject_seq < E.seq`.
- **seal** — observation S@m → attestation X, for every held observation of `S` at
  `seq` m ≤ `X.subject_seq`, **when** the held observation at `X.subject_seq` recomputes
  to `X.subject_head` and `X.witness ≠ S`.

The partial order ⟶ is the transitive closure of these edges.

### 4.3 The partial order

`R ⟶ Q` reads "R provably happened before Q". Most pairs of records are **incomparable** —
neither `R ⟶ Q` nor `Q ⟶ R` — and that is the ordinary, correct state under partition,
not a gap to paper over. A verifier MUST NOT complete an incomparable pair into an order
by any heuristic.

### 4.4 Distinct keys

A seal edge is only evidence when `X.witness ≠ X.subject`; a node attesting its own head
proves nothing and MUST be ignored for bracketing (though retained). Witness **depth** is
the count of *distinct* witness keys sealing a record. Distinct keys are not the same as
distinct parties — see §8.9.

### 4.5 Unanchored attestations

An attestation whose `subject_head` names an entry the verifier does not hold produces
**no seal edge** — the verifier cannot confirm the head. The attestation is retained; the
edge appears if and when the entry arrives. A verifier MUST NOT treat an unanchored
attestation as sealing anything.

### 4.6 Mules

A mule is a node that entangles at both ends of a route and carries opaque bundles it
cannot read. It contributes ack and seal edges exactly like any other node. A path
`Site A ⟶ mule ⟶ Site B` through the mule's own chain is what gives two never-connected
sites an ordering relationship. The mule needs no access to any payload to produce this;
an untrusted courier measurably tightens the ledger.

### 4.7 Determinism

DAG construction MUST be a pure function of the held object set: independent of arrival
order, of duplicates, and of the machine. The same held set MUST produce a byte-identical
`bracket()` result (§5.6) on any two machines. This is asserted on every `vigil-sim` run.

---

## 5. The bracketing rule

### 5.1 Definitions

For an observation R by author A at `seq` r:

- **upper-bound attestation** — the attestation U, `U.witness ≠ A`, with `R ⟶ U`, that is
  earliest in ⟶ (nearest to R). U's witness saw A's chain already past r.
- **lower-bound attestation** — the attestation L, `L.witness ≠ A`, with `L ⟶ R` via an
  ack edge on R or on an earlier entry of A's chain, that is latest in ⟶ (nearest to R).
- **sealed** — R has at least one upper-bound attestation. Otherwise **unwitnessed**.
- **unwitnessed window** — the span the system cannot vouch for: from L (or, if there is
  no L, from A's genesis) to U (or, if there is no U, to the verification moment). Its
  width is **witness latency**. Its lower edge is *never* R's own `hlc`.
- **witness depth** — distinct witness keys among R's upper-bound attestations.

### 5.2 Sealing theorem (the upper bound)

> Let U be a valid attestation with `U.witness = W`, `W ≠ A`, `U.subject = A`,
> `U.subject_seq ≥ r`, and `U.subject_head` equal to the recomputed id of A's entry at
> `U.subject_seq`. Then A's chain up to and including `seq` r existed before W signed U.
> For any record Q with `U ⟶ Q`, R existed before Q. Backdating R past Q requires forging
> W's key or presenting W a different chain (§6).

*Proof.* U's signature binds W to having seen A present a head at `seq` `U.subject_seq`
with id `U.subject_head`. Because that id recomputes from A's held entry, the entry — and,
by the chain rule (`spec/01` §6.6), every entry before it, including R — existed in the
form W saw at the moment W signed. `U ⟶ Q` places W's signing before Q in the partial
order. Therefore R existed before Q. The only escapes are a forged `sig` on U (reduces to
key compromise, out of scope, §8) or A having shown W a chain that does not contain R at
`seq` r — which is a second chain from a shared `prev`, i.e. a fork, detectable the moment
both reach one verifier (§6). ∎

### 5.3 The lower bound, and why it is weak in v1

> Let L be a valid attestation with `L.witness = W`, `W ≠ A`, `L.id ∈ E.acks` for an
> entry E of A's chain at `seq` k ≤ r. Then R was created after A received L, hence after
> the A–W meeting that produced it.

*Proof.* E's content address commits to `L.id`; R is E or later in A's chain; so
`L ⟶ E ⟶ R` (or `L ⟶ R` directly). A held L before publishing E, and W produced L at the
meeting. ∎

This is an **ordering** fact, not a timestamp. It says "R is after that meeting"; it
becomes a wall-clock lower bound only if the meeting itself is bounded below — which in v1
requires an external anchor (`docs/VIGILARCH.md` §8.7), and v1 has none. So in v1:

- the lower-bound attestation is used to **detect contradiction**: if R is placed (by a
  human, an export, or its own body) before an event that `L ⟶ R` proves it followed, the
  claim is provably false;
- it does **not** yield an absolute earliest time. A record with no L — a genesis-isolated
  node's records, and many records in a sparsely-connected fleet — has an unwitnessed
  window open all the way to genesis, and that is the honest answer.

### 5.4 Escaping the bracket

Within `[L, U]` a node may set R's `hlc` to anything; the field is not evidence and no
bound depends on it. To make R appear **before L's meeting**, A must publish an entry at
`seq` k without L in its `acks` — a second entry at `seq` k, i.e. a fork. To make R appear
**after U's meeting**, A must have shown U's witness a chain without R at `seq` r — again a
fork. Both are detectable and attributable (§6). Backdating is confined to the bracket;
leaving it is not a subtle attack, it is equivocation.

### 5.5 Monotonicity

Adding a valid attestation to the held set MUST NOT widen any bracket — it can only move L
later, move U earlier, or leave both unchanged. A verifier that could widen a bracket by
learning *more* is unsound in the direction I5 forbids. `vigil-sim` asserts this on every
run: brackets are monotone non-increasing under attestation ingest.

### 5.6 The query

`bracket(R)` returns `(lower_bound_attestation: Option, upper_bound_attestation: Option,
unwitnessed_window)`. Where the DAG does not establish an ordering the corresponding bound
is `None` and the window is open on that side. The result MUST be identical byte-for-byte
across machines given the same held set (§4.7).

---

## 6. Fork detection

### 6.1 What a fork is

Two valid observations, same `author`, that cannot both sit in one chain: the same `seq`
with different ids, or the same `prev` with different ids. It is proof that the holder of
`author`'s key signed two irreconcilable histories — equivocation.

### 6.2 The ForkProof

`ForkProof` (`spec/01` §6.7) carries the equivocating `key` and the two conflicting
entries, each as its full domain-separated preimage plus its detached signature, ordered
so the smaller recomputed id is `a`. It is **self-verifying**: any node checks that both
preimages decode as `Observation`s, both carry `author == key`, both signatures verify
under `key`, and the two collide as in §6.1. A ForkProof failing any check is discarded
like any malformed frame.

### 6.3 Propagation

A valid ForkProof floods at priority class 0 — ahead of everything, ~350–450 bytes,
fragmented across frames on a link that cannot carry it whole, because nothing matters
more than delivering it.

### 6.4 On receipt

Every node that validates a ForkProof for `key` MUST:

1. mark `key` **quarantined**;
2. mark that key's **unwitnessed** observations **disputed** — never delete them; they
   may be true and the dispute record is itself evidence;
3. keep that key's observations that were **sealed before the fork** as valid — they were
   witnessed by honest parties and the fork does not retroactively unwitness them;
4. raise an operational alert to the org security role.

### 6.5 Quarantine semantics

- Attestations **by** a quarantined witness are disregarded for sealing from then on — the
  witness is not trustworthy — but are retained.
- Honest attestations **about** a quarantined subject still seal that subject's honest
  records; a liar's earlier true history does not become unprovable because they later
  lied.
- A quarantined key's **new** observations do not enter bracketing. They are stored.

### 6.6 What a ForkProof does not prove

It does not say which branch is "real" (both are the attacker's construction), when the
fork happened, or that any specific observation in either branch is false. It proves the
key equivocated. That is enough to quarantine it and to invalidate its unwitnessed
claims; it is not a claim about ground truth.

---

## 7. Independent verification

An export pack MUST carry, for every bracket claim it states: the observation, the chain
segment of its author from genesis (or from the earliest held entry, marked as such) to
the claim, the transitive closure of attestations reachable to and from it in ⟶, the
chains of every witness far enough to anchor their seal edges (§4.5), and any ForkProof
touching any key involved.

`vigil-verify` rebuilds the DAG with its **own** traversal — not `vigil-ledger`'s — and
recomputes every bracket. Where its DAG does not establish an ordering it reports
`unwitnessed` and an open window; it never interpolates, never guesses, and never reports
a bound the pack's evidence does not force. A verifier that overstates is worse than
none, because it launders an unproven claim into an apparent independent confirmation.

The pack's byte framing is a file format, not a negotiated wire protocol, and is fixed
alongside the `vigil-verify` implementation rather than here; it reuses the `spec/01` CBOR
profile.

---

## 8. Non-guarantees

Stated as prominently as the guarantees, because a bound that is not stated precisely is
not a bound.

**8.1 Upper bound only.** An attestation proves a record existed *no later than* a
meeting. It never proves a record did *not* exist earlier. There is no lower wall-clock
bound in v1.

**8.2 Genesis isolation is not detectable.** A node with no contact since genesis can
fabricate a complete, signature-valid, internally consistent chain with any clock values.
There is no contradiction to find. The correct output for its records is a wide
unwitnessed window — open to genesis below, open to now above — labelled unwitnessed. It
is **not** an alarm, a detection, or a fork.

**8.3 The unwitnessed window is real time the system cannot account for.** Its width is
the contact latency of the network. A node alone for 30 days produces 30-day windows.
Vigilarch displays that width; it does not shrink it, and shrinking it by trusting a clock
would be the cardinal defect (I5).

**8.4 Relative, not absolute.** Without external anchoring (`docs/VIGILARCH.md` §8.7, not
in v1) every bound is relative to other chain events and, ultimately, to the verification
moment. "Before Friday 16:20" is shorthand for a chain of relative orderings, not a
timestamp the system can defend on its own.

**8.5 No defence against a real-time lie.** Entanglement orders records. A person who
reports something false as it happens produces a record that seals perfectly. Making
people honest is out of scope; making tampering detectable is the scope.

**8.6 No defence against withholding.** A node that never syncs its bad news is not
compelled to. Detecting that is silence detection (`docs/VIGILARCH.md` §10.3), a v2
concern, not entanglement.

**8.7 The HLC is never evidence.** `hlc`, `witness_hlc` — untrusted device readings, merge
hints only. No bound, no window edge, no ordering claim derives from them.

**8.8 Fork detection needs a common witness.** An equivocator showing chain A to one peer
and chain B to another is undetected until some node holds both. Two nodes that never
share a peer never surface the fork.

**8.9 Distinct keys are not distinct parties.** One actor holding several device keys can
attest their own records under "distinct" keys and inflate witness depth. The mitigation
is org certificate issuance — one key per issued device — which is an operational
assumption, not a cryptographic guarantee. A fully compromised org root defeats
everything and is out of scope (`docs/VIGILARCH.md` §5.3).

---

## 9. Test obligations

Mirroring `spec/01` §9: the evidence lands with or before the code.

**Golden vectors** (`testdata/vectors/`, part of this spec, changes need an ADR):

- an `Observation` carrying a non-empty `acks` — pins field 8's encoding and ordering;
- a `ForkProof` — pins §6.7, including the `a`/`b` canonical ordering.

**Property tests:** DAG construction is independent of ingest order and of duplicates;
⟶ is transitively closed; brackets are monotone non-increasing under attestation ingest
(§5.5).

**`vigil-sim` scenarios**, each seeded, replayable, and paired with an ablation run at the
same seed with attestations disabled (CI asserting the tamper goes undetected without
them):

- `clock-rollback-append` — a node rolls its clock back and appends a backdated entry; on
  reconnect it is reported `unwitnessed` with the correct window and, if it forked to
  escape the bracket, attributed to its key;
- `equivocation` — an equivocating node is detected and quarantined via a gossiped
  ForkProof on every honest node;
- `honest-partition` — a genuinely isolated node produces wide unwitnessed windows and
  **no** alarm (§8.2);
- `mule-relay` — two never-connected sites acquire an ordering relationship through a
  mule that reads nothing.

**Determinism:** the same seed produces a byte-identical run report on two machines.

---

## 10. Changing this document

1. An ADR in `docs/adr/` recording what changed, what was rejected, and the migration
   path for devices that will be offline for weeks.
2. A wire version bump **only if** an existing content address changes. Adding a new
   optional field with a fresh permanent number, or a new object type with a fresh tag,
   changes no existing id and does not bump the version (`spec/01` §11) — but still needs
   the ADR and new golden vectors.
3. The non-guarantees in §8 may not be weakened or moved to an appendix without an ADR
   that argues, explicitly, why the weaker statement is still honest.
