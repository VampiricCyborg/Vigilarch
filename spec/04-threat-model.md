# 04 — Threat model

**Status:** draft. **Wire version:** `1`. **Milestone:** after M1.

This document states which adversaries Vigilarch v1 handles, which it addresses only in
architecture, and which are out of scope; and it states exactly what a sealed record does
and does not prove. It is synthesis, not new design: every decision here already exists in
`spec/01`, `spec/02`, `spec/03`, the ADRs, or the reference implementation, and this
document consolidates them and points to the code and tests that carry each claim.

It is normative in one respect: the non-guarantees in §5, §7 and §8 are part of the
contract and are held to the same review as any guarantee (`spec/02` §10). Overstating
what a sealed record proves is the cardinal defect of this system (README invariant I5),
and a threat model that is vague about its own limits is the most direct route to that
defect.

The adversary catalogue is `docs/VIGILARCH.md` §5.3, restated here with each row placed in
one of three categories that this document does not blur together:

- **Handled and verified** — a mechanism in the shipped code addresses it, and a named
  test or `vigil-sim` scenario exercises that mechanism.
- **Architecturally addressed, not implemented** — the design in `docs/VIGILARCH.md`
  names a defence, but v1 ships none of it and tests none of it. The row is listed so the
  absence is explicit rather than implied.
- **Out of scope for v1** — named as such. The capability is a v2 concern
  (`CLAUDE.md`, "Scope: do not build this"), not an oversight.

---

## 1. What v1 is defending

One record, created on a disconnected device by an actor who may be lying, is later shown
to a third party. The third party runs `vigil-verify` on an export pack (`spec/03`) and
the organisation's public key, and asks: *when was this record created, and what can be
proven about that?*

Everything in this document is about the integrity of that question's answer. It is **not**
about confidentiality, availability, device security, or key custody — those are addressed
by layers `docs/VIGILARCH.md` describes and v1 does not build (§4, §6).

The trust model:

- **Device keys are attacker-controlled.** Any holder of a device key can sign any bytes,
  set any `hlc` (`spec/01` §5.1), and choose what to append, withhold, or show to which
  peer. The system assumes this and is designed around it.
- **The HLC is never evidence.** `hlc` and `witness_hlc` are untrusted device readings and
  merge hints only (`spec/01` §5.1, `spec/02` §8.7, invariant I4). No bound, window edge,
  or ordering claim derives from them.
- **The organisation's signing key is trusted.** A pack names an issuing organisation
  (`spec/03` §2.4); a fully compromised org root defeats the system and is out of scope
  (§6).
- **There is no central authority.** No node — including a hub — has any power the edge
  nodes lack (invariant I1). No verification path consults a node's role.

---

## 2. What a sealed record proves, precisely

This section restates `spec/02` §5.2 and its non-guarantees in `spec/02` §8 for a reader
who has not read `spec/02`. Where the two differ, `spec/02` wins.

### 2.1 The mechanism, in brief

Every node keeps a hash-linked chain of its own observations: entry *n* carries `prev` =
the content address of entry *n−1*, and `seq` = *n* (`spec/01` §6.1, §6.6). A node cannot
insert into its own past without either breaking a `prev` link or publishing two entries
at one `seq` — both detectable (§2.4).

When two nodes meet, each signs an **attestation** about the other's current chain head:
"I, the witness, saw the subject present head *H* at `seq` *s*" (`spec/01` §6.5). The
attestation says nothing in wall-clock terms. Each node embeds the attestation naming it
as subject into its own next entry, via the `acks` field (`spec/01` §6.1 field 8,
`spec/02` §3.4), so that entry — and everything after it — is cryptographically dependent
on the meeting.

Attestations and observations form a DAG whose edges all mean "the tail is in the causal
past of the head" (`spec/02` §4.2). A record's creation is then **bracketed**:

- **upper bound** — the earliest attestation, by a witness other than the author, that the
  record provably precedes. The record existed no later than that meeting.
- **lower bound** — the latest attestation, by a witness other than the author, that
  provably precedes the record via an `acks` edge on the record's own chain. The record
  was created after that meeting.
- **sealed** — the record has at least one upper-bound attestation. Otherwise
  **unwitnessed**.
- **unwitnessed window** — the span from the lower bound (or genesis, if there is none) to
  the upper bound (or the verification moment, if there is none). Its width is the honest
  measure of what the system cannot account for.

### 2.2 The sealing theorem (`spec/02` §5.2)

Let `U` be a valid attestation with witness `W`, subject `A`, `W ≠ A`,
`U.subject_seq ≥ r`, and `U.subject_head` equal to the recomputed id of `A`'s held entry
at `U.subject_seq`. Then `A`'s chain up to and including `seq` *r* existed before `W`
signed `U`. For any record `Q` with `U ⟶ Q` in the DAG, the record at `seq` *r* existed
before `Q`. Backdating that record past `Q` requires forging `W`'s key or having shown `W`
a different chain — the latter is a fork (§2.4).

The bound is **one-sided**: an attestation proves a record existed *no later than* a
meeting. It never proves a record did *not* exist earlier.

### 2.3 What a sealed record does **not** prove (`spec/02` §8)

- **No lower wall-clock bound.** v1 has no external anchor (`docs/VIGILARCH.md` §8.7 is
  not built), so even a record with a lower-bound attestation has only an *ordering* fact
  — "after that meeting" — not an absolute earliest time (`spec/02` §5.3, §8.4).
- **Relative, not absolute.** Every bound is relative to other chain events and,
  ultimately, to the moment `vigil-verify` runs (`spec/03` §7.3, §7.4). "Before Friday" is
  shorthand for a chain of relative orderings.
- **A genesis-isolated node is not detectable.** A node with no contact since genesis can
  fabricate a complete, signature-valid, internally consistent chain with any clock
  values. There is no contradiction to find. The correct output is a wide unwitnessed
  window — open to genesis below, open to now above — labelled `unwitnessed`. It is **not**
  an alarm, a detection, or a fork (`spec/02` §8.2). The `honest-partition` scenario
  (`spec/02` §9) asserts exactly this: no alarm.
- **No defence against a real-time lie.** A person who reports something false as it
  happens produces a record that seals perfectly. Entanglement orders records; it does not
  make people honest (`spec/02` §8.5).
- **The window is real time the system cannot account for.** Its width is the contact
  latency of the network. Vigilarch displays that width; shrinking it by trusting a clock
  would be the cardinal defect (invariant I5, `spec/02` §8.3).
- **Witness depth counts keys, not people.** One actor holding several device keys can
  attest their own records under "distinct" keys and inflate witness depth. The mitigation
  is one key per org-issued device — an operational assumption, not a cryptographic
  guarantee, and not implemented in v1 (`spec/02` §8.9, §6).

### 2.4 What forces backdating into the open

Within its bracket `[L, U]`, a node may set a record's `hlc` to any value; no bound
depends on it (`spec/02` §5.4). To place a record **before** its lower-bound meeting, the
author must publish a second entry at an already-committed `seq` without that meeting in
its `acks` — a fork. To place it **after** its upper-bound meeting, the author must have
shown that witness a chain without the record — again a fork. Both are equivocation, and
both are detectable and attributable the moment one verifier holds both branches
(`spec/02` §6.1). Escaping the bracket is not a subtle attack; it is a fork.

---

## 3. The adversary table

| Adversary (`docs/VIGILARCH.md` §5.3) | Category | Where it is handled |
|---|---|---|
| **Backdater** | Handled and verified, within stated limits (§3.1) | Hash chain `spec/01` §6.6; bracketing `spec/02` §5; `crates/vigil-ledger/src/chain.rs`, `src/bracket.rs`; tests `crates/vigil-ledger/tests/bracket.rs`, `tests/chain.rs`; `vigil-sim` `equivocation` scenario |
| **Deleter** | Handled at the ledger; propagation to peers is v2 (§3.2) | Append-only `Store` (invariant I3); no mutation or delete path in `crates/vigil-ledger/src/store.rs`, `src/memory.rs`; missing `seq` reported `Incomplete`, never `Violated` (`spec/01` §6.6); test `tests/store.rs::equivocation_is_retained_not_rejected` |
| **Withholder** | Out of scope for v1 (§3.3) | Silence detection is v2 (`spec/02` §8.6, `docs/VIGILARCH.md` §10.3, `CLAUDE.md`). Not detected in v1 |
| **Equivocator** | Handled and verified (§3.4) | Fork detection `spec/02` §6; `crates/vigil-ledger/src/fork.rs` `detect_forks`, `Quarantine`; `src/dag.rs` seal-edge drop for quarantined witnesses; tests `crates/vigil-ledger/tests/fork.rs`, `tests/chain.rs::equivocation_is_violated_and_names_the_author`; `vigil-sim` `equivocation` scenario with ablation |
| **Thief** | Architecturally addressed, not implemented (§3.5) | Design assumes at-rest encryption keyed to a hardware store, short-lived data keys, and revocation gossip (`docs/VIGILARCH.md` §5.3, §18). v1 implements and tests none; certificate issuance is stubbed and a compromised device key is unrecoverable (README) |
| **Eavesdropper** | Architecturally addressed, not implemented (§3.6) | Design assumes payloads encrypted end-to-end to the org key (`docs/VIGILARCH.md` §5.3, §9). v1 has no transport and no payload encryption; objects are signed, not sealed. Not implemented, not tested |
| **Compromised hub** | Handled architecturally; censorship-as-coverage-loss is v2 (§3.7) | Invariant I1: no node has authority the edge lacks. No verification path in `vigil-ledger` or `vigil-verify` consults a node role. Detecting censorship as coverage loss depends on coverage math, which is v2 (`CLAUDE.md`) |

### 3.1 Backdater

**Capability.** A site manager holds a valid device key and wants a hazard report to
appear to predate an injury.

**Handled.** The backdater's own hash chain (`spec/01` §6.6) prevents silent insertion
into its past: it can only append or fork. Appending places the new record at the current
head, after every attestation the chain has already acked — so the record's lower bound is
unchanged and its backdated `hlc` carries no weight. Forking to escape the bracket is
equivocation (§3.4). `vigil-verify` recomputes the bracket from the pack and reports the
record `sealed` only within the meeting-bounded window, or `unwitnessed` with an honest
open window otherwise (`spec/03` §5 step 6).

**Limit — stated explicitly because it is easy to misstate.** An observation with a lying
`hlc` that is **honestly appended** — no fork, correct `prev`, correct `seq` — is **not
detected by anything in this system, and is not intended to be**. The chain check passes.
The bracket is computed correctly: the record sits between its true surrounding meetings,
and the false `hlc` inside that bracket changes no bound. If the bracket is wide — a
sparsely connected or long-isolated node — the record can carry any `hlc` within a wide
window and nothing contradicts it. This is `spec/02` §8.1–§8.2 and `docs/VIGILARCH.md`
§4.5, §8.2, restated: **the system does not detect backdating in general.** It detects
backdating only when the backdate also requires *equivocation* — inserting a record at a
`seq` position the chain has already committed, or presenting one witness a chain that
another witness's attestation contradicts. A verifier or reader must not come away
believing a `sealed` verdict rules out an earlier `hlc`; it rules out an earlier position
relative to the *meetings in the DAG*, and nothing more.

### 3.2 Deleter

**Capability.** An actor wants an inconvenient near-miss gone.

**Handled at the ledger.** `Observation` and `Attestation` are immutable and are never
edited (invariant I3). The `Store` trait exposes append and read; there is no update or
delete operation in `crates/vigil-ledger/src/store.rs` or `src/memory.rs`. A retraction,
in the full design, is a new assertion that is itself a permanent record (`spec/01` §6.3)
— the interpretation layer that carries assertions is cut from v1 (`CLAUDE.md`), so v1 has
no retraction mechanism at all and no way to mark a record superseded.

**Limit.** A node can decline to *export* a record just as it can decline to sync one
(`spec/03` §7.1, `spec/02` §8.6). Within v1 the guarantee is narrow: a record that a
verifier *does* hold cannot be silently removed from a pack without detection — a missing
low `seq` is reported `Incomplete` and a broken `prev` link is reported `Violated` and
attributed (`spec/01` §6.6, `spec/03` §6.5 cases T1–T2). "Peers already hold the
observation" (`docs/VIGILARCH.md` §5.3) depends on sync, which is a v2 concern; v1 proves
only the local immutability and the pack's tamper-evidence, not propagation.

**Known tension.** Append-only conflicts with erasure rights under GDPR/DPDP. This is
stated plainly in the README rather than left invisible; it is not resolved in v1.

### 3.3 Withholder

**Capability.** A node never syncs its bad news.

**Out of scope for v1.** Nothing compels a node to sync, and detecting the resulting
silence — silence detection, event-rate weighting, four-way silence classification — is
explicitly a v2 concern (`CLAUDE.md`; `docs/VIGILARCH.md` §10.3; `spec/02` §8.6). v1 does
not detect withholding and does not claim to. The honest position is that a withheld
record simply does not appear, and the system has no signal that it is missing.

### 3.4 Equivocator

**Capability.** The actor presents chain A to one peer and chain B to another: two
signature-valid observations by one key that cannot sit in one chain — the same `seq` with
different ids, or the same `prev` with different ids (`spec/01` §6.1, `spec/02` §6.1).

**Handled and verified.** `detect_forks` (`crates/vigil-ledger/src/fork.rs`) scans every
author's chain for colliding entries and emits a self-verifying `ForkProof` per collision
(`spec/01` §6.7): both preimages, both signatures, ordered so the smaller recomputed id is
`a`. Any node validates a `ForkProof` with no external input. On a validated proof, the
key is **quarantined** (`Quarantine`, `spec/02` §6.4–§6.5): its own unwitnessed records
are marked `disputed` but never deleted; its records that were sealed by honest witnesses
before the fork stay valid; its attestations stop sealing from then on. `Dag::build`
consults the quarantine and drops seal edges from a quarantined witness.

**Tests.** `crates/vigil-ledger/tests/fork.rs` covers a same-`seq` fork, a shared-`prev`
fork, idempotent detection, a garbage collision being ignored as unattributable, and both
quarantine effects (`quarantine_disputes_unwitnessed_records_but_keeps_sealed_ones_valid`,
`an_attestation_by_a_quarantined_witness_no_longer_seals`).
`tests/chain.rs::equivocation_is_violated_and_names_the_author` asserts the chain check
reports `Violated` and names both entries. The `vigil-sim` `equivocation` scenario
(`crates/vigil-sim/src/equivocation.rs`) runs the whole path from a seed — conviction,
one `ForkProof`, quarantine — **paired with its ablation**: the same held objects with an
empty quarantine versus one holding the convicted key, asserting that quarantine changes
only what a convicted key's attestations buy going forward, and never retroactively
unseals what an honest witness attested.

**Limit.** Fork detection needs a common witness. An equivocator showing chain A to one
peer and chain B to another is undetected until some node holds both branches; two nodes
that never share a peer never surface the fork (`spec/02` §8.8).

### 3.5 Thief

**Capability.** The actor steals a device and its key.

**Architecturally addressed, not implemented.** `docs/VIGILARCH.md` §5.3 and §18 assume
at-rest encryption keyed to a hardware-backed store, a short-lived data key, and
certificate revocation that gossips as a class-0 object and cuts the device off at next
contact. **v1 implements none of this and tests none of it.** Key management — rotation,
revocation gossip, remote wipe, HSM custody — is cut from v1 (`CLAUDE.md`; README).
Certificate issuance is stubbed, and a compromised device key is, in v1, unrecoverable:
the thief can sign new observations and new attestations under that key indefinitely, and
the only bound on the damage is that forged history still cannot escape its bracket
without producing a detectable fork (§2.4). This row is listed so that the gap is explicit
and not mistaken for a solved problem.

### 3.6 Eavesdropper

**Capability.** The actor taps a link or steals a mule carrying bundles.

**Architecturally addressed, not implemented.** `docs/VIGILARCH.md` §5.3 and §9 assume
payloads encrypted end-to-end to the org key, so a mule or a link tap sees ciphertext and
routing headers only. **v1 has no transport layer and no payload encryption.** Objects are
signed for integrity and attribution, not encrypted for confidentiality; `vigil-sim`
moves plaintext objects between nodes over a scripted link, and the export pack (`spec/03`
§2) is an unencrypted file. Confidentiality is entirely outside v1's scope. This row
exists to make that explicit: v1 defends the *integrity* of the timing claim, not the
*secrecy* of the record.

### 3.7 Compromised hub

**Capability.** The actor roots the cloud hub.

**Handled architecturally.** Invariant I1 is structural: the hub is a convenience peer
with no authority the edge nodes lack, and it is enforced by there being **no
hub-privileged code path** — neither `vigil-ledger`'s DAG, bracketing, or fork logic nor
`vigil-verify` consults a node's role, and a pack carries no node roles at all (`spec/03`
§2.2). A compromised hub cannot forge a site's signatures, cannot resolve a fork, and
cannot make its own attestations count for more than any other key's. If the hub burns
down the organisation loses convenience and nothing else.

**Limit.** A compromised hub *can* censor what it forwards. Edge-to-edge paths route
around it, and in the full design censorship then surfaces as coverage loss
(`docs/VIGILARCH.md` §5.3, §10). Coverage math is a v2 concern (`CLAUDE.md`), so v1
neither measures nor reports the coverage loss a censoring hub would cause — it only
guarantees that the hub gains no authority by censoring.

---

## 4. The backdating non-guarantee, stated once, plainly

Because it is the single claim most easily misread, it is stated here in one paragraph,
separately from the adversary row:

> **Vigilarch v1 does not detect backdating in general.** An actor who sets a false `hlc`
> on an observation and appends it honestly to their own chain — correct `prev`, correct
> `seq`, no second entry at that position — produces a record that passes every check the
> system performs. The chain verifies. The bracket is computed correctly, and the false
> `hlc` sits inside that bracket where it changes no bound. If the surrounding meetings are
> far apart, or the node has been isolated, the bracket is wide and the false timestamp is
> consistent with everything the system knows. Backdating becomes catchable **only** when
> it additionally requires equivocation: inserting a record at a `seq` position the chain
> has already committed, or presenting one witness a chain that another witness's
> attestation contradicts. Those are forks, and forks are detected and attributed
> (§3.4). A `sealed` verdict from `vigil-verify` means "this record provably existed no
> later than meeting `U`, and provably no earlier than meeting `L` in causal order" — it
> does **not** mean "this record's `hlc` is truthful". See `spec/02` §8.1–§8.2 and
> `docs/VIGILARCH.md` §4.5, §8.2.

---

## 5. Known gaps

These are documented in ADR-0003. They are surfaced here so a reader does not have to find
the ADR to learn the system's edges.

### 5.1 Seal-edge scope under equivocation (ADR-0003 Part 1)

`spec/02` §4.2's seal edge was originally written as a `seq`-number comparison: an
attestation anchoring an author's entry at `seq` *s* was taken to seal every held entry of
that author at `seq ≤ s`. Under equivocation — two entries at one `seq` — that would seal a
fork-branch sibling the witness never saw. The rule is corrected to a **`prev`-walk**: the
seal reaches only the chain ancestors of the anchored head, reachable by walking `prev`.
The two rules coincide on every unforked chain and diverge only under the exact
adversarial condition entanglement exists to catch.

**Status: resolved.** `crates/vigil-ledger/src/dag.rs` implements the `prev`-walk, `spec/02`
§4.2 is corrected, and the `vigil-sim` `equivocation` scenario asserts that a withheld
fork-branch sibling receives no seal edge from an attestation anchoring the other branch,
"despite sharing A's chain and `seq` with sealed O1". It is listed here because the
distinction matters to anyone reasoning about what a witness's attestation covers: a
witness seals what it *saw*, which is one chain walked back through `prev`, not every entry
that happens to carry a lower `seq`.

### 5.2 No cross-author DAG edges — the mule-relay gap (ADR-0003 Part 2)

An `Attestation` carries the subject's head but nothing about the witness's own chain
position. The three edge types in `spec/02` §4.2 therefore produce **no edge between two
different authors' chains**. A mule that entangles Site A and then Site B issues two
attestations, but nothing in wire version 1 records the order in which it issued them, so
no DAG edge connects them. The path `Site A ⟶ mule ⟶ Site B` does not exist in the current
graph.

**Consequence for the threat model.** Two sites connected *only* through a mule produce
`incomparable` records — the honest, conservative output (invariant I5), not a correctness
defect. An untrusted courier still tightens each site's *own* brackets independently; it
does not yet give the two sites an ordering relationship between them. The
`mule-relay` scenario (`spec/02` §9) and its `vigil-sim` scenario are **out of scope until
`witness_seq` is built** — a new `Attestation` field and a fourth edge type, requiring
its own ADR, a new golden vector, and the `spec/01` §11 additive-change process. None of
v1's sealing or bracketing guarantees depends on cross-author ordering; they are all
stated in terms of a single author's chain and its witnesses, and they hold exactly as
specified.

---

## 6. Adversaries assumed away

These match `docs/VIGILARCH.md` §5.3's explicit scope boundary. They are not weaknesses to
be fixed later; they are the assumptions the system is built on, and if one fails the
system's guarantees do not degrade gracefully — they are void.

- **A fully compromised organisation root key.** The org root is the trust anchor for
  device certificate issuance (`docs/VIGILARCH.md` §5.1). An attacker holding it can mint
  device keys at will, so "distinct witness keys" (§2.3) becomes meaningless and witness
  depth can be fabricated to any value. Nothing in Vigilarch defends against this, and
  `spec/02` §8.9 says so directly. v1 does not even implement issuance (§3.5), so in v1
  the org key is a label on a pack (`spec/03` §2.4), not an enforced root.
- **Physical coercion at the moment of capture.** If someone stands over a worker and
  dictates a false observation, the resulting record is a truthful record of what was
  entered and will seal normally. This is the real-time-lie non-guarantee (`spec/02`
  §8.5) in its most direct form. Making capture honest is a physical-security and
  process problem, not a cryptographic one.
- **Majority collusion to withhold en masse.** Vigilarch's forensic resolution is the
  contact frequency of honest nodes. If a majority of nodes in a region collude to not
  attest and not sync, the honest minority's records simply carry wide unwitnessed
  windows — which is the correct output, but it means collusion at that scale degrades the
  system to the genesis-isolation case (§2.3) for everyone caught behind it. Detecting
  coordinated silence is a v2 coverage concern and, past a threshold, is not detectable at
  all.

---

## 7. Non-guarantees carried from `spec/02` §8 and `spec/03` §7

This document does not restate them in full; they are normative there and apply unchanged.
In summary:

- An attestation is an **upper** bound on creation, never a lower one (`spec/02` §8.1).
- Genesis isolation is not detectable and must not raise an alarm (`spec/02` §8.2).
- The unwitnessed window is real time the system cannot account for; its width is not to
  be shrunk (`spec/02` §8.3, invariant I5).
- Every bound is relative, ultimately to the verification moment (`spec/02` §8.4,
  `spec/03` §7.3–§7.4).
- No defence against a real-time lie or against withholding (`spec/02` §8.5–§8.6).
- The HLC is never evidence (`spec/02` §8.7).
- Fork detection needs a common witness (`spec/02` §8.8).
- Distinct keys are not distinct parties (`spec/02` §8.9).
- A pack proves internal consistency, not completeness; a verified pack is a reproducible
  computation, not a certificate (`spec/03` §7.1, §7.6).

---

## 8. Changing this document

1. An ADR in `docs/adr/` recording what changed and why. A change that moves a row between
   the three categories of §3 — for example, implementing at-rest encryption and moving
   **Thief** from "architecturally addressed" to "handled and verified" — must cite the
   code and the tests that justify the move.
2. §2, §4, §5 and §6 may not be weakened or moved to an appendix without an ADR that
   argues, explicitly, why the weaker statement is still honest — the same rule `spec/02`
   §10 and `spec/03` §9 place on their non-guarantees.
3. This document tracks the wire version of `spec/01`. A wire-format change that adds
   `witness_seq` (§5.2) closes the mule-relay gap and requires this document to be updated
   in the same change set.
