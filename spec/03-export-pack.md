# 03 — Export pack

**Status:** draft. **Wire version:** `1`. **Milestone:** M1.

This document defines the **export pack**: the self-contained file a node produces so that
a third party — with no database, no network, and no Vigilarch node — can independently
check the bracket claims the node makes about its own records. It is the file format
`spec/02-entanglement.md` §7 requires and defers, and the input to `vigil-verify`.

It is normative. It introduces **no new object encodings** and **no new
hashing or signing scheme**: every object inside a pack is one of the types
`spec/01-wire-format.md` §6 already defines, carried in its existing canonical form, and
is self-certifying through its own content address and signature (`spec/01` §3–§4). The
pack adds only an outer **envelope** — a container and a file marker — which is itself
never hashed and never signed. The key words **MUST**, **MUST NOT**, **SHOULD**,
**SHOULD NOT** and **MAY** are used as in RFC 2119.

The pack's byte framing is a **file format, not a negotiated wire protocol** (`spec/02`
§7). There is no `hello`, no version negotiation, no session. A reader is handed a file
and either it verifies or it does not.

Changing this document requires an ADR in `docs/adr/`. The envelope reuses the `spec/01`
§2.1 canonical CBOR profile unchanged; a change to that profile is a `spec/01` change and
bumps the wire version there.

---

## 1. What a pack is for

A node claims things about its own history: *this observation was sealed by a meeting no
later than Tuesday*, *this record has an unwitnessed window three weeks wide*. `spec/02`
§5 defines how those claims are computed from the attestation DAG. A pack is how the node
hands the **evidence for a specific set of those claims** to someone who will re-derive
them from scratch and reach their own verdict.

A pack proves exactly one kind of thing: that the objects it carries are internally
consistent and correctly signed, and that a named set of bracket claims **follows from
those objects** under the `spec/02` §4–§5 rules. It is not a ledger dump, not a backup,
and not an audit of everything the node holds — see §4 and §7.

The verifier's discipline is `spec/02` §7: it rebuilds the DAG with its **own**
traversal, recomputes every bracket, and where its DAG does not force an ordering it
reports `unwitnessed` and an open window. It never interpolates and never reports a bound
the pack's evidence does not force. A verifier that overstates is worse than none,
because it launders an unproven claim into an apparent independent confirmation.

---

## 2. The envelope

### 2.1 File marker

A pack file begins with the ASCII marker and one NUL byte, then the canonical CBOR
encoding of the envelope map:

```
pack_file = "vigilarch/1/pack" || 0x00 || canonical_cbor(envelope)
```

This mirrors the domain-separation form of `spec/01` §3.1 **for recognisability only**.
Nothing hashes or signs `pack_file`; the marker is a file-type tag and an explicit wire
version, not a hash preimage. The `1` is the wire version (`spec/01` §3.1): a pack is
tied to exactly one wire version, because every content address inside it is.

A reader MUST reject a file whose first bytes are not exactly `vigilarch/1/pack\x00`, and
MUST reject a file with trailing bytes after the complete envelope (`spec/01` §8).

### 2.2 Envelope fields

The envelope is a CBOR map under the `spec/01` §2.1 profile: definite lengths, shortest
form, keys sorted ascending, no floats, no tags, no null. Field numbers are permanent.

| # | Field | Type | Opt |
|---|---|---|---|
| 1 | `wire_version` | `uint`, MUST equal `1` | |
| 2 | `org` | `PubKey` — the issuing organisation's public key | |
| 3 | `observations` | `[ carried_object, ... ]` ascending by recomputed id | |
| 4 | `attestations` | `[ carried_object, ... ]` ascending by recomputed id | |
| 5 | `fork_proofs` | `[ bstr, ... ]` — each the full domain-separated preimage of a `ForkProof` (`spec/01` §6.7), ascending by recomputed id | opt |
| 6 | `claims` | `[ Hash, ... ]` — the observation id of each bracket claim, ascending, duplicate-free | |

`carried_object` is a 2-element array `[ preimage: bstr, sig: bstr of 64 bytes ]`, where
`preimage` is the object's **full domain-separated preimage** — `tag || 0x00 ||
canonical_cbor` (`spec/01` §3.1) — and `sig` is its detached Ed25519 signature. This is
the same self-contained carriage a `ForkProof` uses for its two entries (`spec/01` §6.7),
applied to whole observations and attestations: a reader that holds neither the object
nor any chain it belongs to can still recompute `id = BLAKE3-256(preimage)` and verify
`sig` against the appropriate key.

`fork_proofs` entries are carried as a bare preimage rather than a `[preimage, sig]` pair
because a `ForkProof` is not a signed object — it is self-verifying from the two
signatures it already contains (`spec/01` §6.7).

### 2.3 Determinism

Two exporters producing a pack for the same claims from the same held objects MUST
produce **byte-identical files**. Every list in §2.2 is ordered by recomputed content
address; the envelope map obeys the `spec/01` §2.1 key ordering; an omitted-because-empty
`fork_proofs` field is omitted, never an empty array (`spec/01` §2.3). This is the same
requirement `spec/02` §4.7 places on DAG construction, extended to the file.

### 2.4 The envelope is not evidence

`org` is carried so a pack is bound to a stated issuer and so a verifier can refuse a
pack meant for a different organisation (§5 step 1). In v1 **no certificate chain is
checked against it** — key issuance is stubbed (README; `spec/04-threat-model.md`). It is
a label that becomes load-bearing when issuance lands, not a signature root today.

No field of the envelope is signed. Corrupting the envelope's framing produces a decode
failure; corrupting a carried object is caught by that object's own id/signature check
(§5). There is deliberately nothing else to attack in the envelope, because there is
nothing else in it.

---

## 3. What goes in a pack

For **every** claim in `claims`, the pack MUST contain all of the following. This is
`spec/02` §7 made concrete.

### 3.1 The claimed observation

The observation named by the claim, as a `carried_object` in `observations`.

### 3.2 The author's chain segment — and how far "far enough" reaches

The chain of the claimed observation's `author`, contiguous by `seq`, from **genesis** —
or from the earliest entry the exporter holds, in which case the pack MUST mark it (§3.5)
— **up to and including the furthest entry any attestation in the pack anchors on**, which
may be past the claimed record.

This is the precise content of `spec/02` §7's "the chains of every witness far enough to
anchor their seal edges (§4.5)". Unpacking it against the reference implementation
(`crates/vigil-ledger/src/dag.rs`):

- A seal edge (`spec/02` §4.2) is drawn from an observation to an attestation `X` only
  when the verifier **holds the entry that `X.subject_head` recomputes to**, and that
  entry's `author` equals `X.subject` and its `seq` equals `X.subject_seq`. That held
  entry is the **anchor**. An attestation whose anchor is not held produces **no seal
  edge** (`spec/02` §4.5) — it seals nothing.
- From the anchor, the seal reaches every entry on the chain **walked back through
  `prev`** — the chain ancestors of the anchored head, not every entry at a lower `seq`
  (ADR-0003 Part 1). So to reproduce a seal edge, the verifier needs the anchor entry
  *and* every `prev` predecessor down to genesis.
- The anchor is always an entry of the **subject's** chain. In wire version 1 the DAG has
  **no edge between two different authors' chains** (ADR-0003 Part 2), so the only chain a
  claim's reachable closure (§3.3) touches is the claimed observation's own author's
  chain. Every attestation that seals the claim therefore has `subject == author`, and
  every anchor the pack must satisfy is an entry of that one chain.

Concretely: if the claim is about entry `r` and the latest sealing attestation anchors on
entry `k > r` (a witness met the author after `r` was written), the segment runs
`0 … k`, not `0 … r`. "Far enough" is `max(r, greatest subject_seq among carried
attestations)`.

> **Why not literally "the witness's chain"?** `spec/02` §7's wording anticipates the
> wire-version-2 witness-order edge (ADR-0003 Part 2), which will let an attestation's own
> witness chain enter a closure. Until that edge exists, a witness contributes exactly one
> vertex — its signed attestation — and none of its own observations. A v1 pack carries no
> witness-chain entries, and a verifier neither expects nor uses them.

### 3.3 The reachable attestation closure

Every attestation `X` for which either `claim ⟶ X` or `X ⟶ claim` holds in the pack's
DAG — the transitive closure of attestations reachable **to and from** the claimed
observation along `spec/02` §4.2 edges — as `carried_object`s in `attestations`.

In v1 this is precisely: every attestation with `subject == author` that is anchored by
an entry in the §3.2 segment and either seals the claim (reachable *from* it) or is acked
by an entry at or below the claim's `seq` (reachable *to* it, the lower bound, `spec/02`
§5.3). Attestations by the author about itself are included if reachable but contribute
no bound (`spec/02` §4.4).

The exporter MUST NOT omit a reachable attestation that would *widen* a bracket by its
absence — that would be manufacturing a tighter claim than the full evidence supports,
the inverse of the §7 minimisation property and a violation of invariant I5. Adding
attestations only ever narrows a bracket (`spec/02` §5.5); a pack MUST carry all of them
that the DAG reaches.

### 3.4 Fork proofs touching any key involved

Every `ForkProof` the exporter holds that convicts **any key that appears** as an
`author`, a `subject`, or a `witness` anywhere in the pack, in `fork_proofs`.

A fork proof against a witness key means that witness is quarantined and its attestations
**stop sealing** from then on (`spec/02` §6.5); a verifier that does not receive the
proof would compute a bracket the exporter knows to be unsound. A fork proof against the
author means the author's unwitnessed records are `disputed` (`spec/02` §6.4). Omitting a
held, relevant fork proof is the one omission that can make a pack *overstate*, so it is
forbidden rather than merely discouraged: an exporter that holds such a proof and leaves
it out has produced an invalid pack.

### 3.5 The "earliest held" marker

When the author's chain segment does not start at `seq` 0, the pack MUST record that the
segment is partial, so the verifier reports the unwitnessed window as open below to the
**earliest held entry** rather than to genesis, and never claims `Verified` for that
chain (`spec/01` §6.6: a missing `seq` is `Incomplete`, not `Verified`). The marker is
carried as: the lowest-`seq` entry in `observations` for that author has `seq > 0`, which
the verifier detects directly — no separate flag field. A verifier seeing a lowest held
`seq` of `n > 0` MUST treat sequences `0 … n-1` as `Incomplete`, not absent-through-tamper.

---

## 4. What a pack leaves out — a minimisation property, not an accident

A pack is **the smallest set of objects from which the stated claims follow**. Everything
else the node holds is deliberately excluded:

- **Records not named in `claims`.** A node may hold thousands of observations; a pack
  about one incident carries that incident's bracket evidence and nothing else.
- **Body content beyond the claimed observations themselves.** The chain segment (§3.2)
  is needed for its `prev` links and its `acks`, not for its prose — but an `Observation`
  is immutable and atomic (invariant I3), so its body travels with it. A pack does not
  add *other* records' bodies, media blobs (there are none in v1 anyway), or tags beyond
  the claimed entries.
- **Attestations, checkpoints, and chains not reachable from any claim.** An attestation
  that neither seals nor precedes any claimed record is not evidence for any claim in the
  pack and MUST NOT be included. Checkpoints are never included — they are not DAG
  vertices (`spec/02` §2.3).
- **The witness's own history.** See §3.2: a v1 witness is one vertex, its attestation.

Stated as a property: **a pack proves ordering; it is not required to be a full ledger.**
A third party checking a bracket claim about one incident learns the chain structure and
meeting history *around that incident* and nothing about the site's other activity. This
is a privacy and data-minimisation guarantee, and it is a reason to prefer packs over
raw ledger sharing, not merely a consequence of how the exporter is written.

The limit of the property is §7.2: minimisation is bounded below by soundness. An exporter
removes what the claims do not need; it MUST NOT remove what would change a verdict.

---

## 5. Verification procedure

`vigil-verify <pack> <org-pubkey>` performs exactly these steps, in order, with its own
code — not by calling `vigil-ledger` (`spec/02` §7). `vigil-verify` depends only on
`vigil-core`: its chain check, DAG construction and bracketing are a **second
implementation** written from this document, not a call into the code that produced the
pack, because a verifier that shares the exporter's traversal reproduces the exporter's
bugs with total confidence (ADR-0005). It builds no database and opens no socket.

1. **Envelope.** Check the file marker (`§2.1`). Decode the envelope under the `spec/01`
   §2.1 profile with the `spec/01` §8 decoder — total rejection on any violation, no
   lenient mode. Check `wire_version == 1`. Check `org` equals the `<org-pubkey>`
   argument; if not, reject the pack — it is not the organisation the caller asked about.
2. **Per-object self-check.** For every `carried_object`: recompute `id =
   BLAKE3-256(preimage)`, decode the preimage as its declared type (`spec/01` §6),
   verify `sig` — against `author` for an observation, against `witness` for an
   attestation (`spec/01` §4). An object failing any check is **discarded and contributes
   nothing** (`spec/01` §3.2, §8); the verifier records that the pack contained an
   invalid object.
3. **Fork proofs.** Validate each `ForkProof` self-contained (`spec/01` §6.7). For each
   valid one, mark its `key` quarantined for the rest of this run.
4. **Chain check.** For each author present, run the `spec/01` §6.6 three-outcome check
   over the carried segment: `Verified` / `Incomplete { missing }` / `Violated`. A
   missing low `seq` from §3.5 is `Incomplete`, never `Violated`.
5. **DAG.** Build the attestation DAG (`spec/02` §4) from the surviving objects, dropping
   seal edges from any quarantined witness (`spec/02` §6.5).
6. **Brackets.** For each id in `claims`, recompute `bracket()` (`spec/02` §5). Report,
   per claim: `sealed` / `unwitnessed`; the upper-bound attestation if any; witness
   depth; the lower-bound attestation if any; the unwitnessed window, with the lower edge
   reported as an attestation, as `genesis` **only when `seq` 0 is held**, or otherwise as
   "open below to the earliest held entry (`seq` n)" (§3.5), and the upper edge as an
   attestation or as the verification moment; `disputed` if the author is quarantined and
   the record is unwitnessed; and any fork proof touching a key in the claim.

Where step 6's DAG does not establish an ordering, the bound is `None` and the window is
open on that side. The verifier does not fill it in.

---

## 6. Worked example

One observation, one entry extending its chain to the witnessed head, one sealing
attestation. Every byte below is derivable from `spec/01` §2–§6, `spec/02` §4–§5, and
this document, with no reference to the implementation — the same test `spec/01` §10
sets itself.

### 6.1 Scenario

- **A** (`author`, signing-key seed `0001…1f`, from `spec/01` §10) writes a genesis note
  `A@0`, then a second note `A@1`.
- **A** meets witness **W** (signing-key seed `8081…9f`) after `A@1` is written. W signs
  one attestation `U` about A's head, anchoring `A@1`.
- The exporter states one claim: **bracket `A@0`**.

| Key | Value |
|---|---|
| `author` A | `03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8` |
| `witness` W | `cd14b37f956e953194ff7fb73b3d81dcc561d61a7538094b7c3e1a643ee5f3aa` |
| `org` | `d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737` (seed `11…11`) |

### 6.2 The three objects

**`A@0`** — the `spec/01` §10 genesis note, reproduced here (CBOR 111 bytes, preimage 135):

```
id  = 7431f38ed1c31a3ef917bd60cd0b52f14c41b49ac8af5796b6c0fc3fba0aac1d
sig = ddb1adecbbaea87a5b7454af66ab0a52b99b14acb3bb04eb4226668717bf5943
      4f54760eaa80e54bc2b568f0f316be5c369b610e5ea990586395b816ce751a07   (by A)
preimage_hex =
766967696c617263682f312f6f62736572766174696f6e00a601582003a107bff3ce10be1d
70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b80250564947494c415243482d5349
54452d410340040005821b0000018bcfe5680000068200a101782273686f72696e67206f6e
2067726964204234206973206f7574206f6620706c756d62
```

**`A@1`** — `Note`, `prev = id(A@0)`, `seq 1`, `hlc [1700000100000, 0]`, body text
`"grid B4 shoring re-checked, area now clear"` (42 bytes), no `geo`, no `acks`.
CBOR 152 bytes, preimage 176:

```
a6
  01 5820 03a107…31b8                                author A
  02 50   564947494c415243482d534954452d41          site VIGILARCH-SITE-A
  03 5820 7431f38ed1c31a3ef917bd60cd0b52f14c41b49ac8af5796b6c0fc3fba0aac1d   prev = id(A@0)
  04 01                                              seq = 1
  05 82 1b 0000018bcfe6eea0 00                       hlc = [1700000100000, 0]
  06 82 00 a1 01 782a 677269…636c656172             body = [0, {1: "grid B4 … clear"}]

id  = 89c08f4dd2da45f1e376c8326309a1d60c1932b88bdc466de8abfe4367cd7817
sig = 8c1f910e75989d8dde4c172e5db7f5a4a0198c7abef40b40344e7b99e2fb2a358
      fa93ca691fe25848c96c7c0add3626eca0154c71cad0cc9fa82a1a5cfe22a04     (by A)
preimage_hex =
766967696c617263682f312f6f62736572766174696f6e00a601582003a107bff3ce10be1d
70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b80250564947494c415243482d5349
54452d410358207431f38ed1c31a3ef917bd60cd0b52f14c41b49ac8af5796b6c0fc3fba0a
ac1d040105821b0000018bcfe6eea000068200a101782a677269642042342073686f72696e
672072652d636865636b65642c2061726561206e6f7720636c656172
```

**`U`** — `Attestation`, `witness W`, `subject A`, `subject_head = id(A@1)`,
`subject_seq 1`, `witness_hlc [1700000100000, 0]`, `nonce a0a1…af`.
CBOR 138 bytes, preimage 162:

```
a6
  01 5820 cd14b37f…5f3aa                             witness W
  02 5820 03a107bf…31b8                              subject A
  03 5820 89c08f4dd2da45f1e376c8326309a1d60c1932b88bdc466de8abfe4367cd7817   subject_head = id(A@1)
  04 01                                              subject_seq = 1
  05 82 1b 0000018bcfe6eea0 00                       witness_hlc = [1700000100000, 0]
  06 50 a0a1a2a3a4a5a6a7a8a9aaabacadaeaf             nonce

id  = 8341ec97be1a4525e0d784def0100a79173168f0c5f8d997bf8057677eb041b6
sig = 34e147f813fd6287f6a0b841465cf5b34abccf9cbfe00548362fafaf280667d41
      2ef83a75333dfbc63340331ad32d9528be9971e12d22c87cb3b395dd481e706     (by W)
preimage_hex =
766967696c617263682f312f6174746573746174696f6e00a6015820cd14b37f956e953194
ff7fb73b3d81dcc561d61a7538094b7c3e1a643ee5f3aa02582003a107bff3ce10be1d70dd1
8e74bc09967e4d6309ba50d5f1ddc8664125531b803582089c08f4dd2da45f1e376c8326309
a1d60c1932b88bdc466de8abfe4367cd7817040105821b0000018bcfe6eea0000650a0a1a2a
3a4a5a6a7a8a9aaabacadaeaf
```

Note `subject_seq = 1`, one past the claimed `A@0`: W saw A's chain at `A@1`. Per §3.2
the pack's author segment therefore runs `A@0, A@1`, not `A@0` alone.

### 6.3 The envelope

`claims = [ id(A@0) ]`. `observations = [ A@0, A@1 ]` (ordered by id: `7431…` < `89c0…`).
`attestations = [ U ]`. `fork_proofs` omitted — none held. Envelope CBOR 758 bytes;
file with marker, 775 bytes:

```
file_hex =
766967696c617263682f312f7061636b00a50101025820d04ab232742bb4ab3a1368bd46
15e4e6d0224ab71a016baf8520a332c97787370382825887766967696c617263682f312f
6f62736572766174696f6e00a601582003a107bff3ce10be1d70dd18e74bc09967e4d630
9ba50d5f1ddc8664125531b80250564947494c415243482d534954452d41034004000582
1b0000018bcfe5680000068200a101782273686f72696e67206f6e206772696420423420
6973206f7574206f6620706c756d625840ddb1adecbbaea87a5b7454af66ab0a52b99b14
acb3bb04eb4226668717bf59434f54760eaa80e54bc2b568f0f316be5c369b610e5ea990
586395b816ce751a078258b0766967696c617263682f312f6f62736572766174696f6e00
a601582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8
0250564947494c415243482d534954452d410358207431f38ed1c31a3ef917bd60cd0b52
f14c41b49ac8af5796b6c0fc3fba0aac1d040105821b0000018bcfe6eea000068200a101
782a677269642042342073686f72696e672072652d636865636b65642c2061726561206e
6f7720636c65617258408c1f910e75989d8dde4c172e5db7f5a4a0198c7abef40b40344e
7b99e2fb2a358fa93ca691fe25848c96c7c0add3626eca0154c71cad0cc9fa82a1a5cfe2
2a0404818258a2766967696c617263682f312f6174746573746174696f6e00a6015820cd
14b37f956e953194ff7fb73b3d81dcc561d61a7538094b7c3e1a643ee5f3aa02582003a1
07bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b803582089c08f
4dd2da45f1e376c8326309a1d60c1932b88bdc466de8abfe4367cd7817040105821b0000
018bcfe6eea0000650a0a1a2a3a4a5a6a7a8a9aaabacadaeaf584034e147f813fd6287f6
a0b841465cf5b34abccf9cbfe00548362fafaf280667d412ef83a75333dfbc63340331ad
32d9528be9971e12d22c87cb3b395dd481e706068158207431f38ed1c31a3ef917bd60cd
0b52f14c41b49ac8af5796b6c0fc3fba0aac1d
```

### 6.4 Honest verification result

Steps from §5:

1. Marker `vigilarch/1/pack\x00` present; envelope decodes; `wire_version == 1`; `org`
   matches. OK.
2. `id(A@0) = 7431f38e…` and `sig` verifies under A. `id(A@1) = 89c08f4d…`, `sig`
   verifies under A. `id(U) = 8341ec97…`, `sig` verifies under W. All three are vertices.
3. No fork proofs.
4. Chain of A over `{A@0 seq 0, A@1 seq 1}`: `A@1.prev` recomputes to `id(A@0)`; every
   `seq` from 0 to 1 present once → **`Verified`**.
5. DAG over `{A@0, A@1, U}`:
   - chain edge `A@0 → A@1`;
   - `U` anchors: `observations[U.subject_head] = A@1`, `A@1.author == A == U.subject`,
     `A@1.seq == 1 == U.subject_seq`. Walk `prev` from `A@1`: `A@1`, then `A@0`, then
     genesis. Seal edges `A@1 → U` and `A@0 → U`.
6. `bracket(A@0)`:
   - sealing attestations reachable from `A@0` with `witness ≠ A`: `{U}` → **`sealed`**;
   - upper bound `U`; witness depth **1**;
   - attestations reachable *to* `A@0`: none → lower bound **`None`**;
   - unwitnessed window **`[Genesis, Attestation(8341ec97…)]`** — sealed above by the
     meeting, honestly open below to genesis (`spec/02` §8.1).

This is the canonical sealed case (`spec/02` §5.1), and it matches the `honest-partition`
/ minimal `vigil-sim` scenario's assertion.

### 6.5 Tampering

Each case takes the honest pack of §6.3 and makes **one** change. The point is that the
three failures are *distinct* and a verifier must name them distinctly — this is the
taxonomy `vigil-verify` is tested against.

**T1 — flip one byte in the claimed observation.** Change the final body byte of `A@0`
from `0x62` (`b`) to `0x63` (`c`). The verifier recomputes
`id = 500f43f4165deeeeeb0f4e8a1af6ed1a87d7ed70243548f860a221637b15a51e`, and the carried
`sig` (over `7431f38e…`) fails under A. Per §5 step 2 the object is **discarded**. Now:

- `claims` names `7431f38e…`, and no surviving object has that id →
  **claim unverifiable: claimed observation absent / failed its self-check**;
- chain of A over `{A@1 seq 1}` → **`Incomplete { missing: [0] }`**.

Conclusion: *the pack does not contain the record it claims about.* One flipped byte does
not forge anything; it removes the object.

**T2 — substitute a validly re-signed genesis.** Replace `A@0` with `A@0″`: identical
fields except `hlc` counter `0 → 1`, re-signed by A. `A@0″` passes its own self-check —
`id = 7ecd2314322d98e1a2efde2db4abd4d8dfed085ed4ead71aad776e3e571de718`, valid signature.
But now the chain of A over `{A@0″ seq 0, A@1 seq 1}`:

- `A@1.prev = 7431f38e…`; the held predecessor at `seq 0` is `A@0″` with
  `id = 7ecd2314…`; `prev` matches nothing held →
  **`Violated`: `BrokenLink { author: A, seq: 1, entry: id(A@1), claimed_prev: 7431f38e…,
  predecessor: [7ecd2314…] }`** (`spec/01` §6.6).

And the claim still names `7431f38e…`, which is absent → claim unverifiable. Conclusion:
*someone re-encoded the genesis; the hash chain does not close.* This is an attributable
integrity finding against A's key, not a slow-link `Incomplete`.

**T3 — drop the anchor entry.** Remove `A@1` from `observations`; keep `A@0` and `U`.
Every surviving object self-checks. Chain of A over `{A@0 seq 0}` → **`Verified`**
(genesis only, complete to the highest held). But in the DAG:

- `U.subject_head = 89c08f4d…` (= `id(A@1)`) names an entry the verifier does not hold →
  **no seal edge** (`spec/02` §4.5); `U` seals nothing.
- `bracket(A@0)`: no sealing attestation → **`unwitnessed`**, window
  **`[Genesis, VerificationMoment]`**.

Conclusion: *the pack carries an attestation it cannot anchor, so the record is reported
unwitnessed, not sealed.* The verifier refuses to seal on evidence it cannot check — the
conservative outcome (invariant I5). An exporter that produced this pack either omitted a
required entry (§3.2 — an invalid pack) or is probing whether the verifier will seal
anyway.

---

## 7. What this format does not claim

Stated as prominently as §3, mirroring `spec/02` §8, because a file that is trusted for
more than it proves is worse than no file.

**7.1 A pack proves internal consistency, not completeness.** Verification establishes
that the objects in the pack are well-formed, correctly signed, chain-consistent, and
that the stated brackets follow from them. It does **not** establish that the exporter
included every record, or every *sealed* record, or the most inconvenient one. Omission
is not something a file format can prevent: a node can always decline to export a record,
just as it can decline to sync one (`spec/02` §8.6). A pack answers "does this claim
follow from this evidence", never "is this all the evidence".

**7.2 A pack is only as sound as the widest evidence the exporter chose to include.**
Minimisation (§4) is bounded by §3: an exporter MUST include every reachable attestation
and every relevant fork proof, because those can only *widen* a bracket or invalidate it.
But a verifier cannot tell, from the pack alone, that the exporter honoured that
obligation for evidence the verifier never sees. A pack that omits a fork proof against
its own witness is invalid, and a verifier holding that proof from elsewhere will catch
it — but the pack does not carry a proof of its own good faith.

**7.3 The verifier's clock is not evidence.** `VerificationMoment` is the only absolute
reference point, and it is "now, on the machine running `vigil-verify`" — an upper bound
on an open window, nothing more. No `hlc` or `witness_hlc` in any carried object is read
as time (`spec/01` §5.1, `spec/02` §8.7).

**7.4 A sealed claim is an upper bound only.** Everything `spec/02` §8.1–§8.4 says about
brackets applies unchanged to a bracket recomputed from a pack. "Sealed by `U`" means
"existed no later than the meeting `U` records", relative to other chain events and
ultimately to `VerificationMoment`. It is never a lower bound and never a wall-clock
timestamp.

**7.5 The envelope authenticates nothing.** `org` is a label (§2.4). A pack is not signed
as a whole and does not need to be: its objects carry their own signatures, and a
tampered object fails its own check (§6.5). "This pack was assembled by that
organisation" is not a claim the format makes.

**7.6 A verified pack is not a certificate.** It is a reproducible computation. Anyone
with the pack and `vigil-verify` reaches the same verdict; the verdict has no authority
beyond the evidence, and re-running it is the only thing that makes it true. There is no
signature from Vigilarch, no registry, and nothing to revoke.

---

## 8. Test obligations

Mirroring `spec/01` §9 and `spec/02` §9: the evidence lands with or before the code.

**Golden vector** (`testdata/vectors/`, part of this spec, changes need an ADR):

- `pack/worked-example` — the §6.3 file, pinning the envelope encoding, the
  `carried_object` shape, and the list ordering. A byte-drift test fails on any change.

**`vigil-verify` fixtures** (`testdata/packs/`):

- the honest §6.3 pack, asserting the §6.4 result exactly;
- the T1, T2, T3 packs, each asserting its distinct §6.5 verdict — claim-absent,
  `BrokenLink`, and `unwitnessed`-via-unanchored respectively;
- a pack with a fork proof against the witness, asserting the seal is dropped and the
  claim reported `unwitnessed` (`spec/02` §6.5);
- a pack with the author's chain starting at `seq > 0` (§3.5), asserting the window is
  reported open to `EarliestHeld`, not `Genesis`, and the chain reported `Incomplete`.

**Property tests:** pack assembly is deterministic (§2.3) — the same claims over the same
held set produce a byte-identical file on two machines; `vigil-verify`'s recomputed
bracket for a claim equals `vigil-ledger`'s `bracket()` over the same object set (the two
independent traversals agree on honest input). Because `vigil-verify` may not link
`vigil-ledger` (ADR-0005), the ledger's side of that equality is generated ahead of time
by `cargo run -p vigil-ledger --example gen_pack_verdicts`, checked in under
`testdata/packs/expected/`, and CI-diffed for reproducibility like the pack fixtures
themselves; `vigil-verify`'s test then asserts its own traversal reproduces it.

**Fuzz:** the envelope decoder is on the `spec/01` §8 attack surface — a pack is a file
from an untrusted party — and every path from `pack_file` bytes to a verdict is fuzzed.
A panic is a bug of the same severity as accepting a bad signature.

---

## 9. Changing this document

1. An ADR in `docs/adr/` recording what changed, what was rejected, and the effect on
   existing packs and on `vigil-verify`.
2. No wire version bump for an additive envelope field with a fresh permanent number
   (`spec/01` §11) — but a new golden vector and the ADR are required. A change to a
   carried object's encoding is a `spec/01` change and bumps the wire version there,
   which changes every id in every pack.
3. §7 may not be weakened or moved to an appendix without an ADR that argues, explicitly,
   why the weaker statement is still honest — the same rule `spec/02` §10 places on its
   non-guarantees.
