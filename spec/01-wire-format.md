# 01 — Wire format

**Status:** draft. **Wire version:** `1`. **Milestone:** M0.

This document defines the canonical encoding, content addressing and signature scheme
for every Vigilarch object, and the version negotiation that guards changes to them.

It is normative. Where it and `docs/VIGILARCH.md` disagree, this document wins for
anything on the encoding path — `docs/VIGILARCH.md` is the original design document and
predates a scope cut. Anything off that path — project scope, and the invariants this
encoding serves — is governed by the [README](../README.md#invariants). The key words
**MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are used as in RFC 2119.

Changing an existing encoding in §2 through §6 changes every content address in history,
and requires an ADR in `docs/adr/` and a wire version bump, without exception. Purely
additive changes — a new optional field, a new object type — take an ADR and new vectors
but not a version bump; see §11.

---

## 1. What is at stake

Two nodes that encode the same object MUST produce byte-identical output — on native
and under WASM, on any CPU, under any compiler version. If they do not, their content
addresses differ, which means the same observation exists under two ids, which means the
ledger silently forks and every ordering claim built on it is void.

That failure is silent. Nothing crashes, no test goes red, and the divergence surfaces
weeks later as an unexplained fork in a partition trace. The rules below exist to make
that outcome impossible rather than unlikely, and several of them are stricter than they
need to be for that reason.

---

## 2. Canonical encoding

Vigilarch uses a restricted profile of CBOR (RFC 8949). The profile is deterministic
encoding as defined in RFC 8949 §4.2.1, with three further restrictions of our own.

### 2.1 The profile

An encoder producing a preimage MUST obey all of the following. A decoder MUST reject
input that violates any of them.

1. **Definite lengths only.** Indefinite-length arrays, maps, byte strings and text
   strings MUST NOT appear. (Major type 7, additional information 31 — the "break" byte
   `0xff` — MUST NOT appear.)
2. **Shortest-form arguments.** Every head MUST use the shortest additional-information
   encoding that represents its argument: `0x00` for zero, never `0x1800`.
3. **Map keys sorted.** Map keys MUST appear in ascending bytewise lexicographic order
   of their own encoded bytes. Duplicate keys MUST NOT appear.
4. **No floating point.** See §2.2.
5. **No tags.** Major type 6 MUST NOT appear. Vigilarch defines no CBOR tags, and a
   decoder MUST reject any it sees rather than skipping it.
6. **No null, no undefined, no simple values** other than the booleans `false` (`0xf4`)
   and `true` (`0xf5`). An absent optional field is absent (§2.3), never null.
7. **Text strings MUST be valid UTF-8** and MUST be encoded exactly as captured. An
   encoder MUST NOT normalise, trim, case-fold or reorder text. Normalisation is a
   capture-time policy question; applying it at encode time would make the id depend on
   which library version was linked.

### 2.2 No floating point, and what to use instead

Float values (`0xf9`, `0xfa`, `0xfb`) MUST NOT appear anywhere in a preimage.

The reason is not aesthetic. Negative zero and positive zero compare equal but encode
differently; NaN has 2^52 distinct payloads that are all "the same" value; and the choice
of half versus single versus double precision for a given value is a property of the
encoding library, not of the number. Any of those makes byte-identical output across
native and WASM a matter of luck.

Quantities that would naturally be floats are carried as scaled integers with a
spec-defined scale:

| Quantity | Representation |
|---|---|
| Latitude, longitude | signed integer microdegrees (10^-6 degrees) |
| Horizontal accuracy | unsigned integer millimetres |
| Sensor reading | `[mantissa: int, exponent: int]`, value = mantissa x 10^exponent |
| Coverage fraction | unsigned integer parts-per-million, 0 to 1000000 |

A reader who needs a float converts on the way out. Nothing converts on the way in.

### 2.3 Field numbering and absent fields

Every object is a CBOR map whose keys are **small unsigned integers assigned by this
document**, not text field names. Field numbers are permanent: once assigned, a number is
never reused for a different meaning, and a retired field's number is never reallocated.

An optional field that has no value MUST be omitted from the map entirely. It MUST NOT be
encoded as null, as a zero value, or as an empty container. Two objects that differ only
in whether an optional field is present-and-empty versus absent would otherwise have
different ids while meaning the same thing.

Because keys are integers in the range 0 to 23, they each encode as a single byte equal
to the key number, so ascending numeric order and ascending bytewise order coincide.
Encoders SHOULD still sort explicitly rather than relying on that coincidence, because it
stops holding at key 24.

### 2.4 ciborium is transport framing only — never the preimage path

**Normative:** `ciborium`, and `serde` derives generally, MUST NOT be used to produce any
byte sequence that is hashed into a content address or signed. The canonical preimage is
constructed explicitly by `vigil-core` from the field tables in §6. `ciborium` MAY be
used for transport framing, local configuration, and diagnostics.

The reason is that a `serde` derive takes its field order, its enum tagging and its
handling of optional fields from the Rust source. A developer reordering two struct
fields for readability, renaming an enum variant, or changing optional-field handling in
a `#[serde(...)]` attribute would change every id in history — with no compile error, no
failing unit test, and no visible symptom until two builds of different vintage disagree
about the id of the same observation. The encoding contract must live in this document
and be readable from it, not be an emergent property of a struct definition.

`ciborium` is also not deterministic by default: it does not guarantee sorted map keys or
shortest-form arguments. Even used carefully it is the wrong tool for this path.

This rule is enforced in review and SHOULD be enforced mechanically — a test asserting
that `vigil-core`'s preimage builder reproduces the golden vectors in `testdata/` will
catch any accidental substitution.

---

## 3. Content addressing

### 3.1 Domain separation

Every hash input is prefixed with a domain separation tag identifying what is being
hashed. The tag is US-ASCII, contains no NUL byte, and is followed by exactly one NUL
byte:

```
preimage = tag || 0x00 || canonical_cbor(fields)
id       = BLAKE3-256(preimage)
```

Because no tag contains NUL, this concatenation is injective: no two (tag, body) pairs
produce the same preimage. Without domain separation, an attacker who could make one
object type's encoding coincide with another's would hold a signature valid for both.

| Object | Tag |
|---|---|
| Observation | `vigilarch/1/observation` |
| Blob manifest | `vigilarch/1/blob` |
| Assertion | `vigilarch/1/assertion` |
| Checkpoint | `vigilarch/1/checkpoint` |
| Attestation | `vigilarch/1/attestation` |
| Fork proof | `vigilarch/1/forkproof` |
| Signature input | `vigilarch/1/sig` |

The version component of the tag is the wire version (§7). Bumping the wire version
therefore changes every id, which is the intended behaviour: objects from different wire
versions are different objects and MUST NOT be conflated.

An `id` is the full 32-byte BLAKE3 output. Truncated ids MUST NOT be used on the wire;
short forms are a display convenience only.

### 3.2 An id is never accepted from the wire

**Normative:** an `id` field MUST NOT appear in any preimage — it cannot, being the hash
of that preimage — and MUST NOT appear in any transport frame. A receiver computes the id
itself from the received preimage and uses that value. If a frame carries a field
purporting to be an id, the receiver MUST reject the frame as malformed.

The `id` field shown in `docs/VIGILARCH.md` §7.2 is an in-memory convenience: a value
cached on construction and on receipt. It is not part of the object's identity on the
wire.

Accepting an id from a peer would let a node assert that arbitrary bytes have an
arbitrary address, which is the whole game. This rule is also why there is no "id
mismatch" error path to get subtly wrong.

### 3.3 Blobs

A blob is addressed by the hash of its *manifest* (§6.2), not of its contents. Each chunk
is separately addressed by `BLAKE3-256(chunk_bytes)` with no domain separation tag,
because chunks are opaque byte ranges rather than Vigilarch objects and are content
addressed for deduplication rather than for identity. Chunk size is 1 MiB except for the
final chunk of a blob.

---

## 4. Signatures

Signatures are Ed25519 (RFC 8032), over a domain-separated commitment to the id:

```
sig = Ed25519-Sign(sk, "vigilarch/1/sig" || 0x00 || id)
```

Signing the id rather than the preimage keeps the signed message a fixed 48 bytes, which
matters on a 50 byte/s link where priority classes 0 and 1 must still fit. It is safe
because the id already commits to the object type through its own domain separation tag
(§3.1), so a signature over one object type's id can never be replayed as a signature
over another's.

Verifiers MUST use a library that rejects non-canonical signature encodings and
small-order public keys. `ed25519-dalek` v2 with default features does both; do not
enable `legacy_compatibility`.

A signature MUST NOT be included in its own preimage.

---

## 5. Primitive encodings

| Type | Encoding | Notes |
|---|---|---|
| `Hash` | `bstr` of exactly 32 bytes | BLAKE3-256 output |
| `PubKey` | `bstr` of exactly 32 bytes | Ed25519 verifying key, compressed |
| `Signature` | `bstr` of exactly 64 bytes | Ed25519 |
| `SiteId` | `bstr` of exactly 16 bytes | opaque, assigned at provisioning |
| `NodeId` | `PubKey` | a node *is* its device key |
| `Hlc` | `[wall_ms: uint, counter: uint]` | see §5.1 |
| `GeoPoint` | `[lat_udeg: int, lon_udeg: int, acc_mm: uint]` | §2.2 |
| `BlobRef` | `Hash` | the blob manifest's id |
| `Seq` | `uint` | per author, starts at 0, no gaps |
| `VersionVector` | `map { PubKey => Seq }` | sorted by key bytes per §2.1 |

### 5.1 Hlc carries no authority

`wall_ms` is milliseconds since the Unix epoch as claimed by the originating device. It
is **untrusted input**. A device clock is a settable field, and a backdater sets it. The
HLC exists to give merges a stable, causally consistent order and to make traces
readable. It is never evidence of when anything happened.

Every temporal claim the system makes comes from the attestation DAG
(`02-entanglement.md`), not from this field. A decoder MUST NOT reject an observation
because its `wall_ms` is implausible — implausibility is a signal to record, not a reason
to lose the record.

`counter` breaks ties within the same millisecond on the same device and resets to 0 when
`wall_ms` advances.

---

## 6. Object encodings

Field numbers are permanent (§2.3). "Opt" marks a field omitted when absent.

### 6.1 Observation — tag `vigilarch/1/observation`

| # | Field | Type | Opt |
|---|---|---|---|
| 1 | `author` | `PubKey` | |
| 2 | `site` | `SiteId` | |
| 3 | `prev` | `Hash`, or `bstr` of length 0 for the genesis entry | |
| 4 | `seq` | `Seq` | |
| 5 | `hlc` | `Hlc` | |
| 6 | `body` | `[variant: uint, payload: map]` | |
| 7 | `geo` | `GeoPoint` | opt |
| 8 | `acks` | `[Hash, ...]` — attestation ids this entry commits to | opt |

`seq` does not appear in `docs/VIGILARCH.md` §7.2 and is added here deliberately. Without
it, a gap in an author's chain is indistinguishable from a chain the receiver has not yet
finished fetching, and `vigil-verify` could only state that the links it holds are
consistent with each other — not that the chain is unbroken. `seq` starts at 0 and
increments by exactly 1 per entry by that author, and is verified jointly with `prev`
per §6.6 — it is attacker-controlled and carries no weight alone.

`acks` was added for M1 and is likewise absent from `docs/VIGILARCH.md` §7.2. It is an
ascending, duplicate-free list of the ids of attestations the author commits to at this
point in its chain; because the entry's content address covers it, the author cannot
later present a history without those attestations except by forking. When present it
MUST be non-empty. `spec/02-entanglement.md` §3.4 defines its semantics and the
integrity checks a verifier applies to it; this section defines only that it is field 8
and how it encodes.

**Body variants.** The variant number comes from this table and MUST NOT be taken from
the declaration order of the Rust enum.

| Variant | Name | Payload |
|---|---|---|
| 0 | `Note` | `{1: text: tstr}` |
| 1 | `Voice` | `{1: transcript: tstr, 2: audio: BlobRef}` |
| 2 | `Media` | `{1: blob: BlobRef, 2: kind: uint, 3: caption: tstr (opt)}` |
| 3 | `Form` | `{1: template: bstr16, 2: answers: map{uint => Value}}` |
| 4 | `Sensor` | `{1: source: bstr16, 2: reading: [mantissa: int, exponent: int]}` |
| 5 | `Presence` | `{1: actor: bstr16, 2: zone: bstr16, 3: event: uint}` — event 0 = Enter, 1 = Exit |
| 6 | `Heartbeat` | `{1: node_state: map}` — shape defined in `06-sync.md` (unwritten, v2; was `03-sync.md` before ADR-0004) |

### 6.2 Blob manifest — tag `vigilarch/1/blob`

| # | Field | Type |
|---|---|---|
| 1 | `size` | `uint`, total bytes |
| 2 | `chunks` | `[Hash, ...]` in order |
| 3 | `mime` | `tstr` |

### 6.3 Assertion — tag `vigilarch/1/assertion`

| # | Field | Type | Opt |
|---|---|---|---|
| 1 | `subject` | `[kind: uint, id: bstr]` — kind 0 = Observation, 1 = Thread, 2 = Entity | |
| 2 | `claim` | `[variant: uint, payload: map]` | |
| 3 | `author` | `PubKey` | |
| 4 | `hlc` | `Hlc` | |
| 5 | `retracts` | `Hash` of a prior assertion, by any author | opt |

A retraction is a new assertion, never a mutation and never a deletion. The retracted
assertion remains in the ledger and remains verifiable; the retraction is additional
information about it. This is what makes the append-only guarantee compatible with people
changing their minds.

### 6.4 Checkpoint — tag `vigilarch/1/checkpoint`

| # | Field | Type |
|---|---|---|
| 1 | `node` | `PubKey` |
| 2 | `head` | `Hash`, id of that node's latest observation |
| 3 | `seq` | `Seq`, that observation's `seq` |
| 4 | `hlc` | `Hlc` |
| 5 | `frontier` | `VersionVector` |

### 6.5 Attestation — tag `vigilarch/1/attestation`

The crown jewel. `02-entanglement.md` defines the exchange protocol; this section defines
only its bytes.

| # | Field | Type |
|---|---|---|
| 1 | `witness` | `PubKey` |
| 2 | `subject` | `PubKey` |
| 3 | `subject_head` | `Hash` |
| 4 | `subject_seq` | `Seq` |
| 5 | `witness_hlc` | `Hlc` |
| 6 | `nonce` | `bstr` of exactly 16 bytes |

The `nonce` MUST come from a cryptographically secure random source and MUST NOT be
derived from a clock. It exists so that two attestations of the same head by the same
witness are distinguishable objects, and so that a replayed attestation is detectable as
a duplicate rather than merging invisibly with a fresh one.

An attestation is signed by `witness`. It says only: *at some point, I saw this subject
claiming this head at this seq.* It says nothing in wall-clock terms, and `witness_hlc`
MUST NOT be read as if it did.

---

### 6.6 Chain integrity: `seq` and `prev` are verified jointly

**Normative:** a verifier MUST check `seq` and `prev` together, and MUST NOT treat either
as advisory when the other appears consistent.

For an observation by author *A* at sequence *n*:

- if *n* = 0, `prev` MUST be a zero-length byte string;
- if *n* > 0, `prev` MUST equal the recomputed id of *A*'s observation at sequence
  *n* - 1.

Neither field is evidence on its own. `seq` is a number the author writes, and a
malicious node sets it freely — it can claim sequence 900 on its second entry, or reuse
sequence 12 for two different observations. `prev` is harder to forge because it is a
hash, but a node can still chain honestly while lying about position. Checking one and
accepting the other on trust gives an attacker a free field, so the pair is checked as a
unit or not at all.

#### A mismatch is an integrity finding, not a decode error

These are different categories with different handling, and conflating them loses
evidence:

| | Decode error (§8) | Integrity finding (this section) |
|---|---|---|
| What happened | The bytes are not a well-formed canonical object | The bytes decode, and the signature verifies under `author` |
| What it proves | Nothing about anyone — any device can emit garbage | That the holder of `author`'s key signed inconsistent claims |
| Attributable | No | **Yes, to a specific key** |
| Handling | Reject the frame; it contributes nothing | **Retain it.** Report the finding with the offending key and both conflicting entries |

A verifier MUST NOT discard an observation because its chain claims are inconsistent. A
signed, self-contradictory entry is the most valuable object the system can hold: it is
cryptographic evidence of misconduct attributable to a key, and deleting it destroys the
proof. This is the same reasoning that makes the ledger append-only (§6.3) and it is why
fork detection quarantines a key rather than erasing its records (`02-entanglement.md`).

#### Three outcomes, and why "incomplete" is not "violated"

A full-chain verification pass MUST distinguish three results per author, and MUST NOT
collapse the middle one into either neighbour:

- **Verified** — every sequence from 0 to the highest held is present, and every `prev`
  matches the recomputed id of its predecessor.
- **Incomplete** — a sequence number is missing, and no held entry contradicts any other.
  The verifier does not hold the whole chain. This is the *normal* state under partition
  and MUST NOT be reported as a violation.
- **Violated** — two entries claim the same `seq` with different ids, or a `prev` does
  not match the predecessor the verifier holds. This is an integrity finding and is
  attributable.

Reporting "incomplete" as "verified" overstates what is known, which is the defect I5
forbids. Reporting it as "violated" accuses an honest node of tampering because a link
was slow, which under this system's threat model is just as bad: it makes the fork alarm
meaningless, and an alarm nobody trusts protects nobody.

---

### 6.7 Fork proof — tag `vigilarch/1/forkproof`

`spec/02-entanglement.md` §6 defines how a fork proof is produced, propagated and acted
on. This section defines only its bytes. It was added for M1; it changes no existing
content address (§11).

| # | Field | Type |
|---|---|---|
| 1 | `key` | `PubKey` — the equivocating author |
| 2 | `a` | `[preimage: bstr, sig: bstr of 64 bytes]` |
| 3 | `b` | `[preimage: bstr, sig: bstr of 64 bytes]` |

`a` and `b` are the two conflicting chain entries. Each `preimage` is the full
domain-separated preimage of an `Observation` — `"vigilarch/1/observation" || 0x00 ||
canonical_cbor` (§3.1) — and each `sig` is that entry's detached Ed25519 signature. The
pair is ordered so that the entry with the lexicographically smaller recomputed id is
`a`; this makes the fork proof's own content address independent of which node built it.

A fork proof is self-verifying with no external input. A verifier MUST decode both
preimages as `Observation`s (§6.1), MUST check both carry `author` equal to `key`, MUST
check both signatures verify under `key` (§4), and MUST check the two entries collide —
the same `seq` with different ids, or the same `prev` with different ids. A fork proof
that fails any check is not evidence and is discarded like any malformed frame (§8).

A fork proof carries no `hlc` and no ordering claim. It proves the holder of `key` signed
two irreconcilable histories; it does not say which came first, when either was written,
or that any observation in either branch is false.

---

## 7. Version negotiation

Every connection begins with a version exchange, before any object is transferred. Every
sneakernet bundle carries the same header.

```
hello = { 1: wire_versions: [uint, ...],   ; supported, descending preference
          2: node: PubKey,
          3: site: SiteId }
```

The connection proceeds at the highest version both sides support. If the sets are
disjoint the connection closes with a version-mismatch reason, and the failure is
recorded as a coverage gap rather than as an error — a peer we cannot talk to is a peer
we are dark to, and §10 of the design document has to see it that way or coverage is
overstated.

Implementations MUST support the current version and the two preceding it. Field devices
go dark for weeks; a version that ships to half the fleet and cannot be rolled back is
the worst failure mode this system has.

The `hello` frame itself is not versioned and MUST NOT change. It is deliberately three
fields of fixed shape.

---

## 8. Decoder requirements

The node parses signed input from devices it does not control. This is the attack
surface.

Note the boundary with §6.6: this section is about bytes that are not well-formed. An
object whose bytes are canonical and whose signature verifies, but whose chain claims are
inconsistent, is **not** a decode error — it is an attributable integrity finding, and it
is retained rather than rejected.

A decoder MUST:

- Reject any input violating §2.1 rather than accepting it leniently. There is no
  tolerant mode. A byte sequence that is not canonical is not a Vigilarch object, even
  when its meaning seems clear.
- Enforce every fixed length in §5 exactly. A 31-byte `PubKey` is a rejection, not
  something to pad.
- Reject unknown field numbers and unknown variant numbers within a wire version it
  claims to support. Forward compatibility comes from the version negotiation in §7, not
  from ignoring unrecognised fields — silently dropping a field that a future version
  made load-bearing is how a node ends up confidently verifying something it did not
  fully read.
- Reject trailing bytes after a complete object.
- Bound allocation by the declared length *and* by the remaining input length, never by
  the declared length alone. A 4 GiB length header in a 40-byte frame is a rejection.
- Never panic. Every deserialisation path is fuzzed, and a panic found by the fuzzer is a
  bug of the same severity as accepting a bad signature.

Rejection MUST be total: a rejected frame contributes nothing, not even partially. A
decoder MUST NOT return a partially populated object alongside an error.

---

## 9. Golden vectors

`testdata/vectors/` holds one JSON file per vector:

```json
{
  "name": "observation/note-genesis",
  "wire_version": 1,
  "tag": "vigilarch/1/observation",
  "fields": { "...": "the input, in readable form" },
  "cbor_hex": "...",
  "preimage_hex": "...",
  "id_hex": "...",
  "signing_key_seed_hex": "...",
  "sig_hex": "..."
}
```

Rules:

- Vectors are generated by `crates/vigil-core/examples/gen_vectors.rs`, which builds each
  preimage **by hand from the tables in this document** and does not call `vigil-core`'s
  encoder. A vector produced by the encoder under test proves only that the encoder
  agrees with itself.
- CI checks the native build and the `wasm32-unknown-unknown` build against the same
  vectors, byte for byte. Vectors without that cross-check are half an artifact:
  divergence between the two targets is precisely the failure this document exists to
  prevent, and it is invisible to a native-only test run.
- A change to any vector requires an ADR. Vectors are part of the spec, not test
  fixtures.
- Signing key seeds in vectors are fixed, published, and never used for anything real.

---

## 10. Worked example

A genesis `Observation` carrying a `Note`. Every byte below is derivable from §2 through
§6 with no reference to the implementation, which is the test this document has to pass:
if you cannot reproduce this triple by hand from the text above, the text is
underspecified and needs fixing before any ledger code depends on it.

**Inputs**

| Field | Value |
|---|---|
| signing key seed | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| `author` (derived) | `03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8` |
| `site` | ASCII `VIGILARCH-SITE-A` |
| `prev` | empty, this is genesis |
| `seq` | 0 |
| `hlc` | `[1700000000000, 0]` |
| `body` | variant 0, `{1: "shoring on grid B4 is out of plumb"}` |
| `geo` | absent, therefore omitted |

**Canonical CBOR** (111 bytes)

```
a6                                              map(6)
  01 5820 03a1...31b8                           1: author, bstr(32)
  02 50 564947494c415243482d534954452d41        2: site, bstr(16)
  03 40                                         3: prev, bstr(0), genesis
  04 00                                         4: seq = 0
  05 82 1b 0000018bcfe56800 00                  5: hlc = [1700000000000, 0]
  06 82 00 a1 01 7822 73686f...6d62             6: body = [0, {1: "shoring...plumb"}]
```

Note `1b` for `wall_ms`: 1700000000000 exceeds 2^32, so the eight-byte argument is the
shortest form (§2.1 rule 2). Note `40` for `prev`: a zero-length byte string, not a
32-byte zero hash and not an omitted field. Genesis is a value, not an absence.

```
cbor_hex =
a601582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b802
50564947494c415243482d534954452d410340040005821b0000018bcfe5680000068200a1
01782273686f72696e67206f6e2067726964204234206973206f7574206f6620706c756d62
```

**Preimage** (135 bytes) — `"vigilarch/1/observation" || 0x00 || cbor`

```
preimage_hex =
766967696c617263682f312f6f62736572766174696f6e00a601582003a107bff3ce10be1d
70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b80250564947494c415243482d5349
54452d410340040005821b0000018bcfe5680000068200a101782273686f72696e67206f6e
2067726964204234206973206f7574206f6620706c756d62
```

**Content address**

```
id = BLAKE3-256(preimage)
   = 7431f38ed1c31a3ef917bd60cd0b52f14c41b49ac8af5796b6c0fc3fba0aac1d
```

**Signature** — over `"vigilarch/1/sig" || 0x00 || id`, 48 bytes signed

```
sig = ddb1adecbbaea87a5b7454af66ab0a52b99b14acb3bb04eb4226668717bf5943
      4f54760eaa80e54bc2b568f0f316be5c369b610e5ea990586395b816ce751a07
```

---

## 11. Changing this document

Most changes to §2 through §6 change every content address in history. The process is:

1. An ADR in `docs/adr/` recording what changed, why, what was rejected, and the
   migration path for devices that will not see the change for weeks.
2. A wire version bump, which changes every domain separation tag in §3.1.
3. New golden vectors under the new version. Old vectors are kept rather than replaced —
   they are how an N-2 decoder is tested.

There is no path that skips step 1.

**Additive changes skip step 2.** Adding a new optional field with a fresh permanent
number (§2.3), or a new object type with a fresh domain separation tag (§3.1), leaves
every existing object byte-identical and every existing id unchanged — so it needs the
ADR and new golden vectors but **not** a version bump. `acks` (§6.1 field 8) and
`ForkProof` (§6.7) were added this way for M1; see ADR-0002. Changing the type,
semantics, presence rule, or number of an *existing* field is not additive and takes all
three steps.
