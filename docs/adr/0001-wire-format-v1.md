# ADR-0001 — Wire format v1

**Status:** accepted. **Date:** 2026-09-05. **Affects:** `spec/01-wire-format.md`,
`testdata/vectors/`.

## Context

`spec/` requires an ADR for every change to a specification document, including the
first. This record covers the decisions embedded in wire format v1 and, more usefully,
the alternatives that were rejected — a reader six months from now will want to know
which of these were considered and which were never thought about.

## Decisions

### Integer field keys, assigned by the spec

Objects are CBOR maps keyed by small unsigned integers whose meanings are fixed in
`01-wire-format.md` §6, not by text field names.

*Rejected: text keys.* More readable in a hex dump, but they make the id sensitive to
spelling and they cost bytes on every object — meaningful when priority class 0 must fit
in roughly 100 bytes on a 50 byte/s link.

*Rejected: positional arrays.* Most compact, but inserting a field is then a silent
reinterpretation of everything after it, and optional fields need placeholder values,
which §2.3 forbids for good reason.

### The preimage is built by hand, never by serde

`ciborium` and `serde` derives are barred from the preimage path (§2.4).

This is the decision most likely to be questioned later, because hand-building an encoder
is more work than a derive and looks like reinventing a wheel. The reason to accept the
cost: a derive takes field order and enum tagging from the Rust source, so an ordinary
refactor — reordering two fields, renaming a variant — changes every id in history with
no compile error and no failing test. The encoding contract has to be readable in the
specification rather than emergent from a struct definition. `ciborium` is additionally
not deterministic by default.

*Rejected: `serde` with a canonicalising wrapper.* Narrows the risk but does not remove
it; field order still comes from the source, and the wrapper becomes a thing to audit.

### No floating point anywhere in a preimage

Scaled integers instead (§2.2). Negative zero, NaN payload diversity, and
library-dependent precision selection each break byte-identical encoding across native
and WASM. Geo is microdegrees; sensor readings are mantissa and decimal exponent.

### `seq` added to `Observation`

`docs/VIGILARCH.md` §7.2 gives `Observation` a `prev` hash but no sequence number. v1
adds `seq`.

Without it, a gap in an author's chain cannot be distinguished from a chain the receiver
has not finished fetching. `vigil-verify` could then only report that the links it holds
are mutually consistent, never that a chain is unbroken — which is a materially weaker
claim, and weaker in exactly the direction the project cannot afford (§I5: never
overstate what is known).

*Rejected: deriving sequence position by walking `prev` to genesis.* Requires holding the
entire chain to say anything about it, which is the normal case only for the author.

### Domain separation by NUL-terminated ASCII tag

`tag || 0x00 || cbor`, with the wire version inside the tag. Signatures are over
`"vigilarch/1/sig" || 0x00 || id`.

*Rejected: BLAKE3 `derive_key` mode.* Equally sound and arguably more idiomatic, but it
makes the worked example in §10 harder to reproduce by hand with common tools, and
hand-reproducibility is the property the golden vectors are meant to test.

*Rejected: signing the preimage rather than the id.* Would mean signing an unbounded
message where a fixed 48 bytes will do. Safe here because the id already commits to the
object type via its own tag.

### An id is never accepted from the wire

The receiver recomputes it (§3.2). The `id` field in the design document's structs is an
in-memory cache. This removes an error path rather than adding one.

### Version in the tag, negotiated per connection, N-2 support

Bumping the wire version changes every id, which is intended: objects of different wire
versions are different objects. The `hello` frame is itself unversioned and fixed, since
something has to be.

## Consequences

- Every content address in the system depends on this document. Changes to §2 through §6
  require a new ADR and a version bump.
- `vigil-core` owes a hand-written preimage builder, and its correctness is pinned by
  `testdata/vectors/` rather than by review alone.
- The golden vectors must be generated independently of that builder, or they prove only
  self-consistency. `crates/vigil-core/examples/gen_vectors.rs` builds preimages directly
  from the §6 tables for this reason.
- CI must run the vectors against both the native and the `wasm32-unknown-unknown`
  builds. A native-only check cannot see the divergence the format exists to prevent.

## Not decided here

`02-entanglement.md` defines the attestation exchange protocol; this ADR fixes only the
bytes of an `Attestation`. `04-threat-model.md` is deliberately deferred until after M1 —
the encoding-constraining decisions (domain separation, no wire-supplied ids, no floats)
are settled above, and the threat model will be a better document once fork detection and
quarantine have surfaced the cases the design document glosses over.
