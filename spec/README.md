# spec/ — the protocol specifications

These documents, not the code, are the contract between nodes. **They are held to
stricter review than code.** A protocol change that ships to half the fleet and cannot
be rolled back is the worst failure mode this system has: field devices go dark for
weeks at a time, so a bad version reaches some of the fleet and is then unreachable.

Rules:

- The wire format is versioned from commit one and negotiated on every connection.
- Keep N−2 compatibility.
- No change to any document here without an ADR in `docs/adr/` recording the reasoning
  and the migration path.
- Golden vectors in `testdata/` are part of the spec. They are cross-verified
  byte-for-byte between the native and WASM builds (architectural invariant #2).

| Document | Covers | Milestone |
|---|---|---|
| `01-wire-format.md` | Canonical CBOR, content addressing, object encodings, version negotiation | M0 |
| `02-entanglement.md` | Checkpoints, attestation exchange, the attestation DAG, the bracketing rule, fork proofs, and the non-guarantees | M1 |
| `03-sync.md` | Merkle range reconciliation, priority classes, resumption, bundle framing | M2 |
| `04-threat-model.md` | Adversaries, guarantees, explicit non-guarantees | after M1 |
| `05-vocabulary.md` | The controlled tag vocabulary that makes signatures federate | M6 |

`01-wire-format.md` and `02-entanglement.md` are written; `03` and `05` are not. `01`
came first, and the golden vectors in `testdata/` were written directly against it before
any ledger code depended on it. The vectors are a test of that document as much as of the
code: if you cannot hand-compute a `fields -> preimage -> id -> signature` triple
straight from the text, the text is underspecified, and it is far cheaper to find that
out early. `vigil-core` now reproduces all four of them, and the §10 worked example, byte
for byte.

`02-entanglement.md` was written before the M1 code, the same way. It adds two objects to
`01` additively — the `acks` field of `Observation` (§6.1) and `ForkProof` (§6.7),
neither changing an existing content address — and states its non-guarantees as
prominently as its guarantees, because overstating a temporal bound is the defect the
whole project exists to avoid. See ADR-0002. Its golden vectors (an observation carrying
`acks`; a fork proof) land with the M1 code.

`04-threat-model.md` is **not** a prerequisite for M0, despite what its place in the
numbering suggests. §5.3 of the design document already carries the adversary table, and
the threat-model-derived decisions that actually constrain the encoding — domain
separation, never accepting an `id` from the wire, no floats in the preimage — are
settled and are stated normatively in `01`. The threat model will be a substantially
better document written after M1, once fork detection and quarantine have surfaced the
cases the design document glosses over. It should not gate the wire format.

## A note on `05-vocabulary.md`

Vigilarch is deliberately sector-neutral, so the controlled vocabulary must fit
construction, mining, ports, utilities, manufacturing and humanitarian response at once.
This is a known cost: free text will not federate, and a vocabulary stretched across six
sectors risks being too coarse to carry signal. Expect to revisit it after the first
pilot with real data rather than to get it right on paper.
