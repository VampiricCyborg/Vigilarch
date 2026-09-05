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
| `02-entanglement.md` | Checkpoints, attestation exchange, the attestation DAG, sealing, fork proofs | M1 |
| `03-sync.md` | Merkle range reconciliation, priority classes, resumption, bundle framing | M2 |
| `04-threat-model.md` | Adversaries, guarantees, explicit non-guarantees | M0 onward |
| `05-vocabulary.md` | The controlled tag vocabulary that makes signatures federate | M6 |

All five are unwritten. `01` and `04` come first — they are prerequisites for M0, and
§16.2 requires golden vectors from day one.

## A note on `05-vocabulary.md`

Vigilarch is deliberately sector-neutral, so the controlled vocabulary must fit
construction, mining, ports, utilities, manufacturing and humanitarian response at once.
This is a known cost: free text will not federate, and a vocabulary stretched across six
sectors risks being too coarse to carry signal. Expect to revisit it after the first
pilot with real data rather than to get it right on paper.
