# Vigilarch

**An append-only incident ledger that can defend *when* a record was created, with no
server, no consensus, and no trusted clock.**

Organisations that run physical work across separated sites — construction, tunnelling,
mining, ports, utilities field operations — depend on incident and near-miss reports as
their main leading indicator of serious harm. Those reports are legally consequential,
and the decisive question in an investigation is almost always temporal: *did the
organisation know about this hazard before someone was hurt?*

Offline-capable systems cannot answer that question. They record whatever the device
clock said, and a device clock is a settable field. A node that was genuinely offline for
three days is indistinguishable from a node that was offline for three days, had its
clock rolled back, and had a favourable record inserted. This is why offline reports are
treated as soft evidence in practice and the paper register stays in the site cabin.

Vigilarch replaces the clock with **contact**. When two nodes meet, they co-sign each
other's current chain head and each embeds the result in its own next entry. A record's
creation time is then bracketed by the attestations either side of it in its own chain.
Backdating is confined to that bracket, and escaping the bracket is either a chain-order
contradiction or a fork — both detectable, and both attributable to a key.

Proof of time becomes a property of a meeting rather than of a clock.

## What this does *not* claim

Stated up front, because a guarantee that is not stated precisely is not a guarantee.

- An attestation gives an **upper** bound on a record's creation, never a lower one. It
  proves the record existed *no later than* the meeting. It cannot prove the record did
  not exist earlier.
- A node that has been isolated since genesis can fabricate its entire history freely.
  The correct output in that case is **a wide unwitnessed window, not a detection**, and
  the system is required to say so rather than guess.
- Where the attestation graph does not prove an ordering, the answer is `unwitnessed`.
  Never an interpolation, never a best estimate.
- None of this is a new protocol. Hash-linked timestamping is Haber–Stornetta (1991);
  mutual attestation between peer histories is Maniatis & Baker's timeline entanglement
  (2002). The contribution here is the application to disconnected incident reporting,
  the honest surfacing of what is *not* known, and the measurement — not the primitives.

## Status

**M0 done; M1 (entanglement) core landed.** The wire format is specified and `vigil-core`
implements it — deterministic CBOR, BLAKE3 content addressing, Ed25519 signatures, the
hybrid logical clock. `vigil-ledger` has the `Store` trait, the append-only store,
per-node hash chains with the three-way `seq`/`prev` verification pass, and the
entanglement layer on top of it: attestation ingest, the attestation DAG, the bracketing
query, fork detection with self-verifying proofs, and quarantine. `vigil-sim` runs three
scenarios over that ledger — a minimal attestation exchange, an equivocation scenario
with a quarantine ablation, and a sealing ablation that runs one honest chain twice, with
and without a single attestation object, to isolate exactly what sealing costs — each
from a seed, with a byte-identical transcript. The
export pack is specified (`spec/03-export-pack.md`, ADR-0004), with a hand-worked example
and three distinct tamper verdicts, and `vigil-verify` implements the `spec/03` §5
verification procedure — an independent second traversal that links only `vigil-core`,
reproduces every bracket claim from the pack alone, and exits nonzero on any tamper.

The three scenarios run across a seed range as one aggregate — `vigil-sim --scale-up
--seeds 1000` — and every scenario passes every seed (see [Evaluation](#evaluation)).

Still to come: `vigil-node`, the rest of the seeded adversarial scenarios with their
ablation runs, and the parts of the evaluation table that need them — witness-latency
distribution, attestation-graph density, key-attribution accuracy.

This is a **public repository with a self-contained demo**, not a product. There are no
customers, sites, hardware or users. Everything runs on one machine from a seed. The
scope is deliberately narrower than `docs/VIGILARCH.md`, which is aspirational and
predates a scope cut; `docs/REALITY-BRIEF.md` records the reasoning.

### What exists today

`spec/01-wire-format.md`, `spec/02-entanglement.md` and `spec/03-export-pack.md`, each
with worked detail reproducible by hand; six golden vectors in `testdata/vectors/`;
`vigil-core`, which
reproduces every one of them — and the wire-format worked example — byte for byte; and
`vigil-ledger`, which builds the per-node chains, the attestation DAG and the bracketing
query on top of a storage-agnostic `Store` trait.

The vectors were written *before* the encoder, by hand from the tables in the documents,
and the encoder was written against them. That order is the point: a vector generated by
the encoder under test proves only that the encoder agrees with itself. If a
`fields -> preimage -> id -> signature` triple cannot be hand-computed from the spec, the
spec is underspecified, and that is far cheaper to learn before the ledger depends on it.
`acks` (field 8) and `ForkProof` are additive wire changes — every M0 content address is
byte-identical — recorded in ADR-0002.

Every row below is exercised by the test suite on every commit. Nothing is claimed here
that the suite does not check.

| Claim | Checked by |
|---|---|
| The encoder reproduces all six golden vectors and the §10 worked example, byte for byte | `crates/vigil-core/tests/vectors.rs` |
| Native and `wasm32` builds agree byte for byte — the divergence that would fork the ledger silently | the same tests, run on both targets in CI |
| The decoder never panics on arbitrary, structurally plausible, mutated or truncated input; a non-canonical `acks` array is rejected | `crates/vigil-core/tests/decode_robustness.rs` |
| Canonical form is a bijection; every field reaches the content address; an absent optional field never encodes as a present one | the same |
| Signatures are over `"vigilarch/1/sig" \|\| 0x00 \|\| id`, and do **not** verify over the bare id | `tests/vectors.rs`, `src/sign.rs` |
| A `ForkProof` self-verifies from the two signed preimages it carries, and rejects a one-byte tamper | `tests/vectors.rs`, `crates/vigil-ledger/tests/fork.rs` |
| A chain is reported `Verified` / `Incomplete` / `Violated`, and the middle case never collapses into either neighbour (§6.6) | `crates/vigil-ledger/tests/chain.rs` |
| The DAG is a pure function of the held set — identical under any delivery order or duplication (§4.7) | `crates/vigil-ledger/tests/dag.rs` |
| An unanchored or self-attestation seals nothing; an unlawful `acks` entry is an attributable finding, not an edge | the same |
| A genesis-isolated node is `unwitnessed` with a window open both sides — **no alarm** (§8.2) | `crates/vigil-ledger/tests/bracket.rs` |
| Adding a valid attestation never widens a bracket (§5.5), and the bracket is identical across ingest orders (§5.6) | the same |
| Equivocation yields one self-verifying `ForkProof`; quarantine disputes the key's unwitnessed records but keeps pre-fork sealed ones valid (§6.4–6.5) | `crates/vigil-ledger/tests/fork.rs` |
| `vigil-sim` produces a byte-identical transcript from a seed; the minimal scenario's sealing invariant holds; the equivocation scenario convicts the author, never seals the withheld sibling, and shows quarantine acting only forward; and the sealing ablation shows one attestation is the whole difference between a sealed, bounded bracket and an unwitnessed, open one over a byte-identical honest chain | `crates/vigil-sim/tests/scenario.rs` |
| `vigil-sim --scale-up` runs every scenario once per seed over a range, counts pass/fail per seed with the total defended by an assertion, and exits non-zero naming the first failing seed | the same |
| Golden vectors regenerate identically, so drift between generator and checked-in bytes cannot pass unnoticed | CI regenerates and diffs |

Current suite: 142 tests native, 13 of them re-run under `wasm32-wasip1`; `vigil-core`
and `vigil-ledger` both compile to `wasm32-unknown-unknown` (invariant I2).

Two observation body variants are deliberately **not** implemented. Variants 3 (`Form`)
and 6 (`Heartbeat`) are named in the spec but no text pins their payloads —
`Form.answers` is typed `map{uint => Value}` and `Value` is never defined. They are
rejected with an error naming the gap rather than encoded to a guess. Guessing would make
the implementation the specification, and once a vector were published against the guess,
correcting it would cost a wire version bump.

### Road to v1

v1 is **done** when these exist, CI is green on a clean clone, and the evaluation table
below carries measured numbers. Development stops at that line.

| # | Deliverable | State |
|---|---|---|
| 1 | `vigil-core` — deterministic CBOR, BLAKE3, Ed25519, HLC | done |
| 2 | `vigil-ledger` — `Store` trait, append-only store, hash chains, full-chain verification | done |
| 3 | Attestation ingest, DAG, bracketing/sealing queries, fork proofs, quarantine | done |
| 4 | `vigil-sim` — seeded simulator over the *real* ledger | minimal, equivocation, and sealing-ablation scenarios landed, with a `--scale-up` runner aggregating them over a seed range; grows with the adversarial suite |
| 5 | `vigil-node --role edge\|hub\|mule` | not started |
| 6 | Export pack + `vigil-verify` — the independent verifier | pack specified (`spec/03`, ADR-0004) and assembled; `vigil-verify` implements the `spec/03` §5 procedure against every fixture |
| 7 | `spec/02-entanglement.md` and `spec/03-export-pack.md` (done, with worked detail), `spec/04-threat-model.md` (after M1, by design) | in progress |
| 8 | Seeded scenarios, each paired with an ablation run | three scenarios (equivocation carries a quarantine ablation; sealing-ablation contrasts a witnessed and an unwitnessed run over one honest chain); the full seeded adversarial set is next |
| 9 | Measured evaluation table and demo transcript | in progress — every scenario passes every seed over 1000 seeds (`--scale-up`); latency, graph density, attribution and the demo transcript still to come |

**Entanglement is the project.** It is built before anything that is not a prerequisite
for it, and it is never cut. `vigil-sim` grows alongside it from the first attestation
onward, not afterwards — every adversarial claim in this repository is evidenced by a
seeded, reproducible run, and each is paired with an ablation run at the same seed with
attestations disabled, asserting that the tamper goes *undetected* without them.

### Evaluation

One command runs every scenario across a seed range and aggregates the result:

```
cargo run -p vigil-sim --release -- --scale-up --seeds 1000
```

Each `(scenario, seed)` pair drives the real ledger once. The runner records pass or
fail per seed — keeping the individual results, not just a counter — checks that
`pass + fail` equals the seed count before printing anything, and exits non-zero
naming the first failing scenario and seed if any scenario fails any seed. That every
seed produces a byte-identical transcript is a separate assertion in the test suite.

| Scenario | Seeds | What must hold on every seed | Result |
|---|---|---|---|
| `minimal` — honest partition | `0..1000` | `bracket(O0)` is sealed by the meeting, with the window honestly open below to genesis | 1000 / 1000 |
| `equivocation` | `0..1000` | one self-verifying `ForkProof` convicts the author; the withheld sibling is never sealed; quarantine changes only what the convicted key's attestations buy going forward | 1000 / 1000 |
| `sealing-ablation` | `0..1000` | with one attestation, `bracket(O0)` is sealed and bounded above; without it, unwitnessed and open above — over a byte-identical honest chain | 1000 / 1000 |

The remaining metrics — witness-latency distribution, attestation-graph density, and
key-attribution accuracy as a rate — are **not measured yet** and will not be filled in
with estimates. They need the scriptable adversarial suite (partition topology, clock
rollback, withholding, mule routes) and `vigil-node`, and the demo transcript that ties
them together.

## Not built here

Deliberately absent. If something below looks like a gap, it is a decision, not an
oversight. Several are good ideas deferred to v2 rather than rejected.

- **Network sync** — no Merkle range reconciliation, no priority classes, no QUIC, no
  mDNS. `vigil-sim` moves objects between nodes over scriptable virtual links, which is
  sufficient to prove every temporal claim. *v2.*
- **Coverage math and silence detection** — `Covered<T>`, event-rate weighting, four-way
  silence classification. *v2.*
- **Federation** — vocabulary, sketches, k-anonymity, precursor mining, lead-time
  statistics. No neural network, no gradient averaging, and the word "AI" does not appear
  in this repository.
- **Any user interface** — no PWA, no WASM artifact, no React, no console. The demo is a
  terminal transcript.
- **Physical transports** — no BLE, LoRa, Wi-Fi Direct, or mule hardware. These are
  modelled as link profiles in `vigil-sim` (bandwidth, latency, loss, MTU); the mule is a
  simulated node.
- **Interpretation layer** — no threads, assertions, entity resolution, or contested
  state. Tags attach directly to observations. This is cut from v1 outright, not deferred
  to v2 alongside sync and coverage.
- **Key management** — no rotation, revocation gossip, remote wipe, or HSM custody.
  Certificate issuance is stubbed. A compromised device key is, in v1, unrecoverable.
- **External anchoring** — no RFC 3161, no transparency log.
- **Deployment** — no Postgres, Docker, Terraform, Ansible, or `deploy/` tree.
- **Media** — no blobs, chunking, or thumbnails. Text plus tags.
- **Product surface** — no multi-tenancy, billing, RBAC, admin console, or onboarding.

The capture-latency and battery figures in `docs/VIGILARCH.md` require hardware and users
that do not exist. They are not acceptance criteria for this repository.

## Layout

```
crates/
  vigil-core/     deterministic CBOR, BLAKE3 addressing, Ed25519, HLC, ForkProof
  vigil-ledger/   Store trait, append-only store, hash chains, attestation DAG,
                  bracketing, fork detection, quarantine
  vigil-node/     the binary: --role edge|hub|mule, loopback HTTP API, pack export
  vigil-sim/      deterministic seeded simulator over the real ledger (lib + bin)
  vigil-verify/   independent verifier: evidence pack + org key in, ordering out
spec/             the protocol specifications — stricter review than code
docs/             design document, reality brief, ADRs
testdata/         golden wire vectors, seeded scenarios
```

`vigil-verify` depends only on `vigil-core` — not `vigil-ledger`, not as a dependency and
not as a dev-dependency — so its chain check, DAG construction and bracketing are a second
implementation written from the spec, not a call into the code that built the pack. No
database, no network, no node. It reproduces every ordering claim from the evidence pack
and the organisation's public key alone, and exits nonzero on any tamper.

The workspace still contains `vigil-sync`, `vigil-transport`, `vigil-insight` and
`vigil-wasm` as empty scaffolding from the pre-cut scope. They build but implement
nothing, and they are slated for removal. `vigil-sim` no longer depends on `vigil-sync`:
it moves objects between nodes over the scripted link directly.

## Invariants

I1–I5 are enforced by code and CI today — I5 now has something to enforce it against: the
bracketing query is conservative one-sidedly, a property test asserts adding evidence
never widens a bracket, and the simulator asserts its sealing invariant on every run. I6
is a design commitment recorded now so the constraint exists before the temptation to
skip it does; v1 has nothing to enforce it against.

1. **No node is the source of truth.** The hub is a convenience peer with no authority an
   edge node lacks. If the hub burns down, the organisation loses convenience and nothing
   else.
2. **One implementation of the ledger.** Chain, attestation and verification logic exists
   once, in Rust, and stays compilable to `wasm32-unknown-unknown` even though no WASM
   artifact ships in v1. Storage therefore lives behind a `Store` trait, `rusqlite` is an
   optional feature, and an in-memory backend is always available.
3. **Capture is immutable.** `Observation` and `Attestation` are never edited.
4. **No wall-clock reads in the ledger.** Enforced by `clippy.toml`. All time flows
   through the HLC, which is a merge hint and never evidence. Device clocks are
   attacker-controlled input.
5. **Never overstate what the system knows.** Any computed confidence is conservative
   one-sidedly, and every simulator run asserts it. Overstating knowledge is the cardinal
   defect of this system.

---

6. **If semantic interpretation is ever modelled, conflicting values are never silently
   resolved.** Two supervisors disagreeing on a severity assessment is information, not a
   merge failure; last-write-wins on a disputed field would be a safety hazard, not just a
   data-modelling shortcut. v1 has no interpretation layer — no threads, no severity
   fields, nothing that could conflict — so nothing today enforces this. It is recorded
   here so the constraint exists before the temptation to skip it does.

## Known tensions and open items

Stated here rather than left for a reader to discover.

**Append-only storage versus the right to erasure.** These pull against each other, and
Vigilarch comes down on the append-only side. A retraction is a new record saying the old
one is withdrawn; it does not remove what was written, and peers who already hold the
original keep holding it. That is what makes the evidence claim work, and it is a real
cost that a deployment under GDPR or DPDP would have to answer for. The usual mitigation
— keep content encrypted and discard the key — shrinks the problem without eliminating
it, since the ordering metadata survives by design.

**Licence.** Not yet chosen. The workspace currently declares `UNLICENSED`, which is
wrong for a public repository and is tracked as a defect to fix before publication.

**The DAG has no edge between two authors' chains.** An `Attestation` carries the
subject's head, never the witness's, so every attestation is confined to its subject's
chain and cross-author records come out `incomparable` — the honest outcome under
partition. `spec/02` §4.6 describes a mule giving two never-connected sites an ordering
relationship "through the mule's own chain"; the three literal edge rules do not produce
that, so the `mule-relay` scenario is on hold pending a spec pass — either a fourth edge
type or a reinterpretation, recorded as an ADR.

**Seal-edge scope.** `spec/02` §4.2 says a seal reaches "every held observation of S at
seq m ≤ X.subject_seq"; the implementation instead walks `prev` from the anchored head,
reaching only its chain ancestors. The two agree on any unforked chain and differ only
under equivocation, where §4.2's own sealing-theorem proof (§5.2) supports only the
ancestor reading. §4.2's wording should be tightened to match.

## Building

Requires a Rust toolchain (1.85+, edition 2024). On Windows without Visual Studio Build
Tools, use the GNU toolchain with mingw-w64 on `PATH`:

```
rustup default stable-x86_64-pc-windows-gnu
```

Then:

```
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p vigil-core --example gen_vectors   # regenerates golden vectors; must be a no-op
cargo run -p vigil-sim -- --scenario minimal --seed 1          # minimal entanglement scenario; same seed, same transcript
cargo run -p vigil-sim -- --scenario equivocation --seed 1     # equivocation + quarantine ablation
cargo run -p vigil-sim -- --scenario sealing-ablation --seed 1 # one honest chain, with vs. without a single attestation
cargo run -p vigil-sim --release -- --scale-up --seeds 1000    # every scenario over 1000 seeds; nonzero exit on any failing seed
```

To run the golden vectors under WASM, as CI does:

```
rustup target add wasm32-wasip1
CARGO_TARGET_WASM32_WASIP1_RUNNER=wasmtime cargo test -p vigil-core --target wasm32-wasip1 --test vectors
```

## Documentation

- `spec/` — the wire format, entanglement protocol, export pack and threat model. Versioned from the
  first commit and held to stricter review than code: a protocol change that ships and
  cannot be rolled back is the worst failure mode this system has.
- `docs/VIGILARCH.md` — the original design document. Aspirational, and it predates the
  scope cut; where it disagrees with this README or the specs, it loses.
- `docs/REALITY-BRIEF.md` — a one-time scope audit recording why the cuts were made.
- `docs/adr/` — decision records. Any change to the wire format requires one.
