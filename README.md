# Vigilarch

**Distributed, offline-first incident intelligence for multi-site physical operations.**

Vigilarch is a safety and security incident system for organisations whose sites lose
connectivity — construction, mining, ports, utilities, multi-plant manufacturing,
disaster response. It is built on the premise that **the network partition is the normal
state, not the failure state**, and that a system which models its own ignorance can be
trusted with evidence that a connected system cannot.

The claim the whole project rests on:

> A record created on a disconnected device by a low-trust actor can later be shown to a
> regulator with a defensible claim about *when* it was created — while the organisation
> still learns from it globally, without ever centralising it.

## Three pillars

**Provable history without a server.** A device clock is a settable field, which is why
offline incident reports are treated as soft evidence everywhere in this industry.
Vigilarch replaces the clock with contact: when any two nodes meet — site LAN, Bluetooth
between two phones in a truck cab, a LoRa beacon, a USB stick in a driver's pocket — they
co-sign each other's chain head and embed the result in their own next entry. Proof of
time becomes a property of a meeting. No consensus protocol, no blockchain, no trusted
timestamp server. Even an untrusted courier carrying opaque ciphertext measurably
strengthens the evidence chain.

**Partition-aware intelligence.** Every figure the system produces carries a
machine-computed statement of what it does not know: `14 incidents · coverage 71% ·
2 sites dark 39h`. Absence is treated as signal. The corollary is silence detection,
which corrects the inversion at the centre of this industry — today, a site that goes
quiet looks like a safe site, because no incumbent can tell "nobody reported" from
"nobody connected". Vigilarch can, because partition is modelled.

**Federation without disclosure.** Sites learn from each other's incidents without ever
transmitting them. Count-min and MinHash sketches cross the wire; evidence does not. The
motivation is legal and industrial-relations survivability — multi-employer sites,
unionised workforces, cross-border joint ventures — not bandwidth.

## Status

Pre-M0 scaffold. No protocol code yet.

This is a **public repository with a self-contained demo**, not a product. Everything
here runs on one machine from a seed, or in a browser tab. The scope below is narrower
than `docs/VIGILARCH.md`, deliberately: the design document describes the full system,
and this repository builds the part of it that carries the thesis. Where the two
disagree, the operating contract in `claude.md` wins.

| Milestone | Scope | State |
|---|---|---|
| M0 | Ledger core — canonical encoding, hashing, signing, HLC, hash chains | not started |
| M1 | **Entanglement** — checkpoints, attestation DAG, sealing, fork proofs | not started |
| `vigil-sim` | Deterministic seeded simulator over the real ledger and sync code | not started |
| M2 | Sync — Merkle range reconciliation, priority classes 0–5, QUIC + mDNS on a LAN | not started |
| M5 | Coverage — `Covered<T>`, coverage math, four-way silence classification | not started |
| M4-lite | Field app — plain PWA over the WASM core, offline capture | not started |
| M8-lite | Export pack + `vigil-verify`, the independent verifier | not started |
| Demo | The simulator hosted in one browser tab: cut the network, report offline, tamper, send the mule, reconnect | not started |
| M6-lite | *Optional* — federated sketches, k-anonymity, and a wire capture proving zero content crossed | not started |

`M0 → M1 → M2` is the critical path and is where the novelty lives. **M1 is never cut.**
Under schedule pressure the cut order is transports first, then federation, then UI
polish. An offline app with sync and no entanglement is a mediocre clone of products
that already exist.

`vigil-sim` is built alongside M1 rather than after it, because M2 is untestable
without it. Golden vectors and the CI check that compares the native and WASM builds
byte-for-byte land with the wire format spec, before any ledger code depends on them.

### Not built here

These are in the design document and are deliberately absent from this repository. If
something below looks like a gap, it is a decision:

- **Physical transports** — BLE, LoRa, Wi-Fi Direct, real mule hardware. The contact
  model above is real, but contact is demonstrated over QUIC on a LAN and modelled
  everywhere else as **link profiles in `vigil-sim`** — bandwidth, latency, loss, MTU,
  down to a 50 byte/s profile. The interesting claim is that a starved, intermittent
  link still carries priority classes 0 and 1, and that is provable against a simulated
  profile without owning a radio.
- **Capacitor, native mobile builds, MDM distribution.** The field app is a plain PWA.
- **Key rotation, revocation gossip, remote wipe, HSM custody.** Certificate issuance is
  stubbed.
- **Postgres hub read model, Terraform, Ansible, edge-box provisioning.** There is no
  `deploy/` tree.
- **Any neural network or gradient-based federated learning.** Sketches and counters
  only.

## Layout

```
crates/
  vigil-core/       L0  canonical CBOR, BLAKE3, Ed25519, HLC, CRDTs
  vigil-ledger/     L2  append-only store, hash chains, attestation DAG, forks
  vigil-sync/       L3  Merkle range reconciliation, priority classes, bundles
  vigil-transport/  L1  Link trait: QUIC + mDNS, sneakernet bundles
  vigil-insight/    L5  coverage math, silence detection, sketches
  vigil-node/           the binary: --role edge|hub|mule, loopback HTTP API
  vigil-wasm/           wasm-bindgen surface for the PWA (bindings only)
  vigil-sim/            deterministic network simulator + adversarial harness
  vigil-verify/         independent verifier: export pack + org key in, ordering out
apps/
  field/                field PWA (React + TS + Vite over the WASM core)
  console/              ops dashboard
spec/                   the protocol specs — stricter review than code
docs/                   design document, ADRs
testdata/               golden wire vectors, recorded partition scenarios
```

`vigil-verify` links `vigil-core` and nothing else in the workspace — in particular not
`vigil-ledger`. A verifier that reuses the ledger's own traversal cannot detect a bug in
it; it reproduces the same wrong answer and calls that agreement.

## Architectural invariants

These are not style preferences. Each one, if violated, costs the project its thesis.

1. **No node is the source of truth.** If the hub burns down the org loses convenience
   and nothing else.
2. **L0–L3 is a single implementation**, compiled to native, WASM and FFI. The phone,
   the edge box, the mule and the hub run byte-identical ledger and sync logic. Do not
   write a JavaScript ledger.
3. **Capture is immutable; interpretation is mutable.** Every conflict-resolution
   question resolves cleanly once you locate which side of that line you are on.

Two evaluation criteria are absolutes rather than targets, because each is a claim the
project rests on. Any nonzero result is a top-severity defect:

- **E6** — reported coverage never exceeds true coverage.
- **E9** — zero bytes of raw incident content cross a site boundary.

### A tension we have not resolved

Append-only storage and the right to erasure pull against each other, and Vigilarch
comes down on the append-only side. A retraction is a new record saying the old one is
withdrawn; it does not remove what was written, and peers who already hold the original
keep holding it. That is what makes the evidence claim work, and it is also a real cost
that a deployment in a jurisdiction with erasure rights would have to answer for. The
usual answer is to keep content encrypted and discard the key, which shrinks the problem
without eliminating it, since the ordering metadata survives. We state the tension here
rather than leaving it for a reader to discover.

## Building

Requires a Rust toolchain (1.85+, edition 2024). On Windows without Visual Studio Build
Tools, use the GNU toolchain with mingw-w64 on `PATH`:

```
rustup default stable-x86_64-pc-windows-gnu
```

Then:

```
cargo check --workspace
cargo clippy --workspace --all-targets
cargo test --workspace
```

## Documentation

- `claude.md` — the operating contract: what is being built, what is deliberately not
  being built, and the invariants that must not be broken. It wins where it and the
  design document disagree.
- `docs/VIGILARCH.md` — the master design and build document. Read §1–§4 for the pitch,
  §5–§11 to implement, §13–§17 to plan, §19–§20 to demo or defend.
- `spec/` — the wire format, entanglement protocol, sync protocol, threat model and
  controlled vocabulary. Versioned, and held to stricter review than code: a protocol
  change that ships to half the fleet and cannot be rolled back is the worst failure mode
  this system has.
