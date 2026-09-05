# CLAUDE.md — Vigilarch

Read `docs/VIGILARCH.md` for the full design. This file is the operating contract: what
we are building, what we are deliberately not building, and the rules that must not be
broken. Where this file and VIGILARCH.md disagree, **this file wins** — it reflects a
deliberate scope cut made after the design doc was written.

---

## What this is

Vigilarch is a safety/security incident system for organisations whose sites lose
connectivity, built on the premise that **the network partition is the normal state, not
the failure state**.

The one sentence the whole project exists to demonstrate:

> A record created on a disconnected device by a low-trust actor can later be shown to
> have existed before a given point in time — while the organisation still learns from
> it across sites, without ever centralising it.

## What this is *for*

This is a **public GitHub repo with a working, self-contained demo**. It is not a
product being sold to customers, and there are no real users, real sites, or real
hardware. Optimise for:

1. **Legibility** — a visitor understands the thesis in 90 seconds.
2. **Verifiability** — claims are demonstrated by runnable code, never asserted in prose.
3. **Self-containment** — everything runs on one machine from a seed, or in a browser tab.

Do **not** optimise for production hardening, enterprise deployment, real-device
support, or feature breadth. Those trade against all three goals above.

---

## Non-negotiable invariants

**I1 — No node is the source of truth.** The hub is a convenience peer with no authority
the edge nodes lack. If you find yourself giving the hub special power to resolve
anything, stop and raise it.

**I2 — One implementation of L0–L3.** Ledger and sync logic is Rust, compiled to native
and WASM. Never write a second implementation of ledger, chain, attestation, or
reconciliation logic in TypeScript, even a "temporary" one for the UI.

**I3 — Capture is immutable; interpretation is mutable.** `Observation` and `Attestation`
are never edited. `Thread` and `Assertion` are freely mutable CRDTs. Every merge question
resolves once you identify which side of this line you're on.

**I4 — No `SystemTime::now()` in the ledger crate.** Enforce at lint level. All time flows
through HLC plus attestations. Device clocks are attacker-controlled input.

**I5 — Coverage is never overstated.** Any computed coverage must be less than or equal to
true coverage, one-sidedly. Overstating what the system knows is the cardinal defect.
Assert this in every simulator run.

**I6 — Semantic conflicts are never auto-resolved.** Two supervisors disagreeing on
severity is information, not a merge failure. Multi-value register, surfaced as
`Contested`. Last-write-wins on a severity field is a safety hazard.

---

## Scope: build this

- **M0 Ledger core** — canonical CBOR, BLAKE3, Ed25519, HLC, append-only SQLite store,
  per-node hash chains.
- **M1 Entanglement** — checkpoints, mutual attestation exchange, attestation DAG,
  sealing queries, fork proofs, quarantine. **This is the project.** Build it before any UI.
- **`vigil-sim`** — deterministic seeded discrete-event simulator running the *real*
  ledger and sync code. Build alongside M1, not after. M2 is untestable without it.
- **M2 Sync** — Merkle range reconciliation, priority classes 0–5, resumable transfer,
  QUIC + mDNS on a LAN.
- **M5 Coverage & silence** — `Covered<T>` everywhere, event-rate-weighted coverage,
  four-way silence classification, coverage-aware UI components.
- **M4-lite field app** — plain PWA, React + TS + Vite, `vigil-core` via WASM. Ugly is
  fine. It must capture offline in under ten seconds and lose nothing across a reconnect.
- **M8-lite export + verifier** — signed export pack, and an independent `vigil-verify`
  binary that reproduces every ordering claim from only the pack and the org public key.
- **Hosted WASM demo** — the simulator in one browser tab with buttons: cut network,
  report offline, tamper with a site, send the mule, reconnect. Highest-leverage artifact
  in the repo after M1.

Optional, only if the above is solid: **M6-lite federation** — controlled vocabulary,
signature extraction, count-min sketches, k-anonymity threshold, and a wire capture
proving zero raw incident content crossed a site boundary.

## Scope: do not build this

Do not start any of the following. If a task seems to require one, say so and propose an
alternative instead of building it.

- **Physical transports** — BLE, LoRa, Wi-Fi Direct, real mule devices. Model them as
  link profiles in `vigil-sim` (bandwidth, latency, loss, MTU) and demo the mule as a
  simulated node.
- **Capacitor, native builds, MDM distribution.** Plain PWA only.
- **Key rotation, revocation gossip, remote wipe, HSM custody.** Stub certificate
  issuance; document as out of scope in the README.
- **Federated learning / gradient averaging / any neural network.** Sketches and counters
  only. Do not put "AI" anywhere in the repo.
- **Postgres hub read model, Terraform, Ansible, edge-box provisioning.**
- **Multi-tenancy, billing, RBAC, admin consoles, onboarding flows.**

---

## Known corrections to the design doc

These are real defects in `docs/VIGILARCH.md`. Do not implement it as written.

1. **Coverage weighting is gameable.** §10.1 weights each node by its *own historical
   event rate*, so a node that suppresses reports lowers its own weight and makes its
   absence cheap — a withholder mechanically inflates coverage, violating I5. Derive
   expected rate from crew size, shift pattern, and work phase, not from the node's own
   recent output.

2. **The federation demo line violates the honesty pillar.** §11.3 prints "median lead
   time 19 days" from n=2. Report honest counts only — "seen at 6 sites, escalated at 2" —
   and put federated outputs behind `Covered<T>` like everything else. The credible part
   of that demo is the wire capture showing zero content crossed, not the statistic.

3. **Vocabulary evolution under partition is unspecified.** Decide and write down in
   `spec/05-vocabulary.md` how a new tag reaches a site dark for three weeks, and what
   happens to sketches computed against different vocabulary versions.

4. **Append-only conflicts with erasure rights.** Not a blocker for a demo repo, but state
   the tension plainly in the README rather than leaving it invisible.

---

## Working rules

- **`spec/` is under stricter review than code.** Version the wire format from commit one
  and negotiate it on every connection. Propose spec changes as a diff with rationale
  before implementing them.
- **Golden vectors from day one** in `testdata/`, cross-verified byte-for-byte between
  native and WASM.
- **Every adversarial scenario is a seeded, reproducible simulator run** asserted in CI:
  backdating, equivocation, withholding, replay, clock rollback. The README should carry
  the pass counts.
- **Property tests on all CRDT merges** — commutativity, associativity, idempotence, under
  randomly generated operation sets and delivery orders.
- **Fuzz every deserialisation path.** The node parses signed input from hostile devices;
  that is the attack surface.
- Prefer small, reviewable commits on the critical path. `vigil-ledger` correctness beats
  velocity everywhere else.

## The failure mode to avoid

The tempting path is to build the PWA first because it is visible and fun. That path ends
in an offline notes app with sync, which is indistinguishable from a hundred other repos.
The entanglement ledger and the simulator are the entire reason this project is worth
publishing. If scope has to be cut, cut transports, then federation, then UI polish.
Never cut M1.