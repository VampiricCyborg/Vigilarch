# Vigilarch — Project Reality Brief

Prepared from the repository at `github.com/VampiricCyborg/Vigilarch` @ `3abcff3` ("chore: initial pre-M0 scaffold", 5 Sep 2026) and the design document `docs/VIGILARCH.md`.

**Headline finding, stated before anything else:** the repository contains **no implementation whatsoever**. One commit. 1,557 lines in the tree, of which ~1,540 are prose. The eight Rust source files contain doc comments, `#![forbid(unsafe_code)]`, and two `println!` statements. There are no types, no functions, no tests, no spec documents, no golden vectors, no CI, and no `deploy/` directory despite the README listing one. Every claim in this brief about "what exists" is therefore about documents, not software. That is not a criticism of the plan — pre-M0 scaffolds are legitimate — but it means the project's entire risk is still ahead of it, and the ratio of design writing to code is currently about 250:1. That ratio is itself the main thing to worry about.

---

## 1. Project Motive

### The real-world problem

Organisations that run physical work across many separated sites — construction, tunnelling, mining, ports, utilities field ops — depend on incident and near-miss reports as their primary leading indicator of serious harm. Three mechanical failures degrade that data:

1. **Capture loss.** Reporting requires connectivity at the moment of observation. Sites frequently have none. The report is deferred, and deferred reports are mostly never written. The data destroyed is disproportionately near-misses: the highest-volume, lowest-severity, most predictive class.

2. **Evidential weakness.** Incident records are legally consequential (regulator investigation, insurance, director liability, litigation). The decisive question is almost always temporal: *did the organisation know about the hazard before the injury?* But an offline-capable system stores whatever the device clock says, and a device clock is a settable field. A node that has been offline for three days is indistinguishable from a node that was offline for three days, had its clock rolled back, and had a fabricated "hazard reported" record inserted. No conventional CRDT/LWW sync stack can tell those apart. This is why offline reports are treated as soft evidence in practice and the paper register stays in the site cabin.

3. **Epistemic dishonesty in aggregation.** A monthly figure computed while nine sites have not synced is presented with the same confidence as one computed with full data. The consequence is an inversion: a site that stops reporting looks identical to a site that stopped having incidents. Reporting collapse under schedule pressure — a well-documented precursor of serious events — renders as improvement.

A fourth problem (no cross-site pattern transfer) is real but is a legal and industrial-relations problem more than a technical one, and it is the weakest leg for a solo build.

### Why offline operation matters

Not as a degraded mode. On these sites, disconnection is the ordinary condition and lasts hours to weeks. A system whose correctness story assumes eventual connectivity within minutes has no correctness story here. The design document's framing — *the partition is the normal state, not the failure state* — is the right framing and is load-bearing for everything else.

### The central insight

Two, and they compose:

> **In a partitioned network, proof of time is not a property of a clock. It is a property of a meeting.** When two nodes meet and co-sign each other's current chain head, they create an irreversible fact: everything in A's chain before the meeting provably existed before everything in B's chain after it. No timestamp server, no consensus, no blockchain. Just contact — and contact is the one thing field operations reliably produce, because vehicles and supervisors physically move between sites daily.

> **A system that measures its own ignorance can be trusted with evidence that a confident system cannot.** Coverage — what fraction of expected data is actually present — is derivable from sync metadata, and once you have it, "nobody reported" becomes distinguishable from "nobody connected."

### An honesty caveat about the motive itself

`docs/VIGILARCH.md` §0 and §21 state plainly that the original documentation was lost and the entire document was reconstructed from a one-line repository description. §21 ends by listing what could not be recovered: *the intended sector, the first user, whether this is academic, commercial or portfolio work, and any external constraints.*

So: the motive above is **coherent, defensible, and unvalidated**. It was written after the project name existed, not before. There is no user research, no named sector, no first user, no regulator's actual export requirement in the repository. `claude.md` partially resolves this by declaring the project *"a public GitHub repo with a working, self-contained demo… not a product being sold to customers,"* which is the honest and correct answer — but that answer should be promoted into the README, because it changes what "finished" means. Do not present the industry motive as a validated market problem to a reviewer; present it as the setting that makes a technical mechanism interesting.

---

## 2. One-Sentence Project Definition

> **Vigilarch is a Rust ledger and deterministic network simulator in which frequently-disconnected devices co-sign each other's append-only hash chains on contact, so that a record created offline by an untrusted device can later have its creation time bracketed and independently verified from an export file, and so that any aggregate computed over those records carries a machine-derived statement of what is missing.**

Everything else in the design document — the PWA, real radios, federation, the ops console, key rotation, TSA anchoring — is either supporting scaffolding for that sentence or is not v1.

---

## 3. Core Thesis

### Primary thesis (the reason the project deserves to exist)

**Contact-based temporal evidence for human field observations.** Per-device hash chains make retroactive insertion impossible without forking; mutual attestation on contact binds each device's timeline to others', so a record's position in real time is bracketed between the attestation preceding it in its own chain and the first attestation sealing it afterwards. The width of that bracket — the *unwitnessed window* — is computed and displayed rather than hidden.

**Remove this and Vigilarch is not Vigilarch.** It becomes an offline-first incident notes app with sync, of which there are hundreds, and the interesting parts of the repository (the simulator, the verifier, the adversary scenarios) lose their subject. `claude.md` already says this ("M1 is the project"); it is correct and should be treated as non-negotiable.

### Secondary thesis (strong, separable)

**Epistemic honesty as a type-level constraint.** `Covered<T>` as the only way an aggregate can leave the system, coverage derived from sync metadata, and the four-way silence classification (normal/alive, zero/dark, zero/alive, falling/alive). The identity-defining claim here is the *one-sided* invariant: computed coverage must never exceed true coverage, and the simulator asserts it every run.

Removing this leaves a coherent project with half its personality. It is also, per unit of effort, the cheapest interesting thing in the repository — it is arithmetic over sync metadata, not cryptography — and it is the part that most clearly separates Vigilarch from "a distributed ledger toy."

### Optional ideas (interesting, not identity-defining)

- Federation without disclosure (sketches, k-anonymity, wire capture proving zero content crossed).
- Real physical transports — BLE, LoRa, Wi-Fi Direct.
- The Thread/Assertion CRDT interpretation layer and contested-state surfacing.
- The field PWA and the ops console.
- External timestamp anchoring, key rotation, revocation.

One flag: **`claude.md`'s build list omits M3 (Threads, Assertions, CRDT merge) entirely, yet invariant I6 mandates that semantic conflicts surface as `Contested` — a state that only exists in M3.** Resolve this explicitly: either drop `Contested` from the v1 claim set, or scope a minimal multi-value severity register. Recommendation below is to drop it.

---

## 4. Intended User and Scenario

One example, carried end to end. Pick a sector and stay in it — the sector-neutrality in §21 is costing the project concreteness, and the vocabulary problem in `spec/README.md` is a direct symptom.

**Setting.** A metro tunnelling contractor, eleven active worksites across a city and its outskirts. Site 14 is a shaft head with no fixed line and intermittent cellular. The edge node is a mini-PC in the site cabin. Field devices are Android phones. A supervisor, Priya, drives between Site 14, Site 9, and the regional office most days.

1. **Tuesday 07:40, no signal.** Ravi, a rigger, watches a load swing wide over a walkway. Nobody is hurt. He opens Vigilarch, taps two tags and dictates ten seconds of voice. It persists locally, signed with the device key, in under ten seconds, and the UI labels it honestly: *"Recorded. Time not yet verified by another device."*

2. **Tuesday 07:41 – Friday.** Site 14's edge node holds the observation in an append-only chain. It has no external contact. The record's unwitnessed window is open and growing, and Site 14's own dashboard says so.

3. **Wednesday.** The site manager, who has an interest in the record of a later injury, rolls his edge node's clock back three days and injects a "hazard reported — walkway barricaded" record dated the previous Saturday. It looks perfect. Every conventional system in this category would accept it, and would render it with a confident timestamp.

4. **Friday 16:20.** Priya's phone reaches the site LAN. The two nodes exchange checkpoints and co-sign: each signs the other's current head and sequence number, and each embeds the attestation it received into its own next chain entry. Ravi's Tuesday observation is now *sealed* — an independent key has stated it existed before Friday 16:20. The manager's fabricated record is not helped: it sits in the chain **after** an attestation that Priya signed on Wednesday morning, so its claimed Saturday timestamp contradicts its own chain position. To place it before that attestation he would have to fork his chain, which produces a compact, self-verifying fork proof that floods at the highest priority class and quarantines his key.

5. **Friday 18:00.** Priya reaches Site 9 and then the office. She carries a sealed bundle she cannot read; she still entangles at both ends. Two sites that have never had a direct link now have a provable ordering relationship through her chain. An untrusted courier has measurably improved the evidence.

6. **Reconnection.** The regional node reconciles. The office dashboard, which for four days read `coverage 61% · 2 sites dark · oldest 94h`, updates to `coverage 100%`. Because coverage was shown throughout, nobody was ever misled into reading Site 14's silence as safety — and because Site 14's heartbeat was absent, silence detection correctly classified it as *disconnected*, not as *reporting failure*.

7. **Eleven weeks later.** A load-swing injury occurs at Site 14. The contractor exports a signed evidence pack. A third party — regulator's technical assessor, insurer, opposing counsel — runs `vigil-verify` with only the pack and the organisation's public key and gets, without trusting the contractor's servers at all:

   - Ravi's Tuesday observation existed **before Friday 16:20**, attested by two independent keys, unwitnessed window 3d 8h.
   - The manager's "barricaded" record is **chain-order inconsistent** with its claimed timestamp, and his key is quarantined with a fork proof attached.
   - Every ordering claim in the pack is reproducible from the pack itself.

**What the organisation can ultimately prove:** that it knew, when it knew it, and how tightly that knowledge is bounded — for records created on disconnected devices by people nobody was watching.

---

## 5. What I Am Actually Building

**Every row below currently exists as a documented stub only.** I have marked implementation status honestly; "stub" means a `lib.rs` with a doc comment and nothing else.

| Component | What it does | Why it exists | Class | In repo? |
|---|---|---|---|---|
| `vigil-core` (L0) | Deterministic CBOR encoding, BLAKE3 content addressing, Ed25519 sign/verify, HLC, golden vectors | Two nodes must produce byte-identical bytes for the same object or content addresses diverge and the ledger silently forks | **CORE** | Stub (`lib.rs`, 21 lines, all comments) |
| `vigil-ledger` (L2) | Append-only store, per-node hash chains, attestation ingest, attestation DAG, sealing/bracketing queries, fork detection + fork proofs, quarantine | This is the thesis | **CORE** | Stub (29 lines, all comments) |
| `vigil-sim` | Seeded discrete-event simulator running the *real* ledger over a scriptable virtual network; adversary scripts (clock rollback, equivocation, withholding, replay); invariant assertions | Conventional tests cannot reach partition topology, message reordering, or clock adversariality. This is how every claim gets evidenced | **CORE** | Stub (`main.rs`, one `println!`) |
| `vigil-verify` | Standalone binary: given an export pack and the org public key, recompute every ordering claim | The credibility artifact. Independent verification is what makes the claim a claim rather than an assertion | **CORE** | **Does not exist — not even a crate.** Named in `claude.md`, absent from the workspace |
| `spec/01-wire-format.md`, `02-entanglement.md`, `04-threat-model.md` | Wire format with versioning, attestation protocol, guarantees *and explicit non-guarantees* | Between nodes the spec, not the code, is the contract; the threat model is where the honest limits live | **CORE** | `spec/` contains an index README only. All five documents unwritten |
| `vigil-sync` (L3) | Merkle-search-tree range reconciliation, priority classes 0–5, resumable transfer, bundle framing | Makes it a network rather than a pair; priority classes carry the "knowledge degrades gracefully" story | SUPPORTING | Stub (23 lines) |
| `vigil-transport` (L1) | `Link` trait; QUIC + mDNS on LAN; sneakernet bundle import/export | One honest transport is enough to prove the protocol works off a loopback | SUPPORTING | Stub (30 lines). `claude.md` correctly rules out BLE/LoRa/Wi-Fi Direct; the crate's own Cargo.toml description still lists them |
| `vigil-insight` (L5) | `Covered<T>`, event-rate coverage math, four-way silence classification | Pillar 2. Cheap, distinctive, and testable in the simulator without any UI | SUPPORTING | Stub (48 lines, mostly a correction notice against the design doc) |
| `vigil-node` | The binary; `--role edge\|hub\|mule`; loopback HTTP API | Something to actually run; hosts the API the demo drives | SUPPORTING | Stub (`println!`) |
| Federation (sketches, k-anonymity, wire capture) | Count-min/MinHash over controlled-vocabulary signatures; assert zero raw content crosses a boundary | Pillar 3. The credible half is the wire capture, not the statistic | OPTIONAL | Documented only |
| `vigil-wasm` + field PWA | wasm-bindgen surface; React capture screen | Makes the "on a disconnected phone" narrative literal | OPTIONAL | Stub. **Blocked — see §10** |
| Ops console | Coverage-aware React component library | Visual proof of pillar 2 | OPTIONAL | README only |
| Threads / Assertions / `Contested` | CRDT interpretation layer over immutable observations | Real, and a nice design point, but not needed to prove either primary thesis | OPTIONAL | Documented only; omitted from `claude.md`'s build list |

---

## 6. Final Deliverables

"Vigilarch v1 is finished" when these artifacts exist, run, and are reproducible by a stranger with `git clone` and a Rust toolchain.

**Libraries**
1. `vigil-core` — deterministic CBOR encoder/decoder, content addressing, Ed25519 identity, HLC. Golden vectors in `testdata/` pinning the encoding, with a test that fails on any byte drift.
2. `vigil-ledger` — SQLite-backed append-only store behind a `Store` trait; chain append and full-chain verification; attestation ingest and DAG; `bracket(observation) -> (lower_bound_attestation, upper_bound_attestation, unwitnessed_window)`; fork detection producing a serialisable `ForkProof`; quarantine.
3. `vigil-sync` — range reconciliation over a Merkle search tree; priority classes 0–5; resumable exchange.
4. `vigil-insight` — `Covered<T>`, coverage computation, four-way silence classification.

**Binaries**
5. `vigil-node --role edge|hub|mule` — runs a node, exposes the loopback HTTP API, syncs over QUIC on a LAN, imports/exports sneakernet bundles.
6. `vigil-sim --scenario <file> --seed <n>` — deterministic simulator; prints a machine-readable run report; exits non-zero on any invariant violation.
7. `vigil-verify <pack> <org-pubkey>` — independent verifier. **Depends only on `vigil-core` and `vigil-ledger`'s verification path — never on the node, the database, or the network.** Prints, per record: sealed/unwitnessed, witness depth, unwitnessed window, ordering claims, and any fork proof.

**Specifications** (short and precise — 3–6 pages each, not essays)
8. `spec/01-wire-format.md` — canonical encoding rules, object encodings, version negotiation.
9. `spec/02-entanglement.md` — checkpoint and attestation exchange, DAG construction, the bracketing rule stated as a theorem with its proof and its **stated non-guarantees**.
10. `spec/04-threat-model.md` — adversaries handled, adversaries not handled, and exactly what a sealed record does and does not prove.

**Tests and evidence**
11. Property tests on encoding round-trips and any CRDT merge that ships.
12. Fuzz targets on every deserialisation path.
13. `testdata/scenarios/` — at minimum: `honest-partition`, `clock-rollback-append`, `equivocation`, `withholding`, `mule-relay`, `coverage-soundness`. Each seeded and replayable.
14. A CI workflow running `cargo test`, `cargo clippy -D warnings`, the golden-vector check, and the full scenario suite.
15. **An evaluation table in the README with measured numbers**, not targets: backdating detection rate over N seeded runs; coverage-overstatement count (must be 0) over N runs; convergence time after a simulated 72h partition heals; median witness latency under a given contact schedule.

**Demo**
16. `make demo` (or one documented command) that runs the full narrated scenario end to end and produces an export pack, followed by a separate `vigil-verify` invocation on that pack.
17. A README that lets a visitor understand the thesis in 90 seconds and reproduce the demo in five minutes, including an asciinema recording or a transcript of the demo output.

**Explicitly not on this list:** the PWA, the console, real radios, Capacitor, Postgres, Terraform, key rotation, TSA anchoring, federation.

---

## 7. Final Demo

CLI-first and deliberately unglamorous. A browser UI would make it prettier and would not make it more convincing; the audience for this project is engineers, and engineers are convinced by reproducibility and by a second program agreeing with the first.

**Setup:** four simulated nodes — Site A edge, Site B edge, Priya (mule phone), Hub. One command, one seed. Every step prints its own assertion result.

| # | Step | Property demonstrated |
|---|---|---|
| 1 | Boot four nodes from a seed, sync everything, print state hashes — identical across all four. | Baseline convergence; the simulator runs the real ledger, not a mock. |
| 2 | Partition A and B. Print the hub's view: `coverage 34% · 2 sites dark · oldest 0h`, timer running. | Coverage is derived from sync metadata, not asserted. The system reports what it stopped knowing. |
| 3 | Capture an honest observation on A while dark. Print its record: `sealed: false · unwitnessed window: open · witnesses: 0`. | Capture never blocks on the network; the honest record is honestly labelled as weak evidence, not dressed up with a confident timestamp. |
| 4 | On B, roll the clock back three days and append a backdated "hazard reported" record. Print it — it looks entirely legitimate, correct signature, plausible timestamp. | The attack is real and would be accepted by any conventional offline-first stack. **Make this step convincing; it is the setup for the whole demo.** |
| 5 | Run the mule: Priya contacts A, then B, then the hub. Print the four attestations exchanged (~150 bytes each) and the resulting DAG edges. | Ordering evidence is created by contact alone, over a link too narrow for anything else. The mule never decrypts a byte and still tightens the guarantee. |
| 6 | Heal the partition. Re-print state hashes — identical again. Re-print the honest record: `sealed: true · witnesses: 3 · created before 16:20 Fri · unwitnessed window 3d 8h`. | Convergence after a long partition; a disconnected record acquires bounded, attributed temporal evidence with no server involved. |
| 7 | Re-print the fabricated record: **chain-order inconsistent** — it appends after an attestation that postdates its claimed timestamp — attributed to B's specific key, with the fork proof if B forked to escape. | The tamper is caught by the shape of the contact graph, not by a trusted authority. Attribution is cryptographic and specific. |
| 8 | **Ablation:** re-run the identical seed with attestation exchange disabled. The fabricated record is now indistinguishable from the honest one. | Proves the mechanism does the work, rather than the scenario being rigged. This step is worth more than any UI. |
| 9 | Export a signed pack. Kill every node. Run `vigil-verify pack.vgl org.pub` in a fresh process. It reproduces every ordering claim, the unwitnessed windows, and the tamper finding. | Evidence survives the system that produced it. A third party needs neither the vendor's servers nor its goodwill. |
| 10 | Run the coverage-soundness scenario across 1,000 seeds; print `coverage overstatement events: 0`. | The one-sided honesty invariant is measured, not claimed. |

**What makes a technically competent engineer say "okay, that's interesting"?**

Not the ledger — hash chains are 1991. Not the sync — range reconciliation is well-trodden. Three things, in order:

1. **Step 8, the ablation.** Almost nobody demonstrating a security mechanism shows the same scenario with the mechanism removed. Doing it turns a demo into an experiment.
2. **Step 9, the independent verifier.** A second binary, with no database and no network, reconstructing the claims from a file and a public key. That is the difference between "I built a system that says it's trustworthy" and "I built evidence."
3. **Step 3 and step 6 together — the honest label.** The system says *"I cannot prove when this happened yet, and here is exactly how wide my uncertainty is,"* then later narrows it and shows by how much. Every product in this space prints a confident timestamp it has no right to. Watching a system refuse to, and then quantify its own uncertainty, is the memorable part.

The thing that will *not* impress anyone: a React screen with a coverage percentage on it. Build the percentage; skip the screen.

---

## 8. Definition of Done

**DONE IF:**

- `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` pass in CI on a clean clone.
- Golden vectors in `testdata/` pin the canonical encoding, and a test fails on any byte-level change to any encoded object.
- 10,000 observations append and verify; a full-chain verification pass detects a single-byte mutation to any historical record, and the test asserts *which* record.
- `vigil-sim` is deterministic: the same seed produces a byte-identical run report on two machines.
- The `clock-rollback-append` scenario is detected in **100%** of 1,000 seeded runs, and detection is attributed to the correct key in 100% of those runs.
- The `equivocation` scenario produces a valid fork proof that quarantines the offending key on every honest node, in 100% of 1,000 seeded runs.
- The **ablation** run (attestations disabled, identical seed) fails to detect the same tamper — proving the mechanism, not the scenario, is doing the work.
- Across ≥1,000 seeded runs including adversarial ones, **coverage overstatement events = 0**.
- Silence detection separates all four cases in §10.3 on seeded scenarios with recall > 0.9 on the "zero reports / live heartbeat" case.
- Two nodes with 100k objects differing by 20 converge in < 5 round trips and < 50 KB; a sync killed at a random point resumes with no duplication or loss.
- `vigil-verify`, given only an export pack and the org public key, in a process with no database and no network access, reproduces every ordering claim, unwitnessed window, and tamper finding in the pack — verified by diffing its output against the simulator's.
- `spec/01`, `spec/02`, and `spec/04` are written, versioned, and match the implementation, with non-guarantees stated as prominently as guarantees.
- One documented command runs the full demo end to end on a clean machine, and the README contains its transcript plus the measured evaluation table.

**NOT DONE IF:**

- Any ordering claim reaches a user or an export pack that `vigil-verify` cannot independently reproduce.
- Any code path can produce an aggregate without a coverage annotation, or coverage can be suppressed.
- Any single computed coverage value exceeds true coverage in any run, ever. (One occurrence is a top-severity defect, not a tuning issue.)
- The wire format is unversioned or unnegotiated on connection.
- Ledger or attestation logic exists in more than one language.
- `SystemTime::now()` or equivalent appears anywhere in `vigil-ledger`.
- The demo requires manual steps, a specific machine, or a human narrating over gaps.
- The README claims a capability the test suite does not exercise.

**Explicitly NOT required for done:** any mobile app, any React component, any physical radio, any cloud deployment, any federation, any key rotation, any real user.

---

## 9. Explicit Non-Goals

Vigilarch v1 will not attempt to:

1. **Drive physical radios.** No BLE, LoRa, Wi-Fi Direct, or real mule hardware. They are link *profiles* in the simulator — bandwidth, latency, loss, MTU. The interesting claim is that classes 0–1 fit a 50 byte/s link, and that is provable against a simulated profile without owning a radio.
2. **Ship a mobile application.** No Capacitor, no native build, no MDM, no Android. If a capture UI is built at all it is a single ugly HTML page against the loopback API.
3. **Manage keys properly.** No rotation, no revocation gossip, no remote wipe, no HSM, no split custody. Certificate issuance is stubbed and the limitation is stated in the README.
4. **Do machine learning.** No federated learning, no gradient averaging, no model. The word "AI" does not appear in the repository. Sketches and counters only, if federation ships at all.
5. **Deploy anything.** No Postgres hub read model, no Terraform, no Ansible, no Docker, no edge-box provisioning. **Delete `deploy/` from the README layout — it does not exist.**
6. **Be a product.** No multi-tenancy, billing, RBAC, admin console, onboarding, or user management.
7. **Anchor to external time.** No RFC 3161, no transparency log. Vigilarch v1 proves *relative* ordering. Absolute anchoring is a paragraph in the threat model, not code.
8. **Build the interpretation layer.** Threads, assertions, entity resolution, and `Contested` state are cut. Tag observations directly; drop the `Contested` claim from the v1 pitch or demote it to future work. (This resolves the I6-without-M3 contradiction in favour of less code.)
9. **Handle media at scale.** No blob chunking, no thumbnail pipeline, no photo sync. A text body and a tag set are sufficient to demonstrate everything above.
10. **Be sector-neutral.** Pick one sector for the vocabulary and the export format. Sector-neutrality is currently costing concreteness and buying nothing.
11. **Solve erasure rights.** Append-only conflicts with GDPR/DPDP erasure. State the tension in the README as a known open problem. Do not attempt cryptographic erasure.
12. **Achieve field-realistic performance targets.** The <10s capture latency and <3%/day battery figures in §14/§17 require hardware and users that do not exist. Drop them from the acceptance criteria.

The design document's most seductive scope traps, named so they can be resisted: **the PWA** (visible, fun, and ends with an offline notes app), **federated learning** (impressive-sounding, statistically worthless at tens of events per site per month, and explicitly banned by `claude.md`), and **real transports** (feels like "making it real," costs weeks, proves nothing the simulator cannot).

---

## 10. Current Repository Reality

### What exists

- A Cargo workspace: resolver 3, edition 2024, rust-version 1.85, eight member crates, a pinned toolchain with `wasm32-unknown-unknown` registered, a release profile, and a `dev.package."*"` opt-level bump for simulator speed. Competently set up.
- `Cargo.lock` resolving 177 packages, so the dependency graph has been resolved at least once locally.
- `clippy.toml` banning `SystemTime::now` and `chrono::Utc::now` workspace-wide with a written rationale. Genuinely good — the invariant is encoded in tooling rather than in a comment. (Currently unenforced: no CI.)
- `#![forbid(unsafe_code)]` on every library crate.
- `docs/VIGILARCH.md` — a 780-line, genuinely well-argued design document, honest about its own reconstruction and about its limits (§4.5, §21).
- `claude.md` — the most useful file in the repository. It cuts scope, wins over the design doc on conflict, states six invariants, lists what not to build, and identifies two real defects in its own design document (gameable coverage weighting; a federation demo statistic from n=2 that violates the honesty pillar). This is unusually good self-critique for a pre-M0 project.
- README, spec index, testdata policy, ADR policy, two app READMEs.

### What is partially implemented

Nothing. There is no partial implementation anywhere in the tree.

### What exists only in documentation

Everything else. Specifically: canonical encoding, hashing, signing, HLC, CRDTs, the store, hash chains, checkpoints, attestations, the DAG, sealing, fork proofs, quarantine, reconciliation, priority classes, bundles, the `Link` trait, QUIC, mDNS, coverage, silence detection, sketches, the node binary's actual behaviour, the WASM surface, the simulator, the verifier, all five spec documents, all golden vectors, all scenarios, all tests, CI.

### What appears stale or contradictory — already, at commit one

1. **`vigil-ledger` depends on `rusqlite` with `bundled`, and `vigil-wasm` (a `cdylib` targeting `wasm32-unknown-unknown`) depends on `vigil-ledger`.** Bundled SQLite compiles C and does not build for `wasm32-unknown-unknown`. As scaffolded, architectural invariant I2 — one implementation compiled to native *and* WASM — is unbuildable. **Fix before writing ledger code:** put storage behind a `Store` trait in `vigil-ledger`, make `rusqlite` an optional/default feature, and provide an in-memory (later OPFS) backend for the WASM target. This is cheap now and expensive after 3,000 lines of SQL are inlined.
2. **`vigil-wasm` declares no `wasm-bindgen` dependency** despite being documented as a wasm-bindgen wrapper. `wasm-bindgen` appears in `Cargo.lock` only transitively.
3. **`vigil-verify` does not exist** as a crate, though `claude.md` names the independent verifier as a deliverable. It is arguably the most persuasive artifact in the project.
4. **`vigil-sim` does not depend on `vigil-insight`**, yet is required to assert coverage soundness (I5) on every run.
5. **README contradicts `claude.md`.** The README still advertises Capacitor, BLE, LoRa, sneakernet radios, M7 and M8, a `deploy/` directory that does not exist, and lists federation as a pillar. `apps/field/README.md` still specifies Capacitor, Android-first, and a battery-drain acceptance criterion. `crates/vigil-transport/Cargo.toml`'s description still lists BLE and LoRa. `claude.md` cuts all of it. Since the README is what a visitor reads first, the scope cut should be visible there.
6. **`license = "UNLICENSED"` on a public portfolio repository.** Default copyright, nobody may reuse it, and some reviewers read it as carelessness. Pick a licence.
7. **No CI.** Every "asserted in CI" claim in `claude.md` is currently aspirational.
8. **The README milestone table lists M3, M6, M7, M8 as project milestones** while `claude.md` cuts or omits them. Two documents, two scopes.
9. **Windows GNU toolchain instructions** suggest the dev environment lacks MSVC build tools. `Cargo.lock` pins `ring` rather than `aws-lc-rs`, which is the workable path for `quinn` there — keep it that way deliberately, and pin the rustls provider explicitly rather than relying on defaults.

### The next logical implementation step

Not code. **`spec/01-wire-format.md` and one golden vector.** Concretely, the next three commits:

1. Write `spec/01-wire-format.md`: the deterministic CBOR subset (map key ordering, integer encoding, no indefinite lengths, no floats), the `Observation` and `Attestation` encodings field by field, and the version tag. Two pages.
2. Implement `vigil-core`: the canonical encoder over `ciborium` (which is not deterministic by default — the workspace manifest already flags this), BLAKE3 addressing, Ed25519 sign/verify, HLC. Commit the first golden vector in `testdata/` and the test that pins it.
3. Restructure `vigil-ledger` around a `Store` trait *before* writing any SQL, so item (1) in the contradiction list never becomes a problem.

Then M1 immediately: checkpoints, attestation exchange, the DAG, and the bracketing query — with `vigil-sim` growing alongside it from the first attestation, exactly as `claude.md` says.

---

## 11. Architecture at Completion (v1 only)

```
┌──────────────────────────────────────────────────────────────────────┐
│  vigil-sim                      vigil-verify                         │
│  deterministic DES              standalone verifier                  │
│  · virtual links (bw/lat/loss)  · reads export pack + org pubkey      │
│  · clock rollback, equivocation · no DB, no network, no node          │
│  · withholding, mule schedule   · reproduces every ordering claim     │
│  · invariant assertions ────────┐                                    │
└─────────────────┬───────────────┼────────────────────────────────────┘
                  │ drives        │ reads
                  ▼               │
┌──────────────────────────────────────────────────────────────────────┐
│  vigil-node   --role edge | hub | mule                               │
│  loopback HTTP API:  POST /obs · GET /obs/:id/provenance             │
│                      GET /insight/coverage · GET /insight/silence     │
│                      POST /export/pack ──────────────────────────────┼──► pack.vgl
└─────────────────┬────────────────────────────────────────────────────┘
                  │
   ┌──────────────┼──────────────┬───────────────────┐
   ▼              ▼              ▼                   ▼
┌────────────┐ ┌────────────┐ ┌────────────────┐ ┌──────────────────┐
│vigil-      │ │vigil-sync  │ │vigil-insight   │ │vigil-transport   │
│ledger  L2  │ │        L3  │ │            L5  │ │              L1  │
│· append-   │ │· Merkle    │ │· Covered<T>    │ │· Link trait      │
│  only store│ │  range     │ │· coverage math │ │· QUIC (quinn)    │
│  (Store    │ │  reconcile │ │· 4-way silence │ │· mDNS discovery  │
│  trait)    │ │· priority  │ │  classification│ │· sneakernet      │
│· hash      │ │  classes   │ │                │ │  bundle in/out   │
│  chains    │ │  0–5       │ │                │ │                  │
│· attest.   │ │· resumable │ │                │ │                  │
│  DAG       │ │            │ │                │ │                  │
│· sealing / │ │            │ │                │ │                  │
│  bracketing│ │            │ │                │ │                  │
│· fork      │ │            │ │                │ │                  │
│  detection │ │            │ │                │ │                  │
└──────┬─────┘ └──────┬─────┘ └───────┬────────┘ └────────┬─────────┘
       └──────────────┴───────────────┴───────────────────┘
                              ▼
                   ┌────────────────────────┐
                   │  vigil-core       L0   │
                   │  · canonical CBOR      │
                   │  · BLAKE3 addressing   │
                   │  · Ed25519 identity    │
                   │  · HLC (hint, not      │
                   │    evidence)           │
                   └────────────────────────┘

  spec/01-wire-format · spec/02-entanglement · spec/04-threat-model
  testdata/  golden vectors + seeded scenarios     CI: test + clippy + scenarios

  NOT IN V1: PWA · WASM · console · BLE/LoRa · federation · threads
             key rotation · TSA anchoring · Postgres hub · deploy/
```

### Data flow for one observation

1. **Capture.** A client POSTs a body and tags to `vigil-node`'s loopback API. The node builds an `Observation`, sets `prev` to its own current chain head, stamps an HLC value (a merge hint, explicitly not evidence), encodes it with `vigil-core`'s canonical CBOR, hashes the bytes with BLAKE3 to produce the content-addressed `id`, and signs the `id` with the device Ed25519 key. No network call. Returns immediately.

2. **Local persistence.** `vigil-ledger` appends through the `Store` trait in one transaction: the object, its chain link, and an index entry. The append is rejected if `prev` is not the current head — a node cannot insert into its own past; it can only append or fork, and a fork is detectable misconduct.

3. **Cryptographic history.** The record now sits at a fixed position in the author's chain. Its temporal standing is `unwitnessed`: bounded below by the most recent attestation preceding it in the same chain, and unbounded above. `GET /obs/:id/provenance` says so in plain language.

4. **Peer interaction.** On any link, before payload reconciliation: exchange `Checkpoint` (head, seq, version vector, signature), then exchange `Attestation` (witness, subject, subject head, subject seq, witness HLC, nonce, signature) — ~150 bytes each, priority class 1, fits any link. Each node embeds the attestation it received in its next chain entry. `vigil-sync` then reconciles payloads by Merkle range in priority order; classes 0–1 always ship, higher classes as bandwidth permits. Attestations gossip onward: an attestation A made about B is useful to C.

5. **Sealing.** When any node holds an attestation whose subject head is a descendant of the observation, the observation becomes `sealed`. `vigil-ledger` computes the bracket: `[last attestation before it in its own chain, first attestation sealing it]`, plus witness depth (distinct keys) and unwitnessed window (bracket width). Where the DAG does not prove an ordering, the answer is `unwitnessed` — never a guess.

6. **Verification.** `POST /export/pack` emits a signed pack: the observations in scope, the full attestation closure needed to justify each claim, chain segments, any fork proofs, and the org certificate chain. `vigil-verify` takes that file and the org public key, re-derives every content address, checks every signature, rebuilds the DAG, and recomputes every bracket — with no database, no network, and no trust in the exporting organisation.

7. **Presentation.** `vigil-insight` wraps every aggregate over these records in `Covered<T>`: value, coverage fraction, contributing nodes, dark nodes and their durations. Nothing reaches a human without it. Per-record, the honest sentence is: *"created before Friday 16:20; three independent devices can prove it; nothing proves it was created after Tuesday 07:38."*

---

## 12. Novelty / Differentiation

Being conservative, because the design document is not.

### Established techniques being reused (no novelty claim)

- Linked timestamping / hash chains — Haber & Stornetta 1991.
- Timeline entanglement via mutual attestation — Maniatis & Baker, USENIX Security 2002. **This is the core mechanism and it is 24 years old.** The design document cites it correctly; the README's framing is more triumphant than the citation supports.
- Per-feed signed hash chains under intermittent connectivity — Secure Scuttlebutt, in production for a decade.
- Witness cosigning and transparency logs — CoSi, Certificate Transparency.
- Range-based set reconciliation over Merkle search trees — Iroh/Willow, Earthstar.
- CRDTs, HLC, count-min and MinHash sketches, k-anonymity, delay-tolerant networking store-carry-forward.

Every individual mechanism in Vigilarch has a citation. There is no new cryptography here and the project should never imply there is.

### Interesting application and synthesis (the honest claim)

1. **Applying timeline entanglement to human-generated field observations under multi-week partitions.** The technique has lived in digital preservation and PKI transparency, where the subjects are documents and certificates and the witnesses are servers. Applying it where the subjects are people's observations, the witnesses are a supervisor's phone in a truck, and the adversary is an employer with a liability motive is, as far as I can determine, unexplored. The adversary model is the interesting part: in CT the log operator is the suspect; here the *record's own author's employer* is.
2. **The physical-mobility insight.** Contact frequency is the forensic resolution of the system, and field operations produce contact for free through vehicle and crew movement. Framing an untrusted courier as something that *improves* evidence quality — it carries ciphertext it cannot read and still tightens the ordering bound — is a genuinely elegant inversion and is the strongest single idea in the document.
3. **Coverage as a non-suppressible type-level property** (`Covered<T>`), derived from sync metadata rather than user input. Alerting on absence exists in observability tooling; making it a compile-time-enforced property of every aggregate in a safety system, with a one-sided soundness invariant asserted in a simulator, is a design position rather than a technique — but it is a defensible one and no incumbent EHS platform does it.
4. **The four-way silence classification** separating "nothing happened" / "nobody reported" / "nobody connected" / "reporting decaying". Simple once partition is modelled; genuinely impossible for systems that aren't.

### Could reasonably be called a contribution

One thing, if you do it properly: **an empirical characterisation of offline evidence quality as a function of contact topology.** Concretely — witness latency distribution, attestation-graph density, and adversarial detection rate measured across seeded partition/mobility scenarios, with an ablation showing what entanglement buys over a plain hash chain. Nobody has published that for this mechanism in this setting, it is achievable with `vigil-sim` alone, and it converts the project from "I implemented a 2002 paper" into "I measured when a 2002 paper's guarantee is worth anything in a mobility regime it was never designed for."

That is a workshop paper, not a top-tier one, and it is a strong portfolio artifact. **Aim there.** Do not claim a novel protocol.

### What is not novel and should not be claimed

The ledger itself. The sync. "Federation without disclosure" — sketch-based aggregation is standard; the application is new but the design document's own example statistic (median lead time from n=2) is statistically indefensible, as `claude.md` already notes. And "no blockchain" is a correct engineering choice, not a contribution.

---

## 13. Scope Reality Check

**Verdict: `claude.md`'s scope is still roughly 2–3× too large for one student developer.** For calibration, `docs/VIGILARCH.md` §21 estimates M0–M8 at 4–8 months for *a small competent team*, or a full academic year for one person. `claude.md` cuts that to M0, M1, sim, M2, M5, M4-lite, M8-lite, plus a hosted WASM demo — realistically still 3–5 months of solid solo work, and that estimate assumes the ledger goes smoothly, which it will not, because canonical encoding and DAG reachability queries are exactly where the quiet, expensive bugs live.

The question to optimise is not "how much of the design can I build" but "what is the smallest artifact set that makes the thesis undeniable." That set is roughly six weeks of focused work.

| Capability | Class | Note |
|---|---|---|
| `vigil-core`: canonical CBOR, BLAKE3, Ed25519, HLC, golden vectors | **MUST BUILD** | Everything downstream is meaningless if encoding is not deterministic across builds |
| `vigil-ledger`: append-only store behind a `Store` trait, hash chains, full-chain verify | **MUST BUILD** | |
| `vigil-ledger`: checkpoints, attestations, DAG, bracketing/sealing queries, fork proofs, quarantine | **MUST BUILD** | This is the project. Never cut, never deferred |
| `vigil-sim`: deterministic DES over the real ledger, adversary scripts, invariant assertions | **MUST BUILD** | The evidence-production machine. Built *alongside* M1 |
| `vigil-verify`: independent verifier binary + export pack format | **MUST BUILD** | Highest persuasion per line of code in the entire project. Currently not even a crate |
| `spec/01`, `spec/02`, `spec/04` | **MUST BUILD** | Short and precise. `spec/02` must state non-guarantees as loudly as guarantees |
| CI + measured evaluation table in README | **MUST BUILD** | Unmeasured claims are worth nothing to a reviewer |
| The ablation run (attestations off, same seed) | **MUST BUILD** | Nearly free, and it is what makes the demo an experiment |
| `vigil-insight`: `Covered<T>`, coverage math, four-way silence | **SHOULD BUILD** | Pillar 2, cheap, arithmetic not crypto, provable entirely in the simulator |
| `vigil-sync`: Merkle range reconciliation + priority classes 0–5 | **SHOULD BUILD** | Needed for the convergence and graceful-degradation claims. **Fallback:** ship naive set-difference sync with a documented Merkle plan, and say so |
| `vigil-transport`: QUIC + mDNS on a real LAN | **SHOULD BUILD** | One honest transport proves it works off a loopback. Two days if the sync API is clean |
| Sneakernet bundle export/import | **NICE TO HAVE** | Cheap, and rhetorically strong ("this works over a USB stick"). Do it if `vigil-sync` lands early |
| Federation: vocabulary, count-min sketches, k-anonymity, **wire capture proving zero content crossed** | **NICE TO HAVE** | The wire capture is the credible half and is nearly free once sync exists. The statistics are not. Cut first under pressure |
| `vigil-wasm` + minimal PWA capture page | **NICE TO HAVE** | Blocked on the `Store` trait fix. Do it only if everything above is done and stable |
| Hosted browser demo of the simulator | **NICE TO HAVE** | Genuinely good for a public repo. A recorded terminal transcript gets 80% of the value for 5% of the cost. Start there |
| Threads / Assertions / CRDT merge / `Contested` | **CUT FROM V1** | Not needed by either primary thesis. Tag observations directly. Drop the `Contested` claim or demote it |
| Real BLE / LoRa / Wi-Fi Direct / mule hardware | **CUT FROM V1** | Simulated link profiles prove the same claim |
| Capacitor / native builds / Android / MDM | **CUT FROM V1** | |
| Ops console React app + coverage component library | **CUT FROM V1** | Build the coverage *math*; a CLI table demonstrates it |
| Key rotation, revocation gossip, remote wipe, HSM | **CUT FROM V1** | Stub issuance, document as out of scope |
| TSA / transparency-log anchoring | **CUT FROM V1** | One paragraph in the threat model |
| Federated learning, gradient averaging, any model | **CUT FROM V1** | Already banned by `claude.md`. Keep it banned |
| Postgres hub, Terraform, Ansible, `deploy/` | **CUT FROM V1** | Remove `deploy/` from the README |
| Media blobs, chunking, thumbnails | **CUT FROM V1** | Text plus tags suffices |
| Field performance targets (<10s capture, <3%/day battery) | **CUT FROM V1** | Requires hardware and users that do not exist |
| Precursor mining, lead-time statistics, entity resolution | **CUT FROM V1** | Statistically indefensible at this data volume |

**Suggested sequence.** (1) `spec/01` + `vigil-core` + golden vectors. (2) `Store` trait + chains + verification. (3) Attestations, DAG, bracketing, fork proofs — with `vigil-sim` growing in parallel from the first attestation. (4) Export pack + `vigil-verify`. (5) `spec/02` + `spec/04` + CI + the measured table. **Stop here and publish.** Anything past this point is a second project: (6) coverage and silence, (7) sync and QUIC, (8) the wire capture.

Step 5 is a complete, defensible, publishable artifact. Recognising that is worth more than any feature below it.

---

## 14. Final Project Brief

*Standalone. Hand this to a reviewer who has never seen the repository.*

**PROJECT:** Vigilarch

**MOTIVE.** Safety and security incident records from physical worksites are legally consequential and are created where there is no connectivity. Existing offline-capable systems store whatever the device clock says, and a device clock is a settable field — so offline records cannot be distinguished from backdated fabrications and are treated as soft evidence in practice. The same systems present aggregates computed over partial data with full confidence, which makes a site that stopped reporting look identical to a site that stopped having incidents.

**PROBLEM.** Produce a record on a disconnected, untrusted device that can later be shown to a third party with a defensible, independently checkable claim about *when* it was created — with no central authority, no consensus protocol, and no assumption of connectivity — and compute aggregates over such records that state honestly what they do not include.

**CORE IDEA.** In a partitioned network, proof of time is a property of contact rather than of a clock. Each device keeps an append-only, per-device hash chain, so it can append or fork but never insert into its own past. Whenever two devices meet — over any link, including one too narrow for anything else — they exchange ~150-byte mutual attestations over each other's current chain head and embed the result in their own next entry. A record's creation is then bracketed between the last attestation preceding it in its own chain and the first attestation sealing it afterwards. The width of that bracket is computed and displayed rather than concealed. Contact frequency is the system's forensic resolution — and physical operations generate contact for free, because vehicles and supervisors move between sites daily. Notably, a courier carrying ciphertext it cannot read still tightens the bound.

**WHAT I AM BUILDING.** A Rust workspace: `vigil-core` (deterministic CBOR, BLAKE3 content addressing, Ed25519, HLC); `vigil-ledger` (append-only store behind a `Store` trait, per-device hash chains, attestation DAG, sealing/bracketing queries, fork detection and quarantine); `vigil-sync` (Merkle-range reconciliation, priority classes 0–5); `vigil-insight` (`Covered<T>` coverage math, four-way silence classification); `vigil-node` (the runnable node with a loopback API and QUIC/mDNS on a LAN); `vigil-sim` (a seeded, deterministic discrete-event simulator running the real ledger over scriptable virtual links with adversarial node behaviour); and `vigil-verify` (a standalone verifier that reproduces every ordering claim from an export file and a public key, with no database and no network). Plus three short protocol specs, golden vectors, seeded adversarial scenarios, and CI. No mobile app, no radios, no cloud, no ML.

**CORE TECHNICAL CONTRIBUTION.** Not the mechanism — timeline entanglement is Maniatis & Baker 2002, and hash chains are Haber & Stornetta 1991. The contribution is (a) applying that mechanism to human field observations under week-long partitions where the adversary is the record author's own employer rather than a log operator, (b) making the resulting uncertainty a first-class, user-visible, non-suppressible property rather than hiding it behind a confident timestamp, and (c) an empirical characterisation — witness latency, attestation-graph density, adversarial detection rate across seeded mobility and partition regimes, with an ablation isolating what entanglement buys over a plain hash chain. That is a workshop-paper-shaped contribution and a strong systems portfolio artifact. It is not a novel protocol and will not be claimed as one.

**FINAL DELIVERABLES.** Four libraries and three binaries as above; `spec/01-wire-format.md`, `spec/02-entanglement.md`, `spec/04-threat-model.md`; golden vectors pinning the canonical encoding; six seeded adversarial scenarios; property tests and fuzz targets on all deserialisation paths; CI running tests, clippy, golden vectors and the full scenario suite; a one-command demo with a recorded transcript; and a README evaluation table of **measured** numbers.

**FINAL DEMO.** One command, four simulated nodes, one seed. Sync and show identical state. Partition two sites; the dashboard drops to 34% coverage with a running dark timer. Capture an honest record offline — labelled `unwitnessed`, honestly. Roll a site's clock back three days and inject a convincing backdated hazard report. Run a mule between the sites: four ~150-byte attestations, no internet. Heal the partition: the honest record is now sealed by three independent keys with a stated 3d 8h unwitnessed window; the fabricated one is chain-order inconsistent and attributed to a specific key. Re-run the identical seed with attestations disabled — the tamper is now undetectable, proving the mechanism rather than the scenario does the work. Export a pack, kill every node, and have a separate `vigil-verify` process reproduce every claim from the file and the org public key. Finally, 1,000 seeded runs reporting zero coverage-overstatement events.

**DEFINITION OF DONE.** Backdating detected in 100% of 1,000 seeded runs with correct key attribution; equivocation always producing a valid gossiped fork proof; the ablation run failing to detect the same tamper; zero coverage-overstatement events across all runs; `vigil-verify` reproducing every ordering claim with no DB and no network; deterministic simulator runs byte-identical across machines; golden vectors pinning the encoding; three specs written and matching the code; CI green on a clean clone; one command running the whole demo. Development stops there — not when the design document is exhausted.

**NON-GOALS.** Mobile app, Capacitor, BLE, LoRa, Wi-Fi Direct, real mule hardware, key rotation, revocation, remote wipe, HSM, TSA anchoring, Postgres hub, Terraform, Ansible, ops console, threads/assertions/`Contested`, media blobs, federated learning, precursor statistics, multi-tenancy, sector neutrality, and any field performance target requiring hardware or users that do not exist.

**CURRENT STATE.** A pre-M0 scaffold at one commit. Cargo workspace (edition 2024, eight crates), a pinned toolchain, a `clippy.toml` banning wall-clock reads near the evidence path, `#![forbid(unsafe_code)]` everywhere, a resolved lockfile, a strong 780-line design document, and a `claude.md` operating contract that cuts scope and correctly identifies two defects in its own design document. **Zero lines of implementation.** No types, no tests, no specs, no golden vectors, no CI. Known defects to fix before writing code: `vigil-ledger`'s bundled `rusqlite` makes the WASM target unbuildable, violating the single-implementation invariant; `vigil-wasm` declares no `wasm-bindgen`; `vigil-verify` is not a crate; `vigil-sim` does not depend on `vigil-insight`; the README still advertises Capacitor, radios, a nonexistent `deploy/` directory and milestones `claude.md` has cut; the licence is `UNLICENSED` on a public repository.

**NEXT STEP.** Write `spec/01-wire-format.md` — the deterministic CBOR subset and the `Observation`/`Attestation` encodings, two pages — then implement `vigil-core` against it and commit the first golden vector with the test that pins it. Restructure `vigil-ledger` around a `Store` trait before any SQL is written. Then M1, with `vigil-sim` growing alongside it from the first attestation.

---

## The question you actually asked

> If I spend the next few weeks building Vigilarch, what exactly am I building, why does it deserve to exist, and what concrete demonstration proves that I succeeded?

**What you are building:** a hash-chained, append-only ledger in which offline devices co-sign each other's chain heads on contact, a deterministic simulator that attacks it, and an independent verifier that reproduces its claims from a file. Three artifacts. Not nine crates, not a PWA, not a platform.

**Why it deserves to exist:** because there is a real and slightly embarrassing gap between what offline-first systems claim about time and what they can prove, the fix is a technique that has existed since 2002 and has never been pointed at this problem, and nobody has measured when that technique's guarantee is actually worth anything under realistic mobility. That is a legitimate systems project with a legitimate small contribution attached.

**What proves you succeeded:** a stranger clones the repository, runs one command, watches a convincing forgery get caught by nothing but the shape of a contact graph, watches the same forgery survive undetected when attestations are switched off, and then watches a second program with no database and no network confirm the finding from a file and a public key.

**The real risk is not technical.** With 1,540 lines of documentation and 6 lines of executable code, the failure mode is not building the wrong thing — the plan is sound and unusually self-aware. It is continuing to write about it. `claude.md` names this exactly ("the tempting path is to build the PWA first"), but the more likely trap for this repository is a fourth document. The next commit should contain a test.
