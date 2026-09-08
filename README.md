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

## Demo

One script runs the whole thesis end to end on one machine, using only what v1 ships —
no cross-process networking between nodes, because that needs `vigil-sync` (v2):

```
./demo.sh          # needs a Rust toolchain and curl
```

It has six steps, each preceded by narration explaining the property it demonstrates
and the spec section it comes from:

1. **honest partition** (`vigil-sim`) — two nodes meet offline; from the far node's
   ledger alone, `bracket(O0)` is **sealed** by the attestation `U`, with the window
   left honestly open below to genesis. `spec/02` §5.2, §8.1.
2. **equivocation** (`vigil-sim`) — one key signs two irreconcilable entries; the fork
   is caught, one self-verifying `ForkProof` is produced, the author is quarantined,
   and the withheld sibling is never sealed. `spec/02` §6, §6.4–6.5; ADR-0003.
3. **export** (`vigil-ledger`) — `export_pack` over step 1's resulting store, the same
   path `testdata/packs/` fixtures come from, emits a real evidence pack (`O0` plus
   `U`). `spec/03` §2–§4.
4. **verify, honest** (`vigil-verify`) — an independent re-check that links only
   `vigil-core`: re-parses the pack, rebuilds the chain and DAG, recomputes the
   bracket. Exit 0, `SEALED`, witness depth 1. `spec/03` §5.
5. **verify, tampered** (`vigil-verify`) — the same tool against
   `testdata/packs/t2-resigned-genesis.vgl`, a validly re-signed genesis. Exit 1,
   chain `VIOLATED`, `BrokenLink` at seq 1, attributed to the author key. A pass here
   would mean the tamper detection had broken. `spec/03` §6.5 T2.
6. **the runnable server** (`vigil-node`) — separate from the rest and making *no*
   sealed claim: starts a real HTTP node, `POST`s one observation, reads its
   provenance back. A lone node holds no attestations, so it correctly reports the
   record **unwitnessed** with the window open both ways.

Steps 1–5 are deterministic from seed 1. Step 6's node mints a fresh key on start, so
its node key and record id differ each run; its verdict (`unwitnessed`, window open
both ways) does not.

<details>
<summary>Captured transcript (<code>./demo.sh</code>, verbatim)</summary>

```
════════════════════════════════════════════════════════════════════
STEP 1 — honest partition: a meeting is the proof of time
════════════════════════════════════════════════════════════════════

Two nodes, no network. Node A writes observation O0 while disconnected. A and B
meet: B co-signs A's current chain head as attestation U, and A embeds U in its
next entry. From B's ledger alone, bracket(O0) is SEALED by U — proof O0 existed
no later than the meeting — with the unwitnessed window left honestly open below
to genesis, because nothing proves O0 did not exist earlier.
  spec/02 §5.2 (sealing theorem), §8.1 (upper bound only).
vigil-sim run report
seed: 1
node A key: 4bb675de4f6376ab61737033d701560e4434be1d6736562ae29b8835b763cd24
node B key: 810f94d89039eee11d927f71e2a9e4550cbda306d4cd8e5acf6020885ed381a1
[t=1000] A appends O0 seq=0 id=05d7efd83a39
[t=2000] A offers checkpoint head=05d7efd83a39 seq=0 id=8b81ec69a258
[t=2000] B declines checkpoint (empty chain)
[t=2000] B attests A@0 -> U id=77df7dc2d721 (witness B)
[t=2000] O0 relayed A->B
[t=3000] A appends O1 seq=1 acks=[77df7dc2d721] id=a8c8ce637cf5; O1 relayed A->B
bracket(O0) from B's ledger:
  sealed: true
  upper bound: U id=77df7dc2d721
  lower bound: none
  witness depth: 1
  unwitnessed window: [genesis, U id=77df7dc2d721]
INVARIANT ok: O0 is sealed from B's view by U, window open below to genesis (spec/02 §8.1)

════════════════════════════════════════════════════════════════════
STEP 2 — equivocation: two stories from one key, caught
════════════════════════════════════════════════════════════════════

The same author signs two irreconcilable entries at seq 1 and lets an honest
witness see only one of them. Once a verifier ends up holding both, verify_chain
convicts the author and detect_forks emits exactly one self-verifying ForkProof.
Quarantine then changes only what that key's *own* attestations buy going
forward: an honest witness's earlier attestation of the branch it actually saw
is not retroactively undone, and the withheld sibling entry is never sealed.
  spec/02 §6 (fork detection), §6.4–6.5 (quarantine semantics); ADR-0003.
vigil-sim equivocation scenario
seed: 1
node A key: 4bb675de4f6376ab61737033d701560e4434be1d6736562ae29b8835b763cd24 (equivocating author + honest witness)
node B key: 810f94d89039eee11d927f71e2a9e4550cbda306d4cd8e5acf6020885ed381a1 (honest witness)
node C key: 003a11215155f4d445aa6302b45f979079bf3b4e087c9896870e098ab679ccc9 (honest, one entry)

step 1: A appends O0 seq=0 id=05d7efd83a39
        A appends O1 seq=1 prev=O0 id=b9a4e7e1adbd
step 2: A equivocates -> O1' seq=1 prev=O0 id=d7224df9074f (distinct body, distinct id)
  [PASS] O1 and O1' are distinct signed objects
step 3: B attests A@1 -> O1 id=7dcfd55749cd (B never saw O1'; a witness cannot know a sibling exists)
step 4: C appends C0 seq=0 id=3bb6858e43dc
        A witnesses C0 -> attestation id=75f871c9615e (A lies on its own chain, but this record is honest)

step 5: verify_chain(world, A)
        verdict: Violated([Equivocation { author: PubKey(4bb675de…), seq: 1, entries: [Hash(b9a4e7e1…), Hash(d7224df9…)] }])
  [PASS] reports Violated
  [PASS] names A and both O1, O1' at seq=1

step 6: detect_forks(world), called twice
  [PASS] run is idempotent (identical proof lists)
  [PASS] exactly one ForkProof
        proof convicts key: 4bb675de4f6376ab61737033d701560e4434be1d6736562ae29b8835b763cd24
  [PASS] the proof convicts A

step 7: Quarantine::apply(proof)
  [PASS] A was newly quarantined
  [PASS] quarantine now contains A

step 8: Dag::build(world, &Quarantine::new())  [empty quarantine]
  [PASS] C0 is sealed by A's honest attestation
  [PASS] C0's upper bound is A's attestation of C0
  [PASS] O1 (the branch B saw) is sealed by B
  [PASS] O1' (the withheld sibling) is NOT sealed, despite sharing A's chain and seq with sealed O1

step 9: Dag::build(world, &quarantine)  [A quarantined; identical held objects]
  [PASS] C0 is NO LONGER sealed — A's attestations stop counting once A is convicted (spec/02 §6.5)
  [PASS] O1 stays sealed by B — a liar's later conviction does not unseal what an honest witness attested (spec/02 §6.5)

INVARIANT ok: equivocation is convicted, the sibling is never sealed, and quarantine changes only what a convicted key's attestations buy going forward (spec/02 §6.5)

════════════════════════════════════════════════════════════════════
STEP 3 — export: package step 1's result as portable evidence
════════════════════════════════════════════════════════════════════

vigil-ledger's export_pack — the exact path testdata/packs/ fixtures come from,
which CI regenerates and byte-diffs — run over node B's store from step 1. The
pack is the minimal object set the claim follows from: O0 and the attestation U.
Reading it back needs no database, no node, and no network.
  spec/03 §2–§4.
pack: exported 515 bytes to target/demo/honest.vgl (claim O0 05d7efd83a39b5e3c6395135ee96f933b6b207c045bca75bd2a7e3a35ef7b457)
verify:       vigil-verify target/demo/honest.vgl d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737

════════════════════════════════════════════════════════════════════
STEP 4 — verify the honest pack independently
════════════════════════════════════════════════════════════════════

vigil-verify links only vigil-core. It re-parses the pack, re-checks every
signature, rebuilds the chain and the attestation DAG, and recomputes the
bracket from scratch — a second implementation of the verification path, not a
call back into the code that built the pack. No database, no node.
Expected: exit 0, SEALED, witness depth 1, upper bound U.
  spec/03 §5.
vigil-verify — spec/03-export-pack.md §5

  pack   515 bytes
  org    d04ab232…78737  (matches argument)
  wire   1

  [1] envelope            OK
  [2] object self-check   2/2 passed
  [3] fork proofs         none
  [4] chains
        4bb675de…3cd24 Verified
  [5] attestation DAG     1 attestation(s) carried
  [6] claims

    05d7efd8…7b457
      status       SEALED
      upper bound  attestation 77df7dc2…cc5de  (witness depth 1)
      lower bound  none
      window       [genesis, attestation 77df7dc2…cc5de]

RESULT: PASS — every claim reproduced from the pack's own evidence.
exit: 0  (0 = every claim reproduced from the pack's own evidence)

════════════════════════════════════════════════════════════════════
STEP 5 — verify a tampered pack: the detection has to fire
════════════════════════════════════════════════════════════════════

testdata/packs/t2-resigned-genesis.vgl replaces the genesis entry with a validly
re-signed one (hlc counter 1, not 0). Every carried object self-checks — the
signature is real — but A@1.prev no longer matches the held predecessor, so the
hash chain does not close. This is an attributable finding against a specific
key, not an ambiguous error.
Expected: exit 1, chain VIOLATED, BrokenLink at seq 1, attributed to the author.
A "success" here would mean the tamper detection had broken.
  spec/03 §6.5 T2; spec/04 (threat model).
vigil-verify — spec/03-export-pack.md §5

  pack   775 bytes
  org    d04ab232…78737  (matches argument)
  wire   1

  [1] envelope            OK
  [2] object self-check   3/3 passed
  [3] fork proofs         none
  [4] chains
        03a107bf…531b8 VIOLATED
          BrokenLink at seq 1: entry 89c08f4d…d7817 claims prev 7431f38e…aac1d, held predecessor is 7ecd2314…de718
  [5] attestation DAG     1 attestation(s) carried
  [6] claims

    7431f38e…aac1d
      status       UNVERIFIABLE — no carried observation has this id, and every carried object self-checked — the chain was re-signed (spec/03 §6.5 T2)

RESULT: FAIL — a chain integrity finding is attributable to an author key; 1 claim(s) could not be bracketed
exit: 1  (1 = tamper detected)

════════════════════════════════════════════════════════════════════
STEP 6 — the runnable server  (this step makes NO sealed claim)
════════════════════════════════════════════════════════════════════

Everything above is a simulated meeting. This step is different in kind: it
starts vigil-node as a real HTTP server a person could actually run, POSTs one
observation, and reads its provenance back. A lone node has met no one, so it
holds no attestations — and it correctly reports the record UNWITNESSED, with
the window open in BOTH directions. That honest "I cannot vouch for when this
happened" is the correct output, not a gap: cross-node sealing needs vigil-sync
(v2). The chain itself still verifies — internal integrity and sealing in time
are different properties.
$ curl -s http://127.0.0.1:8799/health
{
  "chain_len": 0,
  "node_pubkey": "8568deab3ffec2b236f185e32816679e51f8a9ca9e1e03af9dfe312d1e748c2f",
  "status": "ok"
}

$ curl -s -XPOST --data 'shoring on grid B4 is out of plumb' http://127.0.0.1:8799/obs
{
  "id": "0862bc4d7699a726f1950de8067ab78cb806835dd2af33ce5a6edd757961737c",
  "seq": 0
}

$ curl -s http://127.0.0.1:8799/obs/0862bc4d7699a726f1950de8067ab78cb806835dd2af33ce5a6edd757961737c/provenance
{
  "author": "8568deab3ffec2b236f185e32816679e51f8a9ca9e1e03af9dfe312d1e748c2f",
  "chain_verification": "verified",
  "disputed": false,
  "lower_bound": null,
  "observation": "0862bc4d7699a726f1950de8067ab78cb806835dd2af33ce5a6edd757961737c",
  "sealed": false,
  "seq": 0,
  "unwitnessed_window": {
    "lower": "genesis",
    "upper": "verification-moment"
  },
  "upper_bound": null,
  "witness_depth": 0
}

════════════════════════════════════════════════════════════════════
DEMO COMPLETE
════════════════════════════════════════════════════════════════════

Steps 1, 2, 4 passed; step 5 correctly FAILED verification (exit 1); step 6
served a live node that honestly reported its lone record as unwitnessed.

A record written offline by an untrusted actor was shown to a third party with a
defensible, independently checkable claim about when it was created — and a
backdated one was caught and attributed — with no central authority, no
consensus, and no assumption of connectivity.
```

</details>

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

`vigil-node` runs a single process over one in-memory ledger and exposes a loopback HTTP
API: `POST /obs` to capture, `GET /obs/{id}/provenance` for the bracket and chain state
`vigil-ledger` computes, `POST /export` for the pack a person hands to `vigil-verify`,
and `GET /health`. It is not a multi-node system — there is no peer and no sync — so a
record it holds is reported `unwitnessed` with an open window, which is the honest output
for a node with no witness, not a gap.

The three scenarios run across a seed range as one aggregate — `vigil-sim --scale-up
--seeds 1000` — and every scenario passes every seed (see [Measured results](#measured-results)).

Still to come: the multi-node sync `vigil-node` needs to seal anything (v2), the rest of
the seeded adversarial scenarios with their ablation runs, and the parts of the
evaluation table that need them — witness-latency distribution, attestation-graph
density, key-attribution accuracy.

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

Current suite: 149 tests native, 13 of them re-run under `wasm32-wasip1`; `vigil-core`
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
| 5 | `vigil-node` — single-process loopback HTTP ledger (capture, provenance, export, health) | done for v1 scope; `--role edge\|hub\|mule` is a no-op until sync exists (v2) |
| 6 | Export pack + `vigil-verify` — the independent verifier | pack specified (`spec/03`, ADR-0004) and assembled; `vigil-verify` implements the `spec/03` §5 procedure against every fixture |
| 7 | `spec/02-entanglement.md` and `spec/03-export-pack.md` (done, with worked detail), `spec/04-threat-model.md` (after M1, by design) | done — `spec/04-threat-model.md` exists and matches the code |
| 8 | Seeded scenarios, each paired with an ablation run | three scenarios (equivocation carries a quarantine ablation; sealing-ablation contrasts a witnessed and an unwitnessed run over one honest chain); the full seeded adversarial set is next |
| 9 | Measured evaluation table and demo transcript | done — `--scale-up` over 1000 seeds feeds the Measured results section, and `demo.sh`, the README Demo section, and its captured transcript all exist |

**The project considers v1 complete as of commit `4de22c0`** (`feat(demo): end-to-end
demo.sh + vigil-sim --export-pack`), which closed the last open row — the demo transcript
clause of row 9. Row 8 remains accurately partial: the full scriptable adversarial suite
(partition topology, mule routes) is a v2 concern and is not claimed here.

**Entanglement is the project.** It is built before anything that is not a prerequisite
for it, and it is never cut. `vigil-sim` grows alongside it from the first attestation
onward, not afterwards — every adversarial claim in this repository is evidenced by a
seeded, reproducible run, and each is paired with an ablation run at the same seed with
attestations disabled, asserting that the tamper goes *undetected* without them.

### Measured results

Every number in this section is stdout from one command, run on a clean checkout.
Nothing here is estimated, rounded, or reformatted.

```
cargo run -p vigil-sim --release -- --scale-up --seeds 1000
```

Each `(scenario, seed)` pair drives the real ledger once. The runner records pass or
fail per seed — keeping the individual failing seeds, not just a counter — asserts that
`pass + fail` equals the seed count before printing anything, and exits non-zero naming
the first failing scenario and seed if any scenario fails any seed. That every seed
produces a byte-identical transcript is a separate assertion in the test suite.

Verbatim output:

```
scale-up: seeds=0..1000 scenarios=3
minimal           pass=1000 fail=0
equivocation      pass=1000 fail=0
sealing-ablation  pass=1000 fail=0
scale-up: PASS 3000/3000 runs in 7.274s
```

The trailing `in 7.274s` is a monotonic diagnostic the runner prints to catch an
algorithmic regression; it varies run to run and is not a benchmark.

| Scenario | Seeds | Pass | Fail | First failing seed |
|---|---|---|---|---|
| `minimal` (honest partition) | `0..1000` | 1000 | 0 | — |
| `equivocation` | `0..1000` | 1000 | 0 | — |
| `sealing-ablation` | `0..1000` | 1000 | 0 | — |

What a pass demonstrates, per scenario:

- **`minimal`** — on every seed, `bracket(O0)` is sealed by the single attestation
  exchange and its unwitnessed window stays honestly open below, down to genesis:
  the sealing theorem of `spec/02` §5.2 together with the genesis-isolation
  non-guarantee of §8.2.
- **`equivocation`** — on every seed, one self-verifying `ForkProof` convicts the
  author, the withheld sibling entry is never sealed, and quarantine changes only what
  the convicted key's attestations buy going forward (`spec/02` §6, §6.4–6.5;
  ADR-0003).
- **`sealing-ablation`** — on every seed, one honest chain is sealed and bounded above
  with a single attestation object and `unwitnessed` with an open window without it,
  while full-chain verification is unaffected either way: the ablation required by
  `spec/02` §9, contrasting §5.2 against §8.1 and §8.3.

These are three fixed, small, fixed-topology scenarios run 1000 times each for
determinism confidence — every seed must reach the same verdict. They are **not** a
claim about correctness, throughput, or latency at real-world scale; the topology does
not grow with the seed, and only the keys and nonces change between seeds.

The remaining metrics — witness-latency distribution, attestation-graph density, and
key-attribution accuracy as a rate — are **not measured yet** and will not be filled in
with estimates. They need the scriptable adversarial suite (partition topology, clock
rollback, withholding, mule routes) and the demo transcript that ties them together.

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
  vigil-node/     the binary: single-process loopback HTTP ledger (capture, provenance,
                  export, health) over one in-memory Store
  vigil-sim/      deterministic seeded simulator over the real ledger (lib + bin)
  vigil-verify/   independent verifier: evidence pack + org key in, ordering out
  vigil-wasm/     wasm-bindgen wrapper: runs the real vigil-ledger in a browser
spec/             the protocol specifications — stricter review than code
docs/             design document, reality brief, ADRs
testdata/         golden wire vectors, seeded scenarios
demo.sh           the end-to-end demo (see "Demo" above)
```

`vigil-verify` depends only on `vigil-core` — not `vigil-ledger`, not as a dependency and
not as a dev-dependency — so its chain check, DAG construction and bracketing are a second
implementation written from the spec, not a call into the code that built the pack. No
database, no network, no node. It reproduces every ordering claim from the evidence pack
and the organisation's public key alone, and exits nonzero on any tamper.

`vigil-wasm` links `vigil-ledger` directly — the deliberate opposite of `vigil-verify`.
Its point is to run the *real* chain, DAG, bracketing and fork-detection code under
`wasm32-unknown-unknown`, byte-for-byte the same as native (invariant I2), exposed to
JavaScript as a small `Demo` object that walks the same shapes `vigil-sim`'s `honest` and
`equivocation` scenarios prove. It builds to a bundler-free ES module with
`wasm-bindgen --target web`; CI compiles it for `wasm32` on every push, and a native test
module exercises its methods without a JS harness.

The workspace still contains `vigil-sync`, `vigil-transport` and `vigil-insight` as empty
scaffolding from the pre-cut scope. They build but implement nothing, and they are slated
for removal. Neither `vigil-sim` nor `vigil-node` depends on any of them: the simulator
moves objects over the scripted link directly, and the node is a single process with no
sync layer to wire up.

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
./demo.sh                                       # the whole thesis end to end (needs curl); transcript under "Demo" above
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p vigil-core --example gen_vectors   # regenerates golden vectors; must be a no-op
cargo run -p vigil-sim -- --scenario minimal --seed 1          # minimal entanglement scenario; same seed, same transcript
cargo run -p vigil-sim -- --scenario minimal --seed 1 --export-pack pack.vgl  # + export an evidence pack from the run
cargo run -p vigil-sim -- --scenario equivocation --seed 1     # equivocation + quarantine ablation
cargo run -p vigil-sim -- --scenario sealing-ablation --seed 1 # one honest chain, with vs. without a single attestation
cargo run -p vigil-sim --release -- --scale-up --seeds 1000    # every scenario over 1000 seeds; nonzero exit on any failing seed
cargo run -p vigil-node -- --addr 127.0.0.1:8787              # single-process loopback ledger; POST /obs, GET /obs/{id}/provenance, POST /export
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
