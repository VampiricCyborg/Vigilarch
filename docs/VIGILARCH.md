# Vigilarch

**Distributed, Offline-First Incident Intelligence for Multi-Site Physical Operations**

Master design & build document · v1.0 (reconstructed)

---

## 0. About this document

The original documentation for Vigilarch was lost. The only surviving artifact was the repository description line above. This document reconstructs the project end to end: problem, novel thesis, protocol design, architecture, data model, build roadmap, test strategy, and evaluation plan.

Where the original intent could not be recovered, this document makes an explicit, defensible choice and flags it in **§21 Decisions Made On Your Behalf**. Correct those and the rest of the document holds.

Read in this order:
- **§1–§4** if you want the pitch and the reason this is not another incident-reporting app.
- **§5–§11** if you are implementing. This is the actual specification.
- **§13–§17** if you are planning the build.
- **§19–§20** if you are demoing or defending this.

---

## 1. One-line thesis

> Vigilarch is a safety and security incident system for organisations whose sites lose connectivity, built on the premise that **the network partition is the normal state, not the failure state** — and that a system which models its own ignorance can be trusted with evidence that a connected system cannot.

Three claims make it novel. Each is defended in §4.

1. **Provable history without a server.** Vigilarch produces a cryptographically enforced partial ordering of events across mutually distrustful, frequently-disconnected sites, with no central authority and no blockchain, via *timeline entanglement*.
2. **Partition-aware intelligence.** Every number the system produces carries a machine-computed statement of what it does not know. Absence of data is treated as a signal, not a gap.
3. **Federation without disclosure.** Sites learn from each other's incidents without ever transmitting the incidents. Patterns cross the wire; evidence does not.

---

## 2. The problem

### 2.1 The setting

"Multi-site physical operations" means an organisation running work at many geographically separated physical locations, where the work is done by people with their hands and bodies, and where things go wrong physically. Concretely:

| Sector | Sites | Why connectivity fails |
|---|---|---|
| Construction & infrastructure | 30–400 active sites | Greenfield sites have no fixed line for months |
| Mining, quarrying | 5–40 | Underground, remote, RF-hostile |
| Ports, rail yards, logistics | 20–200 | Steel structures, dead zones inside container stacks |
| Utilities & telecom field ops | 1,000s of unmanned sites | Rural towers, substations, pipelines |
| Manufacturing (multi-plant) | 5–50 | Air-gapped OT networks by policy, not accident |
| Disaster response, humanitarian | Dynamic | Infrastructure is what got destroyed |
| Agriculture, plantations, forestry | Large area, few people | No coverage over most of the working area |

### 2.2 What actually happens today

Follow one near-miss through a real organisation:

1. **07:40.** A rigger at Site 14 sees a load swing wide over a walkway. Nobody hurt. This is a near-miss — the single most valuable data point in safety science, because it is a free sample of an accident.
2. **07:41.** He has no signal. The company's safety app spins on a login screen. He does not report it.
3. **13:00.** He remembers, back at the site office on the shared laptop. He types two sentences into a form.
4. **Weekly.** The site safety officer copies it into a spreadsheet and emails it.
5. **Monthly.** Head office aggregates 40 spreadsheets into a slide reading "312 near-misses this month, ↓4% MoM."
6. **Six weeks later.** At Site 31 — a different region, different subcontractor — a load swings over a walkway and breaks a man's pelvis.

Nobody ever compared step 1 to step 6. The information existed inside the organisation for six weeks and could not travel.

### 2.3 The four failures this exposes

**F1 — Capture loss.** Reporting friction at the moment of observation destroys most of the data. Not "some": most. Near-miss reporting is voluntary, low-status, and takes place with cold hands in bad light. Any system that requires connectivity at capture time systematically discards the highest-value, lowest-severity signals — precisely the ones that predict the severe ones.

**F2 — Evidential weakness.** Incident records in physical operations are legally consequential: regulator investigations, insurance claims, criminal liability for directors, wrongful-death litigation. But offline-first systems have a structural problem here that is rarely acknowledged: **a device clock is a settable field.** If a node can be disconnected for three days and then sync, then a node can be disconnected for three days, have its clock rolled back, receive a fabricated "hazard reported" record dated last Tuesday, and sync. Nothing in a conventional CRDT/last-write-wins sync stack can distinguish that from a genuine late arrival. Organisations know this intuitively, which is why offline reports are treated as soft data and the paper register stays in the site cabin.

**F3 — Epistemic dishonesty.** A dashboard reading "312 incidents this month" is a lie of omission when nine sites have not synced in a week. Every offline system silently presents partial data as complete data, because the aggregation layer has no concept of "missing." The dangerous inversion follows: **a site that goes quiet looks like a safe site.** Reporting collapse and safety improvement are indistinguishable on every dashboard in this industry. Worse, they are inversely correlated in reality — reporting collapses when a site is under schedule pressure, which is exactly when it is most dangerous.

**F4 — No cross-site transfer.** Precursor patterns repeat across sites; nobody correlates them. This is partly technical and partly legal: the moment you centralise raw incident data across jurisdictions and subcontractors, you have created a discoverable litigation corpus, a personal-data processing operation under GDPR / India's DPDP Act 2023, and a fight with the works council or union about surveillance. Many operators genuinely cannot pool this data, so they don't, so they learn nothing across sites.

### 2.4 The insight

These four failures look separate. They are one failure: **the system has no model of the network's shape.** It assumes a connected world and degrades badly when reality disagrees. If instead you make partition, distrust, and ignorance into first-class modelled objects, all four become tractable — and F2's evidential problem, the one that looks hardest, becomes the one with the most elegant solution.

---

## 3. What Vigilarch is

A field worker opens the app in a dead zone and reports in under ten seconds. It writes locally and signs. It never blocks.

The site's edge node holds an append-only, hash-chained ledger of everything observed at that site. When any two Vigilarch nodes come within reach of each other — site LAN, Bluetooth between two phones in a truck cab, satellite window, a USB stick carried by a driver — they reconcile, and critically, **they co-sign each other's current position in history.** That mutual signature is what makes offline records provable later.

The intelligence layer runs at the edge. Each site computes its own risk model and pattern sketches locally. Only compact, non-identifying pattern summaries propagate outward. Head office sees *"the signature 'night shift + agency crew + wet surface + overhead lift' has preceded a lost-time injury at 2 of the 6 sites where it appeared"* without ever receiving Site 14's photographs, names, or narrative text.

And every figure it shows is annotated with its own coverage: `14 incidents · coverage 71% · 2 sites dark 39h`.

---

## 4. Why this is novel

Be precise about the claim. Each of the three pillars has prior art in an unrelated domain. **The novelty is the synthesis and the application** — no shipped system in physical-operations software does any one of these, and the combination does not exist in the literature.

### 4.1 Pillar 1 — Timeline entanglement for field evidence

**Prior art:** Maniatis & Baker, *Secure History Preservation Through Timeline Entanglement*, 11th USENIX Security Symposium, 2002, pp. 297–312. Also: Haber–Stornetta linked timestamping (1991), Certificate Transparency, CoSi witness cosigning, Secure Scuttlebutt's per-feed hash chains.

**What is new:** this technique has lived for two decades in digital-preservation and PKI-transparency literature. It has never, to my knowledge, been applied to human-generated field observations under intermittent connectivity, and it has never been paired with a UI that exposes the resulting ordering guarantee to a non-technical user as a legal property of a record.

The insight worth stating plainly: **in a disconnected network, proof of time is not a property of a clock — it is a property of a meeting.** Two nodes that meet and co-sign create an irreversible fact: everything in A's chain before the meeting is now provably older than everything in B's chain after it. You do not need a trusted timestamp server, a consensus protocol, or a coin. You need contact. And contact is the one thing field operations reliably produce — vehicles, supervisors and crews physically move between sites every day.

This inverts the usual framing. Conventional systems treat disconnection as pure loss. Vigilarch treats every reconnection as a *forensic event that adds evidential value*, and the density of the resulting attestation graph becomes a measurable quality of your ledger.

### 4.2 Pillar 2 — Epistemic honesty as a product feature

**Prior art:** vector clocks and version vectors; the "delta of knowledge" concept in DTN; confidence intervals in statistics; alerting-on-absence in observability tooling (Prometheus `absent()`).

**What is new:** treating *coverage* as a mandatory, non-suppressible attribute of every aggregate that reaches a human, and deriving it automatically from sync metadata rather than asking the user to reason about it. And the corollary — **silence detection** — which turns F3's inversion right side up: a site whose reporting rate falls significantly below its own historical baseline, while its heartbeat proves it is online and its people are on shift, generates an alert. *The absence of incidents is itself an incident.*

No commercial EHS/incident platform does this. They cannot, because they cannot tell "no reports" from "no connection." Vigilarch can, because partition is modelled.

### 4.3 Pillar 3 — Federation without pooling

**Prior art:** federated learning (McMahan et al., 2017), secure aggregation, count-min and MinHash sketches, differential privacy.

**What is new:** applying it to safety-incident correlation, where the motivation is not bandwidth (the usual FL motivation) but **legal and industrial-relations survivability**. This makes the architecture adoptable in situations where a centralised system is politically or legally impossible: multi-employer sites, unionised workforces, cross-border operations, joint ventures where partners are commercial rivals. The technical design is downstream of a governance requirement, which is unusual and is the reason it is defensible.

### 4.4 The synthesis

Each pillar alone is a paper. Together they produce a property no existing system has:

> **A record that was created on a disconnected device by a low-trust actor can later be shown to a regulator with a defensible claim about when it was created — while the organisation still learns from it globally, without ever centralising it.**

That sentence is the project. If you can demonstrate it, you have something rare.

### 4.5 Honest limits

State these in any writeup; they make the claim stronger, not weaker.

- Entanglement gives **ordering**, not absolute wall-clock time. It proves "before the meeting" and "after the meeting", not "at 07:41". Absolute anchoring requires an external timestamp authority (§8.7), which requires connectivity at least occasionally.
- Ordering resolution equals contact frequency. A node genuinely isolated for 30 days has a 30-day unwitnessed window, and Vigilarch's honest answer is to *display that window*, not to hide it.
- No cryptography prevents someone from simply not reporting, or from reporting something false in real time. Vigilarch makes withholding *visible* (§10.3) and tampering *detectable*; it cannot make people honest.
- Federated learning at this data scale is weak. Most sites generate tens of incidents per month, not millions. §11 therefore specifies sketch-based pattern matching as v1 and treats gradient-based FL as an optional extension — resist the temptation to lead with "AI".

---

## 5. System model

### 5.1 Entities

- **Org** — the trust root. Owns a root keypair; issues device certificates.
- **Site** — a physical location with an ID, a geofence, and an expected crew profile.
- **Node** — a Vigilarch runtime with its own keypair and its own hash chain. Roles:
  - **Field Node** — a phone/tablet. Capture-primary. Sporadic power, sporadic reach.
  - **Edge Node** — a small always-on box at a site (a mini PC or a rugged SBC). Site-wide store, local analytics, LAN sync point.
  - **Mule Node** — a transport-only relay. A supervisor's phone, a vehicle unit. Carries opaque encrypted bundles between sites; cannot read them; still contributes attestations.
  - **Hub Node** — a cloud or regional instance. Well-connected peer with lots of storage. **Explicitly not authoritative.** It has no power the edge nodes lack.
- **Actor** — a human, bound to a device certificate. Pseudonymous in propagated data.

**Architectural invariant #1: no node is the source of truth.** If the hub burns down, the org loses convenience and loses nothing else. If this invariant is ever violated for expedience, the project's entire thesis collapses. Guard it in code review.

### 5.2 Network model

- Links are intermittent, asymmetric, and of wildly varying capacity: 10 Gb LAN down to a 50 byte/s LoRa link, down to a physical USB stick with a 6-hour latency.
- Partitions are long-lived (hours to weeks) and are the expected condition.
- Clocks are unsynchronised and untrusted. Assume adversarial skew.
- Nodes join and are lost (theft, breakage, water) routinely.

### 5.3 Adversary model

| Adversary | Capability | Vigilarch response |
|---|---|---|
| **Backdater** | Site manager with a valid device key wants a hazard report to appear to predate an injury | Hash chain + entanglement (§8). He can only fork or append. A fork is cryptographic proof of misconduct. |
| **Deleter** | Wants an inconvenient near-miss gone | Append-only; deletion is a retraction assertion which is itself a permanent record. Peers already hold the observation. |
| **Withholder** | Node never syncs the bad news | Cannot be prevented. Detected: silence detection + attestation gaps + heartbeat divergence (§10.3). |
| **Equivocator** | Presents chain A to one peer, chain B to another | Detected the moment any node observes both. Fork proof is a compact, self-verifying, gossipable object. |
| **Thief** | Steals a device | At-rest encryption keyed to hardware-backed store; short-lived data key; certificate revocation propagates by gossip; device is cut off at next contact. |
| **Eavesdropper** | Taps a link or steals a mule | Payloads encrypted end-to-end to org key. Mule sees ciphertext and routing headers only. |
| **Compromised hub** | Root the cloud | Hub holds no unique authority and cannot forge site signatures. It can censor what it forwards; edge-to-edge paths route around it, and censorship shows up as coverage loss. |

**Explicitly out of scope:** a fully compromised org root key; physical coercion of a worker at the moment of capture; collusion by a majority of nodes in a region to withhold en masse.

---

## 6. Architecture

```
┌────────────────────────────────────────────────────────────────┐
│  L6  PRESENTATION   field PWA · ops console · regulator export │
├────────────────────────────────────────────────────────────────┤
│  L5  INTELLIGENCE   coverage math · silence detection ·        │
│                     precursor mining · federated sketches      │
├────────────────────────────────────────────────────────────────┤
│  L4  SEMANTICS      threads · assertions · entity resolution · │
│                     CRDT merge · contested-state surfacing     │
├────────────────────────────────────────────────────────────────┤
│  L3  SYNC           Merkle range reconciliation · priority     │
│                     classes · bundle framing                   │
├────────────────────────────────────────────────────────────────┤
│  L2  LEDGER         append-only store · per-node hash chains · │
│                     attestation DAG · fork detection           │
├────────────────────────────────────────────────────────────────┤
│  L1  TRANSPORT      QUIC · mDNS/LAN · BLE · Wi-Fi Direct ·     │
│                     LoRa · sneakernet bundle                   │
├────────────────────────────────────────────────────────────────┤
│  L0  CRYPTO/ID      Ed25519 · BLAKE3 · XChaCha20 · HLC · certs │
└────────────────────────────────────────────────────────────────┘
```

**Architectural invariant #2: L0–L3 are a single Rust implementation compiled to native, WASM, and FFI.** The phone, the edge box, the mule, and the hub run byte-identical ledger and sync logic. A second implementation of a consensus-adjacent protocol is a guarantee of divergence bugs that will appear only under partition and only in the field. Do not write a JavaScript ledger.

**Architectural invariant #3: capture is immutable; interpretation is mutable.** L2 objects are never edited. L4 objects are edited freely. Every conflict-resolution question resolves cleanly once you locate which side of that line you are on.

---

## 7. Data model

### 7.1 The core move: observations, not incidents

Conventional systems make the reporter classify at capture time — *Is this a Near Miss, a Hazard, or a First Aid Case? Severity 1–5? Which category?* This is wrong for two reasons.

1. **It costs seconds at the exact moment where seconds destroy your data** (F1).
2. **It does not merge.** Two crews on opposite sides of a partition observe the same real-world event and file two incidents with different classifications. On reconnect you have duplicates that no CRDT can reconcile, because the conflict is semantic, not structural.

Vigilarch splits them:

- An **Observation** is an immutable, signed, content-addressed assertion that *someone perceived something at a place and time*. It is atomic, cheap, and un-opinionated. It merges trivially because it is never edited.
- A **Thread** is a mutable, mergeable interpretation: a set of observations someone (or the correlator) believes describe one real situation.
- An **Assertion** is a retractable typed claim attached to observations or threads: classification, severity, causal link, resolution, responsibility.

Two crews reporting the same event now produce two observations (correct — two people did perceive something) which later merge into one thread (also correct). Nothing is lost and nothing conflicts.

### 7.2 Object definitions

```rust
/// Immutable. Content-addressed. The atom of the system.
struct Observation {
    id: Hash,              // BLAKE3 of canonical CBOR of all fields below
    author: PubKey,        // device key
    site: SiteId,
    prev: Hash,            // author's previous observation — the hash chain
    hlc: Hlc,              // hybrid logical clock (untrusted, best-effort)
    body: ObservationBody,
    geo: Option<GeoPoint>, // coarsened by policy
    sig: Signature,        // Ed25519 over id
}

enum ObservationBody {
    Note { text: String },
    Voice { transcript: String, audio: BlobRef },
    Media { blob: BlobRef, kind: MediaKind, caption: Option<String> },
    Form { template: TemplateId, answers: Map<FieldId, Value> },
    Sensor { source: SensorId, reading: Reading },
    Presence { actor: ActorRef, zone: ZoneId, event: Enter | Exit },
    Heartbeat { node_state: NodeSummary },   // proves aliveness — see §10.3
}

/// Content-addressed, chunked, synced at low priority.
struct Blob { id: Hash, size: u64, chunks: Vec<Hash>, mime: String }

/// Mutable, CRDT. The interpretation layer.
struct Thread {
    id: ThreadId,                  // (creator, counter) — no coordination needed
    members: OrSet<Hash>,          // observation ids; add-wins
    title: LwwRegister<String>,
    severity: MvRegister<Severity>,// MULTI-value: conflicts stay visible
    status: MvRegister<Status>,
    links: OrSet<(ThreadId, LinkKind)>,
}

/// Retractable claim. Retraction never destroys the original.
struct Assertion {
    id: Hash,
    subject: Subject,              // Observation | Thread | Entity
    claim: Claim,
    author: PubKey,
    hlc: Hlc,
    retracts: Option<Hash>,
    sig: Signature,
}

/// Durable real-world things. Resolution across sites is itself a merge problem.
struct Entity { id: EntityId, kind: Asset|Actor|Zone|Vendor|Shift|Equipment,
                attrs: Map<Key, MvRegister<Value>>, aliases: OrSet<ExternalId> }

/// A node's signed position in its own history.
struct Checkpoint { node: PubKey, head: Hash, seq: u64, hlc: Hlc,
                    frontier: VersionVector, sig: Signature }

/// The crown jewel — see §8.
struct Attestation { witness: PubKey, subject: PubKey, subject_head: Hash,
                     subject_seq: u64, witness_hlc: Hlc, nonce: [u8;16],
                     sig: Signature }
```

### 7.3 Conflict philosophy

**Vigilarch never silently picks a winner on a semantic question.** Structural merges (set union, chain extension, blob dedup) are automatic and invisible. Semantic disagreement — two supervisors assign severity 2 and severity 4 — is preserved via multi-value registers and surfaced in the UI as a **Contested** state requiring human resolution.

This is deliberate and it is a safety argument, not an engineering one. Last-write-wins on a severity field means the last person to sync silently overrides a colleague's assessment of how dangerous something is. In an operational safety system that is a hazard in itself. Disagreement between two competent observers is *information*, and it is often the most important information in the record.

---

## 8. The Entanglement Ledger

This is the heart of the project. Implement it first and implement it carefully.

### 8.1 The problem restated

A device clock is a settable field. Any offline-first system therefore cannot, by default, distinguish a genuine late-arriving record from a fabricated backdated one. Since the entire value of a safety record is temporal — *did you know about the hazard before the injury?* — this is not a minor gap. It is the reason offline reports are treated as soft evidence everywhere in this industry.

### 8.2 Layer 1 — per-node hash chains

Every observation embeds `prev`, the hash of that node's previous observation. A node's history is therefore a linked chain rooted at its certificate issuance.

Consequence: **a node cannot insert into its own past.** It can append (fine) or fork (creating two chains from one `prev`, which is detectable and is proof of misconduct). Silent retroactive insertion is now impossible.

This is necessary but not sufficient. A node isolated since genesis can still fabricate an entire consistent chain with any timestamps it likes.

### 8.3 Layer 2 — entanglement on contact

Whenever any two nodes establish any link, before or alongside data reconciliation they perform a mutual attestation exchange:

```
A → B:  Checkpoint_A { head: H_a, seq: 412, frontier: VV_a, sig_A }
B → A:  Checkpoint_B { head: H_b, seq: 8891, frontier: VV_b, sig_B }
A → B:  Attestation { witness: A, subject: B, subject_head: H_b,
                      subject_seq: 8891, witness_hlc, nonce, sig_A }
B → A:  Attestation { witness: B, subject: A, subject_head: H_a,
                      subject_seq: 412, witness_hlc, nonce, sig_B }
```

Each node then **embeds the received attestation into its own next chain entry.** A's future is now cryptographically bound to B's past, and vice versa. This is the entanglement.

Attestations are tiny (~150 bytes), so they exchange on any link — including a LoRa link too narrow for anything else. They are also gossiped: an attestation A made about B is useful to C, so it propagates like any other object.

### 8.4 What this proves

The attestation set forms a DAG over which a **provable partial order** is computed.

> **Sealing theorem.** If node W attested subject S at head `H` (call this event `e`), and `e` is reachable in the attestation DAG from any record R held by verifier V, then every entry in S's chain up to and including `H` provably existed before R. Backdating anything into that range requires forging W's key.

Define:

- **Sealed** — an observation with at least one attestation from a distinct key downstream of it. Its upper time bound is fixed by another party.
- **Unwitnessed window** — the span between an observation's creation and its first attestation. During this window the node's own clock is the only evidence, which is to say: no evidence.
- **Witness latency** — the duration of that window. A per-node and per-org KPI.
- **Witness depth** — how many independent keys have sealed a record. More witnesses, stronger claim.

The forensic resolution of the whole system equals the contact frequency of the network. Sites syncing hourly get near-real-time sealing. A site isolated for three weeks gets a three-week window — **and Vigilarch displays that window rather than concealing it.** A regulator or court can then weigh it, which is the correct outcome. Contrast with every existing system, which shows a confident timestamp derived from a settable field.

### 8.5 Fork detection

If any node ever observes two entries from the same key with the same `prev`, it has cryptographic proof of equivocation. It constructs a **Fork Proof** — a compact, self-verifying object containing both signed entries — and floods it at the highest priority class.

On receipt of a valid fork proof, every node:
1. Marks the offending key **quarantined**.
2. Marks that key's unwitnessed observations **disputed** (never deletes them — they may be true, and the record of the dispute is itself evidence).
3. Keeps sealed observations from before the fork as valid, since they were witnessed by honest parties.
4. Raises an operational alert to the org security role.

### 8.6 Mules add evidential value

A crucial and slightly beautiful property: a mule node carrying an opaque encrypted bundle between two sites still exchanges attestations at both ends. It cannot read a single byte of the payload, yet its signature meaningfully tightens the ordering guarantee on the data it carried. **An untrusted courier improves the forensic quality of the ledger.**

This means the cheapest possible deployment — a driver's phone with the app installed, doing his normal route — measurably strengthens your evidence chain. It is the kind of property that makes a demo land.

### 8.7 External anchoring (optional)

When any hub reaches the internet, it publishes its current root hash to an external timestamp authority (RFC 3161 TSA) and/or a public transparency log. This converts the internal partial order into an **absolute upper time bound** grounded outside the organisation: proof that the entire ledger state existed before a legally recognised timestamp, from a party with no stake in the dispute.

Cost: a few hundred bytes per anchor. Do it hourly. This is disproportionately valuable in litigation and costs almost nothing.

---

## 9. Sync and delay-tolerant transport

### 9.1 Reconciliation

Two nodes must efficiently discover what each lacks, with no shared history and no server, over links that may drop mid-exchange.

**Do not use naive version-vector diffing** — it degrades badly when nodes have never met and when vectors grow with node count.

**Use range-based set reconciliation over a Merkle Search Tree.** Nodes agree on a total order over object IDs, exchange range fingerprints, and recursively split only the ranges that disagree. Two nodes holding 100k objects with a 20-object difference converge in a handful of round trips and a few KB. This is the same family of technique used by Iroh/Willow and Earthstar; it is well understood and there are reference implementations to read.

Every exchange must be **resumable** — links die mid-sync constantly. Checkpoint progress; never restart a 400 MB photo sync from zero.

### 9.2 Priority classes — graceful degradation of knowledge

Bandwidth ranges over six orders of magnitude. Everything is classed, and a link carries only what it can:

| Class | Content | Size | LoRa | BLE | LAN |
|---|---|---|---|---|---|
| 0 | Alarms, fork proofs, revocations | ~100 B | ✅ | ✅ | ✅ |
| 1 | Attestations, checkpoints, heartbeats | ~150 B | ✅ | ✅ | ✅ |
| 2 | Observation headers (id, author, site, hlc, type) | ~200 B | ⚠️ | ✅ | ✅ |
| 3 | Text bodies, form answers, assertions | ~1 KB | ❌ | ✅ | ✅ |
| 4 | Thumbnails, audio transcripts | ~30 KB | ❌ | ✅ | ✅ |
| 5 | Full media blobs | 1–20 MB | ❌ | ⚠️ | ✅ |

The design story here is strong: on a starved link the network still knows *that* something happened, *where*, and *when relative to what* — even when it cannot yet know *what*. Knowledge degrades gracefully instead of failing binary. A site on nothing but a LoRa beacon still participates in the ordering graph and still raises alarms.

### 9.3 Transports

One `Link` trait, several implementations:

- **QUIC** (`quinn`) — WAN and site LAN. Multiplexed streams map naturally onto priority classes; connection migration survives a phone moving between Wi-Fi and cellular.
- **mDNS discovery** — nodes find each other on a site LAN with zero configuration.
- **BLE GATT** — phone↔phone in a truck cab, in a lift, in a tunnel. Low throughput; classes 0–3.
- **Wi-Fi Direct / hotspot** — bulk transfer when two devices are deliberately paired for a media dump.
- **LoRa** — a serial radio on the edge box. Classes 0–1 only. Multi-kilometre range at near-zero power. This is how a remote site stays in the ordering graph with no infrastructure at all.
- **Sneakernet** — export an encrypted, signed bundle to a USB stick or as a sequence of QR codes on screen. Latency measured in hours; still fully valid. QR export matters more than it sounds: it works between two devices that are administratively forbidden from networking with each other, which is common in regulated OT environments.

### 9.4 The mule protocol

1. Mule reaches Site A. Entangles. Requests a **bundle** addressed to any node it might plausibly reach, per a simple routing hint (historical contact probability — spray-and-wait style).
2. Bundle is encrypted to the org key. The mule stores ciphertext plus routing headers only.
3. Mule reaches Site B. Entangles. Delivers. Collects a return bundle.
4. Mule's own chain now contains attestations for both A and B — creating a provable ordering link between two sites that were never in direct contact.

Bundles carry a TTL and a hop count. Mules garbage-collect on delivery confirmation or expiry.

---

## 10. Partition-aware intelligence

### 10.1 Coverage as a mandatory attribute

Every derived value carries a coverage descriptor. No API returns a bare aggregate; the type system forbids it.

```rust
struct Covered<T> {
    value: T,
    coverage: f64,          // 0.0–1.0, expected-contribution-weighted
    contributing: Vec<NodeId>,
    missing: Vec<(NodeId, Duration)>,  // who is dark, and for how long
    computed_at: Hlc,
}
```

Coverage is weighted by each node's *historical event rate*, not by node count. A dark node that generates 40 observations a day costs far more coverage than one that generates two. Naive node-count coverage would badly mislead.

```
coverage = Σ(rate_i for i in contributing) / Σ(rate_i for i in expected)
```

The UI renders this always, and never allows it to be suppressed:

```
Lost-time injuries, September
  ▸ 14                        coverage 71%
                              2 sites dark · oldest 39h
                              range if dark sites report at baseline: 14–19
```

That range is the honest answer, and no product in this category gives it.

### 10.2 Confidence propagation

Coverage propagates through derived computations. A trend line comparing two months where coverage was 94% and 61% must not be drawn as a clean line — it is drawn with a widening uncertainty band, and the system will refuse to state a direction ("↓4%") when the coverage delta between the periods exceeds the apparent effect size. **A dashboard that cannot say "I don't know" will eventually say something false about whether people are getting hurt.**

### 10.3 Silence detection — absence as signal

The inversion in F3, solved. For each site, maintain an expected reporting rate from its own history, adjusted for crew size, shift pattern, and work phase. Then classify the four cases the existing tooling collapses into one:

| Reports | Heartbeat | Interpretation |
|---|---|---|
| Normal | Alive | Healthy |
| Zero | Absent | **Disconnected** — coverage loss, not a safety signal |
| Zero | Alive | **Reporting failure** — the dangerous case. People are on shift, the node is online, nothing is being reported. |
| Falling | Alive | **Reporting decay** — early warning. Watch the gradient. |

Case 3 fires an alert. In the literature on organisational accidents this pattern — reporting collapse under schedule pressure while operations continue — is among the strongest leading indicators of a serious event, and it is invisible to every system that cannot separate silence from disconnection.

Additional silence signals worth computing: attestation-graph sparsity (a site whose contact rate with peers has dropped is drifting out of the organisation's awareness), and witness-latency inflation (records are being created but sealed later and later).

---

## 11. Federated intelligence

### 11.1 Design constraint

Raw incident data never leaves its site of origin unless a human explicitly escalates it. Not for bandwidth reasons — for legal, privacy, and industrial-relations reasons (§4.3). Everything below is designed around that constraint.

### 11.2 Local (at the edge)

Runs on the site's edge node, over the full local corpus:

- **Signature extraction.** Reduce each thread to a canonical multi-set of controlled-vocabulary tags: `{night_shift, agency_crew, wet_surface, overhead_lift, zone_type:walkway}`. Controlled vocabulary is essential — free text will not federate.
- **Precursor mining.** Sequence mining over signature streams: which signature patterns preceded severity escalation historically, at what lead time.
- **Local risk scoring.** A small, interpretable model (logistic regression or a shallow gradient-boosted tree). Interpretability is not optional here — an unexplainable safety score will be ignored by the people who have to act on it, and rightly so.

### 11.3 Federated (what crosses the wire)

**Version 1 — sketches. Build this.**

- Count-min sketches of signature frequencies per site.
- MinHash signatures for cross-site thread similarity without exchanging content.
- Aggregate outcome statistics per signature: `(signature_hash, occurrences, escalations, max_severity)`.

That is enough for the flagship capability:

> **Cross-site precursor transfer.** Site 14 logs its fourth near-miss with signature *X*. Vigilarch matches *X* against the federated index and tells the site supervisor: *"This pattern has preceded a lost-time injury at 2 of the 6 sites where it has appeared. Median lead time: 19 days."* Nobody at Site 14 has ever heard of those sites. No data about those sites' incidents was ever transmitted.

This is the demo moment and it is achievable with sketches and counters alone. No neural network required.

**Version 2 — model deltas. Optional.**

FedAvg over the small local models, with DP noise on updates and optional pairwise-masked secure aggregation so the hub cannot see any individual site's contribution. Be realistic about value: with tens of events per site per month, sketch-based matching will outperform this for a long time. Ship v1, measure, and only build v2 if the data volume justifies it.

### 11.4 Privacy mechanics

- Actor identities are pseudonymous org-wide; the mapping to real identity never leaves the originating site.
- Geo is coarsened to zone granularity before federation.
- k-anonymity threshold: a signature is not federated until it has occurred at ≥ k distinct sites (k=3 default), preventing single-site re-identification.
- Every federated payload is human-inspectable and logged, so a works council or DPO can audit exactly what left the site. Build this inspection view early — it is what gets the system approved.

---

## 12. Technology stack

| Layer | Choice | Rationale |
|---|---|---|
| Core (L0–L3) | **Rust** | One implementation → native + WASM + FFI (invariant #2). Memory safety on a codebase handling untrusted signed input from the field. |
| Async runtime | Tokio | Standard; QUIC integration. |
| Hashing | BLAKE3 | Fast, tree-structured (great for chunked blob verification). |
| Signatures | Ed25519 (`ed25519-dalek`) | Small, fast, ubiquitous, hardware-backed on mobile. |
| Symmetric | XChaCha20-Poly1305 | Nonce-misuse headroom matters when devices lose state. |
| Local store | **SQLite** + content-addressed blob dir | Battle-tested, embeddable, transactional, runs identically on phone and edge box. |
| Browser store | OPFS (blobs) + IndexedDB (index) | Real filesystem semantics in the PWA; large media without pain. |
| Transport | QUIC via `quinn` | Multiplexed streams ↔ priority classes; connection migration. |
| Field app | **PWA: React + TypeScript + Vite**, `vigil-core` via WASM, wrapped in **Capacitor** | PWA for zero-install and instant updates; Capacitor for camera, BLE, background sync, hardware keystore. Android-first — that is what field crews carry. |
| Console | React + TypeScript | Coverage-aware component library is the distinctive part. |
| Edge analytics | **DuckDB** over Parquet snapshots | Full analytical SQL on the edge box with no server. Excellent fit. |
| Hub | Same Rust binary, `--role hub` + Postgres | Postgres is a **materialized view only**. The ledger remains truth (invariant #1). |
| Simulation | Custom deterministic DES (`vigil-sim`) | See §16. This is a first-class deliverable, not a test utility. |

**Deliberate rejections:**
- *CouchDB/PouchDB* — the obvious offline-first choice, rejected because it gives revision-tree conflict resolution but no attestation, no priority classes, no Merkle range reconciliation, and no path to entanglement. Adopting it means abandoning pillar 1.
- *Blockchain / DLT of any kind* — requires connectivity and consensus, which is precisely what does not exist here. Entanglement achieves the needed tamper-evidence without either. Say this out loud in any presentation; someone will ask.
- *Firebase/Firestore offline mode* — central authority, no cryptographic history, cannot satisfy the federation constraint.

---

## 13. Repository layout

```
vigilarch/
├─ crates/
│  ├─ vigil-core/        # types, canonical CBOR, hashing, signing, HLC, CRDTs
│  ├─ vigil-ledger/      # append-only store, hash chains, attestation DAG,
│  │                     #   fork detection, sealing queries
│  ├─ vigil-sync/        # Merkle range reconciliation, priority queues, bundles
│  ├─ vigil-transport/   # Link trait: quic, mdns, ble bridge, lora, sneakernet
│  ├─ vigil-insight/     # coverage math, silence detection, sketches, mining
│  ├─ vigil-node/        # binary: --role edge|hub|mule ; local HTTP API
│  ├─ vigil-wasm/        # wasm-bindgen wrapper for the PWA
│  └─ vigil-sim/         # deterministic network simulator + chaos harness
├─ apps/
│  ├─ field/             # PWA (React + TS + Vite + Capacitor)
│  └─ console/           # ops dashboard
├─ spec/                 # THE PROTOCOL SPECS — wire format, attestation,
│  │                     #   sync, threat model. Versioned. Changes need review.
│  ├─ 01-wire-format.md
│  ├─ 02-entanglement.md
│  ├─ 03-sync.md
│  ├─ 04-threat-model.md
│  └─ 05-vocabulary.md   # the controlled tag vocabulary
├─ deploy/               # docker, ansible (edge box), terraform (hub)
├─ docs/                 # this file, ADRs, runbooks
└─ testdata/             # recorded partition scenarios, golden vectors
```

Keep `spec/` under stricter review than code. A protocol change that ships to half the fleet and cannot be rolled back is the worst failure mode this system has. Version the wire format from commit one and negotiate it on every connection.

---

## 14. Build roadmap

Each milestone has a binary acceptance test. Do not proceed on "it basically works."

### M0 — Ledger core *(foundation)*
Canonical encoding, hashing, Ed25519, HLC, append-only SQLite store, per-node hash chains.
**Done when:** 10,000 observations append and verify; any single-byte mutation to any historical record is detected by a full-chain verification pass; canonical encoding round-trips are byte-identical across native and WASM.

### M1 — Entanglement *(the novel core — do not defer this)*
Checkpoints, attestation exchange, attestation DAG, sealing queries, fork proofs.
**Done when:** in a 3-node simulation, a node that rolls its clock back and inserts a backdated observation is detected on reconnect and the record is correctly reported as `unwitnessed`; an equivocating node is detected and quarantined via a gossiped fork proof; sealing queries return correct partial orderings against hand-computed expected results.

### M2 — Sync *(make it a network)*
Merkle range reconciliation, priority classes, resumable transfer, QUIC + LAN discovery.
**Done when:** two nodes with 100k objects and a 20-object difference converge in < 5 round trips and < 50 KB; a sync killed at a random point resumes without duplication or loss; three nodes reach identical state under random link failure across 1,000 simulated runs.

### M3 — Semantics *(make it usable)*
Threads, assertions, CRDT merge, contested-state surfacing, entity model.
**Done when:** concurrent divergent edits on both sides of a partition merge deterministically regardless of delivery order; conflicting severity assertions surface as Contested rather than silently resolving.

### M4 — Field app *(make it real)*
PWA with WASM core, offline capture, camera, voice, background sync, Capacitor build.
**Done when:** capture-to-persisted is < 10 s in airplane mode on a low-end Android with the app cold-started; a week of offline use followed by reconnect loses nothing; battery cost of background sync is under 3%/day.

### M5 — Coverage *(the honesty layer)*
`Covered<T>` throughout, coverage math, silence detection, coverage-aware UI components.
**Done when:** no aggregate can reach the UI without a coverage annotation (enforce with a type-level or lint rule); silence detection correctly separates all four cases in §10.3 against seeded scenarios; a suppressed-reporting scenario fires an alert within one shift.

### M6 — Intelligence *(the payoff)*
Signature extraction, controlled vocabulary, precursor mining, count-min/MinHash sketches, federated index.
**Done when:** on a seeded multi-site dataset with a planted cross-site precursor, the system surfaces the transfer alert at the correct site before the planted severe event, and a wire capture confirms no raw incident content crossed the site boundary.

### M7 — Transports *(the hard-mode differentiator)*
BLE, mule bundles, LoRa class-0/1, sneakernet QR/USB export.
**Done when:** two phones with no internet sync classes 0–3 over BLE; a mule carries a bundle between two never-connected sites and both ends verify the resulting ordering link; a LoRa-only site's alarms arrive and its heartbeat keeps it in the coverage model.

### M8 — Hardening & export
Key rotation, revocation gossip, remote wipe, at-rest encryption, TSA anchoring, regulator export pack (a signed PDF/bundle with the full attestation chain and an honest statement of witness latency per record).
**Done when:** an independent verifier binary, given only the export pack and the org public key, reproduces every ordering claim in it.

**Sequencing advice.** M0→M1→M2 is the critical path and is where the novelty lives; build it before any UI. But build a deliberately ugly M4 prototype early enough to feel the capture-latency problem in your hands — it will change your data model. And build `vigil-sim` (§16) alongside M1, not after; without it, M2 is untestable.

---

## 15. Interfaces

The local node exposes a small HTTP API on loopback; the PWA and console are clients.

```
POST   /obs                        capture (never blocks on network)
GET    /obs/:id
GET    /obs/:id/provenance         chain + attestations + sealing status
POST   /threads                    create
PATCH  /threads/:id                merge-safe edit
POST   /assertions
GET    /threads?site=&since=       → Covered<Vec<ThreadSummary>>
GET    /insight/coverage           current knowledge state of this node
GET    /insight/silence            reporting-anomaly alerts
GET    /insight/signatures/:hash   federated precursor lookup
GET    /sync/status                peers, last contact, pending by class
POST   /sync/bundle/export         sneakernet bundle out
POST   /sync/bundle/import         sneakernet bundle in
GET    /export/regulator?scope=    signed evidential export pack
```

**Note `/obs/:id/provenance`.** This endpoint is the product. It returns: the author chain position, every attestation sealing it, the witness latency, the unwitnessed window if any, and the resulting ordering claims. Design the UI for it carefully — a supervisor should be able to look at a record and understand, without knowing what a hash is, the sentence *"this was created before Tuesday 14:20, and three independent devices can prove it."*

---

## 16. Testing

Conventional testing will not find the bugs in this system. The failures live in partition topology, message reordering, and clock adversariality — regions that unit tests do not reach and that manual QA cannot reproduce.

### 16.1 `vigil-sim` — deterministic network simulator

A discrete-event simulator, seeded and fully reproducible, that instantiates N virtual nodes running the **real** ledger and sync code over a virtual network with scriptable:

- partition topology over time (site 3 dark from t=400 to t=9400)
- per-link bandwidth, latency, loss, and MTU (including a LoRa profile)
- clock skew and drift, including adversarial rollback
- mule movement schedules
- node loss, theft, and re-provisioning
- adversarial node behaviour: backdating, equivocation, withholding, replay

Every simulation run asserts the system invariants:

- **Convergence** — all connected nodes reach identical state given eventual connectivity.
- **Order preservation** — no sealed record's ordering claim is ever violated.
- **Tamper detection** — every adversarial action in the script is detected, and detection is attributed to the correct key.
- **Coverage soundness** — reported coverage never exceeds true coverage. *Overstating knowledge is the cardinal sin of this system.* Assert one-sidedly.
- **No panics, no unbounded growth** — memory and storage stay within envelope over long runs.

### 16.2 Other layers

- **Property tests** (`proptest`) on CRDT merge: commutativity, associativity, idempotence, under randomly generated operation sets and delivery orders.
- **Golden vectors** in `testdata/` for the wire format, checked from day one. Cross-verify native vs WASM byte-for-byte.
- **Fuzzing** on all deserialisation paths. The node parses signed input from potentially hostile field devices; this is the attack surface.
- **Adversarial red-team exercise** — before any pilot, task someone with fabricating a convincing backdated hazard report. If they succeed, M1 is not done. Repeat after every protocol change.
- **Field trial** — one real site, two weeks, a stopwatch on capture latency, and honest interviews about whether people actually reported things.

---

## 17. Evaluation

If this is being defended academically or pitched commercially, these are the numbers that matter. Measure them; do not assert them.

| # | Question | Metric | Target |
|---|---|---|---|
| E1 | Does it capture what others lose? | Reports/worker/week vs. incumbent baseline | ≥ 2× |
| E2 | Is capture fast enough to be used? | p95 capture-to-persisted, offline, cold start | < 10 s |
| E3 | Does entanglement work? | Backdating attempts detected in `vigil-sim` | 100% of sealed range |
| E4 | How good is the ordering? | Median witness latency across the fleet | < 4 h |
| E5 | Does it converge? | Time to full convergence after a 72 h partition heals | < 5 min on LAN |
| E6 | Is it honest? | Instances where reported coverage > true coverage | **0** |
| E7 | Does silence detection work? | Precision/recall on seeded reporting-suppression scenarios | recall > 0.9 |
| E8 | Does federation earn its keep? | Cross-site precursor alerts firing before the planted severe event | > 60% |
| E9 | Does privacy hold? | Bytes of raw incident content crossing a site boundary, by wire capture | **0** |
| E10 | Does it survive the field? | Battery drain, storage growth, crash-free sessions over 2 weeks | < 3%/day, no data loss |

E6 and E9 are absolutes. Any nonzero result is a defect at the highest severity, because both are claims the entire project rests on.

---

## 18. Deployment

**Edge node.** A fanless mini-PC or rugged SBC in the site office. Ships pre-provisioned: org root public key baked in, device keypair generated on first boot inside a hardware-backed store, certificate issued out of band. Ansible-managed, auto-updating with signed images and A/B rollback. Runs on a UPS — the site loses power more often than you think, and this box is the site's memory.

**Field devices.** MDM-distributed Capacitor build, or PWA install for BYOD. Enrolment must work offline: a QR-code-based certificate issuance from an already-enrolled edge node, because new crew arrive on a site with no connectivity constantly.

**Hub.** Standard cloud deployment. Postgres read model, object storage for blobs, the same Rust binary in hub mode. Sized for convenience, not criticality — remember it holds no unique authority.

**Key management.** Org root offline (HSM or air-gapped, split custody). An intermediate signing key per region. Device certificates are short-lived with offline-capable renewal. Revocation lists gossip as class-0 objects and reach devices at next contact, which may be days — accept this, design for it, and pair it with at-rest encryption and short-lived data keys so a stolen device degrades safely rather than instantly.

---

## 19. Risks

| Risk | Severity | Mitigation |
|---|---|---|
| **Scope collapse.** The entanglement layer is hard; pressure builds to ship "an offline app with sync" and add it later. | Fatal | It is never added later. M1 is the project. If entanglement is cut, the result is a mediocre clone of existing products. Build it second, before any UI. |
| Protocol versioning mistakes strand devices | High | Version on the wire from commit one; negotiate on every connection; keep N-2 compatibility; never break `spec/` without an ADR. |
| Media blobs saturate weak links | High | Priority classes (§9.2); aggressive on-device thumbnailing; media is class 5 and may legitimately never arrive. |
| Clock adversariality assumed away in code | High | Ban `SystemTime::now()` in the ledger crate at lint level. All time flows through HLC + attestation. |
| Federated ML underdelivers on thin data | Medium | Ship sketches (v1), not gradients. Do not put "AI" in the pitch; put "cross-site precursor transfer" in the pitch. |
| Users report less because there is no manager watching | Medium | This is a socio-technical problem, not a software one. Capture latency, anonymous reporting mode, and visible closure of reported items are the levers. |
| CRDT bugs surface only under rare orderings | Medium | Property tests + `vigil-sim` with seeded reproducibility. |
| Complexity exceeds team capacity | Medium | Cut M7 transports (BLE/LoRa/mule) and M6 federation before cutting M1. A single-transport, single-org system with real entanglement is still novel. Breadth is expendable; the core thesis is not. |

---

## 20. Demo script

Nine minutes. This sequence is what makes people understand the project.

1. **Setup.** Three laptops or three simulated sites on screen. Site A, Site B, Hub. All in sync. Boring on purpose.
2. **Cut the network.** Physically unplug A and B. The dashboard immediately changes: coverage drops to 34%, two sites shown dark with a running timer. *"Notice it did not pretend. It told you what it stopped knowing."*
3. **Report while dark.** Phone in airplane mode. Photo, three words, submit. Under ten seconds. It's stored, signed, and shown as `unwitnessed` — with an honest label: *"time not yet verified by another device."*
4. **Tamper.** On Site B's node, roll the clock back three days and inject a backdated "hazard reported" record. It looks perfect. Any conventional system would accept it.
5. **The mule.** Take a phone from A to B — walk across the room. Two BLE entanglements. No internet touched. Show the attestations arriving.
6. **Reconnect.** Everything converges in seconds. The genuine offline report is now **sealed**, with three witnesses and a stated ordering guarantee. The fabricated one is flagged: **unwitnessed, disputed, outside every attestation** — and the fork is attributed to a specific key.
7. **The payoff.** Site A's fourth near-miss with a given signature triggers the cross-site alert: *"pattern preceded a lost-time injury at 2 of 6 sites; median lead 19 days."* Then show the wire capture proving zero raw incident content ever crossed a site boundary.
8. **Close on the sentence.** *"Created on a disconnected phone by someone nobody was watching — and still provable in court, while nothing sensitive ever left the site."*

Step 6 is the moment. Rehearse it until it is clean, and make the tamper in step 4 genuinely convincing beforehand.

---

## 21. Decisions made on your behalf

Everything below was reconstructed, not recovered. If the original project differed, these are the load-bearing points to correct:

1. **The three novel pillars.** The description line supports many designs. Entanglement + coverage + federation is the one that makes "distributed, offline-first, incident intelligence" mean something no existing product means. If your original thesis was different, keep the structure and swap §4.
2. **Rust core with WASM.** Chosen for the single-implementation invariant. If your original stack was TypeScript throughout, that is viable through M4 but will hurt at M1–M2. Know the tradeoff before overriding.
3. **Sketch-based federation before ML.** If this is an academic project needing a learning contribution, elevate §11.3 v2 — but keep v1 as the working system.
4. **Sector-neutral.** Written to fit construction, mining, ports, utilities, and disaster response. Picking one sharpens everything: vocabulary (§ `spec/05-vocabulary.md`), regulatory export format, and the incident taxonomy all become concrete.
5. **Scope.** M0–M8 is a substantial build — realistically 4–8 months for a small competent team, or a full academic year for one person. If the timeline is tighter, the cut order is in §19: drop transports, then federation. Never drop M1.

**What I could not reconstruct and you should decide:** the intended sector and first user; whether this is academic, commercial, or portfolio work; team size and deadline; any hard constraints inherited from a supervisor, client, or course rubric.

---

## 22. Glossary

| Term | Meaning |
|---|---|
| **Attestation** | A signed statement by one node about another node's chain head at the moment of contact |
| **Coverage** | Fraction of expected data, event-rate-weighted, present in a given computation |
| **Contested** | A semantic disagreement preserved and surfaced rather than auto-resolved |
| **Entanglement** | Mutual attestation binding two nodes' timelines on contact |
| **Fork proof** | Compact self-verifying evidence that one key signed two conflicting chain entries |
| **Mule** | A transport-only node carrying opaque bundles between sites |
| **Observation** | Immutable signed atom of perception. The system's fundamental unit |
| **Sealed** | An observation with at least one downstream attestation from a distinct key |
| **Signature (pattern)** | Canonical tag multi-set describing a thread, used for federated matching |
| **Silence detection** | Distinguishing "nothing happened" from "nobody reported" from "nobody connected" |
| **Thread** | Mutable CRDT interpretation grouping observations into one situation |
| **Unwitnessed window** | Span between an observation's creation and its first attestation |
| **Witness latency** | Duration of the unwitnessed window; a fleet-level quality KPI |

---

## 23. Reading list

- Maniatis, P. & Baker, M. *Secure History Preservation Through Timeline Entanglement.* 11th USENIX Security Symposium, 2002, pp. 297–312. **Read this first** — it is the theoretical foundation of §8.
- Haber, S. & Stornetta, W.S. *How to Time-Stamp a Digital Document.* Journal of Cryptology, 1991.
- Shapiro, M. et al. *Conflict-Free Replicated Data Types.* INRIA, 2011.
- Kulkarni, S. et al. *Logical Physical Clocks and Consistent Snapshots in Globally Distributed Databases* (HLC), 2014.
- Fall, K. *A Delay-Tolerant Network Architecture for Challenged Internets.* SIGCOMM 2003.
- McMahan, B. et al. *Communication-Efficient Learning of Deep Networks from Decentralized Data.* AISTATS 2017.
- Reason, J. *Managing the Risks of Organizational Accidents*, 1997 — for why near-misses and reporting culture are the right thing to optimise for.
- Iroh / Willow protocol documentation — practical range-based set reconciliation.
- Secure Scuttlebutt protocol guide — production hash-chain feeds under intermittent connectivity.
