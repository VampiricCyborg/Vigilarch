//! # vigil-wasm
//!
//! A `wasm-bindgen` wrapper that runs the **real** `vigil-ledger` in a browser:
//! chain append, the attestation DAG, bracketing, fork detection and quarantine,
//! exactly as `vigil-node` and `vigil-sim` run them natively.
//!
//! ## One implementation of the ledger (invariant I2)
//!
//! This crate contains no chain, attestation or reconciliation logic of its own.
//! It links [`vigil_ledger`] directly and calls its functions — this is the
//! deliberate opposite of `vigil-verify`, whose independence rule forbids that
//! link so its second implementation can be cross-checked against this one. Here
//! the goal is the reverse: prove the same bytes and the same code that seal a
//! record on an edge box seal it identically under `wasm32-unknown-unknown`.
//!
//! ## What it exposes
//!
//! [`Demo`] holds two in-memory nodes, `a` and `b`, each with a deterministic
//! Ed25519 device key and its own [`MemoryStore`](vigil_ledger::MemoryStore),
//! plus one shared [`Quarantine`](vigil_ledger::Quarantine). Its methods walk the
//! same shape of scenario `vigil-sim`'s `honest` and `equivocation` runs already
//! prove natively — an attestation exchange that seals a record, an equivocation
//! that is convicted and quarantined while its withheld sibling stays unsealed —
//! but interactively, one action at a time, rather than as a fixed script. It
//! invents no new scenario and no new vocabulary: the window edges it reports are
//! [`vigil_ledger::WindowEdge`] verbatim (`spec/02-entanglement.md` §5.1).
//!
//! ## The JS boundary
//!
//! Every method returns a plain JSON value built by `serde` from the small DTO
//! structs at the bottom of this file. Those derives live here and nowhere else —
//! `vigil-core` stays free of `serde` on the hashed-preimage path, which
//! `spec/01-wire-format.md` §2.4 requires, because a derived field order that
//! changed between platforms would silently fork every content address.
//!
//! ## Build
//!
//! The artifact is a bundler-free ES module a static page imports with no build
//! tooling of its own:
//!
//! ```text
//! cargo build -p vigil-wasm --target wasm32-unknown-unknown --release
//! wasm-bindgen target/wasm32-unknown-unknown/release/vigil_wasm.wasm \
//!     --target web --out-dir crates/vigil-wasm/pkg
//! ```
//!
//! `--target web` is the contract the frontend depends on: `pkg/vigil_wasm.js`
//! is then an ES module exposing `default` (the wasm init) and the `Demo` class,
//! importable straight from `<script type="module">`.

#![forbid(unsafe_code)]

mod rng;

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use serde::Serialize;
use vigil_core::{
    Attestation, Hash, Hlc, Object, Observation, ObservationBody, PubKey, SignedObject, SiteId,
    public_key,
};
use vigil_ledger::{
    AppendError, Bracket, Dag, IngestError, IngestOutcome, MemoryStore, Quarantine, Store,
    StoreError, WindowEdge, append, detect_forks, ingest_attestation,
};
use wasm_bindgen::prelude::*;

use crate::rng::SplitMix64;

/// The site every observation in the demo is stamped with. A real deployment
/// provisions this; a self-contained demo uses a constant, as `vigil-node` and
/// `vigil-sim` do.
const SITE: SiteId = SiteId(*b"VIGILARCH-WASM-A");

/// The fixed seed [`Demo::new`] uses. Arbitrary — its only jobs are to be stable
/// (so ids are reproducible across machines, which the native tests assert) and
/// to differ from anything a real key ceremony would produce. See [`rng`].
const DEMO_SEED: u64 = 0x5601_2026_A11C_E123;

// ===========================================================================
// Errors
// ===========================================================================

/// Why a [`DemoCore`] call did not complete.
///
/// Every variant is a caller mistake or an empty-state precondition — the ledger
/// itself does not fail on a [`MemoryStore`]. On the JS side each becomes a
/// thrown `Error` carrying this message.
#[derive(Debug, thiserror::Error)]
pub enum DemoError {
    /// The `node` argument was neither `"a"` nor `"b"`.
    #[error("unknown node {0:?}; expected \"a\" or \"b\"")]
    UnknownNode(String),
    /// An exchange or equivocation was asked for before the node had any entry.
    #[error("node {0} has an empty chain — append an observation first")]
    EmptyChain(&'static str),
    /// The observation id was not 64 hex characters.
    #[error("{0:?} is not a 64-hex-character content address")]
    BadHash(String),
    /// The id is well-formed but is not an observation vertex in that node's DAG.
    #[error("{0} is not an observation this node holds")]
    NotAnObservation(String),
    /// [`append`](vigil_ledger::append) refused the entry (a §6.6 join-rule
    /// contradiction). Carries the finding's own message.
    #[error("chain append refused: {0}")]
    Append(String),
    /// [`ingest_attestation`](vigil_ledger::ingest_attestation) rejected the
    /// attestation (only ever a bad signature here, which cannot happen with a
    /// key this crate controls).
    #[error("attestation ingest failed: {0}")]
    Ingest(String),
    /// The storage backend failed — impossible for [`MemoryStore`], kept so the
    /// trait's `Result` is not swallowed.
    #[error("storage backend failure: {0}")]
    Store(String),
}

impl From<AppendError> for DemoError {
    fn from(e: AppendError) -> Self {
        Self::Append(e.to_string())
    }
}
impl From<IngestError> for DemoError {
    fn from(e: IngestError) -> Self {
        Self::Ingest(e.to_string())
    }
}
impl From<StoreError> for DemoError {
    fn from(e: StoreError) -> Self {
        Self::Store(e.to_string())
    }
}

// `DemoError: std::error::Error` (via thiserror), so `wasm_bindgen`'s blanket
// `impl<E: Error> From<E> for JsError` already turns it into a thrown JS `Error`
// at every `?` in the wasm surface. No explicit conversion is needed or allowed.

// ===========================================================================
// Node selection
// ===========================================================================

#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    A,
    B,
}

impl Side {
    fn parse(s: &str) -> Result<Self, DemoError> {
        match s {
            "a" | "A" => Ok(Self::A),
            "b" | "B" => Ok(Self::B),
            other => Err(DemoError::UnknownNode(other.to_owned())),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::B => "b",
        }
    }
}

// ===========================================================================
// The demo core — plain Rust, no JS types, directly unit-testable
// ===========================================================================

/// One simulated node: its device key and the ledger it keeps.
struct DemoNode {
    key: SigningKey,
    pubkey: PubKey,
    store: MemoryStore,
    /// A merge hint only (`spec/01-wire-format.md` §5.1). Advanced from the
    /// demo's logical `clock`, never from wall time (invariant I4).
    hlc: Hlc,
}

impl DemoNode {
    fn from_seed(seed: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&seed);
        let pubkey = public_key(&key);
        Self {
            key,
            pubkey,
            store: MemoryStore::new(),
            hlc: Hlc::default(),
        }
    }
}

/// The demo state behind [`Demo`]. Split out so the four load-bearing methods
/// can be exercised by the native test module without a JS harness.
pub struct DemoCore {
    a: DemoNode,
    b: DemoNode,
    quarantine: Quarantine,
    /// A monotonic logical clock fed to [`Hlc::tick`] in place of a wall clock,
    /// like `vigil_node`'s `tick`. Absolute value carries no meaning.
    clock: u64,
    /// Deterministic nonce source for attestations (`spec/01` §6.5).
    rng: SplitMix64,
}

impl DemoCore {
    /// Fresh state: two empty chains, an empty quarantine, keys derived from
    /// `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        let mut rng = SplitMix64::new(seed);
        let a = DemoNode::from_seed(rng.bytes32());
        let b = DemoNode::from_seed(rng.bytes32());
        Self {
            a,
            b,
            quarantine: Quarantine::new(),
            clock: 0,
            rng,
        }
    }

    fn node(&self, side: Side) -> &DemoNode {
        match side {
            Side::A => &self.a,
            Side::B => &self.b,
        }
    }

    fn node_mut(&mut self, side: Side) -> &mut DemoNode {
        match side {
            Side::A => &mut self.a,
            Side::B => &mut self.b,
        }
    }

    fn tick(&mut self) -> u64 {
        self.clock += 1000;
        self.clock
    }

    // -- 2. append ----------------------------------------------------------

    /// Append a `Note` observation to `node`'s chain through
    /// [`vigil_ledger::append`] — the guarded §6.6 write path, with `seq`/`prev`
    /// taken from the store's own view of the chain.
    ///
    /// # Errors
    ///
    /// [`DemoError::UnknownNode`], or [`DemoError::Append`] if the join rule is
    /// somehow broken (it is not, for a single well-formed chain).
    pub fn append(&mut self, node: &str, text: &str) -> Result<AppendSummary, DemoError> {
        let side = Side::parse(node)?;
        let now = self.tick();
        let n = self.node_mut(side);

        let (seq, prev) = match n.store.chain_head(&n.pubkey)? {
            Some(head) => (head.seq + 1, Some(head.id)),
            None => (0, None),
        };
        n.hlc = n.hlc.tick(now);

        let obs = Observation {
            author: n.pubkey,
            site: SITE,
            prev,
            seq,
            hlc: n.hlc,
            body: ObservationBody::Note {
                text: text.to_owned(),
            },
            geo: None,
            acks: BTreeSet::new(),
        };
        let sig = obs.sign(&n.key);
        let id = append(&mut n.store, &obs, &sig)?;

        Ok(AppendSummary {
            node: side.label(),
            id: id.to_string(),
            seq,
            prev: prev.map(|h| h.to_string()),
        })
    }

    // -- 3. exchange_attestation -----------------------------------------------

    /// The mutual attestation exchange (`spec/02-entanglement.md` §3): `a`
    /// witnesses `b`'s current head and `b` witnesses `a`'s, each attestation
    /// signed with the witness's key and ingested through
    /// [`vigil_ledger::ingest_attestation`] into the subject's store — the store
    /// that will later bracket that subject's chain.
    ///
    /// # Errors
    ///
    /// [`DemoError::EmptyChain`] if either node has no entry to present.
    pub fn exchange_attestation(&mut self) -> Result<ExchangeSummary, DemoError> {
        let a_head = self
            .a
            .store
            .chain_head(&self.a.pubkey)?
            .ok_or(DemoError::EmptyChain("a"))?;
        let b_head = self
            .b
            .store
            .chain_head(&self.b.pubkey)?
            .ok_or(DemoError::EmptyChain("b"))?;
        let now = self.tick();

        // a witnesses b.
        self.a.hlc = self.a.hlc.tick(now);
        let att_ab = Attestation {
            witness: self.a.pubkey,
            subject: self.b.pubkey,
            subject_head: b_head.id,
            subject_seq: b_head.seq,
            witness_hlc: self.a.hlc,
            nonce: self.rng.nonce(),
        };
        let sig_ab = att_ab.sign(&self.a.key);

        // b witnesses a.
        self.b.hlc = self.b.hlc.tick(now);
        let att_ba = Attestation {
            witness: self.b.pubkey,
            subject: self.a.pubkey,
            subject_head: a_head.id,
            subject_seq: a_head.seq,
            witness_hlc: self.b.hlc,
            nonce: self.rng.nonce(),
        };
        let sig_ba = att_ba.sign(&self.b.key);

        // Each attestation goes to the store of the chain it seals.
        let id_ba = outcome_id(ingest_attestation(&mut self.a.store, &att_ba, &sig_ba)?);
        let id_ab = outcome_id(ingest_attestation(&mut self.b.store, &att_ab, &sig_ab)?);

        Ok(ExchangeSummary {
            a_witnesses_b: AttestationSummary {
                id: id_ab.to_string(),
                witness: "a",
                subject: "b",
                subject_head: b_head.id.to_string(),
                subject_seq: b_head.seq,
            },
            b_witnesses_a: AttestationSummary {
                id: id_ba.to_string(),
                witness: "b",
                subject: "a",
                subject_head: a_head.id.to_string(),
                subject_seq: a_head.seq,
            },
        })
    }

    // -- 4. equivocate ------------------------------------------------------

    /// Force a second, distinct entry at `node`'s current head `seq`/`prev` —
    /// the move `vigil-sim`'s `equivocation` scenario makes — then run
    /// [`vigil_ledger::detect_forks`] over that node's store and, if a
    /// [`ForkProof`](vigil_core::ForkProof) convicts the node's key, apply it to
    /// the shared quarantine.
    ///
    /// The guarded [`append`](vigil_ledger::append) does not refuse the sibling
    /// (`spec/01-wire-format.md` §6.6): retaining a signed self-contradiction is
    /// the point.
    ///
    /// # Errors
    ///
    /// [`DemoError::UnknownNode`] or [`DemoError::EmptyChain`].
    pub fn equivocate(&mut self, node: &str, text: &str) -> Result<EquivocateSummary, DemoError> {
        let side = Side::parse(node)?;
        let my_key = self.node(side).pubkey;
        let now = self.tick();

        let sibling = {
            let n = self.node_mut(side);
            let head = n
                .store
                .chain_head(&n.pubkey)?
                .ok_or(DemoError::EmptyChain(side.label()))?;
            let head_obs = n
                .store
                .observation(&head.id)?
                .expect("chain_head names a held observation")
                .observation;

            n.hlc = n.hlc.tick(now);
            let sibling = Observation {
                author: n.pubkey,
                site: SITE,
                // Same position as the head: same seq, same prev, different body.
                prev: head_obs.prev,
                seq: head_obs.seq,
                hlc: n.hlc,
                body: ObservationBody::Note {
                    text: text.to_owned(),
                },
                geo: None,
                acks: BTreeSet::new(),
            };
            let sig = sibling.sign(&n.key);
            let id = append(&mut n.store, &sibling, &sig)?;
            AppendSummary {
                node: side.label(),
                id: id.to_string(),
                seq: sibling.seq,
                prev: sibling.prev.map(|h| h.to_string()),
            }
        };

        // Fork detection over this node's store, then quarantine.
        let proofs = detect_forks(&self.node(side).store)?;
        let mut fork = None;
        for proof in &proofs {
            let Ok(checked) = proof.check() else { continue };
            if checked.key != my_key {
                continue;
            }
            let newly = self.quarantine.apply(&checked);
            let (a_id, b_id) = (checked.a.id(), checked.b.id());
            fork = Some(ForkSummary {
                proof_id: proof.id().to_string(),
                convicted_key: checked.key.to_string(),
                collision: collision_label(&checked.collision),
                entry_a: a_id.to_string(),
                entry_b: b_id.to_string(),
                newly_quarantined: newly,
            });
            break;
        }

        Ok(EquivocateSummary {
            sibling,
            fork_detected: fork.is_some(),
            fork,
            quarantine: self.quarantine_status(),
        })
    }

    // -- 5. bracket -------------------------------------------------------

    /// Rebuild the attestation DAG over `node`'s current store — honouring the
    /// shared quarantine — and return [`Dag::bracket`] for `obs_id_hex`
    /// (`spec/02-entanglement.md` §5).
    ///
    /// # Errors
    ///
    /// [`DemoError::UnknownNode`], [`DemoError::BadHash`], or
    /// [`DemoError::NotAnObservation`] if the id is not an observation vertex.
    pub fn bracket(&self, node: &str, obs_id_hex: &str) -> Result<BracketSummary, DemoError> {
        let side = Side::parse(node)?;
        let id = parse_hash(obs_id_hex)?;
        let dag = Dag::build(&self.node(side).store, &self.quarantine)?;
        let br = dag
            .bracket(id)
            .ok_or_else(|| DemoError::NotAnObservation(obs_id_hex.to_owned()))?;
        Ok(BracketSummary::from_bracket(&br))
    }

    // -- 6. state --------------------------------------------------------

    /// The full current state — both chains as ordered lists, every attestation
    /// either store holds, and the quarantine set — for a frontend to re-render
    /// from scratch after any action.
    ///
    /// # Errors
    ///
    /// [`DemoError::Store`] only, which a [`MemoryStore`] never produces.
    pub fn state(&self) -> Result<StateSummary, DemoError> {
        // Attestations, deduplicated across both stores and ordered by id.
        let mut atts: BTreeMap<Hash, AttestationDto> = BTreeMap::new();
        for store in [&self.a.store, &self.b.store] {
            for sa in store.all_attestations()? {
                atts.entry(sa.id).or_insert_with(|| AttestationDto {
                    id: sa.id.to_string(),
                    witness: sa.attestation.witness.to_string(),
                    subject: sa.attestation.subject.to_string(),
                    subject_head: sa.attestation.subject_head.to_string(),
                    subject_seq: sa.attestation.subject_seq,
                });
            }
        }

        Ok(StateSummary {
            a: self.node_state(Side::A)?,
            b: self.node_state(Side::B)?,
            attestations: atts.into_values().collect(),
            quarantine: self
                .quarantine
                .keys()
                .map(std::string::ToString::to_string)
                .collect(),
        })
    }

    fn node_state(&self, side: Side) -> Result<NodeState, DemoError> {
        let n = self.node(side);
        let chain = n
            .store
            .chain(&n.pubkey)?
            .into_iter()
            .map(|so| ChainEntry {
                id: so.id.to_string(),
                seq: so.observation.seq,
                prev: so.observation.prev.map(|h| h.to_string()),
                text: note_text(&so.observation.body),
            })
            .collect();
        Ok(NodeState {
            node: side.label(),
            pubkey: n.pubkey.to_string(),
            chain,
        })
    }

    fn quarantine_status(&self) -> QuarantineStatus {
        QuarantineStatus {
            keys: self
                .quarantine
                .keys()
                .map(std::string::ToString::to_string)
                .collect(),
            contains_a: self.quarantine.contains(&self.a.pubkey),
            contains_b: self.quarantine.contains(&self.b.pubkey),
        }
    }
}

fn outcome_id(o: IngestOutcome) -> Hash {
    match o {
        IngestOutcome::Stored(h)
        | IngestOutcome::AlreadyHeld(h)
        | IngestOutcome::WitnessConflict { incoming: h, .. } => h,
    }
}

fn collision_label(c: &vigil_core::Collision) -> String {
    match c {
        vigil_core::Collision::SameSeq(seq) => format!("same-seq:{seq}"),
        vigil_core::Collision::SamePrev(None) => "same-prev:genesis".to_owned(),
        vigil_core::Collision::SamePrev(Some(h)) => format!("same-prev:{h}"),
    }
}

fn note_text(body: &ObservationBody) -> String {
    match body {
        ObservationBody::Note { text } => text.clone(),
        // The demo only ever writes Notes; keep this total anyway.
        _ => "<non-note body>".to_owned(),
    }
}

fn parse_hash(s: &str) -> Result<Hash, DemoError> {
    let bytes = hex::decode(s.trim()).map_err(|_| DemoError::BadHash(s.to_owned()))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| DemoError::BadHash(s.to_owned()))?;
    Ok(Hash(arr))
}

// ===========================================================================
// The wasm-bindgen surface
// ===========================================================================

/// Two in-memory nodes and a shared quarantine, driven one action at a time from
/// JavaScript. Every method returns a JSON value (see the DTOs below); the
/// fallible ones throw an `Error` carrying a [`DemoError`] message.
#[wasm_bindgen]
pub struct Demo {
    core: DemoCore,
}

impl Default for Demo {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl Demo {
    /// Fresh state with the fixed [`DEMO_SEED`] identity.
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new() -> Self {
        Self {
            core: DemoCore::new(DEMO_SEED),
        }
    }

    /// Fresh state with a caller-chosen identity — for a second instance on the
    /// same page that must not share `a`/`b` keys with the first.
    #[wasm_bindgen(js_name = withSeed)]
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        Self {
            core: DemoCore::new(seed),
        }
    }

    /// Append a `Note` to `"a"` or `"b"`'s chain. Returns `{ node, id, seq, prev }`.
    ///
    /// # Errors
    ///
    /// Throws if `node` is not `"a"`/`"b"`.
    pub fn append(&mut self, node: &str, text: &str) -> Result<JsValue, JsError> {
        to_js(&self.core.append(node, text)?)
    }

    /// Perform the mutual attestation exchange between `a`'s and `b`'s heads.
    /// Returns `{ a_witnesses_b, b_witnesses_a }`.
    ///
    /// # Errors
    ///
    /// Throws if either chain is empty.
    #[wasm_bindgen(js_name = exchangeAttestation)]
    pub fn exchange_attestation(&mut self) -> Result<JsValue, JsError> {
        to_js(&self.core.exchange_attestation()?)
    }

    /// Force a fork at `node`'s head, run fork detection, and quarantine the key
    /// if convicted. Returns `{ sibling, fork_detected, fork, quarantine }`.
    ///
    /// # Errors
    ///
    /// Throws if `node` is not `"a"`/`"b"` or its chain is empty.
    pub fn equivocate(&mut self, node: &str, text: &str) -> Result<JsValue, JsError> {
        to_js(&self.core.equivocate(node, text)?)
    }

    /// Bracket one observation over `node`'s current DAG. Returns the sealed /
    /// unwitnessed verdict, both bounds, witness depth, the window edges, and
    /// `disputed`.
    ///
    /// # Errors
    ///
    /// Throws if `node` is not `"a"`/`"b"`, the id is malformed, or the id is not
    /// an observation the node holds.
    pub fn bracket(&self, node: &str, obs_id_hex: &str) -> Result<JsValue, JsError> {
        to_js(&self.core.bracket(node, obs_id_hex)?)
    }

    /// The full current state, for re-rendering from scratch.
    ///
    /// # Errors
    ///
    /// Does not throw in practice (the in-memory store is infallible).
    pub fn state(&self) -> Result<JsValue, JsError> {
        to_js(&self.core.state()?)
    }
}

fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsError> {
    serde_wasm_bindgen::to_value(value).map_err(|e| JsError::new(&e.to_string()))
}

// ===========================================================================
// DTOs — the JS boundary shapes. `serde` derives live here only.
// ===========================================================================

/// The result of [`DemoCore::append`] (also the `sibling` of an equivocation).
#[derive(Debug, Clone, Serialize)]
pub struct AppendSummary {
    pub node: &'static str,
    pub id: String,
    pub seq: u64,
    pub prev: Option<String>,
}

/// One attestation from an exchange.
#[derive(Debug, Clone, Serialize)]
pub struct AttestationSummary {
    pub id: String,
    pub witness: &'static str,
    pub subject: &'static str,
    pub subject_head: String,
    pub subject_seq: u64,
}

/// The result of [`DemoCore::exchange_attestation`].
#[derive(Debug, Clone, Serialize)]
pub struct ExchangeSummary {
    pub a_witnesses_b: AttestationSummary,
    pub b_witnesses_a: AttestationSummary,
}

/// A fork proof plus what it did to the quarantine.
#[derive(Debug, Clone, Serialize)]
pub struct ForkSummary {
    pub proof_id: String,
    pub convicted_key: String,
    /// `same-seq:<n>` or `same-prev:<hex|genesis>` (`spec/01-wire-format.md` §6.1).
    pub collision: String,
    pub entry_a: String,
    pub entry_b: String,
    pub newly_quarantined: bool,
}

/// The result of [`DemoCore::equivocate`].
#[derive(Debug, Clone, Serialize)]
pub struct EquivocateSummary {
    pub sibling: AppendSummary,
    pub fork_detected: bool,
    pub fork: Option<ForkSummary>,
    pub quarantine: QuarantineStatus,
}

/// The quarantine set after an action.
#[derive(Debug, Clone, Serialize)]
pub struct QuarantineStatus {
    pub keys: Vec<String>,
    pub contains_a: bool,
    pub contains_b: bool,
}

/// One edge of an unwitnessed window — [`vigil_ledger::WindowEdge`] verbatim
/// (`spec/02-entanglement.md` §5.1). No name here that the spec does not use.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WindowEdgeDto {
    /// Open below to the author's genesis — no lower-bound attestation.
    Genesis,
    /// Bounded by an attestation.
    Attestation { id: String },
    /// Open above to the moment of verification — the record is unwitnessed.
    VerificationMoment,
}

impl From<&WindowEdge> for WindowEdgeDto {
    fn from(e: &WindowEdge) -> Self {
        match e {
            WindowEdge::Genesis => Self::Genesis,
            WindowEdge::Attestation(h) => Self::Attestation { id: h.to_string() },
            WindowEdge::VerificationMoment => Self::VerificationMoment,
        }
    }
}

/// The unwitnessed window: the span the system cannot vouch for.
#[derive(Debug, Clone, Serialize)]
pub struct WindowDto {
    pub lower: WindowEdgeDto,
    pub upper: WindowEdgeDto,
}

/// The result of [`DemoCore::bracket`] — [`vigil_ledger::Bracket`] flattened for
/// JS.
#[derive(Debug, Clone, Serialize)]
pub struct BracketSummary {
    pub observation: String,
    /// `true` when some attestation seals the record; `false` is `unwitnessed`
    /// (invariant I5 — never a guess).
    pub sealed: bool,
    /// The mirror of `sealed`, in the spec's own word.
    pub unwitnessed: bool,
    /// `U` — earliest sealing attestation, or `null` if unwitnessed.
    pub upper_bound: Option<String>,
    /// `L` — latest attestation provably preceding the record in its own chain;
    /// an ordering fact, not a timestamp (`spec/02-entanglement.md` §5.3).
    pub lower_bound: Option<String>,
    /// Distinct witness keys among every sealing attestation.
    pub witness_depth: u32,
    /// Set only when the author is quarantined and the record is unwitnessed
    /// (`spec/02-entanglement.md` §6.4).
    pub disputed: bool,
    pub window: WindowDto,
}

impl BracketSummary {
    fn from_bracket(b: &Bracket) -> Self {
        Self {
            observation: b.observation.to_string(),
            sealed: b.sealed,
            unwitnessed: !b.sealed,
            upper_bound: b.upper_bound.map(|h| h.to_string()),
            lower_bound: b.lower_bound.map(|h| h.to_string()),
            witness_depth: b.witness_depth,
            disputed: b.disputed,
            window: WindowDto {
                lower: (&b.unwitnessed_window.lower).into(),
                upper: (&b.unwitnessed_window.upper).into(),
            },
        }
    }
}

/// One chain entry in [`StateSummary`].
#[derive(Debug, Clone, Serialize)]
pub struct ChainEntry {
    pub id: String,
    pub seq: u64,
    pub prev: Option<String>,
    pub text: String,
}

/// One node's chain in [`StateSummary`].
#[derive(Debug, Clone, Serialize)]
pub struct NodeState {
    pub node: &'static str,
    pub pubkey: String,
    pub chain: Vec<ChainEntry>,
}

/// One attestation in [`StateSummary`].
#[derive(Debug, Clone, Serialize)]
pub struct AttestationDto {
    pub id: String,
    pub witness: String,
    pub subject: String,
    pub subject_head: String,
    pub subject_seq: u64,
}

/// The result of [`DemoCore::state`].
#[derive(Debug, Clone, Serialize)]
pub struct StateSummary {
    pub a: NodeState,
    pub b: NodeState,
    pub attestations: Vec<AttestationDto>,
    pub quarantine: Vec<String>,
}

// ===========================================================================
// Native tests — the same four methods, no JS harness.
// ===========================================================================

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    use super::*;

    fn fresh() -> DemoCore {
        DemoCore::new(DEMO_SEED)
    }

    #[test]
    fn append_builds_a_linked_chain() {
        let mut d = fresh();
        let g = d.append("a", "grid B4 shoring is out of plumb").unwrap();
        assert_eq!(g.seq, 0);
        assert_eq!(g.prev, None);
        let s = d.append("a", "tag-out re-checked, crew clear").unwrap();
        assert_eq!(s.seq, 1);
        assert_eq!(s.prev.as_deref(), Some(g.id.as_str()));

        let state = d.state().unwrap();
        assert_eq!(state.a.chain.len(), 2);
        assert_eq!(state.b.chain.len(), 0);
        assert_eq!(state.a.chain[1].prev.as_deref(), Some(g.id.as_str()));
    }

    #[test]
    fn unknown_node_is_rejected() {
        let mut d = fresh();
        assert!(matches!(
            d.append("c", "x"),
            Err(DemoError::UnknownNode(n)) if n == "c"
        ));
    }

    #[test]
    fn exchange_before_a_chain_exists_is_rejected() {
        let mut d = fresh();
        d.append("a", "only a has an entry").unwrap();
        assert!(matches!(
            d.exchange_attestation(),
            Err(DemoError::EmptyChain("b"))
        ));
    }

    /// The `honest` shape: an exchange seals the record the witness saw — and the
    /// earlier entries on its chain, by the seal-edge walk (`spec/02` §5.2).
    #[test]
    fn exchange_seals_the_earlier_observation() {
        let mut d = fresh();
        let o0 = d.append("a", "grid B4 shoring is out of plumb").unwrap();
        let o1 = d.append("a", "tag-out re-checked, crew clear").unwrap();
        d.append("b", "night shift headcount logged").unwrap();

        // Before the meeting: unwitnessed, window open above to the verification
        // moment (invariant I6, spec/02 §8.1).
        let before = d.bracket("a", &o0.id).unwrap();
        assert!(!before.sealed && before.unwitnessed);
        assert!(matches!(
            before.window.upper,
            WindowEdgeDto::VerificationMoment
        ));

        let x = d.exchange_attestation().unwrap();
        // b witnessed a's head (o1); the seal edge walks prev back to o0.
        assert_eq!(x.b_witnesses_a.subject_head, o1.id);

        let sealed = d.bracket("a", &o0.id).unwrap();
        assert!(sealed.sealed && !sealed.unwitnessed);
        assert_eq!(
            sealed.upper_bound.as_deref(),
            Some(x.b_witnesses_a.id.as_str())
        );
        assert_eq!(sealed.witness_depth, 1);
        assert!(!sealed.disputed);
        assert!(matches!(sealed.window.lower, WindowEdgeDto::Genesis));
        assert!(matches!(
            sealed.window.upper,
            WindowEdgeDto::Attestation { .. }
        ));

        // o1 itself is sealed too.
        assert!(d.bracket("a", &o1.id).unwrap().sealed);
    }

    /// The `equivocation` shape: the convicted key is quarantined, its honestly
    /// witnessed branch stays sealed (`spec/02` §6.5), and the withheld sibling
    /// — never seen by any witness — stays unsealed and is reported `disputed`
    /// (`spec/02` §6.4), exactly as `vigil-sim`'s scenario asserts natively.
    #[test]
    fn equivocation_convicts_and_leaves_the_withheld_sibling_unsealed() {
        let mut d = fresh();
        let _o0 = d.append("a", "grid B4 shoring is out of plumb").unwrap();
        let o1 = d.append("a", "tag-out re-checked, crew clear").unwrap();
        d.append("b", "night shift headcount logged").unwrap();
        d.exchange_attestation().unwrap();

        assert!(d.bracket("a", &o1.id).unwrap().sealed);

        let e = d
            .equivocate("a", "tag-out never applied, crew still on it")
            .unwrap();
        assert!(e.fork_detected);
        let fork = e.fork.expect("a fork proof");
        assert_eq!(fork.collision, "same-seq:1");
        assert!(fork.newly_quarantined);
        assert!(e.quarantine.contains_a);
        assert!(!e.quarantine.contains_b);
        assert_ne!(e.sibling.id, o1.id);
        assert_eq!(e.sibling.seq, 1);

        // o1: sealed by b's honest, earlier attestation — a's later conviction
        // does not undo it (spec/02 §6.5). Sealed ⇒ not disputed (§6.5).
        let br_o1 = d.bracket("a", &o1.id).unwrap();
        assert!(br_o1.sealed);
        assert!(!br_o1.disputed);

        // The withheld sibling: no witness ever saw it, so it is not sealed; its
        // author is quarantined and it is unwitnessed, so it is disputed (§6.4).
        let br_sib = d.bracket("a", &e.sibling.id).unwrap();
        assert!(!br_sib.sealed && br_sib.unwitnessed);
        assert!(br_sib.disputed);
        assert!(matches!(
            br_sib.window.upper,
            WindowEdgeDto::VerificationMoment
        ));

        // The quarantine is visible in state().
        let state = d.state().unwrap();
        assert_eq!(state.quarantine.len(), 1);
        assert_eq!(state.quarantine[0], fork.convicted_key);
    }

    #[test]
    fn bracket_rejects_a_malformed_or_unknown_id() {
        let mut d = fresh();
        let o0 = d.append("a", "x").unwrap();
        assert!(matches!(
            d.bracket("a", "not-hex"),
            Err(DemoError::BadHash(_))
        ));
        // Well-formed hash, not an observation this node holds.
        let absent = "0".repeat(64);
        assert!(matches!(
            d.bracket("a", &absent),
            Err(DemoError::NotAnObservation(_))
        ));
        // And the real one resolves.
        assert!(d.bracket("a", &o0.id).is_ok());
    }

    #[test]
    fn identity_and_ids_are_deterministic_from_the_seed() {
        let mut one = fresh();
        let mut two = fresh();
        assert_eq!(
            one.append("a", "same text").unwrap().id,
            two.append("a", "same text").unwrap().id
        );
        assert_eq!(one.state().unwrap().a.pubkey, two.state().unwrap().a.pubkey);
    }

    #[test]
    fn state_lists_both_attestations_after_an_exchange() {
        let mut d = fresh();
        d.append("a", "a0").unwrap();
        d.append("b", "b0").unwrap();
        d.exchange_attestation().unwrap();
        let state = d.state().unwrap();
        assert_eq!(state.attestations.len(), 2);
        let witnesses: BTreeSet<&str> = state
            .attestations
            .iter()
            .map(|a| a.witness.as_str())
            .collect();
        // One witnessed by a's key, one by b's.
        assert_eq!(witnesses.len(), 2);
    }
}
