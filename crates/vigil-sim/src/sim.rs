//! The smallest real scenario: two in-memory nodes, one attestation exchange,
//! and a check that the ledger's own bracketing query seals the right record.
//!
//! This exists to prove `vigil-ledger`'s M1 API is usable from outside the
//! crate, driven by a seed and nothing else. It is deliberately not scriptable
//! and has no node roles — the adversarial scenario suite (`spec/02` §9) builds
//! on this, later.
//!
//! ## No clock anywhere (invariant I4)
//!
//! This crate never reads wall time. Logical time advances only through the
//! explicit `tick` values the scenario below hard-codes, passed into
//! [`Hlc::tick`]. Device keys and the attestation nonce come from the seeded
//! [`SplitMix64`] stream. Running one seed twice therefore produces a
//! byte-identical [`RunReport`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use ed25519_dalek::SigningKey;
use vigil_core::{
    Attestation, Checkpoint, Hash, Hlc, Object, Observation, ObservationBody, PubKey, Signature,
    SignedObject, SiteId, public_key,
};
use vigil_ledger::{
    Bracket, IngestOutcome, MemoryStore, Store, WindowEdge, append, bracket, ingest_attestation,
};

use crate::rng::SplitMix64;

const SITE: SiteId = SiteId(*b"VIGILARCH-SITE-A");

/// One simulated node: its device key, its ledger, and its logical clock.
struct Node {
    name: &'static str,
    key: SigningKey,
    store: MemoryStore,
    hlc: Hlc,
}

impl Node {
    fn new(name: &'static str, seed: [u8; 32]) -> Self {
        Self {
            name,
            key: SigningKey::from_bytes(&seed),
            store: MemoryStore::new(),
            hlc: Hlc::default(),
        }
    }

    fn pubkey(&self) -> PubKey {
        public_key(&self.key)
    }

    /// Append a `Note` to this node's own chain at `seq`, linked to `prev` and
    /// committing to `acks`. Time advances to `tick`.
    fn append_note(
        &mut self,
        seq: u64,
        prev: Option<Hash>,
        acks: BTreeSet<Hash>,
        tick: u64,
        text: &str,
    ) -> (Hash, Observation, Signature) {
        self.hlc = self.hlc.tick(tick);
        let obs = Observation {
            author: self.pubkey(),
            site: SITE,
            prev,
            seq,
            hlc: self.hlc,
            body: ObservationBody::Note { text: text.into() },
            geo: None,
            acks,
        };
        let sig = obs.sign(&self.key);
        let id = append(&mut self.store, &obs, &sig).expect("a clean link appends");
        (id, obs, sig)
    }

    /// This node's signed offer of its current head (`spec/02` §2).
    fn checkpoint(&self, head: Hash, seq: u64) -> (Checkpoint, Signature) {
        let cp = Checkpoint {
            node: self.pubkey(),
            head,
            seq,
            hlc: self.hlc,
            frontier: BTreeMap::from([(self.pubkey(), seq)]),
        };
        let sig = cp.sign(&self.key);
        (cp, sig)
    }

    /// Sign an attestation that this node witnessed `subject` presenting `head`
    /// at `seq`, with a nonce drawn from the seeded stream.
    fn witness(
        &self,
        subject: PubKey,
        head: Hash,
        seq: u64,
        rng: &mut SplitMix64,
    ) -> (Attestation, Signature) {
        let att = Attestation {
            witness: self.pubkey(),
            subject,
            subject_head: head,
            subject_seq: seq,
            witness_hlc: self.hlc,
            nonce: rng.nonce(),
        };
        let sig = att.sign(&self.key);
        (att, sig)
    }
}

fn short(h: &Hash) -> String {
    h.to_string()[..12].to_string()
}

/// A machine-readable transcript of one run, plus the pass/fail of the invariant
/// the scenario asserts.
pub struct RunReport {
    pub text: String,
    pub sealed_ok: bool,
    /// Node B's ledger as it stands at the end of the run — the object set a
    /// third party assembling an evidence pack actually holds (`O0`, `O1`, and
    /// the attestation `U`). Exposed so the demo (`--export-pack`) can emit a
    /// pack from the very scenario it just printed, through `vigil-ledger`'s
    /// real `export_pack` path, rather than a side fixture. The scale-up runner
    /// ignores it.
    pub b_store: MemoryStore,
    /// `O0`'s content address — the genesis observation a demo pack claims.
    pub o0_id: Hash,
}

/// Run the scenario at `seed` and return its transcript.
///
/// Steps, in order:
/// 1. `t=1000` — node A appends a genesis observation `O0`.
/// 2. `t=2000` — A and B meet: A offers a checkpoint, B (empty chain) offers
///    none, B signs an attestation `U` of A's head and hands it back; A's `O0`
///    is relayed to B over the link.
/// 3. `t=3000` — A appends `O1`, committing to `U` in its `acks`; `O1` is
///    relayed to B.
/// 4. From B's ledger alone, `bracket(O0)` must report it **sealed** by `U`,
///    with witness depth 1 and a window open below to genesis — sealed above,
///    honestly unbounded below (invariant I6, `spec/02` §8.1).
#[must_use]
pub fn run(seed: u64) -> RunReport {
    let mut rng = SplitMix64::new(seed);
    let a_seed = rng.bytes32();
    let b_seed = rng.bytes32();
    let mut a = Node::new("A", a_seed);
    let mut b = Node::new("B", b_seed);

    let mut t = String::new();
    let _ = writeln!(t, "vigil-sim run report");
    let _ = writeln!(t, "seed: {seed}");
    let _ = writeln!(t, "node A key: {}", a.pubkey());
    let _ = writeln!(t, "node B key: {}", b.pubkey());

    // 1. A writes genesis.
    let (o0_id, o0, o0_sig) = a.append_note(
        0,
        None,
        BTreeSet::new(),
        1000,
        "grid B4 shoring is out of plumb",
    );
    let _ = writeln!(t, "[t=1000] A appends O0 seq=0 id={}", short(&o0_id));

    // 2. The meeting.
    let (cp, _cp_sig) = a.checkpoint(o0_id, 0);
    let _ = writeln!(
        t,
        "[t=2000] A offers checkpoint head={} seq=0 id={}",
        short(&cp.head),
        short(&cp.id())
    );
    let _ = writeln!(t, "[t=2000] B declines checkpoint (empty chain)");

    b.hlc = b.hlc.tick(2000);
    let (u, u_sig) = b.witness(a.pubkey(), o0_id, 0, &mut rng);
    let u_id = u.id();
    // B keeps the attestation it issued; A ingests the one about itself.
    b.store.put_attestation(&u, &u_sig).expect("store");
    match ingest_attestation(&mut a.store, &u, &u_sig).expect("ingest") {
        IngestOutcome::Stored(_) => {}
        other => panic!("unexpected ingest outcome for a fresh attestation: {other:?}"),
    }
    let _ = writeln!(
        t,
        "[t=2000] B attests A@0 -> U id={} (witness {})",
        short(&u_id),
        b.name
    );

    // Relay O0 to B over the link (no sync layer in v1 — the sim moves objects).
    b.store.put_observation(&o0, &o0_sig).expect("relay O0");
    let _ = writeln!(t, "[t=2000] O0 relayed A->B");

    // 3. A acks the meeting in its next entry.
    let (o1_id, o1, o1_sig) = a.append_note(
        1,
        Some(o0_id),
        BTreeSet::from([u_id]),
        3000,
        "tag-out re-checked after the meeting",
    );
    b.store.put_observation(&o1, &o1_sig).expect("relay O1");
    let _ = writeln!(
        t,
        "[t=3000] A appends O1 seq=1 acks=[{}] id={}; O1 relayed A->B",
        short(&u_id),
        short(&o1_id)
    );

    // 4. Bracket O0 from B's ledger alone.
    let br: Bracket = bracket(&b.store, o0_id)
        .expect("store")
        .expect("B holds O0");
    let _ = writeln!(t, "bracket(O0) from B's ledger:");
    let _ = writeln!(t, "  sealed: {}", br.sealed);
    let _ = writeln!(
        t,
        "  upper bound: {}",
        br.upper_bound
            .map_or("none".into(), |h| format!("U id={}", short(&h)))
    );
    let _ = writeln!(
        t,
        "  lower bound: {}",
        br.lower_bound
            .map_or("none".into(), |h| format!("id={}", short(&h)))
    );
    let _ = writeln!(t, "  witness depth: {}", br.witness_depth);
    let _ = writeln!(
        t,
        "  unwitnessed window: [{}, {}]",
        window_edge(&br.unwitnessed_window.lower),
        window_edge(&br.unwitnessed_window.upper)
    );

    let sealed_ok = br.sealed
        && br.upper_bound == Some(u_id)
        && br.witness_depth == 1
        && br.lower_bound.is_none()
        && br.unwitnessed_window.lower == WindowEdge::Genesis
        && br.unwitnessed_window.upper == WindowEdge::Attestation(u_id)
        && !br.disputed;

    let _ = writeln!(
        t,
        "INVARIANT {}: O0 is sealed from B's view by U, window open below to genesis (spec/02 §8.1)",
        if sealed_ok { "ok" } else { "VIOLATED" }
    );

    RunReport {
        text: t,
        sealed_ok,
        b_store: b.store,
        o0_id,
    }
}

fn window_edge(e: &WindowEdge) -> String {
    match e {
        WindowEdge::Attestation(h) => format!("U id={}", short(h)),
        WindowEdge::Genesis => "genesis".into(),
        WindowEdge::VerificationMoment => "now".into(),
    }
}
