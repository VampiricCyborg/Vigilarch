//! The sealing ablation: what one attestation object buys, stated at its
//! narrowest.
//!
//! The claim here is deliberately narrower and more precise than "tamper
//! detection needs attestations". It is:
//!
//! > **Sealing** needs an attestation. Chain verification does not.
//!
//! Two runs from the same seed and the same held chain, differing in exactly one
//! stored object:
//!
//! - **Run A (witnessed)** — node B performs the ordinary attestation exchange
//!   over node A's head at `O1`, exactly as in [`crate::sim`]. `bracket(O0)` is
//!   **sealed**: witness depth `1`, upper edge bounded by that attestation.
//! - **Run B (no attestation)** — byte-for-byte the same `O0`, `O1`, `O2` for
//!   A's chain; no `Attestation` object anywhere in the store. `bracket(O0)` is
//!   **unwitnessed**: the window is open above to the verification moment
//!   (`spec/03-export-pack.md` §5 step 6 — an unbounded upper edge is reported
//!   as `VerificationMoment`, never filled in).
//!
//! ## This is not a tamper, and the transcript must not imply one
//!
//! `O0`, `O1`, `O2` are honest in both runs — same author key, same bodies, same
//! `seq`/`prev` links, same signature bytes. Run B forges nothing. The scenario
//! measures a *capability the mechanism adds*, not an *attack it stops*: strip
//! the attestation and the honest record is simply reported with a wide open
//! window, which is the correct conservative output (invariants I5, I6), not a
//! detection and not an accusation. A node with no witnesses can still write
//! whatever it likes; the system's honest answer is "unwitnessed", not "false".
//!
//! ## What does *not* change between the runs
//!
//! `verify_chain` returns `Verified` for A's chain in both runs — the chain is
//! complete and internally consistent with or without any attestation. Chain
//! integrity is a property of the chain's own `seq`/`prev`/signature structure;
//! the attestation adds a *temporal* claim on top, and nothing else. That is the
//! whole distance between "sealed, bounded" and "unwitnessed, open".
//!
//! ## Determinism (invariant I4)
//!
//! No wall-clock read anywhere. Logical time is the hard-coded `tick` values
//! below; the two device keys and the single attestation nonce come from the
//! seeded [`SplitMix64`] stream. One seed produces a byte-identical
//! [`RunReport`].

use std::collections::BTreeSet;
use std::fmt::Write as _;

use ed25519_dalek::SigningKey;
use vigil_core::{
    Attestation, Hash, Hlc, Object, Observation, ObservationBody, PubKey, Signature, SignedObject,
    SiteId, public_key,
};
use vigil_ledger::{
    Bracket, ChainVerification, Dag, MemoryStore, Quarantine, Store, WindowEdge, append,
    verify_chain,
};

use crate::rng::SplitMix64;

const SITE: SiteId = SiteId(*b"VIGILARCH-SITE-A");

/// One simulated node: its device key and its logical clock. Signed objects are
/// gathered into a per-run verifier store in [`run`], never kept here.
struct Node {
    name: &'static str,
    key: SigningKey,
    hlc: Hlc,
}

impl Node {
    fn new(name: &'static str, seed: [u8; 32]) -> Self {
        Self {
            name,
            key: SigningKey::from_bytes(&seed),
            hlc: Hlc::default(),
        }
    }

    fn pubkey(&self) -> PubKey {
        public_key(&self.key)
    }

    /// Sign a `Note` for this node's own chain at `seq`, linked to `prev`. Time
    /// advances to `tick`. Not stored here — the caller places it into whichever
    /// run's store it belongs in.
    fn note(
        &mut self,
        seq: u64,
        prev: Option<Hash>,
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
            acks: BTreeSet::new(),
        };
        let sig = obs.sign(&self.key);
        (obs.id(), obs, sig)
    }

    /// Sign an attestation that this node witnessed `subject` presenting `head`
    /// at `seq`, nonce drawn from the seeded stream. Time advances to `tick`.
    fn witness(
        &mut self,
        subject: PubKey,
        head: Hash,
        seq: u64,
        tick: u64,
        rng: &mut SplitMix64,
    ) -> (Attestation, Signature) {
        self.hlc = self.hlc.tick(tick);
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

fn sig_short(s: &Signature) -> String {
    s.to_string()[..12].to_string()
}

fn window_edge(e: &WindowEdge) -> String {
    match e {
        WindowEdge::Attestation(h) => format!("Attestation({})", short(h)),
        WindowEdge::Genesis => "Genesis".into(),
        WindowEdge::VerificationMoment => "VerificationMoment".into(),
    }
}

/// A machine-readable transcript of one run, plus whether every assertion held
/// and the two `bracket(O0)` results the runs produced.
pub struct RunReport {
    pub text: String,
    pub passed: bool,
    /// `bracket(O0)` from the witnessed run — expected `sealed`.
    pub bracket_a: Bracket,
    /// `bracket(O0)` from the no-attestation run — expected `unwitnessed`.
    pub bracket_b: Bracket,
}

/// Bracket `O0` from `store` and render the result into `t` under `label`.
fn bracket_o0(store: &MemoryStore, o0_id: Hash) -> Bracket {
    Dag::build(store, &Quarantine::new())
        .expect("store")
        .bracket(o0_id)
        .expect("O0 is a vertex in both runs")
}

/// Run the sealing-ablation scenario at `seed` and return its transcript.
///
/// Every assertion prints `PASS` or `FAIL`; [`RunReport::passed`] is the AND of
/// them all, and the binary exits non-zero when it is false.
#[must_use]
pub fn run(seed: u64) -> RunReport {
    let mut rng = SplitMix64::new(seed);
    let a_seed = rng.bytes32();
    let b_seed = rng.bytes32();
    let mut a = Node::new("A", a_seed);
    let mut b = Node::new("B", b_seed);

    let mut t = String::new();
    let mut passed = true;
    let mut check = |t: &mut String, label: &str, cond: bool| {
        passed &= cond;
        let _ = writeln!(t, "  [{}] {label}", if cond { "PASS" } else { "FAIL" });
    };

    let _ = writeln!(t, "vigil-sim sealing-ablation scenario");
    let _ = writeln!(t, "seed: {seed}");
    let _ = writeln!(
        t,
        "node {} key: {} (honest author, both runs)",
        a.name,
        a.pubkey()
    );
    let _ = writeln!(
        t,
        "node {} key: {} (witness; performs the exchange in run A only)",
        b.name,
        b.pubkey()
    );

    // --- A's honest chain: signed once, used verbatim by both runs. -----------
    let (o0_id, o0, o0_sig) = a.note(0, None, 1000, "grid B4 shoring is out of plumb");
    let (o1_id, o1, o1_sig) = a.note(1, Some(o0_id), 2000, "tag-out re-checked, crew clear");
    let (o2_id, o2, o2_sig) = a.note(
        2,
        Some(o1_id),
        3000,
        "shoring re-shimmed, plumb within tolerance",
    );
    let chain: [(&Observation, &Signature); 3] = [(&o0, &o0_sig), (&o1, &o1_sig), (&o2, &o2_sig)];

    let _ = writeln!(
        t,
        "\nA's chain (one set of signed objects, shared by both runs):"
    );
    let _ = writeln!(
        t,
        "  O0 seq=0 prev=-            id={} sig={}",
        short(&o0_id),
        sig_short(&o0_sig)
    );
    let _ = writeln!(
        t,
        "  O1 seq=1 prev={}  id={} sig={}",
        short(&o0_id),
        short(&o1_id),
        sig_short(&o1_sig)
    );
    let _ = writeln!(
        t,
        "  O2 seq=2 prev={}  id={} sig={}",
        short(&o1_id),
        short(&o2_id),
        sig_short(&o2_sig)
    );
    let _ = writeln!(
        t,
        "  none of O0..O2 acks any attestation (acks = {{}} throughout)"
    );

    // --- Run A: A's chain + the ordinary attestation exchange over A@1. -------
    let mut world_a = MemoryStore::new();
    for (obs, sig) in chain {
        append(&mut world_a, obs, sig).expect("A's chain links cleanly (run A)");
    }
    let (att, att_sig) = b.witness(a.pubkey(), o1_id, 1, 2500, &mut rng);
    let att_id = att.id();
    world_a
        .put_attestation(&att, &att_sig)
        .expect("store B's attestation (run A)");
    let _ = writeln!(
        t,
        "\nrun A: B witnesses A@1 -> attestation id={} (subject_head=O1, subject_seq=1)",
        short(&att_id)
    );

    // --- Run B: the identical chain, and nothing else. -----------------------
    let mut world_b = MemoryStore::new();
    for (obs, sig) in chain {
        append(&mut world_b, obs, sig).expect("A's chain links cleanly (run B)");
    }
    let _ = writeln!(
        t,
        "run B: no meeting; not one Attestation object in the store"
    );

    // --- The held chains are byte-for-byte identical. ------------------------
    let chain_a = world_a.chain(&a.pubkey()).expect("store");
    let chain_b = world_b.chain(&a.pubkey()).expect("store");
    check(
        &mut t,
        "A's held chain is identical between the runs (same objects, ids, signature bytes)",
        chain_a == chain_b,
    );
    check(
        &mut t,
        "run A holds exactly one attestation; run B holds zero",
        world_a.all_attestations().expect("store").len() == 1
            && world_b.all_attestations().expect("store").is_empty(),
    );

    // --- verify_chain is unaffected by the attestation. ---------------------
    let vc_a = verify_chain(&world_a, &a.pubkey()).expect("store");
    let vc_b = verify_chain(&world_b, &a.pubkey()).expect("store");
    check(
        &mut t,
        "verify_chain(A) == Verified in BOTH runs — chain integrity needs no attestation",
        vc_a == ChainVerification::Verified && vc_b == ChainVerification::Verified,
    );

    // --- bracket(O0) in each run, side by side. ----------------------------
    let br_a = bracket_o0(&world_a, o0_id);
    let br_b = bracket_o0(&world_b, o0_id);

    let _ = writeln!(t, "\nbracket(O0), side by side:");
    let row = |t: &mut String, field: &str, col_a: String, col_b: String| {
        let _ = writeln!(t, "  {field:<26}{col_a:<26}{col_b}");
    };
    row(
        &mut t,
        "",
        "run A (witnessed)".into(),
        "run B (no attestation)".into(),
    );
    row(
        &mut t,
        "attestations in store",
        world_a.all_attestations().expect("store").len().to_string(),
        world_b.all_attestations().expect("store").len().to_string(),
    );
    row(
        &mut t,
        "sealed",
        br_a.sealed.to_string(),
        br_b.sealed.to_string(),
    );
    row(
        &mut t,
        "upper_bound",
        br_a.upper_bound.map_or("none".into(), |h| short(&h)),
        br_b.upper_bound.map_or("none".into(), |h| short(&h)),
    );
    row(
        &mut t,
        "witness_depth",
        br_a.witness_depth.to_string(),
        br_b.witness_depth.to_string(),
    );
    row(
        &mut t,
        "window lower edge",
        window_edge(&br_a.unwitnessed_window.lower),
        window_edge(&br_b.unwitnessed_window.lower),
    );
    row(
        &mut t,
        "window upper edge",
        window_edge(&br_a.unwitnessed_window.upper),
        window_edge(&br_b.unwitnessed_window.upper),
    );

    // --- Assertions: run A seals O0, run B leaves it unwitnessed and open. --
    let _ = writeln!(t, "\nrun A — the one attestation seals O0:");
    check(&mut t, "bracket(O0).sealed is true", br_a.sealed);
    check(
        &mut t,
        "upper bound is B's attestation of A@1",
        br_a.upper_bound == Some(att_id),
    );
    check(
        &mut t,
        "witness depth is at least 1",
        br_a.witness_depth >= 1,
    );
    check(
        &mut t,
        "window upper edge is bounded (Attestation, not VerificationMoment)",
        br_a.unwitnessed_window.upper == WindowEdge::Attestation(att_id),
    );
    check(
        &mut t,
        "window lower edge is honestly open to Genesis (no lower-bound attestation)",
        br_a.unwitnessed_window.lower == WindowEdge::Genesis,
    );
    check(
        &mut t,
        "O0 is not disputed (author is not quarantined)",
        !br_a.disputed,
    );

    let _ = writeln!(
        t,
        "\nrun B — with no attestation, O0 is unwitnessed and the window is open:"
    );
    check(&mut t, "bracket(O0).sealed is false", !br_b.sealed);
    check(
        &mut t,
        "there is no upper-bound attestation",
        br_b.upper_bound.is_none(),
    );
    check(&mut t, "witness depth is 0", br_b.witness_depth == 0);
    check(
        &mut t,
        "window upper edge is VerificationMoment (spec/03 §5 step 6: unbounded, not filled in)",
        br_b.unwitnessed_window.upper == WindowEdge::VerificationMoment,
    );
    check(
        &mut t,
        "window lower edge is Genesis — the same open-below honesty as run A",
        br_b.unwitnessed_window.lower == WindowEdge::Genesis,
    );
    check(
        &mut t,
        "O0 is not disputed — an unwitnessed honest record is not an accusation",
        !br_b.disputed,
    );

    let _ = writeln!(
        t,
        "\nreading: O0/O1/O2 are honest and byte-identical in both runs. The single \
         difference between\n\"sealed, bounded above\" and \"unwitnessed, open above\" \
         is the presence of one Attestation\nobject. That object is what sealing costs; \
         it is not what detects a forgery, and run B\ncontains no forgery to detect."
    );

    let _ = writeln!(
        t,
        "\nINVARIANT {}: sealing requires an attestation; chain verification does not; and \
         the honest\noutput for the unwitnessed record is a wide open window, never a \
         detection (invariants I5, I6;\nspec/02 §5.1, §5.6; spec/03 §5 step 6)",
        if passed { "ok" } else { "VIOLATED" }
    );

    RunReport {
        text: t,
        passed,
        bracket_a: br_a,
        bracket_b: br_b,
    }
}
