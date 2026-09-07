//! The equivocation scenario: one author signs two irreconcilable entries at the
//! same `seq`, an honest witness attests only the branch that reached it, and the
//! same lying key — wearing its other hat — honestly witnesses a third node.
//!
//! This is the second `vigil-sim` scenario (`spec/02-entanglement.md` §9). Like
//! [`crate::sim::run`] it is driven by a seed and nothing else: logical time is
//! the hard-coded `tick` values below, every key and nonce comes from the seeded
//! [`SplitMix64`] stream, and there is no wall-clock read anywhere (invariant
//! I4). Running one seed twice produces a byte-identical [`RunReport`].
//!
//! ## What it demonstrates
//!
//! 1. `verify_chain` convicts the equivocating author, naming both entries.
//! 2. `detect_forks` produces exactly one `ForkProof` against that key, and is
//!    idempotent.
//! 3. `Quarantine::apply` records the conviction.
//! 4. **Ablation, using existing machinery only** — [`Dag::build`] with an empty
//!    [`Quarantine`] vs. one holding the convicted key:
//!    - the liar's *honest* attestation of a third node seals that node's record
//!      while the liar is not quarantined, and stops sealing it once it is
//!      (`spec/02` §6.5) — same stored objects, only the quarantine argument
//!      differs;
//!    - the honest witness's attestation seals the branch it saw but never the
//!      withheld sibling (the seal-edge walk in `dag.rs` follows `prev` from the
//!      anchored head, not a `seq` comparison), and stays sealing it after the
//!      liar's later conviction — an honest witness's earlier attestation is not
//!      retroactively undone (`spec/02` §6.5).

use std::collections::BTreeSet;
use std::fmt::Write as _;

use ed25519_dalek::SigningKey;
use vigil_core::{
    Attestation, Hash, Hlc, Object, Observation, ObservationBody, PubKey, Signature, SignedObject,
    SiteId, public_key,
};
use vigil_ledger::{
    ChainVerification, ChainViolation, Dag, MemoryStore, Quarantine, Store, append, detect_forks,
    verify_chain,
};

use crate::rng::SplitMix64;

const SITE: SiteId = SiteId(*b"VIGILARCH-SITE-A");

/// One simulated node: its device key and its logical clock. Unlike
/// [`crate::sim`] this scenario keeps no per-node store — every signed object is
/// gathered into one verifier store (`world` in [`run`]), which is what a third
/// party assembling an evidence pack actually holds.
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
    /// advances to `tick`. Not stored here — the caller decides which store it
    /// goes into.
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
    /// at `seq`, with a nonce drawn from the seeded stream. Time advances to
    /// `tick`.
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

/// A machine-readable transcript of one run, plus whether every assertion held.
pub struct RunReport {
    pub text: String,
    pub passed: bool,
}

/// Run the equivocation scenario at `seed` and return its transcript.
///
/// The steps are numbered in the transcript. Every assertion prints `PASS` or
/// `FAIL`; [`RunReport::passed`] is the AND of them all, and the binary exits
/// non-zero when it is false.
#[must_use]
pub fn run(seed: u64) -> RunReport {
    let mut rng = SplitMix64::new(seed);
    let a_seed = rng.bytes32();
    let b_seed = rng.bytes32();
    let c_seed = rng.bytes32();
    let mut a = Node::new("A", a_seed);
    let mut b = Node::new("B", b_seed);
    let mut c = Node::new("C", c_seed);

    let mut t = String::new();
    let mut passed = true;
    let mut check = |t: &mut String, label: &str, cond: bool| {
        passed &= cond;
        let _ = writeln!(t, "  [{}] {label}", if cond { "PASS" } else { "FAIL" });
    };

    let _ = writeln!(t, "vigil-sim equivocation scenario");
    let _ = writeln!(t, "seed: {seed}");
    let _ = writeln!(
        t,
        "node {} key: {} (equivocating author + honest witness)",
        a.name,
        a.pubkey()
    );
    let _ = writeln!(t, "node {} key: {} (honest witness)", b.name, b.pubkey());
    let _ = writeln!(t, "node {} key: {} (honest, one entry)", c.name, c.pubkey());

    // The verifier's store: one place holding every signed object a third party
    // would receive. No sync layer in v1 — the sim just places objects.
    let mut world = MemoryStore::new();

    // 1. A writes an honest genesis and an honest second entry.
    let (o0_id, o0, o0_sig) = a.note(0, None, 1000, "grid B4 shoring is out of plumb");
    append(&mut world, &o0, &o0_sig).expect("O0 is a clean genesis");
    let (o1_id, o1, o1_sig) = a.note(1, Some(o0_id), 2000, "tag-out re-checked, crew clear");
    append(&mut world, &o1, &o1_sig).expect("O1 links cleanly onto O0");
    let _ = writeln!(t, "\nstep 1: A appends O0 seq=0 id={}", short(&o0_id));
    let _ = writeln!(t, "        A appends O1 seq=1 prev=O0 id={}", short(&o1_id));

    // 2. A equivocates: a second, genuinely distinct entry at seq=1, same prev.
    let (o1p_id, o1p, o1p_sig) = a.note(
        1,
        Some(o0_id),
        2500,
        "tag-out never applied, crew still on it",
    );
    append(&mut world, &o1p, &o1p_sig)
        .expect("the guarded append does not refuse a sibling (spec/01 §6.6)");
    let _ = writeln!(
        t,
        "step 2: A equivocates -> O1' seq=1 prev=O0 id={} (distinct body, distinct id)",
        short(&o1p_id)
    );
    check(
        &mut t,
        "O1 and O1' are distinct signed objects",
        o1_id != o1p_id,
    );

    // 3. B witnesses only O1 — the branch that reached it. O1' is withheld from B.
    let (bw, bw_sig) = b.witness(a.pubkey(), o1_id, 1, 3000, &mut rng);
    let bw_id = bw.id();
    world
        .put_attestation(&bw, &bw_sig)
        .expect("store B's attestation");
    let _ = writeln!(
        t,
        "step 3: B attests A@1 -> O1 id={} (B never saw O1'; a witness cannot know a sibling exists)",
        short(&bw_id)
    );

    // 4. C writes one honest entry; A — the same key — honestly witnesses it.
    let (c0_id, c0, c0_sig) = c.note(0, None, 1500, "night shift headcount logged");
    append(&mut world, &c0, &c0_sig).expect("C0 is a clean genesis");
    let (aw, aw_sig) = a.witness(c.pubkey(), c0_id, 0, 3500, &mut rng);
    let aw_id = aw.id();
    world
        .put_attestation(&aw, &aw_sig)
        .expect("store A's attestation of C0");
    let _ = writeln!(t, "step 4: C appends C0 seq=0 id={}", short(&c0_id));
    let _ = writeln!(
        t,
        "        A witnesses C0 -> attestation id={} (A lies on its own chain, but this record is honest)",
        short(&aw_id)
    );

    // 5. verify_chain for A: a chain-order contradiction, naming A and both entries.
    let _ = writeln!(t, "\nstep 5: verify_chain(world, A)");
    let verdict = verify_chain(&world, &a.pubkey()).expect("store");
    let names_both = matches!(
        &verdict,
        ChainVerification::Violated(vs) if vs.iter().any(|v| matches!(
            v,
            ChainViolation::Equivocation { author, seq, entries }
                if *author == a.pubkey()
                    && *seq == 1
                    && entries.contains(&o1_id)
                    && entries.contains(&o1p_id)
        ))
    );
    let _ = writeln!(t, "        verdict: {verdict:?}");
    check(
        &mut t,
        "reports Violated",
        matches!(verdict, ChainVerification::Violated(_)),
    );
    check(&mut t, "names A and both O1, O1' at seq=1", names_both);

    // 6. detect_forks: exactly one proof, convicting A, and idempotent.
    let _ = writeln!(t, "\nstep 6: detect_forks(world), called twice");
    let forks_1 = detect_forks(&world).expect("store");
    let forks_2 = detect_forks(&world).expect("store");
    check(
        &mut t,
        "run is idempotent (identical proof lists)",
        forks_1 == forks_2,
    );
    check(&mut t, "exactly one ForkProof", forks_1.len() == 1);
    let checked = forks_1
        .first()
        .expect("one proof")
        .check()
        .expect("the proof is self-verifying");
    let _ = writeln!(t, "        proof convicts key: {}", checked.key);
    check(&mut t, "the proof convicts A", checked.key == a.pubkey());

    // 7. Quarantine: apply the proof, A is now quarantined.
    let mut quarantine = Quarantine::new();
    let newly = quarantine.apply(&checked);
    let _ = writeln!(t, "\nstep 7: Quarantine::apply(proof)");
    check(&mut t, "A was newly quarantined", newly);
    check(
        &mut t,
        "quarantine now contains A",
        quarantine.contains(&a.pubkey()),
    );

    // 8. Ablation A — empty quarantine. The DAG is unchanged from the ordinary path.
    let _ = writeln!(
        t,
        "\nstep 8: Dag::build(world, &Quarantine::new())  [empty quarantine]"
    );
    let open = Dag::build(&world, &Quarantine::new()).expect("store");

    let br_c0 = open.bracket(c0_id).expect("C0 is a vertex");
    check(
        &mut t,
        "C0 is sealed by A's honest attestation",
        br_c0.sealed,
    );
    check(
        &mut t,
        "C0's upper bound is A's attestation of C0",
        br_c0.upper_bound == Some(aw_id),
    );

    let br_o1 = open.bracket(o1_id).expect("O1 is a vertex");
    let br_o1p = open.bracket(o1p_id).expect("O1' is a vertex");
    check(
        &mut t,
        "O1 (the branch B saw) is sealed by B",
        br_o1.sealed && br_o1.upper_bound == Some(bw_id),
    );
    check(
        &mut t,
        "O1' (the withheld sibling) is NOT sealed, despite sharing A's chain and seq with sealed O1",
        !br_o1p.sealed,
    );

    // 9. Ablation B — same held objects, A quarantined. Only the argument differs.
    let _ = writeln!(
        t,
        "\nstep 9: Dag::build(world, &quarantine)  [A quarantined; identical held objects]"
    );
    let held = Dag::build(&world, &quarantine).expect("store");

    let br_c0_q = held.bracket(c0_id).expect("C0 is a vertex");
    check(
        &mut t,
        "C0 is NO LONGER sealed — A's attestations stop counting once A is convicted (spec/02 §6.5)",
        !br_c0_q.sealed,
    );

    let br_o1_q = held.bracket(o1_id).expect("O1 is a vertex");
    check(
        &mut t,
        "O1 stays sealed by B — a liar's later conviction does not unseal what an honest witness attested (spec/02 §6.5)",
        br_o1_q.sealed && br_o1_q.upper_bound == Some(bw_id),
    );

    let _ = writeln!(
        t,
        "\nINVARIANT {}: equivocation is convicted, the sibling is never sealed, and quarantine \
         changes only what a convicted key's attestations buy going forward (spec/02 §6.5)",
        if passed { "ok" } else { "VIOLATED" }
    );

    RunReport { text: t, passed }
}
