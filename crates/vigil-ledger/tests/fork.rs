//! Fork detection, `ForkProof` construction, and quarantine
//! (`spec/02-entanglement.md` §6).

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use vigil_core::{
    Attestation, Collision, Hash, Hlc, Object, Observation, ObservationBody, PubKey, Seq,
    Signature, SignedObject, SiteId, public_key,
};
use vigil_ledger::{Dag, MemoryStore, Quarantine, Store, append, detect_forks};

const SITE: SiteId = SiteId(*b"VIGILARCH-SITE-A");

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn pk(s: &SigningKey) -> PubKey {
    public_key(s)
}

fn note(author: &SigningKey, seq: Seq, prev: Option<Hash>, text: &str) -> (Observation, Signature) {
    let o = Observation {
        author: pk(author),
        site: SITE,
        prev,
        seq,
        hlc: Hlc::new(1_700_000_000_000 + seq, 0),
        body: ObservationBody::Note { text: text.into() },
        geo: None,
        acks: BTreeSet::new(),
    };
    let s = o.sign(author);
    (o, s)
}

fn attest(
    w: &SigningKey,
    subject: PubKey,
    head: Hash,
    seq: Seq,
    nonce: u8,
) -> (Attestation, Signature) {
    let a = Attestation {
        witness: pk(w),
        subject,
        subject_head: head,
        subject_seq: seq,
        witness_hlc: Hlc::new(1_700_000_000_000, 0),
        nonce: [nonce; 16],
    };
    let s = a.sign(w);
    (a, s)
}

#[test]
fn equivocation_at_one_seq_yields_one_self_verifying_proof() {
    let a = sk(1);
    let mut s = MemoryStore::new();
    let (honest, hs) = note(&a, 0, None, "walkway clear");
    let (forged, fs) = note(&a, 0, None, "walkway barricaded Saturday");
    s.put_observation(&honest, &hs).unwrap();
    s.put_observation(&forged, &fs).unwrap();

    let proofs = detect_forks(&s).unwrap();
    assert_eq!(proofs.len(), 1, "one collision, one proof");
    let checked = proofs[0].check().expect("the proof self-verifies");
    assert_eq!(checked.key, pk(&a), "the proof names the equivocating key");
    assert_eq!(checked.collision, Collision::SameSeq(0));
}

#[test]
fn two_entries_sharing_a_prev_are_a_fork() {
    let a = sk(1);
    let mut s = MemoryStore::new();
    let (o0, s0) = note(&a, 0, None, "genesis");
    let id0 = append(&mut s, &o0, &s0).unwrap();
    // Two different entries both linking back to o0.
    let (o1, s1) = note(&a, 1, Some(id0), "took the east stair");
    let (o1b, s1b) = note(&a, 1, Some(id0), "took the west stair");
    s.put_observation(&o1, &s1).unwrap();
    s.put_observation(&o1b, &s1b).unwrap();

    let proofs = detect_forks(&s).unwrap();
    assert_eq!(proofs.len(), 1);
    let checked = proofs[0].check().unwrap();
    // Same seq AND same prev — either collision kind is a correct description;
    // detect_forks buckets by seq first.
    assert!(matches!(
        checked.collision,
        Collision::SameSeq(1) | Collision::SamePrev(Some(_))
    ));
}

#[test]
fn a_clean_multi_author_store_has_no_forks() {
    let mut s = MemoryStore::new();
    for seed in [1u8, 2, 3] {
        let a = sk(seed);
        let mut prev = None;
        for seq in 0..4 {
            let (o, sig) = note(&a, seq, prev, "e");
            prev = Some(append(&mut s, &o, &sig).unwrap());
        }
    }
    assert!(detect_forks(&s).unwrap().is_empty());
}

#[test]
fn detect_forks_ignores_a_collision_that_is_not_validly_signed() {
    let (a, imposter) = (sk(1), sk(9));
    let mut s = MemoryStore::new();
    let (honest, hs) = note(&a, 0, None, "real");
    s.put_observation(&honest, &hs).unwrap();
    // A second seq-0 entry by A, but signed by the wrong key.
    let (garbage, _) = note(&a, 0, None, "planted");
    let bad_sig = garbage.sign(&imposter);
    s.put_observation(&garbage, &bad_sig).unwrap();

    assert!(
        detect_forks(&s).unwrap().is_empty(),
        "a garbage collision is not attributable"
    );
}

#[test]
fn quarantine_disputes_unwitnessed_records_but_keeps_sealed_ones_valid() {
    // A is witnessed by honest W at seq 0, then equivocates at seq 1.
    let (a, w) = (sk(1), sk(2));
    let mut s = MemoryStore::new();
    let (o0, s0) = note(&a, 0, None, "genesis");
    let id0 = append(&mut s, &o0, &s0).unwrap();
    let (u, us) = attest(&w, pk(&a), id0, 0, 0x10);
    s.put_attestation(&u, &us).unwrap();

    let (o1, s1) = note(&a, 1, Some(id0), "east");
    let (o1b, s1b) = note(&a, 1, Some(id0), "west");
    s.put_observation(&o1, &s1).unwrap();
    s.put_observation(&o1b, &s1b).unwrap();

    let proofs = detect_forks(&s).unwrap();
    assert_eq!(proofs.len(), 1);
    let mut q = Quarantine::new();
    assert!(q.apply(&proofs[0].check().unwrap()));

    let dag = Dag::build(&s, &q).unwrap();
    let b0 = dag.bracket(id0).unwrap();
    assert!(
        b0.sealed,
        "o0 was sealed by an honest witness before the fork"
    );
    assert!(!b0.disputed, "a pre-fork sealed record stays valid (§6.4)");

    let b1 = dag.bracket(o1.id()).unwrap();
    assert!(!b1.sealed);
    assert!(
        b1.disputed,
        "the quarantined key's unwitnessed record is disputed"
    );
}

#[test]
fn an_attestation_by_a_quarantined_witness_no_longer_seals() {
    // W witnesses A, then W itself is quarantined for equivocating.
    let (a, w) = (sk(1), sk(2));
    let mut s = MemoryStore::new();
    let (a0, as0) = note(&a, 0, None, "a genesis");
    let a_id0 = append(&mut s, &a0, &as0).unwrap();
    let (u, us) = attest(&w, pk(&a), a_id0, 0, 0x10);
    s.put_attestation(&u, &us).unwrap();

    // W equivocates on its own chain.
    let (w0, ws0) = note(&w, 0, None, "w genesis");
    let (w0b, ws0b) = note(&w, 0, None, "w other genesis");
    s.put_observation(&w0, &ws0).unwrap();
    s.put_observation(&w0b, &ws0b).unwrap();

    let proofs = detect_forks(&s).unwrap();
    let mut q = Quarantine::new();
    for p in &proofs {
        q.apply(&p.check().unwrap());
    }
    assert!(q.contains(&pk(&w)));

    let sealed_without = Dag::build(&s, &Quarantine::new())
        .unwrap()
        .bracket(a_id0)
        .unwrap()
        .sealed;
    let sealed_with = Dag::build(&s, &q).unwrap().bracket(a_id0).unwrap().sealed;
    assert!(sealed_without, "A's record seals while W is trusted");
    assert!(
        !sealed_with,
        "a quarantined witness's attestation no longer seals (§6.5)"
    );
}
