//! The [`Store`] contract, exercised against [`MemoryStore`].
//!
//! The store is persistence, not policy, so these tests use synthetic keys and
//! signatures — the store never inspects them. What is under test is the
//! storage behaviour: content-addressed idempotent writes, chains that keep
//! their gaps, equivocation retained rather than dropped, and listings that do
//! not leak insertion order.
//!
//! When the `sqlite` backend lands these become a suite parametrised over
//! `S: Store`; nothing here depends on the backend being in-memory.

use vigil_core::{
    Attestation, Hash, Hlc, Object, Observation, ObservationBody, PubKey, Seq, Signature, SiteId,
};
use vigil_ledger::{MemoryStore, Store};

const SITE: SiteId = SiteId(*b"VIGILARCH-SITE-A");

fn author(n: u8) -> PubKey {
    PubKey([n; 32])
}

fn sig(n: u8) -> Signature {
    Signature([n; 64])
}

fn note(author_key: PubKey, seq: Seq, text: &str) -> Observation {
    Observation {
        author: author_key,
        site: SITE,
        prev: None,
        seq,
        hlc: Hlc::new(1_700_000_000_000 + seq, 0),
        body: ObservationBody::Note {
            text: text.to_owned(),
        },
        geo: None,
    }
}

fn attestation(witness: PubKey, subject: PubKey, seq: Seq) -> Attestation {
    Attestation {
        witness,
        subject,
        subject_head: Hash([7; 32]),
        subject_seq: seq,
        witness_hlc: Hlc::new(1_700_000_000_000, 0),
        nonce: [0xAB; 16],
    }
}

#[test]
fn put_recomputes_the_id_and_get_round_trips() {
    let mut s = MemoryStore::new();
    let o = note(author(1), 0, "shoring on grid B4 is out of plumb");
    let id = s.put_observation(&o, &sig(9)).unwrap();
    assert_eq!(id, o.id(), "the store addresses the object by its own hash");

    let got = s.observation(&id).unwrap().expect("just stored");
    assert_eq!(got.id, id);
    assert_eq!(got.observation, o);
    assert_eq!(got.signature, sig(9));
}

#[test]
fn an_unknown_id_is_none_not_an_error() {
    let s = MemoryStore::new();
    assert_eq!(s.observation(&Hash([0; 32])).unwrap(), None);
    assert_eq!(s.attestation(&Hash([0; 32])).unwrap(), None);
    assert!(s.chain(&author(1)).unwrap().is_empty());
    assert_eq!(s.chain_head(&author(1)).unwrap(), None);
}

#[test]
fn put_is_idempotent_and_the_first_signature_wins() {
    let mut s = MemoryStore::new();
    let o = note(author(1), 0, "x");
    let first = s.put_observation(&o, &sig(1)).unwrap();
    let again = s.put_observation(&o, &sig(2)).unwrap(); // same object, other signature

    assert_eq!(first, again);
    assert_eq!(s.chain(&author(1)).unwrap().len(), 1, "not stored twice");
    assert_eq!(
        s.observation(&first).unwrap().unwrap().signature,
        sig(1),
        "the store does not adjudicate between two signatures over one id"
    );
}

#[test]
fn a_chain_keeps_its_gaps() {
    // A missing seq is the normal state under partition (§6.6 "Incomplete"),
    // not something the store repairs or rejects.
    let mut s = MemoryStore::new();
    let a = author(1);
    s.put_observation(&note(a, 0, "zero"), &sig(0)).unwrap();
    s.put_observation(&note(a, 2, "two"), &sig(0)).unwrap();

    let seqs: Vec<Seq> = s
        .chain(&a)
        .unwrap()
        .iter()
        .map(|o| o.observation.seq)
        .collect();
    assert_eq!(seqs, [0, 2]);
    assert!(s.observations_at(&a, 1).unwrap().is_empty());
}

#[test]
fn equivocation_is_retained_not_rejected() {
    // §6.6: two signed observations by one author at one seq is the most
    // valuable object the system can hold. The store keeps both; deciding what
    // to do about it is fork detection's job, above the store.
    let mut s = MemoryStore::new();
    let a = author(1);
    let honest = note(a, 4, "walkway clear");
    let forged = note(a, 4, "walkway barricaded Saturday");
    let honest_id = s.put_observation(&honest, &sig(1)).unwrap();
    let forged_id = s.put_observation(&forged, &sig(1)).unwrap();
    assert_ne!(honest_id, forged_id);

    let at_four = s.observations_at(&a, 4).unwrap();
    assert_eq!(at_four.len(), 2);
    let ids: Vec<Hash> = at_four.iter().map(|o| o.id).collect();
    assert!(ids.contains(&honest_id) && ids.contains(&forged_id));
    assert_eq!(
        s.chain(&a).unwrap().len(),
        2,
        "chain() surfaces the fork too"
    );
}

#[test]
fn chain_head_tracks_the_highest_seq_seen() {
    let mut s = MemoryStore::new();
    let a = author(1);
    assert_eq!(s.chain_head(&a).unwrap(), None);

    for seq in [0u64, 7, 3] {
        s.put_observation(&note(a, seq, "x"), &sig(0)).unwrap();
    }
    assert_eq!(s.chain_head(&a).unwrap().unwrap().seq, 7);
}

#[test]
fn authors_are_listed_in_key_order() {
    let mut s = MemoryStore::new();
    for n in [3u8, 1, 2] {
        s.put_observation(&note(author(n), 0, "x"), &sig(0))
            .unwrap();
    }
    assert_eq!(s.authors().unwrap(), [author(1), author(2), author(3)]);
}

#[test]
fn attestations_are_indexed_by_subject_and_by_witness() {
    let mut s = MemoryStore::new();
    let w = author(10);
    let subject = author(20);
    let att = attestation(w, subject, 3);

    let id = s.put_attestation(&att, &sig(5)).unwrap();
    assert_eq!(id, att.id());
    assert_eq!(s.attestation(&id).unwrap().unwrap().attestation, att);

    assert_eq!(s.attestations_for_subject(&subject).unwrap().len(), 1);
    assert_eq!(s.attestations_by_witness(&w).unwrap().len(), 1);
    assert!(s.attestations_for_subject(&w).unwrap().is_empty());
    assert!(s.attestations_by_witness(&subject).unwrap().is_empty());
    assert_eq!(s.all_attestations().unwrap().len(), 1);
}

#[test]
fn put_attestation_is_idempotent() {
    let mut s = MemoryStore::new();
    let att = attestation(author(1), author(2), 0);
    s.put_attestation(&att, &sig(1)).unwrap();
    s.put_attestation(&att, &sig(1)).unwrap();
    assert_eq!(s.all_attestations().unwrap().len(), 1);
    assert_eq!(s.attestations_for_subject(&author(2)).unwrap().len(), 1);
}

#[test]
fn listings_never_leak_insertion_order() {
    // vigil-sim requires byte-identical runs from a seed. Build the same
    // content two ways; every listing must match.
    let build = |order: &[u8]| {
        let mut s = MemoryStore::new();
        for &n in order {
            for seq in 0..3u64 {
                s.put_observation(&note(author(n), seq, "x"), &sig(n))
                    .unwrap();
            }
            s.put_attestation(
                &attestation(author(n), author(n.wrapping_add(128)), 0),
                &sig(n),
            )
            .unwrap();
        }
        s
    };
    let forward = build(&[1, 2, 3]);
    let shuffled = build(&[3, 1, 2]);

    let obs_ids = |s: &MemoryStore| -> Vec<Hash> {
        s.authors()
            .unwrap()
            .iter()
            .flat_map(|a| s.chain(a).unwrap())
            .map(|o| o.id)
            .collect()
    };
    let att_ids = |s: &MemoryStore| -> Vec<Hash> {
        s.all_attestations().unwrap().iter().map(|a| a.id).collect()
    };

    assert_eq!(obs_ids(&forward), obs_ids(&shuffled));
    assert_eq!(att_ids(&forward), att_ids(&shuffled));
}
