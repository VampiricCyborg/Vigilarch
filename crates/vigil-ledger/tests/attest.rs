//! Attestation ingest (`spec/02-entanglement.md` §3.3): the signature gate and
//! the `(witness, nonce)` deduplication / conflict rule.

use ed25519_dalek::SigningKey;
use vigil_core::{Attestation, Hash, Hlc, Object, PubKey, Signature, SignedObject, public_key};
use vigil_ledger::{IngestError, IngestOutcome, MemoryStore, Store, ingest_attestation};

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn attestation(witness: &SigningKey, subject: PubKey, nonce: u8) -> (Attestation, Signature) {
    let a = Attestation {
        witness: public_key(witness),
        subject,
        subject_head: Hash([7; 32]),
        subject_seq: 3,
        witness_hlc: Hlc::new(1_700_000_000_000, 0),
        nonce: [nonce; 16],
    };
    let s = a.sign(witness);
    (a, s)
}

#[test]
fn a_valid_attestation_is_stored_once_then_idempotent() {
    let (w, subj) = (sk(1), public_key(&sk(2)));
    let mut s = MemoryStore::new();
    let (att, sig) = attestation(&w, subj, 0xAA);

    match ingest_attestation(&mut s, &att, &sig).unwrap() {
        IngestOutcome::Stored(id) => assert_eq!(id, att.id()),
        other => panic!("expected Stored, got {other:?}"),
    }
    assert!(matches!(
        ingest_attestation(&mut s, &att, &sig).unwrap(),
        IngestOutcome::AlreadyHeld(_)
    ));
    assert_eq!(s.all_attestations().unwrap().len(), 1);
}

#[test]
fn a_bad_signature_is_rejected_and_stores_nothing() {
    let (w, imposter, subj) = (sk(1), sk(9), public_key(&sk(2)));
    let mut s = MemoryStore::new();
    let (att, _) = attestation(&w, subj, 0xAA);
    let forged = att.sign(&imposter);

    assert!(matches!(
        ingest_attestation(&mut s, &att, &forged),
        Err(IngestError::BadSignature)
    ));
    assert!(s.all_attestations().unwrap().is_empty());
}

#[test]
fn the_same_nonce_over_different_content_is_a_retained_conflict() {
    // spec/02 §3.3 — one witness, one nonce, two different heads. Both kept;
    // the pair is attributable evidence against the witness.
    let (w, subj) = (sk(1), public_key(&sk(2)));
    let mut s = MemoryStore::new();

    let (att1, sig1) = attestation(&w, subj, 0xBB);
    let mut att2 = att1;
    att2.subject_head = Hash([9; 32]); // same (witness, nonce), different content
    let sig2 = att2.sign(&w);

    let first = ingest_attestation(&mut s, &att1, &sig1).unwrap();
    assert!(matches!(first, IngestOutcome::Stored(_)));

    match ingest_attestation(&mut s, &att2, &sig2).unwrap() {
        IngestOutcome::WitnessConflict {
            witness,
            nonce,
            held,
            incoming,
        } => {
            assert_eq!(witness, public_key(&w));
            assert_eq!(nonce, [0xBB; 16]);
            assert_eq!(held, att1.id());
            assert_eq!(incoming, att2.id());
        }
        other => panic!("expected WitnessConflict, got {other:?}"),
    }
    assert_eq!(
        s.all_attestations().unwrap().len(),
        2,
        "both sides of the conflict are retained"
    );
}
