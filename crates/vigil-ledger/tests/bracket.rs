//! Bracketing queries (`spec/02-entanglement.md` §5): sealed vs unwitnessed,
//! witness depth, the unwitnessed window, monotonicity under ingest, and
//! determinism.

use ed25519_dalek::SigningKey;
use vigil_core::{
    Attestation, Hash, Hlc, Object, Observation, ObservationBody, PubKey, Seq, SignedObject,
    Signature, SiteId, public_key,
};
use vigil_ledger::{Dag, MemoryStore, Quarantine, Store, WindowEdge, append, bracket};

const SITE: SiteId = SiteId(*b"VIGILARCH-SITE-A");

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn pk(s: &SigningKey) -> PubKey {
    public_key(s)
}

fn note(
    author: &SigningKey,
    seq: Seq,
    prev: Option<Hash>,
    acks: impl IntoIterator<Item = Hash>,
    text: &str,
) -> (Observation, Signature) {
    let o = Observation {
        author: pk(author),
        site: SITE,
        prev,
        seq,
        hlc: Hlc::new(1_700_000_000_000 + seq, 0),
        body: ObservationBody::Note { text: text.into() },
        geo: None,
        acks: acks.into_iter().collect(),
    };
    let s = o.sign(author);
    (o, s)
}

fn attest(
    witness: &SigningKey,
    subject: PubKey,
    head: Hash,
    seq: Seq,
    nonce: u8,
) -> (Attestation, Signature) {
    let a = Attestation {
        witness: pk(witness),
        subject,
        subject_head: head,
        subject_seq: seq,
        witness_hlc: Hlc::new(1_700_000_000_000, 0),
        nonce: [nonce; 16],
    };
    let s = a.sign(witness);
    (a, s)
}

#[test]
fn a_genesis_isolated_node_is_unwitnessed_with_a_window_open_both_sides() {
    // spec/02 §8.2 — no contact since genesis. The honest output is a wide
    // unwitnessed window, NOT a detection and NOT an alarm.
    let a = sk(1);
    let mut s = MemoryStore::new();
    let mut prev = None;
    let mut ids = Vec::new();
    for seq in 0..3 {
        let (o, sig) = note(&a, seq, prev, [], &format!("entry {seq}"));
        let id = append(&mut s, &o, &sig).unwrap();
        prev = Some(id);
        ids.push(id);
    }

    for id in ids {
        let b = bracket(&s, id).unwrap().expect("a held observation brackets");
        assert!(!b.sealed, "nothing witnessed this node");
        assert_eq!(b.upper_bound, None);
        assert_eq!(b.lower_bound, None);
        assert_eq!(b.witness_depth, 0);
        assert!(!b.disputed, "isolation is not a dispute");
        assert_eq!(b.unwitnessed_window.lower, WindowEdge::Genesis);
        assert_eq!(b.unwitnessed_window.upper, WindowEdge::VerificationMoment);
    }
}

#[test]
fn a_single_exchange_seals_the_witnessed_entry() {
    let (a, w) = (sk(1), sk(2));
    let mut s = MemoryStore::new();
    let (o0, s0) = note(&a, 0, None, [], "genesis");
    let id0 = append(&mut s, &o0, &s0).unwrap();
    let (u, us) = attest(&w, pk(&a), id0, 0, 0x10);
    let u_id = s.put_attestation(&u, &us).unwrap();

    let b = bracket(&s, id0).unwrap().unwrap();
    assert!(b.sealed);
    assert_eq!(b.upper_bound, Some(u_id));
    assert_eq!(b.witness_depth, 1);
    assert_eq!(b.lower_bound, None, "nothing precedes a genesis entry");
    assert_eq!(b.unwitnessed_window.lower, WindowEdge::Genesis);
    assert_eq!(b.unwitnessed_window.upper, WindowEdge::Attestation(u_id));
}

#[test]
fn two_distinct_witness_keys_give_depth_two() {
    let (a, w1, w2) = (sk(1), sk(2), sk(3));
    let mut s = MemoryStore::new();
    let (o0, s0) = note(&a, 0, None, [], "genesis");
    let id0 = append(&mut s, &o0, &s0).unwrap();
    for (w, nonce) in [(&w1, 0x10u8), (&w2, 0x11)] {
        let (u, us) = attest(w, pk(&a), id0, 0, nonce);
        s.put_attestation(&u, &us).unwrap();
    }

    let b = bracket(&s, id0).unwrap().unwrap();
    assert_eq!(b.witness_depth, 2);
    assert!(b.sealed);
}

#[test]
fn a_prior_ack_is_the_lower_bound_and_a_later_meeting_the_upper() {
    // o0; W witnesses A@0 (U); A's o1 acks U; W witnesses A@1 (U2).
    let (a, w) = (sk(1), sk(2));
    let mut s = MemoryStore::new();
    let (o0, s0) = note(&a, 0, None, [], "genesis");
    let id0 = append(&mut s, &o0, &s0).unwrap();
    let (u, us) = attest(&w, pk(&a), id0, 0, 0x10);
    let u_id = s.put_attestation(&u, &us).unwrap();
    let (o1, s1) = note(&a, 1, Some(id0), [u_id], "acks the first meeting");
    let id1 = append(&mut s, &o1, &s1).unwrap();
    let (u2, u2s) = attest(&w, pk(&a), id1, 1, 0x11);
    let u2_id = s.put_attestation(&u2, &u2s).unwrap();

    let b = bracket(&s, id1).unwrap().unwrap();
    assert_eq!(b.lower_bound, Some(u_id), "the acked meeting precedes o1");
    assert_eq!(b.upper_bound, Some(u2_id), "the later meeting seals o1");
    assert_eq!(b.unwitnessed_window.lower, WindowEdge::Attestation(u_id));
    assert_eq!(b.unwitnessed_window.upper, WindowEdge::Attestation(u2_id));
}

#[test]
fn bracket_of_a_non_vertex_is_none() {
    let s = MemoryStore::new();
    assert_eq!(bracket(&s, Hash([0; 32])).unwrap(), None);
}

#[test]
fn bracket_is_identical_across_ingest_orders() {
    // spec/02 §5.6 / §4.7 — same held set, byte-identical Bracket.
    let build = |order: &[u8]| {
        let (a, w1, w2) = (sk(1), sk(2), sk(3));
        let (o0, s0) = note(&a, 0, None, [], "g");
        let o0_id = o0.id();
        let (u1, u1s) = attest(&w1, pk(&a), o0_id, 0, 0x10);
        let (u2, u2s) = attest(&w2, pk(&a), o0_id, 0, 0x11);
        let mut s = MemoryStore::new();
        for &step in order {
            match step {
                0 => {
                    s.put_observation(&o0, &s0).unwrap();
                }
                1 => {
                    s.put_attestation(&u1, &u1s).unwrap();
                }
                _ => {
                    s.put_attestation(&u2, &u2s).unwrap();
                }
            }
        }
        format!("{:?}", bracket(&s, o0_id).unwrap().unwrap())
    };
    let forward = build(&[0, 1, 2]);
    assert_eq!(build(&[2, 1, 0]), forward);
    assert_eq!(build(&[1, 2, 0, 1, 0, 2]), forward);
}

#[cfg(not(target_family = "wasm"))]
mod property {
    use super::*;
    use proptest::prelude::*;

    /// A held set: A's chain of `chain_len` entries, plus attestations of A's
    /// head at various seqs by up to three witnesses.
    fn scenario(chain_len: u64, atts: &[(u8, u64)]) -> (MemoryStore, Vec<Hash>) {
        let a = sk(1);
        let mut s = MemoryStore::new();
        let mut prev = None;
        let mut ids = Vec::new();
        for seq in 0..chain_len {
            let (o, sig) = note(&a, seq, prev, [], "e");
            let id = append(&mut s, &o, &sig).unwrap();
            prev = Some(id);
            ids.push(id);
        }
        for (i, &(wseed, at)) in atts.iter().enumerate() {
            let at = at.min(chain_len - 1);
            let w = sk(10 + (wseed % 3));
            let (u, us) = attest(&w, pk(&a), ids[at as usize], at, 0x40 + i as u8);
            s.put_attestation(&u, &us).unwrap();
        }
        (s, ids)
    }

    proptest! {
        /// §5.5 — adding a valid attestation never widens a bracket: a bounded
        /// window edge never reopens, `sealed` never flips true→false, and
        /// witness depth never drops.
        #[test]
        fn adding_an_attestation_never_widens_a_bracket(
            chain_len in 1u64..6,
            base in prop::collection::vec((any::<u8>(), 0u64..6), 0..5),
            extra in (any::<u8>(), 0u64..6),
        ) {
            let (mut s, ids) = scenario(chain_len, &base);
            let target = ids[0];
            let before = Dag::build(&s, &Quarantine::new()).unwrap().bracket(target).unwrap();

            let at = extra.1.min(chain_len - 1);
            let w = sk(10 + (extra.0 % 3));
            let (u, us) = attest(&w, pk(&sk(1)), ids[at as usize], at, 0xF0);
            s.put_attestation(&u, &us).unwrap();
            let after = Dag::build(&s, &Quarantine::new()).unwrap().bracket(target).unwrap();

            prop_assert!(after.sealed || !before.sealed, "sealed must not flip true→false");
            prop_assert!(after.witness_depth >= before.witness_depth, "depth must not drop");
            if matches!(before.unwitnessed_window.lower, WindowEdge::Attestation(_)) {
                prop_assert!(
                    matches!(after.unwitnessed_window.lower, WindowEdge::Attestation(_)),
                    "a bounded lower edge must not reopen to genesis"
                );
            }
            if matches!(before.unwitnessed_window.upper, WindowEdge::Attestation(_)) {
                prop_assert!(
                    matches!(after.unwitnessed_window.upper, WindowEdge::Attestation(_)),
                    "a bounded upper edge must not reopen to the verification moment"
                );
            }
        }
    }
}
