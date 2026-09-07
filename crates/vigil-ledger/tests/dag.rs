//! The attestation DAG (`spec/02-entanglement.md` §4): the three edge types, the
//! validity gate on signatures, and the determinism obligation (§4.7).

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use vigil_core::{
    Attestation, Hash, Hlc, Object, Observation, ObservationBody, PubKey, Seq, Signature,
    SignedObject, SiteId, public_key,
};
use vigil_ledger::{Dag, DagNode, MemoryStore, Quarantine, Store, append};

const SITE: SiteId = SiteId(*b"VIGILARCH-SITE-A");

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pk(sk: &SigningKey) -> PubKey {
    public_key(sk)
}

/// A signed note by `author`. `acks` is a set so the caller need not sort.
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
    subject_head: Hash,
    subject_seq: Seq,
    nonce: u8,
) -> (Attestation, Signature) {
    let a = Attestation {
        witness: pk(witness),
        subject,
        subject_head,
        subject_seq,
        witness_hlc: Hlc::new(1_700_000_000_000, 0),
        nonce: [nonce; 16],
    };
    let s = a.sign(witness);
    (a, s)
}

fn dag(store: &MemoryStore) -> Dag {
    Dag::build(store, &Quarantine::new()).expect("in-memory build never fails")
}

// ---------------------------------------------------------------------------
// Edge types
// ---------------------------------------------------------------------------

#[test]
fn chain_edge_links_consecutive_entries() {
    let mut s = MemoryStore::new();
    let a = sk(1);
    let (o0, s0) = note(&a, 0, None, [], "genesis");
    let id0 = append(&mut s, &o0, &s0).unwrap();
    let (o1, s1) = note(&a, 1, Some(id0), [], "second");
    let id1 = append(&mut s, &o1, &s1).unwrap();

    let d = dag(&s);
    assert!(d.reaches(DagNode::Obs(id0), DagNode::Obs(id1)), "0 ⟶ 1");
    assert!(
        !d.reaches(DagNode::Obs(id1), DagNode::Obs(id0)),
        "not 1 ⟶ 0"
    );
}

#[test]
fn seal_edge_from_subject_entry_to_a_distinct_witness_attestation() {
    // W witnesses A's genesis head. A's genesis observation seals it.
    let (a, w) = (sk(1), sk(2));
    let mut s = MemoryStore::new();
    let (o0, s0) = note(&a, 0, None, [], "genesis");
    let id0 = append(&mut s, &o0, &s0).unwrap();
    let (att, atts) = attest(&w, pk(&a), id0, 0, 0x10);
    let att_id = s.put_attestation(&att, &atts).unwrap();

    let d = dag(&s);
    assert!(d.reaches(DagNode::Obs(id0), DagNode::Att(att_id)), "o0 ⟶ U");
    assert_eq!(
        d.attestation(&att_id),
        Some(&att),
        "the attestation is a vertex"
    );
}

#[test]
fn ack_edge_from_attestation_to_the_entry_that_commits_to_it() {
    // W witnesses A@0; A's next entry acks that attestation.
    let (a, w) = (sk(1), sk(2));
    let mut s = MemoryStore::new();
    let (o0, s0) = note(&a, 0, None, [], "genesis");
    let id0 = append(&mut s, &o0, &s0).unwrap();
    let (att, atts) = attest(&w, pk(&a), id0, 0, 0x10);
    let att_id = s.put_attestation(&att, &atts).unwrap();
    let (o1, s1) = note(&a, 1, Some(id0), [att_id], "acks the meeting");
    let id1 = append(&mut s, &o1, &s1).unwrap();

    let d = dag(&s);
    assert!(d.reaches(DagNode::Att(att_id), DagNode::Obs(id1)), "U ⟶ o1");
    assert!(
        d.ack_findings().is_empty(),
        "the ack is lawful — no finding"
    );
}

#[test]
fn the_partial_order_is_transitively_closed() {
    // o0 --seal--> U --ack--> o1, and independently o0 --chain--> o1.
    // Reachability must include the two-hop seal/ack path regardless.
    let (a, w) = (sk(1), sk(2));
    let mut s = MemoryStore::new();
    let (o0, s0) = note(&a, 0, None, [], "genesis");
    let id0 = append(&mut s, &o0, &s0).unwrap();
    let (att, atts) = attest(&w, pk(&a), id0, 0, 0x10);
    let att_id = s.put_attestation(&att, &atts).unwrap();
    let (o1, s1) = note(&a, 1, Some(id0), [att_id], "acks");
    let id1 = append(&mut s, &o1, &s1).unwrap();
    let (o2, s2) = note(&a, 2, Some(id1), [], "third");
    let id2 = append(&mut s, &o2, &s2).unwrap();

    let d = dag(&s);
    assert!(d.reaches(DagNode::Obs(id0), DagNode::Att(att_id)));
    assert!(
        d.reaches(DagNode::Att(att_id), DagNode::Obs(id2)),
        "U ⟶ o1 ⟶ o2"
    );
    assert!(
        d.reaches(DagNode::Obs(id0), DagNode::Obs(id2)),
        "closure: o0 ⟶ o2"
    );
}

#[test]
fn an_unanchored_attestation_seals_nothing() {
    // §4.5 — the attestation's subject_head names an entry the verifier does not
    // hold (here: a head that does not match A's genesis id).
    let (a, w) = (sk(1), sk(2));
    let mut s = MemoryStore::new();
    let (o0, s0) = note(&a, 0, None, [], "genesis");
    let id0 = append(&mut s, &o0, &s0).unwrap();
    let (att, atts) = attest(&w, pk(&a), Hash([0xFE; 32]), 0, 0x10);
    let att_id = s.put_attestation(&att, &atts).unwrap();

    let d = dag(&s);
    assert!(
        d.attestation(&att_id).is_some(),
        "still a vertex (retained)"
    );
    assert!(
        !d.reaches(DagNode::Obs(id0), DagNode::Att(att_id)),
        "no seal edge from an unanchored attestation"
    );
}

#[test]
fn a_self_attestation_seals_nothing() {
    // §4.4 — a node attesting its own head proves nothing.
    let a = sk(1);
    let mut s = MemoryStore::new();
    let (o0, s0) = note(&a, 0, None, [], "genesis");
    let id0 = append(&mut s, &o0, &s0).unwrap();
    let (att, atts) = attest(&a, pk(&a), id0, 0, 0x10);
    let att_id = s.put_attestation(&att, &atts).unwrap();

    let d = dag(&s);
    assert!(
        d.attestation(&att_id).is_some(),
        "still a vertex (retained)"
    );
    assert!(
        !d.reaches(DagNode::Obs(id0), DagNode::Att(att_id)),
        "witness == subject: no seal edge"
    );
}

#[test]
fn an_acks_entry_naming_a_wrong_subject_is_a_finding_not_an_edge() {
    // §3.4 — A's entry acks an attestation whose subject is not A.
    let (a, b, w) = (sk(1), sk(2), sk(3));
    let mut s = MemoryStore::new();
    let (b0, bs0) = note(&b, 0, None, [], "b genesis");
    let b_id0 = append(&mut s, &b0, &bs0).unwrap();
    let (att, atts) = attest(&w, pk(&b), b_id0, 0, 0x20); // subject = B
    let att_id = s.put_attestation(&att, &atts).unwrap();

    let (a0, as0) = note(&a, 0, None, [], "a genesis");
    let a_id0 = append(&mut s, &a0, &as0).unwrap();
    let (a1, as1) = note(&a, 1, Some(a_id0), [att_id], "acks B's attestation");
    let a_id1 = append(&mut s, &a1, &as1).unwrap();

    let d = dag(&s);
    assert!(
        !d.reaches(DagNode::Att(att_id), DagNode::Obs(a_id1)),
        "an unlawful ack contributes no edge"
    );
    let findings = d.ack_findings();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].observation, a_id1);
    assert_eq!(
        findings[0].author,
        pk(&a),
        "attributable to the acking author"
    );
}

#[test]
fn an_observation_with_a_bad_signature_is_not_a_vertex() {
    let (a, imposter) = (sk(1), sk(9));
    let mut s = MemoryStore::new();
    let o0 = Observation {
        author: pk(&a),
        site: SITE,
        prev: None,
        seq: 0,
        hlc: Hlc::new(1_700_000_000_000, 0),
        body: ObservationBody::Note {
            text: "forged".into(),
        },
        geo: None,
        acks: BTreeSet::new(),
    };
    let wrong = o0.sign(&imposter); // signed by the wrong key
    let id0 = s.put_observation(&o0, &wrong).unwrap();

    let d = dag(&s);
    assert!(
        !d.is_vertex(DagNode::Obs(id0)),
        "a signature that does not verify under the author is not a vertex"
    );
}

// ---------------------------------------------------------------------------
// Determinism (§4.7)
// ---------------------------------------------------------------------------

/// Builds a small mixed store — two authors, one witness, chain links, an ack,
/// and a seal — applying the writes in the given order.
fn mixed_store(order: &[usize]) -> MemoryStore {
    let (a, b, w) = (sk(1), sk(2), sk(3));
    let (a0, as0) = note(&a, 0, None, [], "a0");
    let a0_id = a0.id();
    let (batt, batts) = attest(&w, pk(&a), a0_id, 0, 0x30);
    let batt_id = batt.id();
    let (a1, as1) = note(&a, 1, Some(a0_id), [batt_id], "a1");
    let (b0, bs0) = note(&b, 0, None, [], "b0");
    // A second attestation by the same witness under a different nonce.
    let (aw_att, aw_atts) = attest(&w, pk(&a), a0_id, 0, 0x31);

    // Boxed write closures so an arbitrary permutation can be applied.
    type Write = Box<dyn Fn(&mut MemoryStore)>;
    let mut s = MemoryStore::new();
    let writes: Vec<Write> = vec![
        Box::new(move |s: &mut MemoryStore| {
            s.put_observation(&a0, &as0).unwrap();
        }),
        Box::new(move |s: &mut MemoryStore| {
            s.put_observation(&a1, &as1).unwrap();
        }),
        Box::new(move |s: &mut MemoryStore| {
            s.put_observation(&b0, &bs0).unwrap();
        }),
        Box::new(move |s: &mut MemoryStore| {
            s.put_attestation(&batt, &batts).unwrap();
        }),
        Box::new(move |s: &mut MemoryStore| {
            s.put_attestation(&aw_att, &aw_atts).unwrap();
        }),
    ];
    for &i in order {
        writes[i](&mut s);
    }
    s
}

/// A stable textual fingerprint of the whole graph — every vertex, its
/// out-edges, and its full reachable set, all in node order.
fn fingerprint(d: &Dag) -> String {
    use std::fmt::Write as _;
    let mut nodes: Vec<DagNode> = d
        .observation_ids()
        .map(DagNode::Obs)
        .chain(d.attestation_ids().map(DagNode::Att))
        .collect();
    nodes.sort();

    let mut out = String::new();
    for &n in &nodes {
        let mut edges: Vec<DagNode> = d.out_edges(n).collect();
        edges.sort();
        let _ = writeln!(out, "{n:?} -> {edges:?}");
        for &m in &nodes {
            if d.reaches(n, m) {
                let _ = writeln!(out, "  ⟶ {m:?}");
            }
        }
    }
    out
}

#[test]
fn dag_construction_is_independent_of_write_order() {
    let forward = fingerprint(&dag(&mixed_store(&[0, 1, 2, 3, 4])));
    let shuffled = fingerprint(&dag(&mixed_store(&[4, 2, 0, 3, 1])));
    let reversed = fingerprint(&dag(&mixed_store(&[4, 3, 2, 1, 0])));
    assert_eq!(forward, shuffled, "write order must not change the DAG");
    assert_eq!(forward, reversed, "write order must not change the DAG");
}

#[test]
fn dag_construction_is_independent_of_duplicate_writes() {
    let once = fingerprint(&dag(&mixed_store(&[0, 1, 2, 3, 4])));
    let with_dups = fingerprint(&dag(&mixed_store(&[0, 0, 1, 2, 2, 3, 4, 1, 3, 4])));
    assert_eq!(
        once, with_dups,
        "re-delivering an object must change nothing"
    );
}

#[cfg(not(target_family = "wasm"))]
mod property {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// §4.7 — any permutation (with repeats) of the same write set yields a
        /// byte-identical graph fingerprint.
        #[test]
        fn any_delivery_schedule_yields_one_dag(
            schedule in prop::collection::vec(0usize..5, 5..40)
                .prop_filter("must cover every write", |v| {
                    (0..5).all(|i| v.contains(&i))
                }),
        ) {
            let baseline = fingerprint(&dag(&mixed_store(&[0, 1, 2, 3, 4])));
            prop_assert_eq!(fingerprint(&dag(&mixed_store(&schedule))), baseline);
        }
    }
}
