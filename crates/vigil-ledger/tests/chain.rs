//! §6.6 chain integrity: the guarded [`append`] path and the three-way
//! [`verify_chain`] pass — Verified / Incomplete / Violated, with the middle one
//! never collapsing into either neighbour.
//!
//! Neither `append` nor `verify_chain` inspects signatures, so these tests use
//! synthetic keys and signatures. What is under test is chain structure: the
//! joint `seq`/`prev` check, gaps left intact as the normal partition state, and
//! signed self-contradiction retained and named rather than dropped.

use vigil_core::{Hash, Hlc, Object, Observation, ObservationBody, PubKey, Seq, Signature, SiteId};
use vigil_ledger::{
    AppendError, ChainVerification, ChainViolation, MemoryStore, PrevRequirement, Store, append,
    verify_chain,
};

const SITE: SiteId = SiteId(*b"VIGILARCH-SITE-A");

fn author(n: u8) -> PubKey {
    PubKey([n; 32])
}

fn sig(n: u8) -> Signature {
    Signature([n; 64])
}

/// An observation at `seq` pointing at `prev`. The note text is mixed in so that
/// two entries at one `seq` land on different content addresses.
fn linked(a: PubKey, seq: Seq, prev: Option<Hash>, text: &str) -> Observation {
    Observation {
        author: a,
        site: SITE,
        prev,
        seq,
        hlc: Hlc::new(1_700_000_000_000 + seq, 0),
        body: ObservationBody::Note {
            text: text.to_owned(),
        },
        geo: None,
        acks: std::collections::BTreeSet::new(),
    }
}

/// Append a clean, correctly linked chain of `n` notes by one author. Returns
/// the content addresses in `seq` order.
fn clean_chain(store: &mut MemoryStore, a: PubKey, n: u64) -> Vec<Hash> {
    let mut ids = Vec::new();
    let mut prev = None;
    for seq in 0..n {
        let o = linked(a, seq, prev, &format!("entry {seq}"));
        let id = append(store, &o, &sig(0)).expect("a clean link appends");
        prev = Some(id);
        ids.push(id);
    }
    ids
}

#[test]
fn a_clean_chain_verifies() {
    let mut s = MemoryStore::new();
    let a = author(1);
    clean_chain(&mut s, a, 6);
    assert_eq!(verify_chain(&s, &a).unwrap(), ChainVerification::Verified);
}

#[test]
fn removing_an_interior_entry_is_incomplete_not_violated() {
    // A chain arriving over a partition with seq 2 still in flight. This is the
    // normal state, not tampering — §6.6 forbids reporting it as a violation.
    let mut s = MemoryStore::new();
    let a = author(1);

    // Build the linked entries, then store all but seq 2 directly.
    let mut objs = Vec::new();
    let mut prev = None;
    for seq in 0..5u64 {
        let o = linked(a, seq, prev, &format!("entry {seq}"));
        prev = Some(o.id());
        objs.push(o);
    }
    for (seq, o) in objs.iter().enumerate() {
        if seq == 2 {
            continue;
        }
        s.put_observation(o, &sig(0)).unwrap();
    }

    assert_eq!(
        verify_chain(&s, &a).unwrap(),
        ChainVerification::Incomplete { missing: vec![2] },
    );
}

#[test]
fn equivocation_is_violated_and_names_the_author() {
    let mut s = MemoryStore::new();
    let a = author(7);
    let ids = clean_chain(&mut s, a, 3); // seq 0, 1, 2

    // A second, conflicting entry at seq 2 — same author, same predecessor.
    // append does not gate forks; the store retains both (§6.6).
    let forked = linked(a, 2, Some(ids[1]), "walkway barricaded Saturday");
    let forked_id = append(&mut s, &forked, &sig(0)).expect("store retains equivocation");
    assert_ne!(forked_id, ids[2]);

    match verify_chain(&s, &a).unwrap() {
        ChainVerification::Violated(vs) => {
            assert_eq!(vs.len(), 1, "one finding: the equivocation at seq 2");
            match &vs[0] {
                ChainViolation::Equivocation {
                    author,
                    seq,
                    entries,
                } => {
                    assert_eq!(*author, a, "the finding names the offending key");
                    assert_eq!(*seq, 2);
                    assert_eq!(entries.len(), 2);
                    assert!(entries.contains(&ids[2]) && entries.contains(&forked_id));
                }
                other => panic!("expected Equivocation, got {other:?}"),
            }
        }
        other => panic!("expected Violated, got {other:?}"),
    }
}

#[test]
fn a_prev_pointing_at_the_wrong_predecessor_is_violated() {
    let mut s = MemoryStore::new();
    let a = author(3);
    let ids = clean_chain(&mut s, a, 2); // seq 0, 1

    // seq 2 links back to seq 0 instead of seq 1. Stored directly, as a hostile
    // ingest would — append rejects this (see the next test).
    let bent = linked(a, 2, Some(ids[0]), "bent link");
    s.put_observation(&bent, &sig(0)).unwrap();

    match verify_chain(&s, &a).unwrap() {
        ChainVerification::Violated(vs) => {
            assert!(vs.iter().any(|v| matches!(
                v,
                ChainViolation::BrokenLink { author, seq: 2, claimed_prev, .. }
                    if *author == a && *claimed_prev == Some(ids[0])
            )));
        }
        other => panic!("expected Violated, got {other:?}"),
    }
}

#[test]
fn append_rejects_a_bent_link_and_does_not_store_it() {
    let mut s = MemoryStore::new();
    let a = author(3);
    let ids = clean_chain(&mut s, a, 2);

    let bent = linked(a, 2, Some(ids[0]), "bent");
    match append(&mut s, &bent, &sig(0)).unwrap_err() {
        AppendError::ChainMismatch(m) => {
            assert_eq!(m.author, a);
            assert_eq!(m.seq, 2);
            assert_eq!(m.claimed_prev, Some(ids[0]));
            assert_eq!(m.entry, bent.id());
            match m.required {
                PrevRequirement::Predecessor(preds) => assert_eq!(preds, vec![ids[1]]),
                PrevRequirement::Genesis => panic!("seq 2 is not genesis"),
            }
        }
        AppendError::Store(e) => panic!("a mismatch is not a backend fault: {e}"),
    }
    assert!(
        s.observations_at(&a, 2).unwrap().is_empty(),
        "a refused append stores nothing"
    );
}

#[test]
fn append_rejects_genesis_carrying_a_prev() {
    let mut s = MemoryStore::new();
    let a = author(5);
    let bad = linked(a, 0, Some(Hash([9; 32])), "fake genesis");
    match append(&mut s, &bad, &sig(0)).unwrap_err() {
        AppendError::ChainMismatch(m) => {
            assert_eq!(m.seq, 0);
            assert_eq!(m.claimed_prev, Some(Hash([9; 32])));
            assert!(matches!(m.required, PrevRequirement::Genesis));
        }
        AppendError::Store(_) => panic!("not a backend fault"),
    }
}

#[test]
fn append_tolerates_a_gap_below_the_new_entry() {
    // seq 3 with nothing held under it: a chain still arriving, not a
    // contradiction. append stores it; verify_chain reports Incomplete.
    let mut s = MemoryStore::new();
    let a = author(9);
    let o = linked(a, 3, Some(Hash([1; 32])), "arrived early");
    append(&mut s, &o, &sig(0)).expect("a gap is not a violation");

    assert_eq!(
        verify_chain(&s, &a).unwrap(),
        ChainVerification::Incomplete {
            missing: vec![0, 1, 2]
        },
    );
}

#[test]
fn a_violation_outranks_a_gap() {
    // A missing seq and a bent link in the same chain: the outcome is Violated,
    // not Incomplete. An alarm that downgrades itself on partial evidence is
    // useless.
    let mut s = MemoryStore::new();
    let a = author(11);
    let ids = clean_chain(&mut s, a, 2); // seq 0, 1

    let bent = linked(a, 2, Some(ids[0]), "bent"); // wrong predecessor
    s.put_observation(&bent, &sig(0)).unwrap();
    let far = linked(a, 6, Some(Hash([2; 32])), "far"); // leaves 3..=5 missing
    s.put_observation(&far, &sig(0)).unwrap();

    assert!(matches!(
        verify_chain(&s, &a).unwrap(),
        ChainVerification::Violated(_)
    ));
}

#[test]
fn an_unknown_author_is_incomplete_not_verified() {
    let s = MemoryStore::new();
    assert_eq!(
        verify_chain(&s, &author(99)).unwrap(),
        ChainVerification::Incomplete { missing: vec![] },
    );
}

#[cfg(not(target_family = "wasm"))]
mod property {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Any correctly linked chain, of any length and content, verifies as
        /// Verified — never Incomplete, never Violated.
        #[test]
        fn random_valid_chains_always_verify(
            seed in any::<u8>(),
            texts in prop::collection::vec("[a-z0-9 ]{0,40}", 1..24),
        ) {
            let mut s = MemoryStore::new();
            let a = author(seed);
            let mut prev = None;
            for (seq, text) in texts.iter().enumerate() {
                let o = linked(a, seq as u64, prev, text);
                let id = append(&mut s, &o, &sig(0)).expect("a valid link appends");
                prev = Some(id);
            }
            prop_assert_eq!(verify_chain(&s, &a).unwrap(), ChainVerification::Verified);
        }

        /// Delivery order does not matter: appending a valid chain in any
        /// permutation, skipping links whose predecessor has not arrived yet and
        /// retrying them, still ends Verified.
        #[test]
        fn append_order_does_not_change_the_verdict(
            seed in any::<u8>(),
            len in 1u64..16,
            perm_seed in any::<u64>(),
        ) {
            // Build the canonical linked chain.
            let a = author(seed);
            let mut objs = Vec::new();
            let mut prev = None;
            for seq in 0..len {
                let o = linked(a, seq, prev, &format!("entry {seq}"));
                prev = Some(o.id());
                objs.push(o);
            }

            // A cheap deterministic shuffle of the indices.
            let mut order: Vec<usize> = (0..objs.len()).collect();
            let mut x = perm_seed | 1;
            for i in (1..order.len()).rev() {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                order.swap(i, (x % (i as u64 + 1)) as usize);
            }

            let mut s = MemoryStore::new();
            let mut pending = order;
            // Repeatedly sweep, appending whatever links now; a bent link never
            // occurs here so the only reason to defer is a missing predecessor.
            loop {
                let before = pending.len();
                pending.retain(|&i| append(&mut s, &objs[i], &sig(0)).is_err());
                if pending.is_empty() || pending.len() == before {
                    break;
                }
            }
            prop_assert!(pending.is_empty(), "every entry eventually appended");
            prop_assert_eq!(verify_chain(&s, &a).unwrap(), ChainVerification::Verified);
        }
    }
}
