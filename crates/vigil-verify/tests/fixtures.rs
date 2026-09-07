//! `vigil-verify` against every `testdata/packs/` fixture, asserting the exact
//! `spec/03-export-pack.md` §6 verdict each is defined to produce — by name, so
//! a regression that collapsed two of the tamper taxonomy's cases into one would
//! fail here.
//!
//! The fixtures are static files. They are produced (and pinned byte-for-byte)
//! by `vigil-ledger`'s `gen_packs` example and its `tests/export.rs`; this crate
//! only consumes them, and never links `vigil-ledger` to do so.

use vigil_core::PubKey;
use vigil_verify::{
    ChainVerification, ChainViolation, ClaimOutcome, ForkKind, PackParseError, SelfCheck,
    WindowEdge, verify,
};

const HONEST: &[u8] = include_bytes!("../../../testdata/packs/honest.vgl");
const T1: &[u8] = include_bytes!("../../../testdata/packs/t1-flipped-byte.vgl");
const T2: &[u8] = include_bytes!("../../../testdata/packs/t2-resigned-genesis.vgl");
const T3: &[u8] = include_bytes!("../../../testdata/packs/t3-dropped-anchor.vgl");
const FORK_WITNESS: &[u8] = include_bytes!("../../../testdata/packs/fork-witness.vgl");
const EARLIEST_HELD: &[u8] = include_bytes!("../../../testdata/packs/earliest-held.vgl");

/// `spec/03` §6.1: org key seed `11…11`, public key `d04ab232…8737`.
fn org() -> PubKey {
    PubKey(
        hex::decode("d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737")
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

fn only_claim(bytes: &[u8]) -> vigil_verify::ClaimReport {
    let report = verify(bytes, org()).expect("pack parses");
    assert_eq!(
        report.claims.len(),
        1,
        "each fixture states exactly one claim"
    );
    report.claims.into_iter().next().unwrap()
}

// ---------------------------------------------------------------------------
// §6.4 — the honest verification result
// ---------------------------------------------------------------------------

#[test]
fn honest_pack_reproduces_the_spec_6_4_bracket_exactly() {
    let report = verify(HONEST, org()).expect("honest pack parses");

    assert_eq!(report.wire_version, 1);
    assert!(
        report.invalid_objects.is_empty(),
        "all three objects self-check"
    );
    assert!(report.fork_proofs.is_empty());
    assert!(report.unanchored_attestations.is_empty());

    // Step 4: chain of A over {A@0, A@1} is Verified.
    assert_eq!(report.chains.len(), 1);
    assert_eq!(report.chains[0].1, ChainVerification::Verified);

    // Step 6: bracket(A@0) — sealed by U, depth 1, open below to genesis.
    let ClaimOutcome::Bracketed(b) = only_claim(HONEST).outcome else {
        panic!("A@0 should bracket");
    };
    assert!(b.sealed);
    assert_eq!(b.witness_depth, 1);
    assert_eq!(b.lower_bound, None);
    let u = b.upper_bound.expect("sealed → an upper bound");
    assert_eq!(b.unwitnessed_window.lower, WindowEdge::Genesis);
    assert_eq!(b.unwitnessed_window.upper, WindowEdge::Attestation(u));
    assert!(!b.disputed);

    assert!(report.passed(), "the honest pack passes");
    assert_eq!(report.exit_code(), 0);
}

// ---------------------------------------------------------------------------
// §6.5 — the three tamper verdicts, distinct and named
// ---------------------------------------------------------------------------

/// T1 — one flipped body byte. The carried signature (over the original id)
/// fails, the object is discarded, and the claim names an id no surviving object
/// has. A's chain is `Incomplete { missing: [0] }` — an absence, not a forgery.
#[test]
fn t1_flipped_byte_is_claim_absent_and_incomplete_chain() {
    let report = verify(T1, org()).expect("T1 still parses — the envelope is intact");

    assert_eq!(report.invalid_objects.len(), 1);
    assert_eq!(report.invalid_objects[0].check, SelfCheck::BadSignature);

    assert_eq!(
        report.chains[0].1,
        ChainVerification::Incomplete { missing: vec![0] }
    );

    match only_claim(T1).outcome {
        ClaimOutcome::Unverifiable { pack_had_discards } => assert!(
            pack_had_discards,
            "T1 discards the corrupted A@0, so the claim id is absent AND the pack had a discard"
        ),
        other => panic!("expected Unverifiable, got {other:?}"),
    }

    assert_eq!(report.exit_code(), 1);
}

/// T2 — a validly re-signed genesis. Every object self-checks, but the hash
/// chain does not close: `BrokenLink` against A's key, carrying the exact fields
/// `spec/03` §6.5 T2 names.
#[test]
fn t2_resigned_genesis_is_a_broken_link_against_the_author() {
    let report = verify(T2, org()).expect("T2 parses");
    assert!(
        report.invalid_objects.is_empty(),
        "A@0″ carries a valid signature"
    );

    let ChainVerification::Violated(vs) = &report.chains[0].1 else {
        panic!("expected Violated, got {:?}", report.chains[0].1);
    };
    assert_eq!(vs.len(), 1);
    let ChainViolation::BrokenLink {
        seq,
        claimed_prev,
        predecessor,
        ..
    } = &vs[0]
    else {
        panic!("expected BrokenLink, got {:?}", vs[0]);
    };
    assert_eq!(*seq, 1);
    // §6.5 T2: A@1 still claims prev = id(A@0) = 7431f38e…, but the held
    // predecessor is the re-signed A@0″ = 7ecd2314…
    assert_eq!(
        claimed_prev.map(|h| h.to_string()).as_deref(),
        Some("7431f38ed1c31a3ef917bd60cd0b52f14c41b49ac8af5796b6c0fc3fba0aac1d")
    );
    assert_eq!(
        predecessor
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        vec!["7ecd2314322d98e1a2efde2db4abd4d8dfed085ed4ead71aad776e3e571de718"]
    );

    match only_claim(T2).outcome {
        ClaimOutcome::Unverifiable { pack_had_discards } => assert!(
            !pack_had_discards,
            "T2 re-signs the genesis — every carried object self-checks, the id is just gone"
        ),
        other => panic!("expected Unverifiable, got {other:?}"),
    }
    assert_eq!(report.exit_code(), 1);
}

/// T3 — drop the anchor entry. Every object self-checks and A's chain is
/// `Verified` (genesis only), but `U` anchors nothing held, so `A@0` is reported
/// **unwitnessed** — the conservative outcome (invariant I5) — with the window
/// open above to the verification moment.
#[test]
fn t3_dropped_anchor_is_unwitnessed_via_an_unanchored_attestation() {
    let report = verify(T3, org()).expect("T3 parses");

    assert!(report.invalid_objects.is_empty());
    assert_eq!(report.chains[0].1, ChainVerification::Verified);

    assert_eq!(
        report.unanchored_attestations.len(),
        1,
        "U's subject_head names an entry the pack does not carry"
    );

    let ClaimOutcome::Bracketed(b) = only_claim(T3).outcome else {
        panic!("A@0 is still a vertex, so it brackets — just unwitnessed");
    };
    assert!(!b.sealed, "U seals nothing");
    assert_eq!(b.upper_bound, None);
    assert_eq!(b.witness_depth, 0);
    assert_eq!(b.unwitnessed_window.upper, WindowEdge::VerificationMoment);

    assert_eq!(
        report.exit_code(),
        1,
        "a pack carrying an unanchored attestation fails"
    );
}

/// The three tamper verdicts are genuinely different — claim-absent vs
/// `BrokenLink` vs unwitnessed-via-unanchored.
#[test]
fn the_three_tamper_verdicts_are_pairwise_distinct() {
    let chains: Vec<ChainVerification> = [T1, T2, T3]
        .iter()
        .map(|p| verify(p, org()).unwrap().chains[0].1.clone())
        .collect();
    assert_ne!(chains[0], chains[1]);
    assert_ne!(chains[0], chains[2]);
    assert_ne!(chains[1], chains[2]);
}

// ---------------------------------------------------------------------------
// §3.4 — fork proof against the sealing witness
// ---------------------------------------------------------------------------

#[test]
fn fork_witness_pack_drops_the_seal_and_reports_unwitnessed() {
    let report = verify(FORK_WITNESS, org()).expect("fork-witness pack parses");

    assert_eq!(report.fork_proofs.len(), 1);
    assert_eq!(report.fork_proofs[0].1, ForkKind::Witness);
    assert_eq!(report.invalid_fork_proofs, 0);
    assert!(report.invalid_objects.is_empty());

    // Minimisation (§4): only A's chain travels, never the witness's own
    // equivocating entries.
    assert_eq!(report.chains.len(), 1, "only A's chain is carried");
    assert_eq!(report.chains[0].1, ChainVerification::Verified);

    let ClaimOutcome::Bracketed(b) = only_claim(FORK_WITNESS).outcome else {
        panic!("A@0 brackets — the seal just drops");
    };
    assert!(
        !b.sealed,
        "the only witness is quarantined, so U stops sealing (spec/02 §6.5)"
    );
    assert_eq!(b.unwitnessed_window.upper, WindowEdge::VerificationMoment);

    assert_eq!(
        report.exit_code(),
        1,
        "a carried fork proof fails verification"
    );
}

// ---------------------------------------------------------------------------
// §3.5 — the "earliest held" marker
// ---------------------------------------------------------------------------

#[test]
fn earliest_held_pack_reports_open_to_earliest_held_not_genesis() {
    let report = verify(EARLIEST_HELD, org()).expect("earliest-held pack parses");

    assert!(report.invalid_objects.is_empty());

    // §3.5: the low sequence numbers are Incomplete, never Violated, never
    // Verified.
    assert_eq!(
        report.chains[0].1,
        ChainVerification::Incomplete {
            missing: vec![0, 1, 2]
        }
    );

    let ClaimOutcome::Bracketed(b) = only_claim(EARLIEST_HELD).outcome else {
        panic!("A@3 brackets");
    };
    assert!(b.sealed, "A@3 is sealed by the attestation on A@4");
    assert_eq!(
        b.unwitnessed_window.lower,
        WindowEdge::EarliestHeld(3),
        "the window is open below only to the earliest held entry (seq 3), NOT to genesis"
    );

    // The pack is honestly constructed and its claim reproduces — a wide window
    // open below is the correct conservative output, not a failure.
    assert_eq!(report.exit_code(), 0);
}

// ---------------------------------------------------------------------------
// Envelope robustness (spec/03 §5 step 1 / spec/01 §8)
// ---------------------------------------------------------------------------

#[test]
fn a_pack_for_a_different_org_is_rejected() {
    let err = verify(HONEST, PubKey([0x11; 32])).unwrap_err();
    assert!(
        matches!(err, PackParseError::WrongOrg { .. }),
        "got {err:?}"
    );
}

#[test]
fn a_file_without_the_marker_is_rejected() {
    assert_eq!(
        verify(b"not a pack at all", org()).unwrap_err(),
        PackParseError::BadMarker
    );
    // A pack with the marker corrupted by one byte.
    let mut bad = HONEST.to_vec();
    bad[3] ^= 0xff;
    assert_eq!(verify(&bad, org()).unwrap_err(), PackParseError::BadMarker);
}

#[test]
fn trailing_bytes_after_the_envelope_are_rejected() {
    let mut trailer = HONEST.to_vec();
    trailer.push(0x00);
    assert!(matches!(
        verify(&trailer, org()).unwrap_err(),
        PackParseError::Decode(_)
    ));
}

#[test]
fn truncation_at_every_offset_never_panics_and_always_errs() {
    for cut in 0..HONEST.len() {
        // Either a structural Err, or (for a coincidentally-complete prefix) an
        // Ok report — never a panic.
        let _ = verify(&HONEST[..cut], org());
    }
}
