//! The minimal scenario's two obligations: the sealing invariant holds, and the
//! run is byte-identical from a seed (`spec/02-entanglement.md` §9, invariant
//! I4). The adversarial suite will depend on the second.

use vigil_sim::{equivocation, sealing_ablation, sim};

#[test]
fn the_scenario_seals_the_observation_from_the_far_node() {
    let report = sim::run(1);
    assert!(
        report.sealed_ok,
        "O0 must be sealed from B's ledger by U, with an open-below window:\n{}",
        report.text
    );
}

#[test]
fn the_same_seed_produces_a_byte_identical_report() {
    for seed in [0u64, 1, 7, 42, u64::MAX] {
        assert_eq!(
            sim::run(seed).text,
            sim::run(seed).text,
            "seed {seed} is not reproducible"
        );
    }
}

#[test]
fn the_equivocation_scenario_holds_every_assertion_at_a_fixed_seed() {
    let report = equivocation::run(1);
    assert!(
        report.passed,
        "every assertion in the equivocation scenario must hold:\n{}",
        report.text
    );
}

#[test]
fn the_equivocation_scenario_is_byte_identical_from_a_seed() {
    for seed in [0u64, 1, 7, 42, u64::MAX] {
        assert_eq!(
            equivocation::run(seed).text,
            equivocation::run(seed).text,
            "seed {seed} is not reproducible"
        );
    }
}

#[test]
fn the_sealing_ablation_holds_every_assertion_at_a_fixed_seed() {
    let report = sealing_ablation::run(1);
    assert!(
        report.passed,
        "every assertion in the sealing-ablation scenario must hold:\n{}",
        report.text
    );
}

#[test]
fn the_one_attestation_is_the_whole_difference_between_sealed_and_unwitnessed() {
    // Same held chain for A in both runs; the only difference is one attestation
    // object. Run A seals O0; run B leaves it unwitnessed with an open window.
    for seed in [0u64, 1, 7, 42, u64::MAX] {
        let report = sealing_ablation::run(seed);
        assert!(
            report.bracket_a.sealed,
            "run A (with the attestation) must seal O0 at seed {seed}:\n{}",
            report.text
        );
        assert!(
            !report.bracket_b.sealed,
            "run B (no attestation) must leave O0 unwitnessed at seed {seed}:\n{}",
            report.text
        );
        assert!(
            report.bracket_b.upper_bound.is_none() && report.bracket_a.upper_bound.is_some(),
            "the upper bound appears only when the attestation does, seed {seed}:\n{}",
            report.text
        );
    }
}

#[test]
fn the_sealing_ablation_is_byte_identical_from_a_seed() {
    for seed in [0u64, 1, 7, 42, u64::MAX] {
        assert_eq!(
            sealing_ablation::run(seed).text,
            sealing_ablation::run(seed).text,
            "seed {seed} is not reproducible"
        );
    }
}

#[test]
fn different_seeds_produce_different_keys_but_still_seal() {
    let one = sim::run(1);
    let two = sim::run(2);
    assert_ne!(
        one.text, two.text,
        "different seeds must diverge (keys and nonce differ)"
    );
    assert!(one.sealed_ok && two.sealed_ok, "the invariant holds at any seed");
}
