//! The minimal scenario's two obligations: the sealing invariant holds, and the
//! run is byte-identical from a seed (`spec/02-entanglement.md` §9, invariant
//! I4). The adversarial suite will depend on the second.

use vigil_sim::sim;

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
fn different_seeds_produce_different_keys_but_still_seal() {
    let one = sim::run(1);
    let two = sim::run(2);
    assert_ne!(
        one.text, two.text,
        "different seeds must diverge (keys and nonce differ)"
    );
    assert!(one.sealed_ok && two.sealed_ok, "the invariant holds at any seed");
}
