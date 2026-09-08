//! The minimal scenario's two obligations: the sealing invariant holds, and the
//! run is byte-identical from a seed (`spec/02-entanglement.md` §9, invariant
//! I4). The adversarial suite will depend on the second.

use vigil_ledger::{Quarantine, export_pack, parse_pack};
use vigil_sim::{equivocation, scale, sealing_ablation, sim};

#[test]
fn the_scenario_seals_the_observation_from_the_far_node() {
    let report = sim::run(1);
    assert!(
        report.sealed_ok,
        "O0 must be sealed from B's ledger by U, with an open-below window:\n{}",
        report.text
    );
}

/// The `--export-pack` path: node B's resulting store, run through
/// `vigil-ledger`'s real `export_pack`, produces a well-formed pack that carries
/// O0 as its claim, self-checks clean, and is byte-identical from a seed.
#[test]
fn the_honest_store_exports_a_verifiable_pack() {
    let org = vigil_core::public_key(&ed25519_dalek::SigningKey::from_bytes(&[0x11; 32]));

    let report = sim::run(1);
    let pack = export_pack(&report.b_store, &Quarantine::new(), org, &[report.o0_id])
        .expect("export the honest store");

    let contents = parse_pack(&pack).expect("the exported pack parses");
    assert_eq!(contents.wire_version, 1);
    assert_eq!(contents.org, org);
    assert_eq!(
        contents.invalid_object_count, 0,
        "every carried object self-checks"
    );
    assert!(
        contents.claims.contains(&report.o0_id),
        "the pack claims O0"
    );
    assert_eq!(
        contents.valid_attestations().count(),
        1,
        "the sealing attestation U travels with the pack"
    );

    let again = export_pack(
        &sim::run(1).b_store,
        &Quarantine::new(),
        org,
        &[report.o0_id],
    )
    .expect("export again");
    assert_eq!(pack, again, "the pack is byte-identical from a seed");
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
fn scale_up_runs_every_scenario_across_every_seed_and_all_pass() {
    let report = scale::run_scale_up(32);
    assert_eq!(report.outcomes.len(), 3, "three scenarios are covered");
    for o in &report.outcomes {
        // Counting discipline: every seed is accounted for exactly once.
        assert_eq!(
            o.pass + o.fail(),
            report.seeds,
            "scenario {} lost a run: {} + {} != {}",
            o.name,
            o.pass,
            o.fail(),
            report.seeds
        );
        assert!(
            o.failing_seeds.is_empty(),
            "scenario {} failed at seeds {:?}",
            o.name,
            o.failing_seeds
        );
    }
    assert!(report.all_passed());
    assert_eq!(report.first_failure(), None);
    assert_eq!(report.total_pass(), report.total_runs());
}

#[test]
fn scale_up_traces_a_failure_to_its_exact_scenario_and_seed() {
    // A stand-in scenario that fails only at seed 7, run through the same
    // counting path the real runner uses.
    let scenario = |seed: u64| seed != 7;
    let seeds = 20u64;
    let mut pass = 0u64;
    let mut failing = Vec::new();
    for seed in 0..seeds {
        if scenario(seed) {
            pass += 1;
        } else {
            failing.push(seed);
        }
    }
    assert_eq!(pass + failing.len() as u64, seeds);
    assert_eq!(failing, vec![7]);
}

#[test]
fn scale_up_aggregate_is_deterministic() {
    let a = scale::run_scale_up(16);
    let b = scale::run_scale_up(16);
    assert_eq!(
        a.outcomes, b.outcomes,
        "the pass/fail aggregate is a pure function of the seed range"
    );

    // The rendered table is identical too, once the (wall-time) summary and any
    // timing-dependent WARNING line are removed.
    let table = |s: &str| {
        s.lines()
            .filter(|l| !l.starts_with("scale-up: PASS") && !l.starts_with("scale-up: WARNING"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert_eq!(table(&scale::render(&a)), table(&scale::render(&b)));
}

#[test]
fn different_seeds_produce_different_keys_but_still_seal() {
    let one = sim::run(1);
    let two = sim::run(2);
    assert_ne!(
        one.text, two.text,
        "different seeds must diverge (keys and nonce differ)"
    );
    assert!(
        one.sealed_ok && two.sealed_ok,
        "the invariant holds at any seed"
    );
}
