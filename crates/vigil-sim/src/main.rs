//! # vigil-sim
//!
//! A seeded, fully reproducible simulator that runs virtual nodes on the *real*
//! `vigil-ledger` over a scripted link. See `docs/VIGILARCH.md` §16.1.
//!
//! Three scenarios so far, all seed-driven and byte-identical from a seed:
//!
//! - `minimal` — two nodes, one attestation exchange, a check that the far
//!   node's ledger seals the right record ([`vigil_sim::sim`]).
//! - `equivocation` — one author signs two irreconcilable entries, an honest
//!   witness attests only the branch it saw, and quarantine is shown to change
//!   only what a convicted key's attestations buy going forward
//!   ([`vigil_sim::equivocation`]).
//! - `sealing-ablation` — one honest chain run twice, with and without a single
//!   attestation object, showing that the attestation is the entire distance
//!   between "sealed, bounded" and "unwitnessed, open" — and that chain
//!   verification is unaffected either way ([`vigil_sim::sealing_ablation`]).
//!
//! The scriptable adversarial suite — partition topology, clock rollback,
//! withholding, mule routes, each with an ablation (`spec/02` §9) — builds on
//! these.
//!
//! ## Determinism is the point
//!
//! Running one seed twice produces a byte-identical report. There is no
//! wall-clock read anywhere in the crate (invariant I4); logical time is the
//! scenario's hard-coded ticks, and every key and nonce comes from a seeded
//! `splitmix64` stream. A scenario asserts its invariant and the binary exits
//! non-zero on any violation.
//!
//! ```text
//! cargo run -p vigil-sim -- --scenario minimal --seed 1
//! cargo run -p vigil-sim -- --scenario equivocation --seed 1
//! cargo run -p vigil-sim -- --scenario sealing-ablation --seed 1
//! ```
//!
//! ## Scale-up
//!
//! `--scale-up [--seeds N]` runs every scenario once per seed in `0..N`
//! (default 1000) and prints a flat, greppable table — pass count, fail count,
//! and the exact seed of any failure per scenario — then exits non-zero if any
//! scenario failed any seed, naming the first failure. This feeds the README's
//! measured evaluation table. See [`vigil_sim::scale`].
//!
//! ```text
//! cargo run -p vigil-sim --release -- --scale-up --seeds 1000
//! ```

use std::process::ExitCode;

use vigil_sim::{equivocation, scale, sealing_ablation, sim};

/// Which scenario to run in single mode.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Minimal,
    Equivocation,
    SealingAblation,
}

/// What the binary was asked to do.
enum Mode {
    /// Run one scenario at one seed and print its transcript.
    Single { scenario: Scenario, seed: u64 },
    /// Run every scenario across `0..seeds` and print the aggregate.
    ScaleUp { seeds: u64 },
}

const USAGE: &str = "usage:\n  \
    vigil-sim --scenario minimal|equivocation|sealing-ablation --seed <n>\n  \
    vigil-sim --scale-up [--seeds <n>]";

fn main() -> ExitCode {
    let mode = match parse_args(std::env::args().skip(1)) {
        Ok(mode) => mode,
        Err(msg) => {
            eprintln!("{msg}");
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    match mode {
        Mode::Single { scenario, seed } => run_single(scenario, seed),
        Mode::ScaleUp { seeds } => run_scale_up(seeds),
    }
}

fn run_single(scenario: Scenario, seed: u64) -> ExitCode {
    let (text, ok) = match scenario {
        Scenario::Minimal => {
            let r = sim::run(seed);
            (r.text, r.sealed_ok)
        }
        Scenario::Equivocation => {
            let r = equivocation::run(seed);
            (r.text, r.passed)
        }
        Scenario::SealingAblation => {
            let r = sealing_ablation::run(seed);
            (r.text, r.passed)
        }
    };
    print!("{text}");

    if ok {
        ExitCode::SUCCESS
    } else {
        eprintln!("invariant violation: an assertion in the scenario did not hold");
        ExitCode::FAILURE
    }
}

fn run_scale_up(seeds: u64) -> ExitCode {
    let report = scale::run_scale_up(seeds);
    print!("{}", scale::render(&report));

    match report.first_failure() {
        None => ExitCode::SUCCESS,
        Some((name, seed)) => {
            eprintln!("scale-up failed: scenario {name} did not pass seed {seed}");
            ExitCode::FAILURE
        }
    }
}

/// Order-independent argument parsing.
///
/// - `--scenario <name>` + `--seed <n>` selects single mode (defaults:
///   `minimal`, seed `1`).
/// - `--scale-up` selects scale-up mode; `--seeds <n>` sets the range
///   (default `1000`). `--scenario` / `--seed` are rejected alongside it rather
///   than silently ignored.
fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Mode, String> {
    let mut scenario = Scenario::Minimal;
    let mut seed: u64 = 1;
    let mut scale_up = false;
    let mut seeds: u64 = 1000;
    let mut saw_single_arg = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--seed" => {
                let raw = args.next().ok_or("--seed needs a value")?;
                seed = raw.parse().map_err(|_| format!("not a u64: {raw}"))?;
                saw_single_arg = true;
            }
            "--scenario" => {
                let name = args.next().ok_or("--scenario needs a value")?;
                scenario = match name.as_str() {
                    "minimal" => Scenario::Minimal,
                    "equivocation" => Scenario::Equivocation,
                    "sealing-ablation" => Scenario::SealingAblation,
                    other => return Err(format!("unknown scenario: {other}")),
                };
                saw_single_arg = true;
            }
            "--scale-up" => scale_up = true,
            "--seeds" => {
                let raw = args.next().ok_or("--seeds needs a value")?;
                seeds = raw.parse().map_err(|_| format!("not a u64: {raw}"))?;
            }
            other => return Err(format!("unexpected argument: {other}")),
        }
    }

    if scale_up {
        if saw_single_arg {
            return Err("--scale-up runs every scenario across a seed range; \
                        drop --scenario/--seed (use --seeds to set the range)"
                .into());
        }
        if seeds == 0 {
            return Err("--seeds must be at least 1".into());
        }
        Ok(Mode::ScaleUp { seeds })
    } else {
        Ok(Mode::Single { scenario, seed })
    }
}
