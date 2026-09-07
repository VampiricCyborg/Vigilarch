//! # vigil-sim
//!
//! A seeded, fully reproducible simulator that runs virtual nodes on the *real*
//! `vigil-ledger` over a scripted link. See `docs/VIGILARCH.md` §16.1.
//!
//! Two scenarios so far, both seed-driven and byte-identical from a seed:
//!
//! - `minimal` — two nodes, one attestation exchange, a check that the far
//!   node's ledger seals the right record ([`vigil_sim::sim`]).
//! - `equivocation` — one author signs two irreconcilable entries, an honest
//!   witness attests only the branch it saw, and quarantine is shown to change
//!   only what a convicted key's attestations buy going forward
//!   ([`vigil_sim::equivocation`]).
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
//! ```

use std::process::ExitCode;

use vigil_sim::{equivocation, sim};

/// Which scenario to run.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Minimal,
    Equivocation,
}

fn main() -> ExitCode {
    let (scenario, seed) = match parse_args(std::env::args().skip(1)) {
        Ok(parsed) => parsed,
        Err(msg) => {
            eprintln!("{msg}");
            eprintln!("usage: vigil-sim --scenario minimal|equivocation --seed <n>");
            return ExitCode::from(2);
        }
    };

    let (text, ok) = match scenario {
        Scenario::Minimal => {
            let r = sim::run(seed);
            (r.text, r.sealed_ok)
        }
        Scenario::Equivocation => {
            let r = equivocation::run(seed);
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

/// Accepts `--scenario minimal|equivocation` and `--seed <n>`, order-independent.
/// The scenario defaults to `minimal` and the seed to `1`.
fn parse_args(mut args: impl Iterator<Item = String>) -> Result<(Scenario, u64), String> {
    let mut scenario = Scenario::Minimal;
    let mut seed: u64 = 1;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--seed" => {
                let raw = args.next().ok_or("--seed needs a value")?;
                seed = raw.parse().map_err(|_| format!("not a u64: {raw}"))?;
            }
            "--scenario" => {
                let name = args.next().ok_or("--scenario needs a value")?;
                scenario = match name.as_str() {
                    "minimal" => Scenario::Minimal,
                    "equivocation" => Scenario::Equivocation,
                    other => return Err(format!("unknown scenario: {other}")),
                };
            }
            other => return Err(format!("unexpected argument: {other}")),
        }
    }
    Ok((scenario, seed))
}
