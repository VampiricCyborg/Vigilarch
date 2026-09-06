//! # vigil-sim
//!
//! A seeded, fully reproducible simulator that runs virtual nodes on the *real*
//! `vigil-ledger` over a scripted link. See `docs/VIGILARCH.md` §16.1.
//!
//! This is the smallest real version: two nodes, one attestation exchange, and a
//! check that `vigil-ledger`'s bracketing query seals the right record from the
//! far node's point of view. It grew alongside M1, not after it. The scriptable
//! adversarial suite — partition topology, clock rollback, equivocation,
//! withholding, mule routes, each with an ablation (`spec/02` §9) — builds on
//! this.
//!
//! ## Determinism is the point
//!
//! Running one seed twice produces a byte-identical report. There is no
//! wall-clock read anywhere in the crate (invariant I4); logical time is the
//! scenario's hard-coded ticks, and every key and nonce comes from a seeded
//! `splitmix64` stream. Later scenarios assert invariant violations and exit
//! non-zero; this one asserts the sealing invariant and does the same.
//!
//! ```text
//! cargo run -p vigil-sim -- --seed 1
//! ```

use std::process::ExitCode;

use vigil_sim::sim;

fn main() -> ExitCode {
    let seed = match parse_seed(std::env::args().skip(1)) {
        Ok(seed) => seed,
        Err(msg) => {
            eprintln!("{msg}");
            eprintln!("usage: vigil-sim --scenario minimal --seed <n>");
            return ExitCode::from(2);
        }
    };

    let report = sim::run(seed);
    print!("{}", report.text);

    if report.sealed_ok {
        ExitCode::SUCCESS
    } else {
        eprintln!("invariant violation: the sealing check did not hold");
        ExitCode::FAILURE
    }
}

/// Accepts `--seed <n>` and an optional `--scenario minimal` (the only scenario
/// in this version). Order-independent; defaults the seed to 1.
fn parse_seed(mut args: impl Iterator<Item = String>) -> Result<u64, String> {
    let mut seed: u64 = 1;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--seed" => {
                let raw = args.next().ok_or("--seed needs a value")?;
                seed = raw.parse().map_err(|_| format!("not a u64: {raw}"))?;
            }
            "--scenario" => {
                let name = args.next().ok_or("--scenario needs a value")?;
                if name != "minimal" {
                    return Err(format!("unknown scenario: {name} (only `minimal` in v1)"));
                }
            }
            other => return Err(format!("unexpected argument: {other}")),
        }
    }
    Ok(seed)
}
