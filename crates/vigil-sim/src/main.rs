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
//! ## Exporting a pack from the run
//!
//! `--scenario minimal --export-pack <path>` runs the honest scenario and then
//! writes an evidence pack for `O0` from node B's resulting store, through
//! `vigil-ledger`'s real [`export_pack`] — the same path `testdata/packs/`
//! fixtures come from. It prints the org key and the exact `vigil-verify` line
//! to run against the file. This is what `demo.sh` uses to join the simulated
//! meeting to the independent verifier. Only the `minimal` scenario ends with a
//! store that seals a record, so the flag is rejected for the others.
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

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context as _;
use ed25519_dalek::SigningKey;
use vigil_core::{Hash, public_key};
use vigil_ledger::{MemoryStore, Quarantine, export_pack};
use vigil_sim::{equivocation, scale, sealing_ablation, sim};

/// The org identity every export pack in this repository is labelled with: the
/// `spec/03-export-pack.md` §6.1 worked-example org key, seed `0x11…11`. The
/// demo reuses it so `vigil-verify` is handed the same key a reader already
/// meets in `spec/03` and `testdata/README.md`.
const DEMO_ORG_SEED: [u8; 32] = [0x11; 32];

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
    Single {
        scenario: Scenario,
        seed: u64,
        /// `--export-pack <path>`: after the transcript, export an evidence pack
        /// for `O0` from the honest scenario's resulting store. Only valid for
        /// `--scenario minimal`.
        export_pack: Option<PathBuf>,
    },
    /// Run every scenario across `0..seeds` and print the aggregate.
    ScaleUp { seeds: u64 },
}

const USAGE: &str = "usage:\n  \
    vigil-sim --scenario minimal|equivocation|sealing-ablation --seed <n> [--export-pack <path>]\n  \
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
        Mode::Single {
            scenario,
            seed,
            export_pack,
        } => run_single(scenario, seed, export_pack.as_deref()),
        Mode::ScaleUp { seeds } => run_scale_up(seeds),
    }
}

fn run_single(scenario: Scenario, seed: u64, export_pack_path: Option<&Path>) -> ExitCode {
    // Only the minimal scenario ends with a store that seals a record, so it is
    // the only one `--export-pack` accepts; parse_args has already rejected the
    // flag for the others.
    let (text, ok, pack_source) = match scenario {
        Scenario::Minimal => {
            let r = sim::run(seed);
            (r.text, r.sealed_ok, Some((r.b_store, r.o0_id)))
        }
        Scenario::Equivocation => {
            let r = equivocation::run(seed);
            (r.text, r.passed, None)
        }
        Scenario::SealingAblation => {
            let r = sealing_ablation::run(seed);
            (r.text, r.passed, None)
        }
    };
    print!("{text}");

    if let (Some(path), Some((store, claim))) = (export_pack_path, pack_source) {
        if let Err(e) = write_demo_pack(&store, claim, path) {
            eprintln!("vigil-sim: --export-pack failed: {e:#}");
            return ExitCode::FAILURE;
        }
    }

    if ok {
        ExitCode::SUCCESS
    } else {
        eprintln!("invariant violation: an assertion in the scenario did not hold");
        ExitCode::FAILURE
    }
}

/// Export an evidence pack for `claim` from `store` via `vigil-ledger`'s real
/// [`export_pack`] — the same path `testdata/packs/` fixtures come from — and
/// write it to `path`. Prints the org key and the `vigil-verify` line to run.
fn write_demo_pack(store: &MemoryStore, claim: Hash, path: &Path) -> anyhow::Result<()> {
    let org = public_key(&SigningKey::from_bytes(&DEMO_ORG_SEED));
    let pack = export_pack(store, &Quarantine::new(), org, &[claim])
        .context("export_pack over node B's store")?;
    std::fs::write(path, &pack).with_context(|| format!("writing {}", path.display()))?;

    println!();
    println!(
        "pack: exported {} bytes to {} (claim O0 {claim})",
        pack.len(),
        path.display()
    );
    println!("pack org key: {org}");
    println!("verify:       vigil-verify {} {org}", path.display());
    Ok(())
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
///   `minimal`, seed `1`). `--export-pack <path>` additionally exports an
///   evidence pack from the run and is only valid with `--scenario minimal`.
/// - `--scale-up` selects scale-up mode; `--seeds <n>` sets the range
///   (default `1000`). `--scenario` / `--seed` / `--export-pack` are rejected
///   alongside it rather than silently ignored.
fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Mode, String> {
    let mut scenario = Scenario::Minimal;
    let mut seed: u64 = 1;
    let mut scale_up = false;
    let mut seeds: u64 = 1000;
    let mut saw_single_arg = false;
    let mut export_pack: Option<PathBuf> = None;

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
            "--export-pack" => {
                let raw = args.next().ok_or("--export-pack needs a path")?;
                export_pack = Some(PathBuf::from(raw));
                saw_single_arg = true;
            }
            other => return Err(format!("unexpected argument: {other}")),
        }
    }

    if scale_up {
        if saw_single_arg {
            return Err("--scale-up runs every scenario across a seed range; \
                        drop --scenario/--seed/--export-pack (use --seeds to set the range)"
                .into());
        }
        if seeds == 0 {
            return Err("--seeds must be at least 1".into());
        }
        Ok(Mode::ScaleUp { seeds })
    } else {
        if export_pack.is_some() && scenario != Scenario::Minimal {
            return Err("--export-pack is only valid with --scenario minimal — \
                        it is the honest scenario whose resulting store seals a record"
                .into());
        }
        Ok(Mode::Single {
            scenario,
            seed,
            export_pack,
        })
    }
}
