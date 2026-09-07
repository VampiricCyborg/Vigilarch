//! `vigil-verify <pack> <org-pubkey>` — the CLI wrapper around
//! [`vigil_verify::verify`].
//!
//! The invocation matches `spec/03-export-pack.md` §5's own header. It reads the
//! pack file, runs the §5 six-step procedure with `vigil-verify`'s own code
//! (never `vigil-ledger`), prints the [`Report`](vigil_verify::Report), and
//! exits:
//!
//! - `0` — every claim reproduced from the pack's own evidence;
//! - `1` — a claim failed to reproduce (an object failed its self-check, a chain
//!   is `Violated`, an attestation anchors nothing, a fork proof convicts a key
//!   the pack depends on, or a claim could not be bracketed) — the report names
//!   which;
//! - `2` — the pack is structurally malformed, is not wire version 1, or is
//!   issued for a different organisation than the one asked about.

use std::process::ExitCode;

use anyhow::{Context, bail};
use vigil_core::PubKey;
use vigil_verify::verify;

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("vigil-verify: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> anyhow::Result<ExitCode> {
    let mut args = std::env::args_os().skip(1);
    let (Some(pack_arg), Some(org_arg), None) = (args.next(), args.next(), args.next()) else {
        bail!(
            "usage: vigil-verify <pack> <org-pubkey>\n\n\
               <pack>        path to an export pack file (spec/03-export-pack.md)\n\
               <org-pubkey>  the issuing organisation's Ed25519 public key, 64 hex chars"
        );
    };

    let pack_path = std::path::PathBuf::from(&pack_arg);
    let pack_bytes = std::fs::read(&pack_path)
        .with_context(|| format!("reading pack file {}", pack_path.display()))?;

    let org = parse_pubkey(&org_arg.to_string_lossy()).context("parsing <org-pubkey>")?;

    match verify(&pack_bytes, org) {
        Ok(report) => {
            print!("{report}");
            Ok(ExitCode::from(
                u8::try_from(report.exit_code()).unwrap_or(1),
            ))
        }
        Err(e) => {
            // A structural rejection: the file is not a wire-version-1 pack for
            // this organisation. Distinct exit code from a claim that failed to
            // reproduce.
            eprintln!("vigil-verify: pack rejected at spec/03 §5 step 1: {e}");
            Ok(ExitCode::from(2))
        }
    }
}

fn parse_pubkey(s: &str) -> anyhow::Result<PubKey> {
    let s = s.trim();
    let bytes = hex::decode(s).context("<org-pubkey> is not valid hex")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("<org-pubkey> is {} bytes, expected 32", bytes.len()))?;
    Ok(PubKey(arr))
}
