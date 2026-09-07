//! Export-pack fixture generator.
//!
//! Writes the `spec/03-export-pack.md` §6 worked pack and its tamper variants to
//! `testdata/packs/`. Run with `cargo run -p vigil-ledger --example gen_packs`.
//!
//! Like the golden-vector generator, this is deterministic and CI regenerates
//! then diffs: a change to a checked-in `.vgl` file that is not reflected here is
//! a spec change and must not pass silently. The honest pack is additionally
//! pinned, byte-for-byte, against the hand-built golden vector
//! `testdata/vectors/pack-worked-example.json` by `tests/export.rs`.

#[path = "../testsupport/pack_scenarios.rs"]
mod pack_scenarios;

use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/packs");
    std::fs::create_dir_all(&dir).expect("create testdata/packs");

    for (name, bytes) in pack_scenarios::all_fixtures() {
        std::fs::write(dir.join(name), &bytes).unwrap_or_else(|e| panic!("write {name}: {e}"));
        println!("{name:<24} {} bytes", bytes.len());
    }
    println!(
        "fork-witness proof convicts {}",
        pack_scenarios::fork_witness_proof_key()
    );
}
