//! # vigil-verify
//!
//! An independent verifier. Given only an export pack and the organisation's
//! public key, it reproduces every ordering claim the pack makes and exits
//! nonzero if any of them fails to hold.
//!
//! Milestone: **M8-lite**. See `claude.md` (scope) and `docs/VIGILARCH.md` §14 M8,
//! whose acceptance criterion is precisely this binary.
//!
//! ## Why this crate exists
//!
//! Every other artifact in this repository asserts that the ledger is sound.
//! This one demonstrates it, to someone who trusts none of the code that
//! produced the pack. That makes it the highest-credibility thing the project
//! ships: a regulator, an auditor, or a sceptical reader can run it against a
//! pack they were handed and get a yes or no that does not depend on taking
//! Vigilarch's word for anything.
//!
//! ## The independence rule
//!
//! This binary must depend on `vigil-core` for the canonical encoding and on
//! nothing else in the workspace. In particular it must **not** link
//! `vigil-ledger`.
//!
//! The reason is that a verifier which reuses the ledger's own traversal,
//! sealing and fork-detection code cannot detect a bug in that code — it will
//! reproduce the same wrong answer with great confidence and call it agreement.
//! The verifier re-derives ordering from the attestation DAG in the pack using
//! its own independent traversal. Sharing `vigil-core` is the deliberate
//! exception, and it is not a weakening of the guarantee: architectural
//! invariant #2 requires exactly one implementation of the canonical encoding,
//! and the golden vectors in `testdata/` are what hold that implementation
//! honest. Re-deriving the encoding here would create the second implementation
//! that invariant exists to forbid.
//!
//! If you find yourself adding `vigil-ledger` to this crate's dependencies to
//! avoid duplicating a traversal, stop: that duplication is the product.
//!
//! ## What it must check
//!
//! - Every object's content address recomputes from its canonical preimage.
//!   The `id` in the pack is never trusted (`spec/01-wire-format.md` §3).
//! - Every signature verifies against the claimed author key, and every author
//!   key chains to the org key supplied on the command line.
//! - Every per-node hash chain is unbroken: each entry's `prev` is the previous
//!   entry's recomputed id, with no gaps in `seq`.
//! - Every attestation in the DAG is well-formed and signed by its witness.
//! - Every ordering claim the pack states is re-derived from that DAG
//!   independently — and where the DAG does not prove an ordering, the verifier
//!   reports **unwitnessed** rather than guessing. A verifier that overstates
//!   what the evidence shows is worse than no verifier, because it launders an
//!   unproven claim into an apparently independent confirmation.
//! - Witness latency per record is reported honestly, including when it is
//!   unbounded.
//!
//! ## Exit codes
//!
//! `0` every claim reproduced. `1` a claim failed to reproduce, or the pack is
//! malformed. Nonzero is the load-bearing behaviour: this binary is meant to be
//! run in someone else's CI against a pack we did not produce.

fn main() {
    println!(
        "vigil-verify: scaffold only — see docs/VIGILARCH.md §14 M8 for the acceptance criterion"
    );
}
