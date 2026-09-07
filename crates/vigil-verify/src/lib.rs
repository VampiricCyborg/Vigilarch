//! # vigil-verify
//!
//! An independent verifier. Given only an export pack and the organisation's
//! public key, it reproduces every ordering claim the pack makes and exits
//! nonzero if any of them fails to hold.
//!
//! Milestone: **M1**. See `CLAUDE.md` (deliverable 5) and
//! `spec/03-export-pack.md` §5, whose ordered six-step procedure this crate
//! implements.
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
//! This crate depends on `vigil-core` for the canonical encoding and on nothing
//! else in the workspace. In particular it does **not** link `vigil-ledger` —
//! not as a dependency and not as a dev-dependency.
//!
//! The reason is that a verifier which reuses the ledger's own traversal,
//! sealing and fork-detection code cannot detect a bug in that code — it will
//! reproduce the same wrong answer with great confidence and call it agreement.
//! So [`chain`], [`dag`] and [`bracket`] here are second implementations of
//! logic that also exists in `vigil-ledger`, written from the specification
//! text, and [`pack`] is a second pack parser. Sharing `vigil-core` is the
//! deliberate exception and not a weakening: invariant I2 requires exactly one
//! implementation of the canonical encoding, and the golden vectors in
//! `testdata/` are what hold it honest. Re-deriving the encoding here would
//! create the second implementation that invariant exists to forbid.
//!
//! If you find yourself adding `vigil-ledger` to this crate's dependencies to
//! avoid duplicating a traversal, stop: that duplication is the product. The
//! `testdata/packs/` fixtures are static files, and the expected verdicts this
//! crate is cross-checked against (`testdata/packs/expected/`) are generated
//! ahead of time by a `vigil-ledger` example, then checked in — not produced by
//! linking the ledger into a test here.
//!
//! ## What it checks — `spec/03-export-pack.md` §5, in order
//!
//! 1. **Envelope.** File marker; strict `spec/01` §2.1 / §8 CBOR decode with
//!    total rejection on any violation; `wire_version == 1`; `org` equals the
//!    argument.
//! 2. **Per-object self-check.** Recompute `id = BLAKE3(preimage)`, decode the
//!    preimage, verify the detached signature — under `author` for an
//!    observation, `witness` for an attestation. A failure discards the object;
//!    the verifier records that the pack contained an invalid object.
//! 3. **Fork proofs.** Validate each `ForkProof` self-contained; a valid one
//!    quarantines its key for the rest of the run.
//! 4. **Chain check per author.** The `spec/01` §6.6 three-outcome check over
//!    exactly the carried segment — `Verified` / `Incomplete` / `Violated`. A
//!    low missing `seq` (`spec/03` §3.5) is `Incomplete`, never `Violated`.
//! 5. **DAG construction** over the surviving objects, dropping seal edges from
//!    any quarantined witness.
//! 6. **Bracket recomputation** for each claimed id: sealed / unwitnessed, upper
//!    bound, witness depth, lower bound, the unwitnessed window with the
//!    genesis / earliest-held / verification-moment cases handled per §3.5, and
//!    any fork proof touching the claim.
//!
//! ## Exit codes
//!
//! `0` every claim reproduced. `1` a claim failed to reproduce. `2` the pack is
//! structurally malformed or is for a different organisation. Nonzero is the
//! load-bearing behaviour: this binary is meant to be run in someone else's CI
//! against a pack we did not produce.

#![forbid(unsafe_code)]

pub mod bracket;
pub mod chain;
pub mod dag;
pub mod pack;
pub mod report;

pub use bracket::{AuthorSegment, Bracket, UnwitnessedWindow, WindowEdge};
pub use chain::{ChainEntry, ChainVerification, ChainViolation};
pub use dag::{Dag, DagNode, SealStatus};
pub use pack::{CarriedObject, PACK_MARKER, PackContents, PackParseError, SelfCheck, parse_pack};
pub use report::{
    ClaimOutcome, ClaimReport, ForkKind, InvalidObject, ObjectKind, Report, UnanchoredAttestation,
    verify,
};
