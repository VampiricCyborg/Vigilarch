//! # vigil-ledger — L2, the entanglement ledger
//!
//! The heart of the project. Append-only storage, per-node hash chains, the
//! attestation DAG, fork detection, and sealing queries.
//!
//! Milestone: **M1**. See `docs/VIGILARCH.md` §8.
//!
//! ## The thesis this crate carries
//!
//! A device clock is a settable field, so a disconnected node's own timestamps
//! are not evidence of anything. Vigilarch replaces the clock with contact:
//! when two nodes meet they co-sign each other's chain head, and each embeds
//! the attestation it received into its own next entry. Proof of time becomes
//! a property of a meeting rather than a property of a clock.
//!
//! ## Rules this crate must never break
//!
//! - Objects here are immutable (invariant #3). Interpretation is L4's job.
//! - `SystemTime::now()` is banned in this crate at lint level — see
//!   `clippy.toml` at the workspace root. All time flows through HLC plus
//!   attestation (§19).
//! - Sealing queries must be *conservative*. Where the attestation DAG does not
//!   prove an ordering, the answer is "unwitnessed", never a guess. Overstating
//!   what we know is the cardinal sin of this system (§16.1, E6).
//! - A detected fork quarantines a key and marks that key's unwitnessed
//!   observations disputed. It never deletes them — they may be true, and the
//!   record of the dispute is itself evidence (§8.5).

#![forbid(unsafe_code)]
