//! # vigil-sync — L3
//!
//! Range-based set reconciliation over a Merkle search tree, priority classes,
//! resumable transfer, and sneakernet bundle framing.
//!
//! Milestone: **M2**. See `docs/VIGILARCH.md` §9.
//!
//! ## Design constraints
//!
//! - Naive version-vector diffing is explicitly rejected: it degrades badly
//!   when nodes have never met and when vectors grow with node count (§9.1).
//! - Every exchange is resumable. Links die mid-sync constantly, and a 400 MB
//!   photo transfer must never restart from zero.
//! - Bandwidth spans six orders of magnitude, from a 10 Gb LAN to a 50 byte/s
//!   LoRa link to a USB stick with six-hour latency. Everything is classed, and
//!   a link carries only what it can (§9.2). Knowledge degrades gracefully: a
//!   starved link still conveys *that* something happened, *where*, and *when
//!   relative to what*, long before it can convey *what*.
//! - The wire format is versioned from commit one and negotiated on every
//!   connection. A protocol change that ships to half the fleet and cannot be
//!   rolled back is the worst failure mode this system has (§13).

#![forbid(unsafe_code)]
