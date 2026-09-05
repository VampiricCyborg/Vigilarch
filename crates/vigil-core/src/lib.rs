//! # vigil-core — L0
//!
//! Canonical encoding, content addressing, identity, logical time, and CRDT
//! primitives. Every other crate speaks in the types defined here.
//!
//! Milestone: **M0**. See `docs/VIGILARCH.md` §7 (data model) and §14 (roadmap).
//!
//! ## What this crate owes the rest of the system
//!
//! - A *canonical* CBOR encoding. Two nodes that encode the same object must
//!   produce byte-identical output, on native and under WASM alike — otherwise
//!   content addresses diverge and the ledger silently forks. Golden vectors
//!   live in `testdata/` and are checked from commit one (§16.2).
//! - BLAKE3 content addressing and Ed25519 signing over those bytes.
//! - A hybrid logical clock. Note carefully: the HLC is *best effort and
//!   untrusted*. It is a hint for ordering and merge, never evidence. Temporal
//!   evidence comes from attestations in `vigil-ledger` (§8).
//! - CRDT registers and sets, including the multi-value register that keeps
//!   semantic disagreement visible rather than resolving it (§7.3).

#![forbid(unsafe_code)]

pub mod cbor;
pub mod error;
pub mod object;
pub mod sign;
pub mod types;

pub use error::{DecodeError, SignatureError};
pub use object::{
    Attestation, BlobManifest, Checkpoint, Object, Observation, ObservationBody, PresenceEvent,
    SIG_TAG, domain_sep,
};
pub use sign::{SignedObject, public_key, sign_id, signing_message, verify_id};
pub use types::{GeoPoint, Hash, Hlc, OpaqueId, PubKey, Reading, Seq, Signature, SiteId};

/// The wire version this build speaks (`spec/01-wire-format.md` §7).
///
/// It is part of every domain separation tag, so bumping it changes every content
/// address in history — deliberately, since objects of different wire versions
/// are different objects and must not be conflated (§3.1).
pub const WIRE_VERSION: u32 = 1;
