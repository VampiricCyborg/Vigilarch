//! Fork detection, `ForkProof` construction, and quarantine
//! (`spec/02-entanglement.md` §6).
//!
//! A fork is two valid observations by one author that cannot sit in one chain:
//! the same `seq` with different ids, or the same `prev` with different ids
//! (`spec/01-wire-format.md` §6.1). It is cryptographic proof that the holder of
//! that key signed two irreconcilable histories, and it is the one thing in this
//! system that justifies acting against a key rather than merely reporting a
//! wide unwitnessed window.
//!
//! Detection lands in a later commit. This module currently carries only
//! [`Quarantine`], which [`Dag::build`](crate::Dag::build) consults so that a
//! quarantined witness's attestations stop sealing (§6.5).

use std::collections::BTreeSet;

use vigil_core::PubKey;

/// The set of keys a validated [`ForkProof`](vigil_core::ForkProof) has shown to
/// equivocate (`spec/02-entanglement.md` §6.4).
///
/// Quarantine changes what the DAG does with a key, never what the store keeps:
///
/// - attestations **by** a quarantined witness are disregarded for sealing from
///   then on, but are retained (§6.5);
/// - honest attestations **about** a quarantined subject still seal that
///   subject's honest records — a liar's earlier true history does not become
///   unprovable because they later lied;
/// - a quarantined key's own unwitnessed observations are reported `disputed`,
///   never deleted; they may be true and the dispute record is itself evidence
///   (§6.4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Quarantine(BTreeSet<PubKey>);

impl Quarantine {
    /// An empty quarantine — the ordinary state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark `key` quarantined. Returns `true` if it was not already.
    pub fn insert(&mut self, key: PubKey) -> bool {
        self.0.insert(key)
    }

    /// Whether `key` is quarantined.
    #[must_use]
    pub fn contains(&self, key: &PubKey) -> bool {
        self.0.contains(key)
    }

    /// Whether no key is quarantined.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The quarantined keys, ascending by key bytes.
    pub fn keys(&self) -> impl Iterator<Item = &PubKey> {
        self.0.iter()
    }
}
