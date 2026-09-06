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
//! [`detect_forks`] scans a [`Store`] for colliding entries and produces a
//! self-verifying [`ForkProof`] per collision. [`Quarantine`] records the keys a
//! validated proof has convicted; [`Dag::build`](crate::Dag::build) consults it
//! so that a quarantined witness's attestations stop sealing (§6.5) and a
//! quarantined author's unwitnessed records are reported `disputed` (§6.4).

use std::collections::{BTreeMap, BTreeSet};

use vigil_core::{CheckedFork, ForkProof, Hash, Object, PubKey, verify_id};

use crate::store::{Store, StoreError};

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

    /// Quarantine the key a validated fork proof convicts
    /// (`spec/02-entanglement.md` §6.4). Taking a [`CheckedFork`] rather than a
    /// raw [`ForkProof`] makes it impossible to quarantine on an unverified
    /// proof. Returns `true` if the key was not already quarantined.
    pub fn apply(&mut self, proof: &CheckedFork) -> bool {
        self.0.insert(proof.key)
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

/// Scan every author's chain for equivocation and return a self-verifying
/// [`ForkProof`] for each distinct collision found (`spec/02-entanglement.md`
/// §6.1).
///
/// A collision is two signature-valid observations by one author that cannot sit
/// in one chain: the same `seq` with different ids, or the same `prev` with
/// different ids. An observation whose signature does not verify under its
/// `author` is ignored — a garbage collision is not attributable.
///
/// The result is deduplicated by proof content address and ordered by it, so two
/// verifiers holding the same objects produce the same list.
///
/// # Errors
///
/// [`StoreError`] if the backend fails.
pub fn detect_forks<S: Store + ?Sized>(store: &S) -> Result<Vec<ForkProof>, StoreError> {
    let mut proofs: BTreeMap<Hash, ForkProof> = BTreeMap::new();

    for author in store.authors()? {
        let entries: Vec<_> = store
            .chain(&author)?
            .into_iter()
            .filter(|so| verify_id(so.observation.author, so.id, &so.signature).is_ok())
            .collect();

        // Bucket by `seq` and by `prev`; a bucket of two or more is a set of
        // mutually conflicting entries.
        let mut by_seq: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        let mut by_prev: BTreeMap<Option<Hash>, Vec<usize>> = BTreeMap::new();
        for (i, so) in entries.iter().enumerate() {
            by_seq.entry(so.observation.seq).or_default().push(i);
            by_prev.entry(so.observation.prev).or_default().push(i);
        }

        for bucket in by_seq.values().chain(by_prev.values()) {
            for (a, &i) in bucket.iter().enumerate() {
                for &j in &bucket[a + 1..] {
                    let (e1, e2) = (&entries[i], &entries[j]);
                    if e1.id == e2.id {
                        continue;
                    }
                    let proof = ForkProof::build(
                        author,
                        &e1.observation,
                        &e1.signature,
                        &e2.observation,
                        &e2.signature,
                    );
                    proofs.entry(proof.id()).or_insert(proof);
                }
            }
        }
    }

    Ok(proofs.into_values().collect())
}
