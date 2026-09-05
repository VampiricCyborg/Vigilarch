//! The storage abstraction the ledger is built on.
//!
//! Observations and their per-author chains, attestations and their indexes —
//! everything the ledger persists goes through the [`Store`] trait. No code
//! above this trait names a concrete backend.
//!
//! ## Why the trait exists (invariant I2)
//!
//! The ledger and its attestation logic are written once and must stay
//! compilable to `wasm32-unknown-unknown`. `rusqlite` bundles a C SQLite that
//! does not cross-compile there, so it sits behind the `sqlite` feature, and
//! [`MemoryStore`](crate::MemoryStore) — pure Rust, always available — is the
//! backend every test and every `vigil-sim` run uses. Chain traversal, DAG
//! construction, bracketing and fork detection are implemented against `Store`,
//! never against a database, so that a second backend is a drop-in rather than
//! a rewrite.
//!
//! ## The trait is persistence, not policy
//!
//! A `Store` records what it is given and hands it back. It does **not** verify
//! signatures, enforce the chain rule (`seq`/`prev` continuity,
//! `spec/01-wire-format.md` §6.6), detect forks, or reject implausible input.
//! Those are the ledger's job, above this line. Two consequences worth stating:
//!
//! - **Equivocation is stored, not refused.** Two observations by one author at
//!   one `seq` both persist, and both come back from [`Store::observations_at`].
//!   A signed self-contradiction is the most valuable object the system can
//!   hold (§6.6); the store is not where it gets dropped.
//! - **Gaps are normal.** A chain may hold `seq` 0 and 2 with nothing at 1.
//!   That is the ordinary state under partition, not an error.
//!
//! ## Append-only
//!
//! There is no method that mutates or deletes a stored object. Objects are
//! content-addressed (`id = BLAKE3(preimage)`), so "changing" one yields a
//! different id and leaves the original in place. Re-storing an id that is
//! already held is an idempotent success — the first write wins, including for
//! the accompanying signature, because the store does not judge which of two
//! signatures over one id is the right one.
//!
//! ## Determinism
//!
//! Every listing method returns results in a fixed order — by key bytes, then
//! `seq`, then content address — and never leaks insertion order. `vigil-sim`
//! requires byte-identical runs from a seed, and a store that ordered results
//! by insertion would break that silently.

use vigil_core::{Attestation, Hash, Observation, PubKey, Seq, Signature};

/// A stored observation: the object, the signature that accompanied it, and the
/// content address recomputed from the object itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredObservation {
    pub id: Hash,
    pub observation: Observation,
    pub signature: Signature,
}

/// A stored attestation: the object, its witness signature, and its recomputed
/// content address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredAttestation {
    pub id: Hash,
    pub attestation: Attestation,
    pub signature: Signature,
}

/// The furthest point reached in one author's chain: the highest `seq` the
/// store holds for that author, and the content address of an observation at
/// that `seq`.
///
/// If the author equivocated at their head `seq`, `id` is the lowest of the
/// competing content addresses and the caller must consult
/// [`Store::observations_at`] to see the fork. Resolving that is fork
/// detection's job, not the store's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainHead {
    pub id: Hash,
    pub seq: Seq,
}

/// A failure in the storage backend itself — not a rejection of the caller's
/// data, which the store does not judge.
///
/// [`MemoryStore`](crate::MemoryStore) does not produce these in practice; the
/// type exists so that a fallible backend (SQLite now, an OPFS-backed WASM
/// store later) fits the same trait without changing a signature.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The backend could not complete an operation. The string is for an
    /// operator's log, not for branching on.
    #[error("storage backend failure: {0}")]
    Backend(String),

    #[cfg(feature = "sqlite")]
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

/// Append-only persistence for observations, per-author chains, and
/// attestations. See the [module docs](self) for the persistence-not-policy
/// contract and the determinism guarantee.
///
/// Writing methods take `&mut self`; reading methods take `&self`. The trait is
/// object-safe: `Box<dyn Store>` is usable where a node's backend is chosen at
/// runtime.
pub trait Store {
    // --- Observations and chains --------------------------------------------

    /// Persist an observation and the signature that came with it, returning
    /// the content address recomputed from the object. An id is never taken
    /// from a caller (`spec/01-wire-format.md` §3.2).
    ///
    /// Idempotent: storing an object whose id is already held changes nothing
    /// and returns that id. The store does not verify `signature`.
    fn put_observation(
        &mut self,
        observation: &Observation,
        signature: &Signature,
    ) -> Result<Hash, StoreError>;

    /// The stored observation with this id, or `Ok(None)` if it is not held.
    fn observation(&self, id: &Hash) -> Result<Option<StoredObservation>, StoreError>;

    /// Every observation held for one author, ascending by `seq`. Gaps are
    /// preserved; an equivocated `seq` yields more than one entry, ordered by
    /// content address. Empty if the author is unknown.
    fn chain(&self, author: &PubKey) -> Result<Vec<StoredObservation>, StoreError>;

    /// Every observation this author has stored at exactly `seq`. More than one
    /// entry means the author signed conflicting observations at that position
    /// — retained, per §6.6, as attributable evidence.
    fn observations_at(
        &self,
        author: &PubKey,
        seq: Seq,
    ) -> Result<Vec<StoredObservation>, StoreError>;

    /// The head of this author's chain — the highest `seq` held — or `Ok(None)`
    /// if no observation by this author is stored.
    fn chain_head(&self, author: &PubKey) -> Result<Option<ChainHead>, StoreError>;

    /// Every author with at least one stored observation, ascending by key
    /// bytes.
    fn authors(&self) -> Result<Vec<PubKey>, StoreError>;

    // --- Attestations ------------------------------------------------------

    /// Persist an attestation and its witness signature, returning the
    /// recomputed content address. Idempotent, like
    /// [`put_observation`](Store::put_observation).
    fn put_attestation(
        &mut self,
        attestation: &Attestation,
        signature: &Signature,
    ) -> Result<Hash, StoreError>;

    /// The stored attestation with this id, or `Ok(None)`.
    fn attestation(&self, id: &Hash) -> Result<Option<StoredAttestation>, StoreError>;

    /// Attestations whose `subject` is this key, ordered by content address.
    fn attestations_for_subject(
        &self,
        subject: &PubKey,
    ) -> Result<Vec<StoredAttestation>, StoreError>;

    /// Attestations whose `witness` is this key, ordered by content address.
    fn attestations_by_witness(
        &self,
        witness: &PubKey,
    ) -> Result<Vec<StoredAttestation>, StoreError>;

    /// Every stored attestation, ordered by content address. The raw material
    /// for building the attestation DAG.
    fn all_attestations(&self) -> Result<Vec<StoredAttestation>, StoreError>;
}
