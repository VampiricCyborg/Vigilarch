//! In-memory [`Store`] — always compiled, no feature flag, no I/O.
//!
//! This is the backend for every test and every `vigil-sim` run: deterministic,
//! fast, and it compiles wherever Rust does, `wasm32-unknown-unknown` included.
//! It is not durable — dropping it drops the ledger.

use std::collections::{BTreeMap, BTreeSet};

use vigil_core::{Attestation, Hash, Object, Observation, PubKey, Seq, Signature};

use crate::store::{ChainHead, Store, StoreError, StoredAttestation, StoredObservation};

/// A [`Store`] backed by ordered maps held in memory.
///
/// Ordered containers throughout, so every listing is deterministic with no
/// sort step: `BTreeMap` and `BTreeSet` iterate ascending, which is the
/// content-address / key order the [`Store`] contract promises.
#[derive(Debug, Default)]
pub struct MemoryStore {
    /// Every observation, keyed by content address.
    observations: BTreeMap<Hash, StoredObservation>,
    /// author → seq → content addresses at that seq. More than one id at a seq
    /// is equivocation, retained per `spec/01-wire-format.md` §6.6.
    chains: BTreeMap<PubKey, BTreeMap<Seq, BTreeSet<Hash>>>,
    /// Every attestation, keyed by content address.
    attestations: BTreeMap<Hash, StoredAttestation>,
    /// subject key → ids of attestations naming it.
    by_subject: BTreeMap<PubKey, BTreeSet<Hash>>,
    /// witness key → ids of attestations it signed.
    by_witness: BTreeMap<PubKey, BTreeSet<Hash>>,
}

impl MemoryStore {
    /// A new, empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The attestations an index points at, in content-address order.
    fn indexed(
        &self,
        index: &BTreeMap<PubKey, BTreeSet<Hash>>,
        key: &PubKey,
    ) -> Vec<StoredAttestation> {
        index
            .get(key)
            .map(|ids| ids.iter().map(|id| self.attestations[id]).collect())
            .unwrap_or_default()
    }
}

impl Store for MemoryStore {
    fn put_observation(
        &mut self,
        observation: &Observation,
        signature: &Signature,
    ) -> Result<Hash, StoreError> {
        let id = observation.id();
        if self.observations.contains_key(&id) {
            return Ok(id);
        }
        self.observations.insert(
            id,
            StoredObservation {
                id,
                observation: observation.clone(),
                signature: *signature,
            },
        );
        self.chains
            .entry(observation.author)
            .or_default()
            .entry(observation.seq)
            .or_default()
            .insert(id);
        Ok(id)
    }

    fn observation(&self, id: &Hash) -> Result<Option<StoredObservation>, StoreError> {
        Ok(self.observations.get(id).cloned())
    }

    fn chain(&self, author: &PubKey) -> Result<Vec<StoredObservation>, StoreError> {
        let Some(seqs) = self.chains.get(author) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for ids in seqs.values() {
            for id in ids {
                out.push(self.observations[id].clone());
            }
        }
        Ok(out)
    }

    fn observations_at(
        &self,
        author: &PubKey,
        seq: Seq,
    ) -> Result<Vec<StoredObservation>, StoreError> {
        Ok(self
            .chains
            .get(author)
            .and_then(|seqs| seqs.get(&seq))
            .map(|ids| ids.iter().map(|id| self.observations[id].clone()).collect())
            .unwrap_or_default())
    }

    fn chain_head(&self, author: &PubKey) -> Result<Option<ChainHead>, StoreError> {
        Ok(self.chains.get(author).and_then(|seqs| {
            seqs.iter().next_back().map(|(&seq, ids)| ChainHead {
                seq,
                id: *ids
                    .iter()
                    .next()
                    .expect("a seq bucket is only created with an entry in it"),
            })
        }))
    }

    fn authors(&self) -> Result<Vec<PubKey>, StoreError> {
        Ok(self.chains.keys().copied().collect())
    }

    fn put_attestation(
        &mut self,
        attestation: &Attestation,
        signature: &Signature,
    ) -> Result<Hash, StoreError> {
        let id = attestation.id();
        if self.attestations.contains_key(&id) {
            return Ok(id);
        }
        self.attestations.insert(
            id,
            StoredAttestation {
                id,
                attestation: *attestation,
                signature: *signature,
            },
        );
        self.by_subject
            .entry(attestation.subject)
            .or_default()
            .insert(id);
        self.by_witness
            .entry(attestation.witness)
            .or_default()
            .insert(id);
        Ok(id)
    }

    fn attestation(&self, id: &Hash) -> Result<Option<StoredAttestation>, StoreError> {
        Ok(self.attestations.get(id).copied())
    }

    fn attestations_for_subject(
        &self,
        subject: &PubKey,
    ) -> Result<Vec<StoredAttestation>, StoreError> {
        Ok(self.indexed(&self.by_subject, subject))
    }

    fn attestations_by_witness(
        &self,
        witness: &PubKey,
    ) -> Result<Vec<StoredAttestation>, StoreError> {
        Ok(self.indexed(&self.by_witness, witness))
    }

    fn all_attestations(&self) -> Result<Vec<StoredAttestation>, StoreError> {
        Ok(self.attestations.values().copied().collect())
    }
}
