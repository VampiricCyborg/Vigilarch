//! Attestation ingest (`spec/02-entanglement.md` §3.3).
//!
//! The [`Store`] persists any attestation it is handed; it does not verify
//! signatures. This is the one gate above it: an attestation whose signature
//! does not verify under its `witness` contributes nothing and is never stored
//! (`spec/01-wire-format.md` §8). An attestation that does verify is stored, and
//! the caller is told whether the `(witness, nonce)` pair already named a
//! *different* object — which is an integrity finding against the witness, kept
//! rather than dropped (§3.3).

use vigil_core::{Attestation, Hash, Object, PubKey, Signature, verify_id};

use crate::store::{Store, StoreError};

/// What [`ingest_attestation`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestOutcome {
    /// The attestation verified and was newly stored.
    Stored(Hash),
    /// The exact object was already held. Idempotent, nothing changed.
    AlreadyHeld(Hash),
    /// The witness has signed a *different* attestation under this same
    /// `nonce` (`spec/02-entanglement.md` §3.3). Both are retained — the pair is
    /// attributable evidence against the witness — and this names them.
    WitnessConflict {
        witness: PubKey,
        nonce: [u8; 16],
        /// The id already held under `(witness, nonce)`.
        held: Hash,
        /// The id of the conflicting attestation just stored.
        incoming: Hash,
    },
}

/// Why an attestation was not ingested.
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    /// The signature does not verify under `witness`. The frame is discarded and
    /// contributes nothing (`spec/02-entanglement.md` §3.3).
    #[error("attestation signature does not verify under its witness (spec/02 §3.3)")]
    BadSignature,

    /// The storage backend failed — nothing to do with the caller's data.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Verify an attestation under its `witness` and, on success, store it.
///
/// # Errors
///
/// [`IngestError::BadSignature`] if the signature does not verify (nothing is
/// stored); [`IngestError::Store`] if the backend fails.
pub fn ingest_attestation<S: Store + ?Sized>(
    store: &mut S,
    attestation: &Attestation,
    signature: &Signature,
) -> Result<IngestOutcome, IngestError> {
    let id = attestation.id();
    verify_id(attestation.witness, id, signature).map_err(|_| IngestError::BadSignature)?;

    // `(witness, nonce)` is the deduplication key (spec/02 §3.3). Same pair and
    // same content is the same object; same pair, different content is an
    // integrity finding — retained, not dropped.
    let mut conflict = None;
    for held in store.attestations_by_witness(&attestation.witness)? {
        if held.attestation.nonce == attestation.nonce {
            if held.id == id {
                return Ok(IngestOutcome::AlreadyHeld(id));
            }
            conflict = Some(held.id);
            break;
        }
    }

    let incoming = store.put_attestation(attestation, signature)?;
    Ok(match conflict {
        Some(held) => IngestOutcome::WitnessConflict {
            witness: attestation.witness,
            nonce: attestation.nonce,
            held,
            incoming,
        },
        None => IngestOutcome::Stored(incoming),
    })
}
