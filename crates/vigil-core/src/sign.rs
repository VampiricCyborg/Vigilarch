//! Ed25519 signatures, per `spec/01-wire-format.md` §4.
//!
//! ```text
//! sig = Ed25519-Sign(sk, "vigilarch/1/sig" || 0x00 || id)
//! ```
//!
//! The signed message is the domain-separated **id**, not the preimage. That
//! keeps it a fixed 48 bytes, which is what lets priority classes 0 and 1 still
//! fit on a 50 byte/s link, and it is safe because the id already commits to the
//! object type through its own separation tag (§3.1) — a signature over one
//! object type's id can never be replayed as a signature over another's.
//!
//! ## Verification is strict, and failure is opaque
//!
//! §4 requires a verifier that rejects non-canonical signature encodings and
//! small-order public keys, so [`verify_id`] uses `verify_strict` rather than
//! `verify`. The permissive path accepts signatures that verify under more than
//! one public key, which would let a witness later disown an attestation it
//! really made.
//!
//! Every failure returns the same unit [`SignatureError`]. Distinguishing "key
//! is not a valid point" from "signature is malformed" from "signature does not
//! verify" hands an attacker a probing oracle and tells an honest operator
//! nothing they can act on.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use crate::error::SignatureError;
use crate::object::{Object, SIG_TAG, domain_sep};
use crate::types::{Hash, PubKey, Signature};

/// The exact 48 bytes that get signed: `"vigilarch/1/sig" || 0x00 || id`.
///
/// Exposed because `vigil-verify` must be able to reconstruct the signed message
/// from a published export pack alone, without linking anything that could have
/// produced the signature.
#[must_use]
pub fn signing_message(id: Hash) -> Vec<u8> {
    domain_sep(SIG_TAG, id.as_bytes())
}

/// Signs a content address.
#[must_use]
pub fn sign_id(sk: &SigningKey, id: Hash) -> Signature {
    Signature(sk.sign(&signing_message(id)).to_bytes())
}

/// Verifies a signature over a content address.
///
/// # Errors
///
/// Returns [`SignatureError`] if the key is not a valid Ed25519 point, the
/// signature is not canonically encoded, or it does not verify. The variants are
/// deliberately not distinguished.
pub fn verify_id(key: PubKey, id: Hash, sig: &Signature) -> Result<(), SignatureError> {
    let vk = VerifyingKey::from_bytes(&key.0).map_err(|_| SignatureError)?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig.0);
    vk.verify_strict(&signing_message(id), &sig)
        .map_err(|_| SignatureError)
}

/// The public half of a signing key, in Vigilarch's own type. A node *is* its
/// device key (§5).
#[must_use]
pub fn public_key(sk: &SigningKey) -> PubKey {
    PubKey(sk.verifying_key().to_bytes())
}

/// Signing and verification for any content-addressed object.
///
/// Blanket-implemented, so no object can opt out of computing its own id before
/// signing. A caller cannot hand this trait a hash it chose itself, which is the
/// same reasoning as §3.2: an id is always recomputed, never supplied.
pub trait SignedObject: Object {
    /// Signs this object's id.
    fn sign(&self, sk: &SigningKey) -> Signature {
        sign_id(sk, self.id())
    }

    /// Verifies a signature against this object's recomputed id.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureError`] on any verification failure.
    fn verify(&self, key: PubKey, sig: &Signature) -> Result<(), SignatureError> {
        verify_id(key, self.id(), sig)
    }
}

impl<T: Object> SignedObject for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::Observation;
    use crate::types::{Hlc, SiteId};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn observation(text: &str) -> Observation {
        Observation {
            author: public_key(&key(1)),
            site: SiteId(*b"VIGILARCH-SITE-A"),
            prev: None,
            seq: 0,
            hlc: Hlc::new(1_700_000_000_000, 0),
            body: crate::object::ObservationBody::Note {
                text: text.to_owned(),
            },
            geo: None,
        }
    }

    #[test]
    fn a_signature_verifies_over_the_object_it_was_made_for() {
        let sk = key(1);
        let obs = observation("shoring on grid B4 is out of plumb");
        let sig = obs.sign(&sk);
        assert!(obs.verify(public_key(&sk), &sig).is_ok());
    }

    #[test]
    fn the_signed_message_is_domain_separated_and_48_bytes() {
        let id = observation("x").id();
        let msg = signing_message(id);
        assert_eq!(msg.len(), SIG_TAG.len() + 1 + 32);
        assert_eq!(msg.len(), 48, "§4 fixes the signed message at 48 bytes");
        assert_eq!(&msg[..SIG_TAG.len()], SIG_TAG.as_bytes());
        assert_eq!(msg[SIG_TAG.len()], 0x00);
        assert_eq!(&msg[SIG_TAG.len() + 1..], id.as_bytes());
    }

    #[test]
    fn a_signature_over_the_bare_id_does_not_verify() {
        // If it did, domain separation would be decorative and a signature could
        // be replayed across hash contexts.
        let sk = key(1);
        let obs = observation("x");
        let bare = Signature(sk.sign(obs.id().as_bytes()).to_bytes());
        assert!(obs.verify(public_key(&sk), &bare).is_err());
    }

    #[test]
    fn editing_any_field_invalidates_the_signature() {
        let sk = key(1);
        let obs = observation("shoring on grid B4 is out of plumb");
        let sig = obs.sign(&sk);

        // I3: capture is immutable. This is what enforces it cryptographically —
        // a "corrected" observation is a different object with a different id,
        // and the old signature does not travel to it.
        let edited = observation("shoring on grid B4 is fine");
        assert!(edited.verify(public_key(&sk), &sig).is_err());
    }

    #[test]
    fn another_key_cannot_claim_the_signature() {
        let obs = observation("x");
        let sig = obs.sign(&key(1));
        assert!(obs.verify(public_key(&key(2)), &sig).is_err());
    }

    #[test]
    fn a_malformed_key_or_signature_is_an_error_and_never_a_panic() {
        let obs = observation("x");
        // Not a valid curve point.
        assert!(obs.verify(PubKey([0xff; 32]), &Signature([0; 64])).is_err());
        // Valid key, garbage signature.
        assert!(
            obs.verify(public_key(&key(1)), &Signature([0xff; 64]))
                .is_err()
        );
    }
}
