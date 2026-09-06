//! Property tests over the decoder, per `spec/01-wire-format.md` §8.
//!
//! The node parses signed input from devices it does not control, so this is the
//! attack surface. §8 states the requirement plainly: *never panic*, and a panic
//! found by a fuzzer is a bug of the same severity as accepting a bad signature.
//!
//! These are property tests rather than a coverage-guided fuzzer. A `cargo-fuzz`
//! target belongs here too and is a better tool for finding deep structural bugs,
//! but it needs a nightly toolchain and does not run in this workspace's CI, and
//! an unrun fuzzer proves nothing. What runs on every commit is worth more than
//! what runs once. The properties below are the ones a fuzzer would be checking
//! for anyway:
//!
//! 1. **No input panics.** Arbitrary bytes, and near-miss mutations of real
//!    vectors, produce `Ok` or `Err` — never an abort.
//! 2. **Rejection is total.** There is no partially populated object on the error
//!    path; the API cannot express one.
//! 3. **Encode/decode round-trip.** Anything the encoder produces, the decoder
//!    accepts and recovers exactly.
//! 4. **Canonical form is a bijection.** Anything the decoder accepts re-encodes
//!    to the identical bytes. This is the property that matters most: if the
//!    decoder accepted some non-canonical spelling of an object, two nodes could
//!    hold the same object under two content addresses, which is the silent fork
//!    §1 exists to prevent.
//!
//! Native-only. `proptest` pulls in `wait-timeout`, which does not build for
//! `wasm32`, and the cross-target obligation is on the golden vectors (see
//! `vectors.rs`), which do run under WASM.

#![cfg(not(target_family = "wasm"))]

use std::collections::BTreeSet;

use proptest::prelude::*;
use vigil_core::{
    Attestation, BlobManifest, Checkpoint, ForkEntry, ForkProof, GeoPoint, Hash, Hlc, Object,
    Observation, ObservationBody, OpaqueId, PresenceEvent, PubKey, Reading, Signature, SiteId,
};

/// Runs every decoder over the same bytes. A panic in any of them fails the test;
/// the return values are deliberately ignored, because *which* error comes back
/// is not the property under test — only that one does.
fn decode_all(bytes: &[u8]) {
    let _ = Observation::decode_cbor(bytes);
    let _ = Attestation::decode_cbor(bytes);
    let _ = Checkpoint::decode_cbor(bytes);
    let _ = BlobManifest::decode_cbor(bytes);
    let _ = ForkProof::decode_cbor(bytes);
    let _ = Observation::decode_preimage(bytes);
    let _ = Attestation::decode_preimage(bytes);
    let _ = Checkpoint::decode_preimage(bytes);
    let _ = BlobManifest::decode_preimage(bytes);
    let _ = ForkProof::decode_preimage(bytes);
    // A ForkProof carries Observation preimages; feeding it its own check path
    // over arbitrary bytes must also never panic.
    if let Ok(fp) = ForkProof::decode_cbor(bytes) {
        let _ = fp.check();
    }
}

// --- Generators ---------------------------------------------------------------

fn arb_hash() -> impl Strategy<Value = Hash> {
    any::<[u8; 32]>().prop_map(Hash)
}

fn arb_pubkey() -> impl Strategy<Value = PubKey> {
    any::<[u8; 32]>().prop_map(PubKey)
}

fn arb_opaque() -> impl Strategy<Value = OpaqueId> {
    any::<[u8; 16]>().prop_map(OpaqueId)
}

fn arb_hlc() -> impl Strategy<Value = Hlc> {
    (any::<u64>(), any::<u64>()).prop_map(|(w, c)| Hlc::new(w, c))
}

/// Full-range microdegrees and accuracy, including negatives and the boundary
/// values — the quantities §2.2 forbids encoding as floats.
fn arb_geo() -> impl Strategy<Value = GeoPoint> {
    (any::<i32>(), any::<i32>(), any::<u32>()).prop_map(|(lat_udeg, lon_udeg, acc_mm)| GeoPoint {
        lat_udeg,
        lon_udeg,
        acc_mm,
    })
}

/// Every body variant the spec pins. Variants 3 (`Form`) and 6 (`Heartbeat`) are
/// absent because their payloads are unspecified and `vigil-core` rejects them
/// rather than guessing an encoding.
fn arb_body() -> impl Strategy<Value = ObservationBody> {
    prop_oneof![
        any::<String>().prop_map(|text| ObservationBody::Note { text }),
        (any::<String>(), arb_hash())
            .prop_map(|(transcript, audio)| ObservationBody::Voice { transcript, audio }),
        (arb_hash(), any::<u64>(), any::<Option<String>>()).prop_map(|(blob, kind, caption)| {
            ObservationBody::Media {
                blob,
                kind,
                caption,
            }
        }),
        (arb_opaque(), any::<i64>(), any::<i64>()).prop_map(|(source, mantissa, exponent)| {
            ObservationBody::Sensor {
                source,
                reading: Reading { mantissa, exponent },
            }
        }),
        (arb_opaque(), arb_opaque(), any::<bool>()).prop_map(|(actor, zone, enter)| {
            ObservationBody::Presence {
                actor,
                zone,
                event: if enter {
                    PresenceEvent::Enter
                } else {
                    PresenceEvent::Exit
                },
            }
        }),
    ]
}

fn arb_acks() -> impl Strategy<Value = BTreeSet<Hash>> {
    proptest::collection::vec(arb_hash(), 0..4).prop_map(|v| v.into_iter().collect())
}

fn arb_observation() -> impl Strategy<Value = Observation> {
    (
        arb_pubkey(),
        any::<[u8; 16]>(),
        proptest::option::of(arb_hash()),
        any::<u64>(),
        arb_hlc(),
        arb_body(),
        proptest::option::of(arb_geo()),
        arb_acks(),
    )
        .prop_map(
            |(author, site, prev, seq, hlc, body, geo, acks)| Observation {
                author,
                site: SiteId(site),
                prev,
                seq,
                hlc,
                body,
                geo,
                acks,
            },
        )
}

fn arb_signature() -> impl Strategy<Value = Signature> {
    any::<[u8; 64]>().prop_map(Signature)
}

/// A structurally well-formed `ForkProof` over arbitrary preimage bytes and
/// signatures. It almost never passes `check()` — that is not the point; the
/// point is that decode and re-encode round-trip regardless.
fn arb_forkproof() -> impl Strategy<Value = ForkProof> {
    (
        arb_pubkey(),
        proptest::collection::vec(any::<u8>(), 0..80),
        arb_signature(),
        proptest::collection::vec(any::<u8>(), 0..80),
        arb_signature(),
    )
        .prop_map(|(key, pa, sa, pb, sb)| ForkProof {
            key,
            a: ForkEntry {
                preimage: pa,
                sig: sa,
            },
            b: ForkEntry {
                preimage: pb,
                sig: sb,
            },
        })
}

fn arb_attestation() -> impl Strategy<Value = Attestation> {
    (
        arb_pubkey(),
        arb_pubkey(),
        arb_hash(),
        any::<u64>(),
        arb_hlc(),
        any::<[u8; 16]>(),
    )
        .prop_map(
            |(witness, subject, subject_head, subject_seq, witness_hlc, nonce)| Attestation {
                witness,
                subject,
                subject_head,
                subject_seq,
                witness_hlc,
                nonce,
            },
        )
}

fn arb_checkpoint() -> impl Strategy<Value = Checkpoint> {
    (
        arb_pubkey(),
        arb_hash(),
        any::<u64>(),
        arb_hlc(),
        proptest::collection::hash_map(any::<[u8; 32]>(), any::<u64>(), 0..6),
    )
        .prop_map(|(node, head, seq, hlc, frontier)| Checkpoint {
            node,
            head,
            seq,
            hlc,
            // Collected into a `BTreeMap`, so ordering and uniqueness hold by
            // construction. That the *type* carries the invariant is the point:
            // the earlier `Vec` let this generator build two unequal checkpoints
            // with one content address, and this test is what caught it.
            frontier: frontier.into_iter().map(|(k, v)| (PubKey(k), v)).collect(),
        })
}

fn arb_blob_manifest() -> impl Strategy<Value = BlobManifest> {
    (
        any::<u64>(),
        proptest::collection::vec(arb_hash(), 0..8),
        any::<String>(),
    )
        .prop_map(|(size, chunks, mime)| BlobManifest { size, chunks, mime })
}

// --- Properties ---------------------------------------------------------------

/// Round trip, and canonical form as a bijection, for one object type.
fn round_trip<T>(obj: &T) -> Result<(), TestCaseError>
where
    T: Object + PartialEq + core::fmt::Debug,
{
    let cbor = obj.canonical_cbor();

    let decoded = T::decode_cbor(&cbor).map_err(|e| {
        TestCaseError::fail(format!("encoder produced bytes it cannot decode: {e}"))
    })?;
    prop_assert_eq!(&decoded, obj, "decode did not recover the object");

    // Re-encoding must be byte-identical. Anything else means two spellings of
    // one object, and therefore two content addresses for it.
    prop_assert_eq!(
        hex::encode(decoded.canonical_cbor()),
        hex::encode(&cbor),
        "re-encoding changed the bytes"
    );
    prop_assert_eq!(decoded.id(), obj.id(), "content address is not stable");

    // The preimage path agrees with the CBOR path.
    let from_preimage = T::decode_preimage(&obj.preimage())
        .map_err(|e| TestCaseError::fail(format!("preimage does not decode: {e}")))?;
    prop_assert_eq!(&from_preimage, obj, "preimage decode lost something");

    Ok(())
}

proptest! {
    /// §8 — arbitrary bytes never panic. Short inputs are weighted in because
    /// truncation bugs live at the head-parsing boundary, not deep in a frame.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
        decode_all(&bytes);
    }

    /// Bytes drawn from the alphabet that actually appears in CBOR heads. Uniform
    /// random bytes almost never form a valid head, so they exercise the first
    /// rejection and stop; this reaches deeper into the structure.
    #[test]
    fn plausible_cbor_never_panics(
        bytes in proptest::collection::vec(
            prop_oneof![
                // Head bytes across every major type and argument width.
                any::<u8>(),
                Just(0xa1u8), Just(0xa6), Just(0x82), Just(0x58), Just(0x20),
                Just(0x50), Just(0x40), Just(0x1b), Just(0x9f), Just(0xff),
                Just(0xf6), Just(0xfb), Just(0xc0), Just(0x00), Just(0x01),
            ],
            0..300,
        )
    ) {
        decode_all(&bytes);
    }

    /// Near misses: a real object with one byte changed. These reach far deeper
    /// than random input, because the frame stays structurally plausible.
    #[test]
    fn single_byte_mutations_never_panic(
        obs in arb_observation(),
        index in any::<prop::sample::Index>(),
        delta in 1u8..=255,
    ) {
        let mut bytes = obs.canonical_cbor();
        let i = index.index(bytes.len());
        bytes[i] = bytes[i].wrapping_add(delta);
        decode_all(&bytes);
    }

    /// Truncation at every offset. A decoder that reads past its input, or that
    /// trusts a length header, fails here.
    #[test]
    fn truncation_at_any_offset_never_panics(
        obs in arb_observation(),
        index in any::<prop::sample::Index>(),
    ) {
        let bytes = obs.canonical_cbor();
        let cut = index.index(bytes.len() + 1);
        decode_all(&bytes[..cut]);
    }

    #[test]
    fn observations_round_trip(obs in arb_observation()) {
        round_trip(&obs)?;
    }

    #[test]
    fn attestations_round_trip(att in arb_attestation()) {
        round_trip(&att)?;
    }

    #[test]
    fn checkpoints_round_trip(cp in arb_checkpoint()) {
        round_trip(&cp)?;
    }

    #[test]
    fn blob_manifests_round_trip(bm in arb_blob_manifest()) {
        round_trip(&bm)?;
    }

    #[test]
    fn forkproofs_round_trip(fp in arb_forkproof()) {
        round_trip(&fp)?;
    }

    /// §6.1 / §2.3 — `acks` is omitted when empty, and a present `acks` array is
    /// strictly ascending and non-empty. A decoder that accepted an empty array,
    /// a duplicate, or a descending pair would give one set two content
    /// addresses. Checked by mutating a valid two-element encoding.
    #[test]
    fn non_canonical_acks_arrays_are_rejected(
        mut obs in arb_observation(),
        x in arb_hash(),
        y in arb_hash(),
    ) {
        prop_assume!(x != y);
        let (lo, hi) = if x < y { (x, y) } else { (y, x) };
        obs.acks = BTreeSet::from([lo, hi]);
        let valid = obs.canonical_cbor();
        prop_assert!(Observation::decode_cbor(&valid).is_ok(), "the ascending pair decodes");

        // The `acks` array is the 70-byte tail `08 82 5820 <lo:32> 5820 <hi:32>`.
        let n = valid.len();
        let lo_off = n - 66;   // start of lo's 32 bytes
        let hi_off = n - 32;   // start of hi's 32 bytes

        // Descending: swap the two hashes.
        let mut descending = valid.clone();
        descending[lo_off..lo_off + 32].copy_from_slice(hi.as_bytes());
        descending[hi_off..hi_off + 32].copy_from_slice(lo.as_bytes());
        prop_assert!(
            Observation::decode_cbor(&descending).is_err(),
            "a descending acks pair must be rejected"
        );

        // Duplicate: make hi equal to lo.
        let mut duplicate = valid.clone();
        duplicate[hi_off..hi_off + 32].copy_from_slice(lo.as_bytes());
        prop_assert!(
            Observation::decode_cbor(&duplicate).is_err(),
            "a duplicated acks entry must be rejected"
        );

        // Empty: array head `82` -> `80`, and drop the 68 trailing bytes.
        let mut empty = valid[..n - 68].to_vec();
        let head = empty.len() - 1;
        empty[head] = 0x80;
        prop_assert!(
            Observation::decode_cbor(&empty).is_err(),
            "a present-but-empty acks array must be rejected"
        );
    }

    /// Distinct objects get distinct ids. Not a claim about BLAKE3 — it is a
    /// check that every field actually reaches the preimage. A field omitted from
    /// `encode_fields` by mistake would make two different observations share a
    /// content address, and nothing else in the suite would notice.
    #[test]
    fn every_field_reaches_the_content_address(a in arb_observation(), b in arb_observation()) {
        prop_assume!(a != b);
        prop_assert_ne!(a.id(), b.id(), "two distinct observations share a content address");
    }

    /// §2.3 — an absent optional field is absent, never a zero value or an empty
    /// container. Present-and-empty must not encode the same as absent.
    #[test]
    fn an_absent_optional_field_differs_from_a_present_one(obs in arb_observation(), geo in arb_geo()) {
        let mut without = obs.clone();
        without.geo = None;
        let mut with = obs;
        with.geo = Some(geo);
        prop_assert_ne!(
            without.canonical_cbor(),
            with.canonical_cbor(),
            "an omitted optional field encodes the same as a present one"
        );
    }

    /// §6.1 — genesis is a value, not an absence. `prev: None` encodes as a
    /// zero-length byte string and must not collide with any real predecessor.
    #[test]
    fn genesis_does_not_collide_with_a_real_predecessor(obs in arb_observation(), prev in arb_hash()) {
        let mut genesis = obs.clone();
        genesis.prev = None;
        let mut chained = obs;
        chained.prev = Some(prev);
        prop_assert_ne!(genesis.id(), chained.id());
    }
}
