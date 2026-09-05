//! Golden vector integrity, per `spec/01-wire-format.md` §9.
//!
//! These tests check that every checked-in vector is internally consistent and
//! that its cryptographic claims hold: the preimage really is `tag || 0x00 ||
//! cbor`, the id really is BLAKE3 of that preimage, and the signature really
//! verifies under the key derived from the published seed.
//!
//! They then do the load-bearing thing: build each object with `vigil-core` and
//! assert that its encoding equals `cbor_hex` **byte for byte**. The vectors were
//! written first, by hand from the specification tables, and the encoder was
//! written against them — so this is the encoder being checked against the
//! document, not a record of whatever the encoder happened to produce.
//!
//! Each vector is also decoded back through the strict reader and re-encoded.
//! That closes the loop the `0xff` note below leaves open: a canonical-form
//! violation anywhere in a vector fails the decode, and a decoder that accepts
//! something the encoder cannot produce fails the re-encode.
//!
//! The vectors are embedded with `include_str!` rather than read from disk so
//! that this file compiles and runs unchanged on `wasm32`, where there is no
//! filesystem. That is the whole point: the same assertions run on both targets,
//! and CI compares the results. A divergence in canonical encoding between
//! native and WASM means the same observation has two content addresses, which
//! means a silent fork — and it is invisible to a native-only test run.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use vigil_core::{
    Attestation, BlobManifest, Checkpoint, GeoPoint, Hash, Hlc, Object, Observation,
    ObservationBody, PubKey, SignedObject, SiteId,
};

const VECTORS: &[(&str, &str)] = &[
    (
        "observation/note-genesis",
        include_str!("../../../testdata/vectors/observation-note-genesis.json"),
    ),
    (
        "observation/media-with-geo",
        include_str!("../../../testdata/vectors/observation-media-with-geo.json"),
    ),
    (
        "attestation/basic",
        include_str!("../../../testdata/vectors/attestation-basic.json"),
    ),
    (
        "checkpoint/with-frontier",
        include_str!("../../../testdata/vectors/checkpoint-with-frontier.json"),
    ),
];

struct Vector {
    name: String,
    tag: String,
    cbor: Vec<u8>,
    preimage: Vec<u8>,
    id: Vec<u8>,
    seed: [u8; 32],
    sig: Vec<u8>,
}

fn parse(raw: &str) -> Vector {
    let v: serde_json::Value = serde_json::from_str(raw).expect("vector is valid JSON");
    let hex_field = |k: &str| {
        hex::decode(v[k].as_str().unwrap_or_else(|| panic!("missing {k}")))
            .unwrap_or_else(|_| panic!("{k} is not hex"))
    };
    let seed_vec = hex_field("signing_key_seed_hex");
    Vector {
        name: v["name"].as_str().expect("name").to_owned(),
        tag: v["tag"].as_str().expect("tag").to_owned(),
        cbor: hex_field("cbor_hex"),
        preimage: hex_field("preimage_hex"),
        id: hex_field("id_hex"),
        seed: seed_vec.try_into().expect("seed is 32 bytes"),
        sig: hex_field("sig_hex"),
    }
}

fn domain_sep(tag: &str, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.len() + 1 + body.len());
    out.extend_from_slice(tag.as_bytes());
    out.push(0x00);
    out.extend_from_slice(body);
    out
}

/// §3.1 — the preimage is exactly `tag || 0x00 || canonical_cbor`, and the tag
/// contains no NUL, which is what makes the concatenation injective.
#[test]
fn preimage_is_domain_separated_cbor() {
    for (name, raw) in VECTORS {
        let v = parse(raw);
        assert_eq!(&v.name, name, "vector name matches its file");
        assert!(
            !v.tag.as_bytes().contains(&0x00),
            "{name}: domain separation tag must contain no NUL byte"
        );
        assert!(
            v.tag.is_ascii(),
            "{name}: domain separation tag must be US-ASCII"
        );
        assert_eq!(
            v.preimage,
            domain_sep(&v.tag, &v.cbor),
            "{name}: preimage is not tag || 0x00 || cbor"
        );
    }
}

/// §3.1 — the id is the full 32-byte BLAKE3 of the preimage. Never truncated.
#[test]
fn id_is_blake3_of_preimage() {
    for (name, raw) in VECTORS {
        let v = parse(raw);
        assert_eq!(
            v.id.len(),
            32,
            "{name}: id must be 32 bytes, never truncated"
        );
        assert_eq!(
            v.id,
            blake3::hash(&v.preimage).as_bytes(),
            "{name}: id does not match BLAKE3 of the preimage"
        );
    }
}

/// §4 — the signature is over `"vigilarch/1/sig" || 0x00 || id`, not over the
/// preimage and not over the bare id.
#[test]
fn signature_verifies_over_domain_separated_id() {
    for (name, raw) in VECTORS {
        let v = parse(raw);
        let vk: VerifyingKey = ed25519_dalek::SigningKey::from_bytes(&v.seed).verifying_key();
        let sig = Signature::from_slice(&v.sig).expect("signature is 64 bytes");
        let msg = domain_sep("vigilarch/1/sig", &v.id);
        vk.verify(&msg, &sig)
            .unwrap_or_else(|e| panic!("{name}: signature does not verify: {e}"));

        // The bare id must NOT verify — if it did, domain separation would be
        // decorative and a signature could be replayed across hash contexts.
        assert!(
            vk.verify(&v.id, &sig).is_err(),
            "{name}: signature verifies over the undomain-separated id"
        );
    }
}

// §2.1 rule 1 forbids indefinite-length items, so the break byte 0xff can never
// appear as a *head* in a valid preimage. There is deliberately no flat byte scan
// for it: 0xff occurs naturally inside byte strings — hashes and public keys are
// opaque bytes and roughly one in eight of these vectors' 32-byte fields contains
// one — so a scan reports false positives. Distinguishing a break byte from
// payload requires walking the structure, which is what the round-trip test below
// does: the strict reader rejects an indefinite-length head wherever it appears.

/// Every vector has a distinct id. Two vectors sharing an id would mean the
/// domain separation or the field encoding is not doing its job.
#[test]
fn vector_ids_are_distinct() {
    let mut ids: Vec<Vec<u8>> = VECTORS.iter().map(|(_, raw)| parse(raw).id).collect();
    let before = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!(before, ids.len(), "two vectors share a content address");
}

// ---------------------------------------------------------------------------
// The encoder, held against the document
// ---------------------------------------------------------------------------
//
// Everything above holds the vectors internally consistent. Everything below
// holds `vigil-core` to them.

fn vector(name: &str) -> Vector {
    let raw = VECTORS
        .iter()
        .find(|(n, _)| *n == name)
        .unwrap_or_else(|| panic!("no vector named {name}"))
        .1;
    parse(raw)
}

/// The fixed, published seeds from §9. Never used for anything real.
fn seed_a() -> [u8; 32] {
    core::array::from_fn(|i| i as u8)
}

fn seed_b() -> [u8; 32] {
    core::array::from_fn(|i| 0x80 ^ i as u8)
}

fn key(seed: [u8; 32]) -> PubKey {
    PubKey(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
}

fn hash_of(s: &[u8]) -> Hash {
    Hash(*blake3::hash(s).as_bytes())
}

const SITE: SiteId = SiteId(*b"VIGILARCH-SITE-A");

/// Checks one object against its vector: the encoding, the domain-separated
/// preimage, the content address, and a decode round trip.
///
/// The byte-for-byte CBOR comparison is the assertion that matters; the id is
/// compared separately so that a failure says whether the encoding drifted or the
/// hashing did. Hex is compared rather than raw bytes so a failure prints
/// something a person can diff against the specification.
fn check<T>(name: &str, obj: &T)
where
    T: Object + PartialEq + core::fmt::Debug,
{
    let v = vector(name);
    assert_eq!(v.tag, T::TAG, "{name}: domain separation tag");
    assert_eq!(
        hex::encode(obj.canonical_cbor()),
        hex::encode(&v.cbor),
        "{name}: canonical CBOR does not match the vector"
    );
    assert_eq!(
        hex::encode(obj.preimage()),
        hex::encode(&v.preimage),
        "{name}: preimage does not match the vector"
    );
    assert_eq!(
        hex::encode(obj.id().as_bytes()),
        hex::encode(&v.id),
        "{name}: content address does not match the vector"
    );

    let decoded = T::decode_cbor(&v.cbor)
        .unwrap_or_else(|e| panic!("{name}: the vector does not decode: {e}"));
    assert_eq!(&decoded, obj, "{name}: decode did not recover the object");

    let from_preimage = T::decode_preimage(&v.preimage)
        .unwrap_or_else(|e| panic!("{name}: preimage does not decode: {e}"));
    assert_eq!(
        &from_preimage, obj,
        "{name}: preimage decode lost something"
    );
}

fn note_genesis() -> Observation {
    Observation {
        author: key(seed_a()),
        site: SITE,
        prev: None,
        seq: 0,
        hlc: Hlc::new(1_700_000_000_000, 0),
        body: ObservationBody::Note {
            text: "shoring on grid B4 is out of plumb".to_owned(),
        },
        geo: None,
    }
}

fn media_with_geo() -> Observation {
    Observation {
        author: key(seed_a()),
        site: SITE,
        prev: Some(hash_of(b"vigilarch test prev")),
        seq: 41,
        hlc: Hlc::new(1_700_000_123_456, 7),
        body: ObservationBody::Media {
            blob: hash_of(b"vigilarch test blob manifest"),
            kind: 0,
            caption: Some("edge protection missing, level 3 east".to_owned()),
        },
        geo: Some(GeoPoint {
            lat_udeg: -33_868_820,
            lon_udeg: 151_209_290,
            acc_mm: 4_500,
        }),
    }
}

fn attestation_basic() -> Attestation {
    Attestation {
        witness: key(seed_b()),
        subject: key(seed_a()),
        subject_head: hash_of(b"vigilarch test head"),
        subject_seq: 41,
        witness_hlc: Hlc::new(1_700_000_200_000, 0),
        nonce: core::array::from_fn(|i| 0xa0 ^ i as u8),
    }
}

fn checkpoint_with_frontier() -> Checkpoint {
    Checkpoint {
        node: key(seed_a()),
        head: hash_of(b"vigilarch test head"),
        seq: 41,
        hlc: Hlc::new(1_700_000_300_000, 0),
        // Inserted in the order a caller would naturally write them, which is
        // not the canonical order: §2.1 rule 3 sorts map keys by their encoded
        // bytes, and `seed_b`'s key sorts first. The map type, not the caller,
        // is what guarantees the encoding comes out canonical.
        frontier: BTreeMap::from([(key(seed_a()), 41), (key(seed_b()), 17)]),
    }
}

#[test]
fn encoder_reproduces_the_observation_vectors() {
    check("observation/note-genesis", &note_genesis());
    check("observation/media-with-geo", &media_with_geo());
}

#[test]
fn encoder_reproduces_the_attestation_vector() {
    check("attestation/basic", &attestation_basic());
}

#[test]
fn encoder_reproduces_the_checkpoint_vector() {
    check("checkpoint/with-frontier", &checkpoint_with_frontier());
}

/// §10 — the worked example reproduced exactly, including the byte counts the
/// document states. If this fails, either the encoder or the document is wrong,
/// and the document is not automatically the one that yields.
#[test]
fn the_worked_example_in_the_spec_holds() {
    let obs = note_genesis();
    assert_eq!(
        obs.author.to_string(),
        "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
        "§10 input table: author key derived from the published seed"
    );
    assert_eq!(obs.canonical_cbor().len(), 111, "§10: 111 bytes of CBOR");
    assert_eq!(obs.preimage().len(), 135, "§10: 135 bytes of preimage");
    assert_eq!(
        obs.id().to_string(),
        "7431f38ed1c31a3ef917bd60cd0b52f14c41b49ac8af5796b6c0fc3fba0aac1d",
        "§10: the published content address"
    );
    assert_eq!(
        hex::encode(obs.sign(&SigningKey::from_bytes(&seed_a())).0),
        "ddb1adecbbaea87a5b7454af66ab0a52b99b14acb3bb04eb4226668717bf59434f54760e\
         aa80e54bc2b568f0f316be5c369b610e5ea990586395b816ce751a07"
            .replace(['\n', ' '], ""),
        "§10: the published signature"
    );
}

/// §4 — `vigil-core`'s signing path produces exactly the vectors' signatures and
/// its verifier accepts them. The generator signs by hand from the document; this
/// is the implementation agreeing with it rather than with itself.
#[test]
fn signing_path_reproduces_every_vector_signature() {
    let cases: [(&str, [u8; 32], Hash); 4] = [
        ("observation/note-genesis", seed_a(), note_genesis().id()),
        (
            "observation/media-with-geo",
            seed_a(),
            media_with_geo().id(),
        ),
        // Signed by the witness, per §6.5 — not by the subject.
        ("attestation/basic", seed_b(), attestation_basic().id()),
        (
            "checkpoint/with-frontier",
            seed_a(),
            checkpoint_with_frontier().id(),
        ),
    ];
    for (name, seed, id) in cases {
        let v = vector(name);
        let sk = SigningKey::from_bytes(&seed);
        let sig = vigil_core::sign_id(&sk, id);
        assert_eq!(hex::encode(sig.0), hex::encode(&v.sig), "{name}: signature");
        vigil_core::verify_id(vigil_core::public_key(&sk), id, &sig)
            .unwrap_or_else(|_| panic!("{name}: own signature does not verify"));
    }
}

/// Every vector decodes through the strict reader and re-encodes to the same
/// bytes. This is what rules out a decoder that accepts input the encoder could
/// never have produced — the asymmetry that would let a hostile peer hand two
/// nodes byte sequences that differ while claiming to be the same object.
#[test]
fn round_trips_through_the_decoder() {
    fn round_trip<T: Object>(name: &str) {
        let v = vector(name);
        let decoded =
            T::decode_cbor(&v.cbor).unwrap_or_else(|e| panic!("{name}: does not decode: {e}"));
        assert_eq!(
            hex::encode(decoded.canonical_cbor()),
            hex::encode(&v.cbor),
            "{name}: re-encoding a decoded vector changed its bytes"
        );
    }
    round_trip::<Observation>("observation/note-genesis");
    round_trip::<Observation>("observation/media-with-geo");
    round_trip::<Attestation>("attestation/basic");
    round_trip::<Checkpoint>("checkpoint/with-frontier");
}

/// §8 — rejection is total. Checked by mutating real vector bytes, so each input
/// differs from a valid object in exactly one property rather than being a
/// hand-built fragment that might fail for an unrelated reason.
#[test]
fn mutated_vectors_are_rejected_totally() {
    let v = vector("observation/note-genesis");

    let mut extra = v.cbor.clone();
    extra.push(0x00);
    assert!(
        Observation::decode_cbor(&extra).is_err(),
        "trailing bytes must be rejected"
    );

    for cut in 1..=8 {
        let truncated = &v.cbor[..v.cbor.len() - cut];
        assert!(
            Observation::decode_cbor(truncated).is_err(),
            "truncation by {cut} bytes must be rejected"
        );
    }

    // The right bytes under the wrong tag. Domain separation (§3.1) is what stops
    // one object type's preimage from ever being read as another's.
    assert!(
        Attestation::decode_preimage(&v.preimage).is_err(),
        "an observation preimage must not decode as an attestation"
    );

    // A blob manifest declaring 2^31-1 chunks in a nine-byte frame. §8: bound
    // allocation by the remaining input, never by the declared length alone.
    let bomb = hex::decode("a3010002821a7fffffff0360").expect("valid hex");
    assert!(
        BlobManifest::decode_cbor(&bomb).is_err(),
        "a length header beyond the input must be rejected without allocating"
    );
}
