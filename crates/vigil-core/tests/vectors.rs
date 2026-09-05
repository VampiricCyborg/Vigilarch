//! Golden vector integrity, per `spec/01-wire-format.md` §9.
//!
//! These tests check that every checked-in vector is internally consistent and
//! that its cryptographic claims hold: the preimage really is `tag || 0x00 ||
//! cbor`, the id really is BLAKE3 of that preimage, and the signature really
//! verifies under the key derived from the published seed.
//!
//! What they deliberately do *not* do yet is compare the vectors against
//! `vigil-core`'s encoder, because there is no encoder yet — M0 has not landed.
//! When it does, the load-bearing assertion is added here: `encode(object)` must
//! equal `cbor_hex` byte for byte. Until then these tests hold the vectors
//! themselves honest, which is what makes them usable as the target the encoder
//! is written against rather than a record of whatever the encoder happened to
//! produce.
//!
//! The vectors are embedded with `include_str!` rather than read from disk so
//! that this file compiles and runs unchanged on `wasm32`, where there is no
//! filesystem. That is the whole point: the same assertions run on both targets,
//! and CI compares the results. A divergence in canonical encoding between
//! native and WASM means the same observation has two content addresses, which
//! means a silent fork — and it is invisible to a native-only test run.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

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
// appear as a *head* in a valid preimage. There is deliberately no test for that
// here: 0xff occurs naturally inside byte strings — hashes and public keys are
// opaque bytes and roughly one in eight of these vectors' 32-byte fields contains
// one — so a flat byte scan reports false positives. Distinguishing a break byte
// from payload requires actually walking the structure, which is the M0 decoder's
// job. The canonical-form validator lands with it, and this file gains a test that
// every vector round-trips through it.

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
