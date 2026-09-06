//! Golden vector generator.
//!
//! This program builds the canonical preimage for each golden vector **by hand**,
//! byte by byte, directly from the field tables in `spec/01-wire-format.md`. It
//! deliberately does not use `vigil-core`'s encoder, because a vector produced by
//! the encoder under test proves only that the encoder agrees with itself. The
//! expected bytes have to come from the specification independently, or they are
//! not evidence of anything.
//!
//! Run with `cargo run -p vigil-core --example gen_vectors`. Output is written to
//! `testdata/vectors/`. The run is deterministic: CI regenerates and then asserts
//! that nothing changed, so a drift between this generator and the checked-in
//! vectors fails the build rather than being silently overwritten.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};

const WIRE_VERSION: u32 = 1;

// --- CBOR primitives, per spec/01-wire-format.md §2.1 ------------------------

fn cbor_head(major: u8, arg: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    // Shortest-form argument (§2.1 rule 2).
    match arg {
        0..=23 => out.push(m | arg as u8),
        24..=0xff => {
            out.push(m | 24);
            out.push(arg as u8);
        }
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(arg as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend_from_slice(&(arg as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend_from_slice(&arg.to_be_bytes());
        }
    }
}

fn uint(n: u64, out: &mut Vec<u8>) {
    cbor_head(0, n, out);
}

/// Signed integer: major type 1 encodes -1 - n. Used for geo microdegrees and
/// sensor exponents (§2.2) — never for anything that would otherwise be a float.
fn int(n: i64, out: &mut Vec<u8>) {
    if n >= 0 {
        cbor_head(0, n as u64, out);
    } else {
        cbor_head(1, (-1 - n) as u64, out);
    }
}

fn bstr(b: &[u8], out: &mut Vec<u8>) {
    cbor_head(2, b.len() as u64, out);
    out.extend_from_slice(b);
}

fn tstr(s: &str, out: &mut Vec<u8>) {
    cbor_head(3, s.len() as u64, out);
    out.extend_from_slice(s.as_bytes());
}

fn array(n: u64, out: &mut Vec<u8>) {
    cbor_head(4, n, out);
}

fn map(n: u64, out: &mut Vec<u8>) {
    cbor_head(5, n, out);
}

// --- Domain separation, per §3.1 ---------------------------------------------

/// `tag || 0x00 || body`. The tag is ASCII and contains no NUL, so this is
/// injective: no two (tag, body) pairs collide.
fn domain_sep(tag: &str, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(tag.len() + 1 + body.len());
    v.extend_from_slice(tag.as_bytes());
    v.push(0x00);
    v.extend_from_slice(body);
    v
}

// --- Vector emission ----------------------------------------------------------

struct Vector {
    name: &'static str,
    tag: &'static str,
    fields: Vec<(&'static str, String)>,
    cbor: Vec<u8>,
    seed: [u8; 32],
}

impl Vector {
    fn write(&self, dir: &Path) {
        let sk = SigningKey::from_bytes(&self.seed);
        let preimage = domain_sep(self.tag, &self.cbor);
        let id = blake3::hash(&preimage);
        let sig = sk.sign(&domain_sep("vigilarch/1/sig", id.as_bytes()));

        let mut fields = String::new();
        for (i, (k, v)) in self.fields.iter().enumerate() {
            let comma = if i + 1 == self.fields.len() { "" } else { "," };
            let _ = write!(fields, "\n    \"{k}\": \"{v}\"{comma}");
        }

        let json = format!(
            "{{\n  \"name\": \"{name}\",\n  \"wire_version\": {ver},\n  \"tag\": \"{tag}\",\
             \n  \"fields\": {{{fields}\n  }},\n  \"cbor_hex\": \"{cbor}\",\
             \n  \"preimage_hex\": \"{pre}\",\n  \"id_hex\": \"{id}\",\
             \n  \"signing_key_seed_hex\": \"{seed}\",\n  \"sig_hex\": \"{sig}\"\n}}\n",
            name = self.name,
            ver = WIRE_VERSION,
            tag = self.tag,
            fields = fields,
            cbor = hex::encode(&self.cbor),
            pre = hex::encode(&preimage),
            id = hex::encode(id.as_bytes()),
            seed = hex::encode(self.seed),
            sig = hex::encode(sig.to_bytes()),
        );

        let path = dir.join(format!("{}.json", self.name.replace('/', "-")));
        std::fs::write(&path, json).expect("write vector");
        println!("{:<28} id={}", self.name, hex::encode(id.as_bytes()));
    }
}

/// Fixed, published test seed. Never used for anything real (§9).
fn seed_a() -> [u8; 32] {
    core::array::from_fn(|i| i as u8)
}

fn seed_b() -> [u8; 32] {
    core::array::from_fn(|i| 0x80 ^ i as u8)
}

fn main() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/vectors")
        .canonicalize()
        .unwrap_or_else(|_| {
            let d = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/vectors");
            std::fs::create_dir_all(&d).expect("create testdata/vectors");
            d.canonicalize().expect("canonicalize")
        });

    let key_a = SigningKey::from_bytes(&seed_a()).verifying_key().to_bytes();
    let key_b = SigningKey::from_bytes(&seed_b()).verifying_key().to_bytes();
    let site: [u8; 16] = *b"VIGILARCH-SITE-A";

    // --- observation/note-genesis --------------------------------------------
    // The worked example in spec/01-wire-format.md §10. Genesis entry: `prev` is
    // a zero-length byte string, and the optional `geo` is omitted entirely
    // rather than encoded as null (§2.3).
    let text = "shoring on grid B4 is out of plumb";
    let mut c = Vec::new();
    map(6, &mut c);
    uint(1, &mut c);
    bstr(&key_a, &mut c);
    uint(2, &mut c);
    bstr(&site, &mut c);
    uint(3, &mut c);
    bstr(&[], &mut c);
    uint(4, &mut c);
    uint(0, &mut c);
    uint(5, &mut c);
    array(2, &mut c);
    uint(1_700_000_000_000, &mut c);
    uint(0, &mut c);
    uint(6, &mut c);
    array(2, &mut c);
    uint(0, &mut c);
    map(1, &mut c);
    uint(1, &mut c);
    tstr(text, &mut c);

    Vector {
        name: "observation/note-genesis",
        tag: "vigilarch/1/observation",
        fields: vec![
            ("author", hex::encode(key_a)),
            ("site", "VIGILARCH-SITE-A".into()),
            ("prev", "(empty - genesis)".into()),
            ("seq", "0".into()),
            ("hlc", "[1700000000000, 0]".into()),
            ("body", format!("variant 0 Note, text: {text}")),
            ("geo", "(absent - omitted)".into()),
        ],
        cbor: c,
        seed: seed_a(),
    }
    .write(&dir);

    // --- observation/media-with-geo ------------------------------------------
    // Exercises what the genesis vector does not: a non-empty `prev`, a nonzero
    // `seq`, the optional `geo` present, and negative microdegrees — the case
    // that would have been a float if §2.2 allowed one.
    let prev = blake3::hash(b"vigilarch test prev");
    let blob = blake3::hash(b"vigilarch test blob manifest");
    let mut c = Vec::new();
    map(7, &mut c);
    uint(1, &mut c);
    bstr(&key_a, &mut c);
    uint(2, &mut c);
    bstr(&site, &mut c);
    uint(3, &mut c);
    bstr(prev.as_bytes(), &mut c);
    uint(4, &mut c);
    uint(41, &mut c);
    uint(5, &mut c);
    array(2, &mut c);
    uint(1_700_000_123_456, &mut c);
    uint(7, &mut c);
    uint(6, &mut c);
    array(2, &mut c);
    uint(2, &mut c); // variant 2 = Media
    map(3, &mut c);
    uint(1, &mut c);
    bstr(blob.as_bytes(), &mut c);
    uint(2, &mut c);
    uint(0, &mut c); // kind 0 = photo
    uint(3, &mut c);
    tstr("edge protection missing, level 3 east", &mut c);
    uint(7, &mut c);
    array(3, &mut c); // geo
    int(-33_868_820, &mut c); // lat, southern hemisphere
    int(151_209_290, &mut c); // lon
    uint(4_500, &mut c); // accuracy, mm

    Vector {
        name: "observation/media-with-geo",
        tag: "vigilarch/1/observation",
        fields: vec![
            ("author", hex::encode(key_a)),
            ("site", "VIGILARCH-SITE-A".into()),
            ("prev", hex::encode(prev.as_bytes())),
            ("seq", "41".into()),
            ("hlc", "[1700000123456, 7]".into()),
            ("body", "variant 2 Media, kind 0, with caption".into()),
            ("geo", "[-33868820, 151209290, 4500]".into()),
        ],
        cbor: c,
        seed: seed_a(),
    }
    .write(&dir);

    // --- attestation/basic ----------------------------------------------------
    // Key B witnesses key A's head. Signed by the witness, per §6.5.
    let head = blake3::hash(b"vigilarch test head");
    let nonce: [u8; 16] = core::array::from_fn(|i| 0xa0 ^ i as u8);
    let mut c = Vec::new();
    map(6, &mut c);
    uint(1, &mut c);
    bstr(&key_b, &mut c);
    uint(2, &mut c);
    bstr(&key_a, &mut c);
    uint(3, &mut c);
    bstr(head.as_bytes(), &mut c);
    uint(4, &mut c);
    uint(41, &mut c);
    uint(5, &mut c);
    array(2, &mut c);
    uint(1_700_000_200_000, &mut c);
    uint(0, &mut c);
    uint(6, &mut c);
    bstr(&nonce, &mut c);

    Vector {
        name: "attestation/basic",
        tag: "vigilarch/1/attestation",
        fields: vec![
            ("witness", hex::encode(key_b)),
            ("subject", hex::encode(key_a)),
            ("subject_head", hex::encode(head.as_bytes())),
            ("subject_seq", "41".into()),
            ("witness_hlc", "[1700000200000, 0]".into()),
            ("nonce", hex::encode(nonce)),
        ],
        cbor: c,
        seed: seed_b(), // signed by the witness
    }
    .write(&dir);

    // --- checkpoint/with-frontier ---------------------------------------------
    // The only vector with a map whose keys are not small integers. Its two
    // PubKey keys must appear in ascending bytewise order of their encoded bytes
    // (§2.1 rule 3), which is the rule most likely to be got wrong by an encoder
    // that sorts by insertion order or by logical name.
    let mut frontier = [(key_a, 41u64), (key_b, 17u64)];
    frontier.sort_by_key(|entry| entry.0);
    let mut c = Vec::new();
    map(5, &mut c);
    uint(1, &mut c);
    bstr(&key_a, &mut c);
    uint(2, &mut c);
    bstr(head.as_bytes(), &mut c);
    uint(3, &mut c);
    uint(41, &mut c);
    uint(4, &mut c);
    array(2, &mut c);
    uint(1_700_000_300_000, &mut c);
    uint(0, &mut c);
    uint(5, &mut c);
    map(2, &mut c);
    for (k, v) in &frontier {
        bstr(k, &mut c);
        uint(*v, &mut c);
    }

    Vector {
        name: "checkpoint/with-frontier",
        tag: "vigilarch/1/checkpoint",
        fields: vec![
            ("node", hex::encode(key_a)),
            ("head", hex::encode(head.as_bytes())),
            ("seq", "41".into()),
            ("hlc", "[1700000300000, 0]".into()),
            (
                "frontier",
                format!(
                    "{{{}: 41, {}: 17}} sorted bytewise",
                    &hex::encode(key_a)[..8],
                    &hex::encode(key_b)[..8]
                ),
            ),
        ],
        cbor: c,
        seed: seed_a(),
    }
    .write(&dir);

    // --- observation/note-with-acks ----------------------------------------------
    // Field 8, `acks` (spec/01 §6.1, spec/02 §3.4): the M1 addition. A non-genesis
    // note that commits to two attestation ids. The ids are encoded as a CBOR array
    // of 32-byte byte strings in strictly ascending order — the same ordering rule
    // as canonical map keys, and the one an encoder that preserved insertion order
    // would get wrong. `geo` (field 7) is absent, so field 8 follows field 6.
    let acks_prev = blake3::hash(b"vigilarch acks vector prev");
    let mut ack_ids = [
        *blake3::hash(b"vigilarch acks vector attestation alpha").as_bytes(),
        *blake3::hash(b"vigilarch acks vector attestation beta").as_bytes(),
    ];
    ack_ids.sort();
    let acks_text = "crane tag-out re-checked against the witnessed head";
    let mut c = Vec::new();
    map(7, &mut c);
    uint(1, &mut c);
    bstr(&key_a, &mut c);
    uint(2, &mut c);
    bstr(&site, &mut c);
    uint(3, &mut c);
    bstr(acks_prev.as_bytes(), &mut c);
    uint(4, &mut c);
    uint(1, &mut c);
    uint(5, &mut c);
    array(2, &mut c);
    uint(1_700_000_050_000, &mut c);
    uint(0, &mut c);
    uint(6, &mut c);
    array(2, &mut c);
    uint(0, &mut c); // variant 0 = Note
    map(1, &mut c);
    uint(1, &mut c);
    tstr(acks_text, &mut c);
    uint(8, &mut c);
    array(2, &mut c);
    bstr(&ack_ids[0], &mut c);
    bstr(&ack_ids[1], &mut c);

    Vector {
        name: "observation/note-with-acks",
        tag: "vigilarch/1/observation",
        fields: vec![
            ("author", hex::encode(key_a)),
            ("site", "VIGILARCH-SITE-A".into()),
            ("prev", hex::encode(acks_prev.as_bytes())),
            ("seq", "1".into()),
            ("hlc", "[1700000050000, 0]".into()),
            ("body", format!("variant 0 Note, text: {acks_text}")),
            ("geo", "(absent - omitted)".into()),
            (
                "acks",
                format!(
                    "[{}, {}] ascending",
                    &hex::encode(ack_ids[0])[..8],
                    &hex::encode(ack_ids[1])[..8]
                ),
            ),
        ],
        cbor: c,
        seed: seed_a(),
    }
    .write(&dir);

    // --- forkproof/basic -------------------------------------------------------
    // spec/01 §6.7 / spec/02 §6. `seed_a` equivocates at genesis: two seq-0 notes,
    // both with an empty `prev`, different text, hence different ids. The proof
    // carries each entry's full domain-separated Observation preimage and detached
    // signature, and orders them so the lexicographically smaller recomputed id is
    // `a` — which is what makes two independently built proofs of one fork share a
    // content address. The `sig_hex` on the vector itself is over the ForkProof id
    // and is included only for format uniformity: a ForkProof is not a signed
    // object, it is self-verifying from the two signatures it carries.
    let sk_a = SigningKey::from_bytes(&seed_a());
    let fork_a = genesis_note_preimage(&key_a, &site, "north stair handrail is loose");
    let fork_b = genesis_note_preimage(&key_a, &site, "north stair handrail removed for grinding");
    let id_a = blake3::hash(&fork_a);
    let id_b = blake3::hash(&fork_b);
    let sig_a = sk_a
        .sign(&domain_sep("vigilarch/1/sig", id_a.as_bytes()))
        .to_bytes();
    let sig_b = sk_a
        .sign(&domain_sep("vigilarch/1/sig", id_b.as_bytes()))
        .to_bytes();
    let (first, second) = if id_a.as_bytes() <= id_b.as_bytes() {
        ((&fork_a, &sig_a), (&fork_b, &sig_b))
    } else {
        ((&fork_b, &sig_b), (&fork_a, &sig_a))
    };
    let mut c = Vec::new();
    map(3, &mut c);
    uint(1, &mut c);
    bstr(&key_a, &mut c);
    uint(2, &mut c);
    array(2, &mut c);
    bstr(first.0, &mut c);
    bstr(first.1, &mut c);
    uint(3, &mut c);
    array(2, &mut c);
    bstr(second.0, &mut c);
    bstr(second.1, &mut c);

    Vector {
        name: "forkproof/basic",
        tag: "vigilarch/1/forkproof",
        fields: vec![
            ("key", hex::encode(key_a)),
            (
                "collision",
                "same seq 0, different ids (genesis equivocation)".into(),
            ),
            ("a_id", hex::encode(blake3::hash(first.0).as_bytes())),
            ("b_id", hex::encode(blake3::hash(second.0).as_bytes())),
        ],
        cbor: c,
        seed: seed_a(),
    }
    .write(&dir);
}

/// The full domain-separated preimage of a genesis `Note` observation, built by
/// hand from the spec/01 §6.1 table — the two conflicting entries a `forkproof`
/// vector carries. `prev` is the zero-length byte string; `seq` is 0; `geo` and
/// `acks` are absent.
fn genesis_note_preimage(key: &[u8; 32], site: &[u8; 16], text: &str) -> Vec<u8> {
    let mut c = Vec::new();
    map(6, &mut c);
    uint(1, &mut c);
    bstr(key, &mut c);
    uint(2, &mut c);
    bstr(site, &mut c);
    uint(3, &mut c);
    bstr(&[], &mut c);
    uint(4, &mut c);
    uint(0, &mut c);
    uint(5, &mut c);
    array(2, &mut c);
    uint(1_700_000_000_000, &mut c);
    uint(0, &mut c);
    uint(6, &mut c);
    array(2, &mut c);
    uint(0, &mut c);
    map(1, &mut c);
    uint(1, &mut c);
    tstr(text, &mut c);
    domain_sep("vigilarch/1/observation", &c)
}
