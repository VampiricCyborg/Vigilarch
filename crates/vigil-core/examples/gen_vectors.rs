//! Golden vector generator.
//!
//! This program builds the canonical preimage for each golden vector **by hand**,
//! byte by byte, directly from the field tables in `spec/01-wire-format.md`. It
//! deliberately does not use `vigil-core`'s encoder, because a vector produced by
//! the encoder under test proves only that the encoder agrees with itself. The
//! expected bytes have to come from the specification independently, or they are
//! not evidence of anything.
//!
//! Run with: `cargo run -p vigil-core --example gen_vectors`

use ed25519_dalek::{Signer, SigningKey};

/// Length-prefix-free domain separation: the tag is ASCII, contains no NUL, and
/// is terminated by one NUL byte, so `tag || 0x00 || body` is injective.
fn domain_sep(tag: &str, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(tag.len() + 1 + body.len());
    v.extend_from_slice(tag.as_bytes());
    v.push(0x00);
    v.extend_from_slice(body);
    v
}

fn cbor_head(major: u8, arg: u64, out: &mut Vec<u8>) {
    let m = major << 5;
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

fn main() {
    // Fixed test seed: bytes 0x00..=0x1f. Never used for anything real.
    let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
    let sk = SigningKey::from_bytes(&seed);
    let author = sk.verifying_key().to_bytes();

    let site: [u8; 16] = *b"VIGILARCH-SITE-A";
    let wall_ms: u64 = 1_700_000_000_000;
    let text = "shoring on grid B4 is out of plumb";

    // --- Observation preimage, per spec/01-wire-format.md §6.1 ---------------
    let mut cbor = Vec::new();
    map(6, &mut cbor); // keys 1..6; key 7 (geo) absent, so omitted entirely
    uint(1, &mut cbor);
    bstr(&author, &mut cbor); // 1 author
    uint(2, &mut cbor);
    bstr(&site, &mut cbor); // 2 site
    uint(3, &mut cbor);
    bstr(&[], &mut cbor); // 3 prev: empty = genesis
    uint(4, &mut cbor);
    uint(0, &mut cbor); // 4 seq
    uint(5, &mut cbor);
    array(2, &mut cbor); // 5 hlc
    uint(wall_ms, &mut cbor);
    uint(0, &mut cbor);
    uint(6, &mut cbor);
    array(2, &mut cbor); // 6 body
    uint(0, &mut cbor); // variant 0 = Note
    map(1, &mut cbor);
    uint(1, &mut cbor);
    tstr(text, &mut cbor);

    let preimage = domain_sep("vigilarch/1/observation", &cbor);
    let id = blake3::hash(&preimage);
    let sig = sk.sign(&domain_sep("vigilarch/1/sig", id.as_bytes()));

    println!("author_pubkey  = {}", hex::encode(author));
    println!("cbor_len       = {}", cbor.len());
    println!("cbor           = {}", hex::encode(&cbor));
    println!("preimage_len   = {}", preimage.len());
    println!("preimage       = {}", hex::encode(&preimage));
    println!("id             = {}", hex::encode(id.as_bytes()));
    println!("sig            = {}", hex::encode(sig.to_bytes()));
}
