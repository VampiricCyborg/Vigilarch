//! `splitmix64` — a tiny, fully specified deterministic stream.
//!
//! The real protocol draws device keys and attestation nonces from a CSPRNG
//! (`spec/01-wire-format.md` §6.5). This crate runs a *demo* in a browser, where
//! there is no seed ceremony and no key custody (both are out of v1 scope), so it
//! substitutes this deterministic stream — exactly as `vigil-sim` does, and as
//! the HLC takes `now_ms` from its caller rather than reading a clock (invariant
//! I4). Nothing here is a security primitive.
//!
//! A fixed seed also means two `Demo` instances built the same way have the same
//! identities and produce byte-identical ids, which is what the native test
//! module asserts. [`Demo::with_seed`](crate::Demo::with_seed) exists for a page
//! that wants a second, distinct instance.
//!
//! The algorithm is Vigna's `splitmix64` (public domain), reproduced so the
//! output depends on no external crate's version.

/// A deterministic 64-bit stream seeded from one `u64`.
pub(crate) struct SplitMix64(u64);

impl SplitMix64 {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&bytes[..n]);
        }
    }

    /// A fresh 32-byte array — an Ed25519 signing-key seed.
    pub(crate) fn bytes32(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        self.fill(&mut b);
        b
    }

    /// A fresh 16-byte array — an attestation nonce (`spec/01` §6.5).
    pub(crate) fn nonce(&mut self) -> [u8; 16] {
        let mut b = [0u8; 16];
        self.fill(&mut b);
        b
    }
}
