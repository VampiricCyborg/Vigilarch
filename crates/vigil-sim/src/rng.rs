//! `splitmix64` — a tiny, fully specified PRNG.
//!
//! `vigil-sim` must be byte-identical from a seed on any machine (invariant I4,
//! `spec/02-entanglement.md` §9). The real protocol draws attestation nonces and
//! device keys from a CSPRNG (`spec/01-wire-format.md` §6.5); the simulator
//! substitutes this deterministic stream, exactly as the HLC takes `now_ms` from
//! the caller rather than reading a clock. Nothing here is a security primitive.
//!
//! The algorithm is Vigna's `splitmix64` (public domain), reproduced so the
//! output does not depend on any external crate's version.

/// A deterministic 64-bit stream seeded from one `u64`.
pub struct SplitMix64(u64);

impl SplitMix64 {
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// The next value in the stream.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Fill `buf` with stream bytes, little-endian per 8-byte block.
    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&bytes[..n]);
        }
    }

    /// A fresh 32-byte array from the stream — a device key seed or a hash-sized
    /// nonce source.
    pub fn bytes32(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        self.fill(&mut b);
        b
    }

    /// A fresh 16-byte array from the stream — an attestation nonce.
    pub fn nonce(&mut self) -> [u8; 16] {
        let mut b = [0u8; 16];
        self.fill(&mut b);
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stream_is_reproducible_from_a_seed() {
        let mut a = SplitMix64::new(42);
        let mut b = SplitMix64::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seeds_diverge_immediately() {
        assert_ne!(SplitMix64::new(1).next_u64(), SplitMix64::new(2).next_u64());
    }

    #[test]
    fn fill_handles_a_non_multiple_of_eight() {
        let mut r = SplitMix64::new(7);
        let mut buf = [0u8; 20];
        r.fill(&mut buf); // must not panic on the trailing 4-byte block
        assert!(buf.iter().any(|&b| b != 0));
    }
}
