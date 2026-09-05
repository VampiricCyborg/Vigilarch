//! Primitive types, per `spec/01-wire-format.md` §5.
//!
//! Every fixed-length type here is a newtype over an array rather than a `Vec`,
//! so a wrong length is a decode error at the boundary (§8: "a 31-byte `PubKey`
//! is a rejection, not something to pad") and cannot exist further in.

use core::fmt;

/// A BLAKE3-256 content address. Always the full 32 bytes — §3.1 forbids
/// truncated ids on the wire.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash(pub [u8; 32]);

/// An Ed25519 verifying key. A node *is* its device key (§5).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PubKey(pub [u8; 32]);

/// An opaque site identifier, assigned at provisioning.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SiteId(pub [u8; 16]);

/// An opaque 16-byte identifier: template, sensor, actor or zone.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpaqueId(pub [u8; 16]);

/// A detached Ed25519 signature (§5). Sixty-four bytes, never truncated.
///
/// Held as opaque bytes rather than as an `ed25519_dalek::Signature` because a
/// signature that fails to parse and one that fails to verify must be
/// indistinguishable to a caller — see [`SignatureError`](crate::SignatureError).
/// Parsing happens inside verification, not at the type boundary.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Signature(pub [u8; 64]);

macro_rules! hex_debug {
    ($t:ty, $label:literal) => {
        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                // Short form for logs and traces only. Never for the wire.
                write!(f, concat!($label, "({}…)"), hex::encode(&self.0[..4]))
            }
        }
        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&hex::encode(self.0))
            }
        }
        impl $t {
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }
    };
}

hex_debug!(Hash, "Hash");
hex_debug!(PubKey, "PubKey");
hex_debug!(SiteId, "SiteId");
hex_debug!(OpaqueId, "OpaqueId");
hex_debug!(Signature, "Signature");

/// A hybrid logical clock reading (§5.1).
///
/// **This carries no authority.** `wall_ms` is whatever the originating device
/// claimed, and a device clock is a settable field that a backdater sets. The
/// HLC gives merges a stable causal order and makes traces readable; it is never
/// evidence of when anything happened. Temporal claims come from the attestation
/// DAG, which is M1's job.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct Hlc {
    pub wall_ms: u64,
    pub counter: u64,
}

impl Hlc {
    pub const fn new(wall_ms: u64, counter: u64) -> Self {
        Self { wall_ms, counter }
    }

    /// Advances the clock for a locally generated event.
    ///
    /// `now_ms` is supplied by the caller and never read from the system clock
    /// here. Invariant I4 bans wall-clock reads in the evidence path; pushing the
    /// read out to the caller is what lets `vigil-ledger` and `vigil-sim` run
    /// with no real clock at all, which in turn is what makes simulator runs
    /// reproducible from a seed.
    #[must_use]
    pub fn tick(self, now_ms: u64) -> Self {
        if now_ms > self.wall_ms {
            Self::new(now_ms, 0)
        } else {
            // The local clock did not advance, or went backwards. Keep the
            // logical component moving so ordering stays total.
            Self::new(self.wall_ms, self.counter + 1)
        }
    }

    /// Merges a remote reading on receipt.
    #[must_use]
    pub fn merge(self, remote: Hlc, now_ms: u64) -> Self {
        let wall = self.wall_ms.max(remote.wall_ms).max(now_ms);
        if wall == self.wall_ms && wall == remote.wall_ms {
            Self::new(wall, self.counter.max(remote.counter) + 1)
        } else if wall == self.wall_ms {
            Self::new(wall, self.counter + 1)
        } else if wall == remote.wall_ms {
            Self::new(wall, remote.counter + 1)
        } else {
            Self::new(wall, 0)
        }
    }
}

/// A coarsened position (§2.2). Integers, not floats — see `spec` §2.2 for why
/// a float here would make ids diverge between native and WASM.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GeoPoint {
    /// Latitude in microdegrees (10^-6 degrees).
    pub lat_udeg: i32,
    /// Longitude in microdegrees.
    pub lon_udeg: i32,
    /// Horizontal accuracy in millimetres.
    pub acc_mm: u32,
}

/// A sensor reading as mantissa and decimal exponent: `mantissa x 10^exponent`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Reading {
    pub mantissa: i64,
    pub exponent: i64,
}

/// Per-author sequence number. Starts at 0, increments by exactly 1, and is
/// verified jointly with `prev` (§6.6) because it is attacker-controlled.
pub type Seq = u64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_advances_wall_when_clock_moves_forward() {
        let h = Hlc::new(100, 5);
        assert_eq!(h.tick(200), Hlc::new(200, 0));
    }

    #[test]
    fn tick_advances_counter_when_clock_stalls_or_rolls_back() {
        let h = Hlc::new(100, 5);
        assert_eq!(h.tick(100), Hlc::new(100, 6), "stalled clock");
        assert_eq!(h.tick(50), Hlc::new(100, 6), "rolled-back clock");
    }

    #[test]
    fn merge_never_moves_backwards() {
        let local = Hlc::new(100, 3);
        for remote in [Hlc::new(50, 0), Hlc::new(100, 9), Hlc::new(400, 1)] {
            for now in [0u64, 100, 500] {
                let merged = local.merge(remote, now);
                assert!(
                    merged >= local && merged >= remote,
                    "merge({local:?}, {remote:?}, {now}) = {merged:?} went backwards"
                );
            }
        }
    }

    #[test]
    fn a_rolled_back_remote_clock_cannot_drag_local_time_backwards() {
        // The backdater's move: claim a wall time three days ago.
        let local = Hlc::new(1_700_000_000_000, 0);
        let backdated = Hlc::new(1_699_740_000_000, 0);
        let merged = local.merge(backdated, 0);
        assert_eq!(merged.wall_ms, 1_700_000_000_000);
        assert!(merged > local, "merge must still advance");
    }
}
