//! The canonical CBOR profile of `spec/01-wire-format.md` §2.
//!
//! This is a hand-written encoder and decoder for a deliberately small subset of
//! RFC 8949. It is not a general CBOR library and must not grow into one.
//!
//! `serde` and `ciborium` are barred from this path by §2.4: a derive takes its
//! field order and enum tagging from Rust source, so an ordinary refactor would
//! change every content address in history with no compile error and no failing
//! test. Every byte produced here traces to a table in the specification.
//!
//! ## Where the rules are enforced structurally
//!
//! Two of the profile's rules are easy to violate by accident, so neither is left
//! to the caller's discipline:
//!
//! - **Sorted, unique map keys** (§2.1 rule 3) — [`MapWriter`] buffers entries and
//!   sorts them by encoded key bytes on `finish()`. A caller emitting fields in
//!   the wrong order cannot produce a non-canonical map.
//! - **Shortest-form arguments** (§2.1 rule 2) — [`write_head`] computes the width
//!   from the value, and the decoder rejects any wider encoding it is handed.
//!
//! Everything the encoder can produce, the decoder accepts; everything the
//! decoder accepts, the encoder can produce. That round-trip property is what the
//! golden vectors and the fuzz targets check.

use crate::error::DecodeError;

// Major types, per RFC 8949 §3.1.
pub(crate) const MAJOR_UINT: u8 = 0;
pub(crate) const MAJOR_NEGINT: u8 = 1;
pub(crate) const MAJOR_BYTES: u8 = 2;
pub(crate) const MAJOR_TEXT: u8 = 3;
pub(crate) const MAJOR_ARRAY: u8 = 4;
pub(crate) const MAJOR_MAP: u8 = 5;
pub(crate) const MAJOR_TAG: u8 = 6;
pub(crate) const MAJOR_SIMPLE: u8 = 7;

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// Writes a head in the shortest form that represents `arg` (§2.1 rule 2).
pub fn write_head(major: u8, arg: u64, out: &mut Vec<u8>) {
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

pub fn write_uint(n: u64, out: &mut Vec<u8>) {
    write_head(MAJOR_UINT, n, out);
}

/// Signed integer. Major type 1 encodes `-1 - n`.
///
/// Used for geo microdegrees and sensor exponents — the quantities that would be
/// floats if §2.2 permitted any.
pub fn write_int(n: i64, out: &mut Vec<u8>) {
    if n >= 0 {
        write_head(MAJOR_UINT, n as u64, out);
    } else {
        // -1 - n, computed so that i64::MIN does not overflow.
        write_head(MAJOR_NEGINT, (n + 1).unsigned_abs(), out);
    }
}

pub fn write_bytes(b: &[u8], out: &mut Vec<u8>) {
    write_head(MAJOR_BYTES, b.len() as u64, out);
    out.extend_from_slice(b);
}

pub fn write_text(s: &str, out: &mut Vec<u8>) {
    write_head(MAJOR_TEXT, s.len() as u64, out);
    out.extend_from_slice(s.as_bytes());
}

pub fn write_array_head(n: u64, out: &mut Vec<u8>) {
    write_head(MAJOR_ARRAY, n, out);
}

pub fn write_bool(b: bool, out: &mut Vec<u8>) {
    out.push((MAJOR_SIMPLE << 5) | if b { 21 } else { 20 });
}

/// Buffers map entries and emits them in canonical key order.
///
/// The caller adds fields in whatever order reads well; `finish` sorts by encoded
/// key bytes (§2.1 rule 3) and panics on a duplicate key, which is always a
/// programming error rather than untrusted input.
#[derive(Default)]
pub struct MapWriter {
    entries: Vec<(Vec<u8>, Vec<u8>)>,
}

impl MapWriter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a field. `build` writes the value; it is skipped entirely for absent
    /// optional fields, which are omitted rather than encoded as null (§2.3).
    pub fn field<F: FnOnce(&mut Vec<u8>)>(&mut self, key: u64, build: F) {
        let mut k = Vec::new();
        write_uint(key, &mut k);
        let mut v = Vec::new();
        build(&mut v);
        self.entries.push((k, v));
    }

    /// Adds a field only when `value` is present (§2.3).
    pub fn optional<T, F: FnOnce(&T, &mut Vec<u8>)>(
        &mut self,
        key: u64,
        value: &Option<T>,
        build: F,
    ) {
        if let Some(v) = value {
            self.field(key, |out| build(v, out));
        }
    }

    /// Adds an entry whose key is a byte string rather than an integer — the
    /// `VersionVector` case, where keys are public keys.
    pub fn bytes_key<F: FnOnce(&mut Vec<u8>)>(&mut self, key: &[u8], build: F) {
        let mut k = Vec::new();
        write_bytes(key, &mut k);
        let mut v = Vec::new();
        build(&mut v);
        self.entries.push((k, v));
    }

    pub fn finish(mut self, out: &mut Vec<u8>) {
        self.entries.sort_by(|a, b| a.0.cmp(&b.0));
        debug_assert!(
            self.entries.windows(2).all(|w| w[0].0 != w[1].0),
            "duplicate map key: a caller bug, never untrusted input"
        );
        write_head(MAJOR_MAP, self.entries.len() as u64, out);
        for (k, v) in self.entries {
            out.extend_from_slice(&k);
            out.extend_from_slice(&v);
        }
    }
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// A strict reader over canonical CBOR.
///
/// Rejects everything §2.1 forbids rather than tolerating it. This parses input
/// from devices we do not control, so leniency here is the attack surface
/// (§8).
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Asserts the whole input was consumed (§8: no trailing bytes).
    pub fn finish(self) -> Result<(), DecodeError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes {
                count: self.buf.len() - self.pos,
            })
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.remaining() < n {
            return Err(DecodeError::Truncated {
                wanted: n,
                available: self.remaining(),
            });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Reads one head, enforcing shortest form and rejecting indefinite lengths,
    /// tags, floats and reserved encodings.
    fn read_head(&mut self) -> Result<(u8, u64), DecodeError> {
        let b = self.take(1)?[0];
        let major = b >> 5;
        let ai = b & 0x1f;

        if major == MAJOR_TAG {
            return Err(DecodeError::Tag);
        }

        let arg = match ai {
            0..=23 => u64::from(ai),
            24 => {
                let v = u64::from(self.take(1)?[0]);
                // 0..=23 must have used the immediate form.
                if v < 24 {
                    return Err(DecodeError::NonShortestForm { value: v, width: 1 });
                }
                v
            }
            25 => {
                let raw = self.take(2)?;
                let v = u64::from(u16::from_be_bytes([raw[0], raw[1]]));
                if major == MAJOR_SIMPLE {
                    return Err(DecodeError::FloatingPoint); // half-precision
                }
                if v <= 0xff {
                    return Err(DecodeError::NonShortestForm { value: v, width: 2 });
                }
                v
            }
            26 => {
                let raw = self.take(4)?;
                let v = u64::from(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]));
                if major == MAJOR_SIMPLE {
                    return Err(DecodeError::FloatingPoint); // single-precision
                }
                if v <= 0xffff {
                    return Err(DecodeError::NonShortestForm { value: v, width: 4 });
                }
                v
            }
            27 => {
                let raw = self.take(8)?;
                let v = u64::from_be_bytes(raw.try_into().expect("8 bytes"));
                if major == MAJOR_SIMPLE {
                    return Err(DecodeError::FloatingPoint); // double-precision
                }
                if v <= 0xffff_ffff {
                    return Err(DecodeError::NonShortestForm { value: v, width: 8 });
                }
                v
            }
            28..=30 => return Err(DecodeError::ReservedAdditionalInfo(ai)),
            31 => return Err(DecodeError::IndefiniteLength),
            _ => unreachable!("ai is five bits"),
        };

        Ok((major, arg))
    }

    fn expect(&mut self, expected: u8) -> Result<u64, DecodeError> {
        let (major, arg) = self.read_head()?;
        if major != expected {
            return Err(DecodeError::WrongMajorType {
                expected,
                found: major,
            });
        }
        Ok(arg)
    }

    pub fn uint(&mut self) -> Result<u64, DecodeError> {
        self.expect(MAJOR_UINT)
    }

    pub fn int(&mut self) -> Result<i64, DecodeError> {
        let (major, arg) = self.read_head()?;
        match major {
            MAJOR_UINT => i64::try_from(arg).map_err(|_| DecodeError::IntegerOverflow {
                value: arg,
                target: "i64",
            }),
            MAJOR_NEGINT => {
                // Value is -1 - arg.
                let magnitude = i64::try_from(arg).map_err(|_| DecodeError::IntegerOverflow {
                    value: arg,
                    target: "i64",
                })?;
                Ok(-1 - magnitude)
            }
            found => Err(DecodeError::WrongMajorType {
                expected: MAJOR_UINT,
                found,
            }),
        }
    }

    /// Bounds the allocation by the remaining input as well as by the declared
    /// length (§8) — a 4 GiB header in a 40-byte frame is a rejection, not an
    /// allocation.
    fn length(&mut self, major: u8) -> Result<usize, DecodeError> {
        let declared = self.expect(major)?;
        if declared > self.remaining() as u64 {
            return Err(DecodeError::LengthExceedsInput {
                declared,
                remaining: self.remaining(),
            });
        }
        Ok(declared as usize)
    }

    pub fn bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let n = self.length(MAJOR_BYTES)?;
        self.take(n)
    }

    pub fn fixed_bytes<const N: usize>(
        &mut self,
        what: &'static str,
    ) -> Result<[u8; N], DecodeError> {
        let b = self.bytes()?;
        b.try_into().map_err(|_| DecodeError::WrongLength {
            what,
            expected: N,
            found: b.len(),
        })
    }

    pub fn text(&mut self) -> Result<&'a str, DecodeError> {
        let n = self.length(MAJOR_TEXT)?;
        let raw = self.take(n)?;
        core::str::from_utf8(raw).map_err(|_| DecodeError::InvalidUtf8)
    }

    pub fn bool(&mut self) -> Result<bool, DecodeError> {
        let b = self.take(1)?[0];
        match b {
            0xf4 => Ok(false),
            0xf5 => Ok(true),
            _ if b >> 5 == MAJOR_SIMPLE => Err(DecodeError::SimpleValue(b & 0x1f)),
            _ => Err(DecodeError::WrongMajorType {
                expected: MAJOR_SIMPLE,
                found: b >> 5,
            }),
        }
    }

    /// Reads an array head and returns its element count.
    pub fn array_head(&mut self) -> Result<u64, DecodeError> {
        self.expect(MAJOR_ARRAY)
    }

    pub fn expect_array(&mut self, n: u64) -> Result<(), DecodeError> {
        let got = self.array_head()?;
        if got == n {
            Ok(())
        } else {
            Err(DecodeError::WrongLength {
                what: "array",
                expected: n as usize,
                found: got as usize,
            })
        }
    }

    /// Reads a map head and returns a cursor that enforces key ordering.
    pub fn map(&mut self) -> Result<MapReader, DecodeError> {
        let n = self.expect(MAJOR_MAP)?;
        // Each entry is at least two bytes, so a declared count larger than half
        // the remaining input cannot be honoured. Bounds allocation before it is
        // attempted (§8).
        if n > self.remaining() as u64 {
            return Err(DecodeError::LengthExceedsInput {
                declared: n,
                remaining: self.remaining(),
            });
        }
        Ok(MapReader {
            len: n,
            read: 0,
            last_key: None,
        })
    }
}

/// Tracks progress and key ordering through one map.
pub struct MapReader {
    len: u64,
    read: u64,
    last_key: Option<Vec<u8>>,
}

impl MapReader {
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Reads the next key as an unsigned integer, checking that keys are in
    /// ascending bytewise order of their encoded bytes and not duplicated
    /// (§2.1 rule 3).
    pub fn next_uint_key(&mut self, r: &mut Reader) -> Result<Option<u64>, DecodeError> {
        if self.read == self.len {
            return Ok(None);
        }
        let start = r.pos;
        let key = r.uint()?;
        let encoded = r.buf[start..r.pos].to_vec();
        self.check_order(encoded)?;
        self.read += 1;
        Ok(Some(key))
    }

    /// Reads the next key as a byte string, with the same ordering check. Used
    /// for `VersionVector`, whose keys are public keys.
    pub fn next_bytes_key<'a>(
        &mut self,
        r: &mut Reader<'a>,
    ) -> Result<Option<&'a [u8]>, DecodeError> {
        if self.read == self.len {
            return Ok(None);
        }
        let start = r.pos;
        let key = r.bytes()?;
        let encoded = r.buf[start..r.pos].to_vec();
        self.check_order(encoded)?;
        self.read += 1;
        Ok(Some(key))
    }

    fn check_order(&mut self, encoded: Vec<u8>) -> Result<(), DecodeError> {
        if let Some(prev) = &self.last_key {
            if encoded.as_slice() <= prev.as_slice() {
                return Err(DecodeError::MapKeyOrder);
            }
        }
        self.last_key = Some(encoded);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_round_trips_at_every_width_boundary() {
        for v in [
            0u64,
            23,
            24,
            255,
            256,
            65535,
            65536,
            u32::MAX as u64,
            u32::MAX as u64 + 1,
            u64::MAX,
        ] {
            let mut out = Vec::new();
            write_uint(v, &mut out);
            let mut r = Reader::new(&out);
            assert_eq!(r.uint().unwrap(), v, "round trip for {v}");
            r.finish().unwrap();
        }
    }

    #[test]
    fn negative_integers_round_trip_including_min() {
        for v in [-1i64, -24, -25, -256, -257, i64::MIN + 1, i64::MIN] {
            let mut out = Vec::new();
            write_int(v, &mut out);
            let mut r = Reader::new(&out);
            assert_eq!(r.int().unwrap(), v, "round trip for {v}");
        }
    }

    #[test]
    fn non_shortest_form_is_rejected() {
        // 0 encoded in the one-byte-argument form instead of the immediate form.
        let mut r = Reader::new(&[0x18, 0x00]);
        assert_eq!(
            r.uint().unwrap_err(),
            DecodeError::NonShortestForm { value: 0, width: 1 }
        );
        // 255 encoded in two bytes instead of one.
        let mut r = Reader::new(&[0x19, 0x00, 0xff]);
        assert_eq!(
            r.uint().unwrap_err(),
            DecodeError::NonShortestForm {
                value: 255,
                width: 2
            }
        );
    }

    #[test]
    fn indefinite_length_is_rejected() {
        let mut r = Reader::new(&[0x5f]); // indefinite byte string
        assert_eq!(r.bytes().unwrap_err(), DecodeError::IndefiniteLength);
    }

    #[test]
    fn floats_are_rejected() {
        for enc in [
            vec![0xf9, 0x00, 0x00],             // half
            vec![0xfa, 0x00, 0x00, 0x00, 0x00], // single
            vec![0xfb, 0, 0, 0, 0, 0, 0, 0, 0], // double
        ] {
            let mut r = Reader::new(&enc);
            assert_eq!(r.int().unwrap_err(), DecodeError::FloatingPoint, "{enc:?}");
        }
    }

    #[test]
    fn tags_are_rejected() {
        let mut r = Reader::new(&[0xc0, 0x00]);
        assert_eq!(r.uint().unwrap_err(), DecodeError::Tag);
    }

    #[test]
    fn null_and_undefined_are_rejected() {
        for b in [0xf6u8, 0xf7] {
            let enc = [b];
            let mut r = Reader::new(&enc);
            assert!(matches!(r.bool().unwrap_err(), DecodeError::SimpleValue(_)));
        }
    }

    #[test]
    fn declared_length_beyond_input_is_rejected_without_allocating() {
        // A four-gigabyte byte string declared in a five-byte frame.
        let mut r = Reader::new(&[0x5a, 0xff, 0xff, 0xff, 0xff]);
        assert!(matches!(
            r.bytes().unwrap_err(),
            DecodeError::LengthExceedsInput { .. }
        ));
    }

    #[test]
    fn map_writer_sorts_regardless_of_insertion_order() {
        let mut m = MapWriter::new();
        m.field(6, |o| write_uint(60, o));
        m.field(1, |o| write_uint(10, o));
        m.field(3, |o| write_uint(30, o));
        let mut out = Vec::new();
        m.finish(&mut out);
        assert_eq!(
            out,
            vec![0xa3, 0x01, 0x0a, 0x03, 0x18, 0x1e, 0x06, 0x18, 0x3c]
        );
    }

    #[test]
    fn out_of_order_map_keys_are_rejected() {
        // {3: 0, 1: 0} — descending keys.
        let enc = [0xa2, 0x03, 0x00, 0x01, 0x00];
        let mut r = Reader::new(&enc);
        let mut m = r.map().unwrap();
        m.next_uint_key(&mut r).unwrap();
        r.uint().unwrap();
        assert_eq!(
            m.next_uint_key(&mut r).unwrap_err(),
            DecodeError::MapKeyOrder
        );
    }

    #[test]
    fn duplicate_map_keys_are_rejected() {
        let enc = [0xa2, 0x01, 0x00, 0x01, 0x00];
        let mut r = Reader::new(&enc);
        let mut m = r.map().unwrap();
        m.next_uint_key(&mut r).unwrap();
        r.uint().unwrap();
        assert_eq!(
            m.next_uint_key(&mut r).unwrap_err(),
            DecodeError::MapKeyOrder
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut r = Reader::new(&[0x00, 0x00]);
        r.uint().unwrap();
        assert_eq!(
            r.finish().unwrap_err(),
            DecodeError::TrailingBytes { count: 1 }
        );
    }
}
