//! Errors for the encoding and identity layer.

use thiserror::Error;

/// A failure to decode bytes as a canonical Vigilarch object.
///
/// Every variant means the same thing operationally: the bytes are **not** a
/// Vigilarch object and contribute nothing (`spec/01-wire-format.md` §8). The
/// variants exist so that a fuzzer failure and a field report can say which rule
/// was broken, not so callers can decide which ones to tolerate. There is no
/// lenient mode.
///
/// Note the boundary drawn in §6.6: a `DecodeError` means the *bytes* are
/// malformed and it attributes nothing to anyone, since any device can emit
/// garbage. An object that decodes cleanly and whose signature verifies, but
/// whose chain claims contradict each other, is an entirely different thing — an
/// integrity finding attributable to a key — and it is not represented here.
/// `vigil-ledger` owns that.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum DecodeError {
    #[error("unexpected end of input: wanted {wanted} more bytes, {available} available")]
    Truncated { wanted: usize, available: usize },

    #[error("trailing bytes after a complete object: {count} left over")]
    TrailingBytes { count: usize },

    #[error("indefinite-length item (§2.1 rule 1)")]
    IndefiniteLength,

    #[error("non-shortest-form argument (§2.1 rule 2): {value} encoded in {width} bytes")]
    NonShortestForm { value: u64, width: u8 },

    #[error("map keys out of order or duplicated (§2.1 rule 3)")]
    MapKeyOrder,

    #[error("floating point value (§2.2) — use a scaled integer")]
    FloatingPoint,

    #[error("CBOR tag (§2.1 rule 5) — Vigilarch defines none")]
    Tag,

    #[error("simple value {0} (§2.1 rule 6) — only false and true are permitted")]
    SimpleValue(u8),

    #[error("reserved additional information {0}")]
    ReservedAdditionalInfo(u8),

    #[error("expected CBOR major type {expected}, found {found}")]
    WrongMajorType { expected: u8, found: u8 },

    #[error("declared length {declared} exceeds {remaining} remaining input bytes")]
    LengthExceedsInput { declared: u64, remaining: usize },

    #[error("expected exactly {expected} bytes for {what}, found {found}")]
    WrongLength {
        what: &'static str,
        expected: usize,
        found: usize,
    },

    #[error("text is not valid UTF-8 (§2.1 rule 7)")]
    InvalidUtf8,

    #[error("value {value} does not fit in {target}")]
    IntegerOverflow { value: u64, target: &'static str },

    #[error("wrong domain separation tag: expected {expected:?}")]
    WrongTag { expected: &'static str },

    #[error("unknown field number {0} (§8) — forward compatibility is via version negotiation")]
    UnknownField(u64),

    #[error("unknown variant number {0} (§8)")]
    UnknownVariant(u64),

    #[error("required field {0} is missing")]
    MissingField(u64),

    #[error("an id field was present on the wire (§3.2) — ids are always recomputed")]
    IdOnTheWire,

    /// A variant the specification names but does not pin the payload of.
    ///
    /// This is not "unknown" — §8 requires rejecting unknown variants, and this
    /// is a *known* one whose encoding no document defines. Guessing a payload
    /// here would make the implementation the specification, and once a vector
    /// were published against the guess, correcting it would cost a wire version
    /// bump (§11). `gap` names the missing text so the failure reads as the spec
    /// bug it is rather than as a malformed frame.
    #[error("variant {variant} is named in the spec but its payload is unspecified: {gap}")]
    UnspecifiedInSpec { variant: u64, gap: &'static str },
}

/// A signature that did not verify.
///
/// Deliberately carries no detail. Distinguishing "wrong key" from "wrong
/// message" from "malformed signature" gives an attacker a probing oracle and
/// tells an honest operator nothing they can act on.
#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
#[error("signature verification failed")]
pub struct SignatureError;
