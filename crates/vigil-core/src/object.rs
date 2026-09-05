//! Object encodings, per `spec/01-wire-format.md` §6.
//!
//! Every field number and variant number in this file comes from a table in the
//! specification, never from the declaration order of a Rust struct or enum
//! (§2.4). Reordering anything here must not change a single byte of output; the
//! golden vectors in `testdata/vectors/` are what enforce that.

use std::collections::BTreeMap;

use crate::cbor::{MapReader, MapWriter, Reader, write_bytes, write_int, write_text, write_uint};
use crate::error::DecodeError;
use crate::types::{GeoPoint, Hash, Hlc, OpaqueId, PubKey, Reading, Seq, SiteId};

/// Domain separation: `tag || 0x00 || body` (§3.1).
///
/// The tag is US-ASCII and contains no NUL, so this concatenation is injective —
/// no two (tag, body) pairs collide. That injectivity is what makes it safe to
/// sign the bare 32-byte id in §4; see ADR-0001, where the coupling is recorded.
pub fn domain_sep(tag: &str, body: &[u8]) -> Vec<u8> {
    debug_assert!(
        tag.is_ascii() && !tag.as_bytes().contains(&0),
        "§3.1 tag rules"
    );
    let mut out = Vec::with_capacity(tag.len() + 1 + body.len());
    out.extend_from_slice(tag.as_bytes());
    out.push(0x00);
    out.extend_from_slice(body);
    out
}

/// The domain separation tag prefixed to a signed message (§4).
pub const SIG_TAG: &str = "vigilarch/1/sig";

/// A content-addressed, canonically encoded Vigilarch object.
pub trait Object: Sized {
    /// The domain separation tag from the §3.1 table.
    const TAG: &'static str;

    /// Writes this object's fields using the numbers from its §6 table.
    fn encode_fields(&self, m: &mut MapWriter);

    /// Reads fields back. Keys arrive in ascending order, guaranteed by the
    /// reader's ordering check.
    fn decode_fields(r: &mut Reader, m: &mut MapReader) -> Result<Self, DecodeError>;

    /// The canonical CBOR body, without the domain separation tag.
    fn canonical_cbor(&self) -> Vec<u8> {
        let mut m = MapWriter::new();
        self.encode_fields(&mut m);
        let mut out = Vec::new();
        m.finish(&mut out);
        out
    }

    /// The full hash preimage: `tag || 0x00 || canonical_cbor`.
    fn preimage(&self) -> Vec<u8> {
        domain_sep(Self::TAG, &self.canonical_cbor())
    }

    /// The content address (§3.1).
    ///
    /// Always computed, never read from the wire — §3.2 forbids an `id` field in
    /// any frame, which is why there is no "id mismatch" path to get wrong.
    fn id(&self) -> Hash {
        Hash(*blake3::hash(&self.preimage()).as_bytes())
    }

    /// Decodes from a full preimage, checking the domain separation tag.
    fn decode_preimage(bytes: &[u8]) -> Result<Self, DecodeError> {
        let tag = Self::TAG.as_bytes();
        if bytes.len() <= tag.len() || &bytes[..tag.len()] != tag || bytes[tag.len()] != 0 {
            return Err(DecodeError::WrongTag {
                expected: Self::TAG,
            });
        }
        Self::decode_cbor(&bytes[tag.len() + 1..])
    }

    /// Decodes from the canonical CBOR body alone.
    fn decode_cbor(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let mut m = r.map()?;
        let value = Self::decode_fields(&mut r, &mut m)?;
        r.finish()?;
        Ok(value)
    }
}

// ---------------------------------------------------------------------------
// Shared field encodings
// ---------------------------------------------------------------------------

fn write_hlc(h: &Hlc, out: &mut Vec<u8>) {
    crate::cbor::write_array_head(2, out);
    write_uint(h.wall_ms, out);
    write_uint(h.counter, out);
}

fn read_hlc(r: &mut Reader) -> Result<Hlc, DecodeError> {
    r.expect_array(2)?;
    Ok(Hlc::new(r.uint()?, r.uint()?))
}

fn write_geo(g: &GeoPoint, out: &mut Vec<u8>) {
    crate::cbor::write_array_head(3, out);
    write_int(i64::from(g.lat_udeg), out);
    write_int(i64::from(g.lon_udeg), out);
    write_uint(u64::from(g.acc_mm), out);
}

fn read_geo(r: &mut Reader) -> Result<GeoPoint, DecodeError> {
    r.expect_array(3)?;
    let lat = r.int()?;
    let lon = r.int()?;
    let acc = r.uint()?;
    Ok(GeoPoint {
        lat_udeg: i32::try_from(lat).map_err(|_| DecodeError::IntegerOverflow {
            value: lat.unsigned_abs(),
            target: "i32 microdegrees",
        })?,
        lon_udeg: i32::try_from(lon).map_err(|_| DecodeError::IntegerOverflow {
            value: lon.unsigned_abs(),
            target: "i32 microdegrees",
        })?,
        acc_mm: u32::try_from(acc).map_err(|_| DecodeError::IntegerOverflow {
            value: acc,
            target: "u32 millimetres",
        })?,
    })
}

fn missing<T>(field: u64) -> Result<T, DecodeError> {
    Err(DecodeError::MissingField(field))
}

// ---------------------------------------------------------------------------
// Observation (§6.1)
// ---------------------------------------------------------------------------

/// An immutable, content-addressed assertion that someone perceived something.
///
/// Never edited — invariant I3 puts capture on the immutable side of the line and
/// interpretation on the mutable side. Correcting an observation means writing a
/// new one and, at M3-lite, an `Assertion` that retracts the old.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Observation {
    pub author: PubKey,
    pub site: SiteId,
    /// `None` is genesis, encoded as a zero-length byte string (§6.1). Genesis is
    /// a value, not an absence, so this field is never omitted.
    pub prev: Option<Hash>,
    pub seq: Seq,
    pub hlc: Hlc,
    pub body: ObservationBody,
    pub geo: Option<GeoPoint>,
}

/// Body variants. **The discriminants come from the §6.1 table**, not from
/// declaration order — reordering these must not change any encoding.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ObservationBody {
    Note {
        text: String,
    },
    Voice {
        transcript: String,
        audio: Hash,
    },
    Media {
        blob: Hash,
        kind: u64,
        caption: Option<String>,
    },
    Sensor {
        source: OpaqueId,
        reading: Reading,
    },
    Presence {
        actor: OpaqueId,
        zone: OpaqueId,
        event: PresenceEvent,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PresenceEvent {
    Enter,
    Exit,
}

impl ObservationBody {
    /// The variant number from the §6.1 table.
    fn variant(&self) -> u64 {
        match self {
            Self::Note { .. } => 0,
            Self::Voice { .. } => 1,
            Self::Media { .. } => 2,
            // 3 = Form — see decode, the payload type is not yet specified.
            Self::Sensor { .. } => 4,
            Self::Presence { .. } => 5,
            // 6 = Heartbeat — see decode.
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        crate::cbor::write_array_head(2, out);
        write_uint(self.variant(), out);
        let mut m = MapWriter::new();
        match self {
            Self::Note { text } => {
                m.field(1, |o| write_text(text, o));
            }
            Self::Voice { transcript, audio } => {
                m.field(1, |o| write_text(transcript, o));
                m.field(2, |o| write_bytes(audio.as_bytes(), o));
            }
            Self::Media {
                blob,
                kind,
                caption,
            } => {
                m.field(1, |o| write_bytes(blob.as_bytes(), o));
                m.field(2, |o| write_uint(*kind, o));
                m.optional(3, caption, |c, o| write_text(c, o));
            }
            Self::Sensor { source, reading } => {
                m.field(1, |o| write_bytes(source.as_bytes(), o));
                m.field(2, |o| {
                    crate::cbor::write_array_head(2, o);
                    write_int(reading.mantissa, o);
                    write_int(reading.exponent, o);
                });
            }
            Self::Presence { actor, zone, event } => {
                m.field(1, |o| write_bytes(actor.as_bytes(), o));
                m.field(2, |o| write_bytes(zone.as_bytes(), o));
                m.field(3, |o| {
                    write_uint(
                        if matches!(event, PresenceEvent::Enter) {
                            0
                        } else {
                            1
                        },
                        o,
                    )
                });
            }
        }
        m.finish(out);
    }

    fn decode(r: &mut Reader) -> Result<Self, DecodeError> {
        r.expect_array(2)?;
        let variant = r.uint()?;
        let mut m = r.map()?;

        // Field slots, filled as keys arrive in ascending order.
        let (mut f1_text, mut f1_bytes) = (None::<String>, None::<Vec<u8>>);
        let (mut f2_bytes, mut f2_uint) = (None::<Vec<u8>>, None::<u64>);
        let mut f2_reading = None::<Reading>;
        let (mut f3_text, mut f3_uint) = (None::<String>, None::<u64>);

        while let Some(key) = m.next_uint_key(r)? {
            match (variant, key) {
                (0, 1) | (1, 1) => f1_text = Some(r.text()?.to_owned()),
                (2, 1) | (4, 1) | (5, 1) => f1_bytes = Some(r.bytes()?.to_vec()),
                (1, 2) | (5, 2) => f2_bytes = Some(r.bytes()?.to_vec()),
                (2, 2) => f2_uint = Some(r.uint()?),
                (4, 2) => {
                    r.expect_array(2)?;
                    f2_reading = Some(Reading {
                        mantissa: r.int()?,
                        exponent: r.int()?,
                    });
                }
                (2, 3) => f3_text = Some(r.text()?.to_owned()),
                (5, 3) => f3_uint = Some(r.uint()?),
                (3, _) | (6, _) => return Err(unspecified_variant(variant)),
                (0..=6, k) => return Err(DecodeError::UnknownField(k)),
                _ => return Err(DecodeError::UnknownVariant(variant)),
            }
        }

        // `field` is the number from the §6.1 table, so an omitted payload field
        // reports the number the spec gives it rather than a placeholder.
        let hash32 = |b: Option<Vec<u8>>, field, what| -> Result<Hash, DecodeError> {
            let v = b.ok_or(DecodeError::MissingField(field))?;
            Ok(Hash(v.as_slice().try_into().map_err(|_| {
                DecodeError::WrongLength {
                    what,
                    expected: 32,
                    found: v.len(),
                }
            })?))
        };
        let opaque16 = |b: Option<Vec<u8>>, field, what| -> Result<OpaqueId, DecodeError> {
            let v = b.ok_or(DecodeError::MissingField(field))?;
            Ok(OpaqueId(v.as_slice().try_into().map_err(|_| {
                DecodeError::WrongLength {
                    what,
                    expected: 16,
                    found: v.len(),
                }
            })?))
        };

        match variant {
            0 => Ok(Self::Note {
                text: f1_text.ok_or(DecodeError::MissingField(1))?,
            }),
            1 => Ok(Self::Voice {
                transcript: f1_text.ok_or(DecodeError::MissingField(1))?,
                audio: hash32(f2_bytes, 2, "audio BlobRef")?,
            }),
            2 => Ok(Self::Media {
                blob: hash32(f1_bytes, 1, "blob BlobRef")?,
                kind: f2_uint.ok_or(DecodeError::MissingField(2))?,
                caption: f3_text,
            }),
            4 => Ok(Self::Sensor {
                source: opaque16(f1_bytes, 1, "sensor source")?,
                reading: f2_reading.ok_or(DecodeError::MissingField(2))?,
            }),
            5 => {
                let event = match f3_uint.ok_or(DecodeError::MissingField(3))? {
                    0 => PresenceEvent::Enter,
                    1 => PresenceEvent::Exit,
                    other => return Err(DecodeError::UnknownVariant(other)),
                };
                Ok(Self::Presence {
                    actor: opaque16(f1_bytes, 1, "presence actor")?,
                    zone: opaque16(f2_bytes, 2, "presence zone")?,
                    event,
                })
            }
            3 | 6 => Err(unspecified_variant(variant)),
            other => Err(DecodeError::UnknownVariant(other)),
        }
    }
}

/// Variants 3 (`Form`) and 6 (`Heartbeat`) are named in the §6.1 table but their
/// payloads are not pinned by any specification text: `Form.answers` is typed
/// `map{uint => Value}` and `Value` is never defined, and `Heartbeat.node_state`
/// defers to `03-sync.md`, which is unwritten.
///
/// They are rejected rather than guessed. Inventing an encoding here would make
/// the implementation the specification, which is exactly the failure the
/// hand-written-preimage rule (§2.4) exists to prevent — and once a vector is
/// published against a guessed encoding, changing it costs a wire version bump.
fn unspecified_variant(variant: u64) -> DecodeError {
    DecodeError::UnspecifiedInSpec {
        variant,
        gap: match variant {
            3 => "Form.answers: the Value type is not defined in spec/01-wire-format.md §6.1",
            _ => "Heartbeat.node_state: shape deferred to spec/03-sync.md, which is unwritten",
        },
    }
}

impl Object for Observation {
    const TAG: &'static str = "vigilarch/1/observation";

    fn encode_fields(&self, m: &mut MapWriter) {
        m.field(1, |o| write_bytes(self.author.as_bytes(), o));
        m.field(2, |o| write_bytes(self.site.as_bytes(), o));
        // Genesis is a zero-length byte string, not an omitted field (§6.1).
        m.field(3, |o| {
            write_bytes(self.prev.as_ref().map_or(&[][..], |h| h.as_bytes()), o)
        });
        m.field(4, |o| write_uint(self.seq, o));
        m.field(5, |o| write_hlc(&self.hlc, o));
        m.field(6, |o| self.body.encode(o));
        m.optional(7, &self.geo, write_geo);
    }

    fn decode_fields(r: &mut Reader, m: &mut MapReader) -> Result<Self, DecodeError> {
        let (mut author, mut site, mut prev, mut seq, mut hlc, mut body, mut geo) =
            (None, None, None, None, None, None, None);
        while let Some(key) = m.next_uint_key(r)? {
            match key {
                1 => author = Some(PubKey(r.fixed_bytes("author PubKey")?)),
                2 => site = Some(SiteId(r.fixed_bytes("site SiteId")?)),
                3 => {
                    let b = r.bytes()?;
                    prev = Some(match b.len() {
                        0 => None,
                        32 => Some(Hash(b.try_into().expect("32 bytes"))),
                        found => {
                            return Err(DecodeError::WrongLength {
                                what: "prev Hash",
                                expected: 32,
                                found,
                            });
                        }
                    });
                }
                4 => seq = Some(r.uint()?),
                5 => hlc = Some(read_hlc(r)?),
                6 => body = Some(ObservationBody::decode(r)?),
                7 => geo = Some(read_geo(r)?),
                k => return Err(DecodeError::UnknownField(k)),
            }
        }
        Ok(Self {
            author: author.map_or_else(|| missing(1), Ok)?,
            site: site.map_or_else(|| missing(2), Ok)?,
            prev: prev.map_or_else(|| missing(3), Ok)?,
            seq: seq.map_or_else(|| missing(4), Ok)?,
            hlc: hlc.map_or_else(|| missing(5), Ok)?,
            body: body.map_or_else(|| missing(6), Ok)?,
            geo,
        })
    }
}

// ---------------------------------------------------------------------------
// Attestation (§6.5)
// ---------------------------------------------------------------------------

/// A witness's signed record that it saw a subject claiming a head.
///
/// It says only *at some point, I saw this subject at this head and seq*. It says
/// nothing in wall-clock terms, and `witness_hlc` must not be read as if it did.
/// M1 builds the DAG that turns these into ordering evidence; M0 only encodes
/// them so the format is pinned before anything depends on it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Attestation {
    pub witness: PubKey,
    pub subject: PubKey,
    pub subject_head: Hash,
    pub subject_seq: Seq,
    pub witness_hlc: Hlc,
    /// From a CSPRNG, never derived from a clock (§6.5). It makes two
    /// attestations of the same head distinguishable, so a replay is detectable
    /// as a duplicate rather than merging invisibly with a fresh one.
    pub nonce: [u8; 16],
}

impl Object for Attestation {
    const TAG: &'static str = "vigilarch/1/attestation";

    fn encode_fields(&self, m: &mut MapWriter) {
        m.field(1, |o| write_bytes(self.witness.as_bytes(), o));
        m.field(2, |o| write_bytes(self.subject.as_bytes(), o));
        m.field(3, |o| write_bytes(self.subject_head.as_bytes(), o));
        m.field(4, |o| write_uint(self.subject_seq, o));
        m.field(5, |o| write_hlc(&self.witness_hlc, o));
        m.field(6, |o| write_bytes(&self.nonce, o));
    }

    fn decode_fields(r: &mut Reader, m: &mut MapReader) -> Result<Self, DecodeError> {
        let (mut w, mut s, mut head, mut seq, mut hlc, mut nonce) =
            (None, None, None, None, None, None);
        while let Some(key) = m.next_uint_key(r)? {
            match key {
                1 => w = Some(PubKey(r.fixed_bytes("witness PubKey")?)),
                2 => s = Some(PubKey(r.fixed_bytes("subject PubKey")?)),
                3 => head = Some(Hash(r.fixed_bytes("subject_head Hash")?)),
                4 => seq = Some(r.uint()?),
                5 => hlc = Some(read_hlc(r)?),
                6 => nonce = Some(r.fixed_bytes::<16>("nonce")?),
                k => return Err(DecodeError::UnknownField(k)),
            }
        }
        Ok(Self {
            witness: w.map_or_else(|| missing(1), Ok)?,
            subject: s.map_or_else(|| missing(2), Ok)?,
            subject_head: head.map_or_else(|| missing(3), Ok)?,
            subject_seq: seq.map_or_else(|| missing(4), Ok)?,
            witness_hlc: hlc.map_or_else(|| missing(5), Ok)?,
            nonce: nonce.map_or_else(|| missing(6), Ok)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Checkpoint (§6.4)
// ---------------------------------------------------------------------------

/// A node's signed position in its own history.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Checkpoint {
    pub node: PubKey,
    pub head: Hash,
    pub seq: Seq,
    pub hlc: Hlc,
    /// A `VersionVector` (§5): what this node had seen from every author it knew
    /// of, at the moment it signed.
    ///
    /// A `BTreeMap` rather than a `Vec<(PubKey, Seq)>`, so that ordering and
    /// uniqueness are properties of the type rather than a convention a caller
    /// has to honour. A vector permits two values that are unequal in Rust but
    /// encode to identical bytes — same content address, same object as far as
    /// the ledger is concerned — and any code that deduplicates or compares
    /// checkpoints structurally would then disagree with the ledger about what is
    /// the same object. A property test caught exactly that.
    ///
    /// Iteration order is the canonical order for free: every key is 32 bytes, so
    /// all encoded keys share the `0x5820` prefix and bytewise order over encoded
    /// keys coincides with `Ord` over the raw key bytes (§2.1 rule 3).
    pub frontier: BTreeMap<PubKey, Seq>,
}

impl Object for Checkpoint {
    const TAG: &'static str = "vigilarch/1/checkpoint";

    fn encode_fields(&self, m: &mut MapWriter) {
        m.field(1, |o| write_bytes(self.node.as_bytes(), o));
        m.field(2, |o| write_bytes(self.head.as_bytes(), o));
        m.field(3, |o| write_uint(self.seq, o));
        m.field(4, |o| write_hlc(&self.hlc, o));
        m.field(5, |o| {
            let mut inner = MapWriter::new();
            for (key, seq) in &self.frontier {
                inner.bytes_key(key.as_bytes(), |v| write_uint(*seq, v));
            }
            inner.finish(o);
        });
    }

    fn decode_fields(r: &mut Reader, m: &mut MapReader) -> Result<Self, DecodeError> {
        let (mut node, mut head, mut seq, mut hlc, mut frontier) = (None, None, None, None, None);
        while let Some(key) = m.next_uint_key(r)? {
            match key {
                1 => node = Some(PubKey(r.fixed_bytes("node PubKey")?)),
                2 => head = Some(Hash(r.fixed_bytes("head Hash")?)),
                3 => seq = Some(r.uint()?),
                4 => hlc = Some(read_hlc(r)?),
                5 => {
                    let mut inner = r.map()?;
                    let mut entries = BTreeMap::new();
                    // A duplicate key cannot reach here: the reader rejects a key
                    // that does not strictly exceed its predecessor (§2.1 rule 3),
                    // so no entry is ever silently overwritten.
                    while let Some(k) = inner.next_bytes_key(r)? {
                        let pk: [u8; 32] = k.try_into().map_err(|_| DecodeError::WrongLength {
                            what: "frontier PubKey",
                            expected: 32,
                            found: k.len(),
                        })?;
                        entries.insert(PubKey(pk), r.uint()?);
                    }
                    frontier = Some(entries);
                }
                k => return Err(DecodeError::UnknownField(k)),
            }
        }
        Ok(Self {
            node: node.map_or_else(|| missing(1), Ok)?,
            head: head.map_or_else(|| missing(2), Ok)?,
            seq: seq.map_or_else(|| missing(3), Ok)?,
            hlc: hlc.map_or_else(|| missing(4), Ok)?,
            frontier: frontier.map_or_else(|| missing(5), Ok)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Blob manifest (§6.2)
// ---------------------------------------------------------------------------

/// A blob is addressed by the hash of this manifest, not of its contents (§3.3).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlobManifest {
    pub size: u64,
    pub chunks: Vec<Hash>,
    pub mime: String,
}

impl Object for BlobManifest {
    const TAG: &'static str = "vigilarch/1/blob";

    fn encode_fields(&self, m: &mut MapWriter) {
        m.field(1, |o| write_uint(self.size, o));
        m.field(2, |o| {
            crate::cbor::write_array_head(self.chunks.len() as u64, o);
            for c in &self.chunks {
                write_bytes(c.as_bytes(), o);
            }
        });
        m.field(3, |o| write_text(&self.mime, o));
    }

    fn decode_fields(r: &mut Reader, m: &mut MapReader) -> Result<Self, DecodeError> {
        let (mut size, mut chunks, mut mime) = (None, None, None);
        while let Some(key) = m.next_uint_key(r)? {
            match key {
                1 => size = Some(r.uint()?),
                2 => {
                    let n = r.array_head()?;
                    // Each chunk hash costs 34 bytes on the wire, so a declared
                    // count exceeding the remaining input cannot be honoured.
                    // Bound before allocating (§8).
                    if n > r.remaining() as u64 {
                        return Err(DecodeError::LengthExceedsInput {
                            declared: n,
                            remaining: r.remaining(),
                        });
                    }
                    let mut v = Vec::with_capacity(n as usize);
                    for _ in 0..n {
                        v.push(Hash(r.fixed_bytes("chunk Hash")?));
                    }
                    chunks = Some(v);
                }
                3 => mime = Some(r.text()?.to_owned()),
                k => return Err(DecodeError::UnknownField(k)),
            }
        }
        Ok(Self {
            size: size.map_or_else(|| missing(1), Ok)?,
            chunks: chunks.map_or_else(|| missing(2), Ok)?,
            mime: mime.map_or_else(|| missing(3), Ok)?,
        })
    }
}
