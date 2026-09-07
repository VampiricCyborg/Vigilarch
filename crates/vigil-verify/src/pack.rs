//! Step 1–3 of `spec/03-export-pack.md` §5: the envelope, the per-object
//! self-check, and fork-proof validation — reimplemented here against
//! `vigil-core` alone.
//!
//! `vigil-ledger` has an [`export::parse_pack`] that does the same job. This is
//! deliberately *not* that function. The whole worth of `vigil-verify` is that a
//! second pair of eyes re-derives the verdict; a parser shared with the exporter
//! would reproduce an exporter bug with total confidence (`src/lib.rs`, the
//! independence rule). The only shared code is the canonical CBOR reader and the
//! object decoders in `vigil-core`, which invariant I2 requires there be exactly
//! one of and which the golden vectors in `testdata/vectors/` hold honest.
//!
//! [`export::parse_pack`]: https://docs.rs/vigil-ledger

use vigil_core::cbor::Reader;
use vigil_core::{
    Attestation, DecodeError, ForkProof, Hash, Object, Observation, PubKey, Signature,
    WIRE_VERSION, verify_id,
};

/// The file marker every pack begins with: `"vigilarch/1/pack" || 0x00`
/// (`spec/03-export-pack.md` §2.1). Never hashed, never signed — a file-type tag
/// and an explicit wire version.
pub const PACK_MARKER: &[u8] = b"vigilarch/1/pack\x00";

/// Why a pack file could not be parsed as far as its envelope structure
/// (`spec/03-export-pack.md` §5 step 1). Every one of these is a *structural*
/// rejection: the file is not a wire-version-1 pack for the organisation asked
/// about. A carried object that fails its own id/signature check is **not** one
/// of these — it is retained in [`PackContents`] with a non-`Ok` [`SelfCheck`]
/// and contributes nothing further (§5 step 2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PackParseError {
    /// The file did not begin with [`PACK_MARKER`].
    #[error("not an export pack: missing the `vigilarch/1/pack` marker")]
    BadMarker,

    /// `wire_version` was absent or not `1`. A pack is tied to exactly one wire
    /// version because every content address inside it is (`spec/03` §2.1).
    #[error("wire version {0} is not 1")]
    WrongWireVersion(u64),

    /// A required envelope field (1 `wire_version`, 2 `org`, 3 `observations`,
    /// 4 `attestations`, 6 `claims`) was missing.
    #[error("required envelope field {0} is missing")]
    MissingField(u64),

    /// An envelope field number this wire version does not define (`spec/01` §8:
    /// unknown fields are rejected, not ignored).
    #[error("unknown envelope field number {0}")]
    UnknownField(u64),

    /// `claims` (envelope field 6) was not strictly ascending and duplicate-free
    /// as `spec/03` §2.2 requires.
    #[error("claims are not strictly ascending and duplicate-free (spec/03 §2.2 field 6)")]
    ClaimsNotAscending,

    /// The `<org-pubkey>` argument did not match the envelope's `org`. The pack
    /// is for a different organisation than the caller asked about (`spec/03` §5
    /// step 1).
    #[error("pack is issued for org {found} but verification was requested for {requested}")]
    WrongOrg { requested: PubKey, found: PubKey },

    /// The envelope CBOR violated the `spec/01` §2.1 profile or §8 framing.
    #[error("envelope decode failed: {0}")]
    Decode(#[from] DecodeError),
}

/// The verdict of the `spec/03` §5 step 2 self-check on one carried object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfCheck {
    /// The preimage decoded as its declared type, the recomputed id is the
    /// BLAKE3 of the preimage, and the detached signature verified — under
    /// `author` for an observation, under `witness` for an attestation.
    Ok,
    /// The carried preimage did not decode as a canonical object of its declared
    /// type (`spec/01` §8). One flipped byte in a body does this.
    Undecodable,
    /// The object decoded but its detached signature did not verify under the
    /// appropriate key.
    BadSignature,
}

impl SelfCheck {
    #[must_use]
    pub fn is_ok(self) -> bool {
        matches!(self, SelfCheck::Ok)
    }
}

/// One object carried in a pack, after the `spec/03` §5 step 2 self-check.
#[derive(Debug, Clone)]
pub struct CarriedObject<T> {
    /// Position in the envelope array, for diagnostics ("observation #2").
    pub index: usize,
    /// The decoded object, or `None` if the preimage did not decode.
    pub object: Option<T>,
    /// The recomputed content address, or `None` if the preimage did not decode.
    /// Never read from the wire (`spec/01` §3.2).
    pub id: Option<Hash>,
    pub signature: Signature,
    pub check: SelfCheck,
}

/// The decoded contents of a pack file: the envelope fields plus every carried
/// object with its self-check verdict. Produced by [`parse_pack`], which is
/// `spec/03` §5 steps 1–3.
#[derive(Debug, Clone)]
pub struct PackContents {
    pub wire_version: u64,
    pub org: PubKey,
    pub observations: Vec<CarriedObject<Observation>>,
    pub attestations: Vec<CarriedObject<Attestation>>,
    /// Fork proofs that decoded *and* passed [`ForkProof::check`] — each carried
    /// as a bare preimage (`spec/03` §2.2 field 5). Position `usize` is the
    /// envelope-array index, for diagnostics.
    pub fork_proofs: Vec<(usize, ForkProof)>,
    /// How many `fork_proofs` entries were present but failed to decode or
    /// failed [`ForkProof::check`] (`spec/03` §5 step 3). A pack should never
    /// carry one — it is an invalid pack, not a tolerated condition.
    pub invalid_fork_proofs: usize,
    /// The claimed observation ids, in envelope order (which the parser has
    /// checked is strictly ascending — `spec/03` §2.2 field 6).
    pub claims: Vec<Hash>,
}

impl PackContents {
    /// How many carried objects failed their self-check (`spec/03` §5 step 2).
    #[must_use]
    pub fn invalid_object_count(&self) -> usize {
        self.observations
            .iter()
            .filter(|c| !c.check.is_ok())
            .count()
            + self
                .attestations
                .iter()
                .filter(|c| !c.check.is_ok())
                .count()
    }

    /// Every carried observation that passed its self-check.
    pub fn valid_observations(&self) -> impl Iterator<Item = (Hash, &Observation, &Signature)> {
        self.observations
            .iter()
            .filter_map(|c| match (c.check.is_ok(), &c.object, c.id) {
                (true, Some(o), Some(id)) => Some((id, o, &c.signature)),
                _ => None,
            })
    }

    /// Every carried attestation that passed its self-check.
    pub fn valid_attestations(&self) -> impl Iterator<Item = (Hash, &Attestation, &Signature)> {
        self.attestations
            .iter()
            .filter_map(|c| match (c.check.is_ok(), &c.object, c.id) {
                (true, Some(a), Some(id)) => Some((id, a, &c.signature)),
                _ => None,
            })
    }
}

/// `spec/03` §5 step 1–3: check the file marker, decode the envelope with the
/// strict `spec/01` §8 reader (total rejection on any violation — there is no
/// lenient mode), check `wire_version == 1` and `org == <org-pubkey>`, then
/// self-check every carried object and validate every carried fork proof.
///
/// The chain check, DAG rebuild and bracket recomputation of §5 steps 4–6 are
/// [`crate::verify`]'s job over the surviving objects.
///
/// # Errors
///
/// [`PackParseError`] on any structural failure. A carried object failing its
/// self-check is *not* an error — see [`PackContents::invalid_object_count`].
pub fn parse_pack(bytes: &[u8], org_arg: PubKey) -> Result<PackContents, PackParseError> {
    let body = bytes
        .strip_prefix(PACK_MARKER)
        .ok_or(PackParseError::BadMarker)?;

    let mut r = Reader::new(body);
    let mut m = r.map()?;

    let mut wire_version: Option<u64> = None;
    let mut org: Option<PubKey> = None;
    let mut observations: Option<Vec<CarriedObject<Observation>>> = None;
    let mut attestations: Option<Vec<CarriedObject<Attestation>>> = None;
    let mut fork_proofs: Vec<(usize, ForkProof)> = Vec::new();
    let mut invalid_fork_proofs = 0usize;
    let mut claims: Option<Vec<Hash>> = None;

    while let Some(key) = m.next_uint_key(&mut r)? {
        match key {
            1 => wire_version = Some(r.uint()?),
            2 => org = Some(PubKey(r.fixed_bytes::<32>("org PubKey")?)),
            3 => observations = Some(read_carried(&mut r, |o: &Observation| o.author)?),
            4 => attestations = Some(read_carried(&mut r, |a: &Attestation| a.witness)?),
            5 => read_fork_proofs(&mut r, &mut fork_proofs, &mut invalid_fork_proofs)?,
            6 => claims = Some(read_claims(&mut r)?),
            other => return Err(PackParseError::UnknownField(other)),
        }
    }
    r.finish()?;

    let wire_version = wire_version.ok_or(PackParseError::MissingField(1))?;
    if wire_version != u64::from(WIRE_VERSION) {
        return Err(PackParseError::WrongWireVersion(wire_version));
    }
    let org = org.ok_or(PackParseError::MissingField(2))?;
    if org != org_arg {
        return Err(PackParseError::WrongOrg {
            requested: org_arg,
            found: org,
        });
    }
    let observations = observations.ok_or(PackParseError::MissingField(3))?;
    let attestations = attestations.ok_or(PackParseError::MissingField(4))?;
    let claims = claims.ok_or(PackParseError::MissingField(6))?;

    Ok(PackContents {
        wire_version,
        org,
        observations,
        attestations,
        fork_proofs,
        invalid_fork_proofs,
        claims,
    })
}

/// Read envelope field 3 or 4: an array of `[preimage, sig]` pairs, each
/// self-checked (`spec/03` §5 step 2). `verify_key` pulls the signing key out of
/// the decoded object — `author` for an observation, `witness` for an
/// attestation.
fn read_carried<T: Object, F: Fn(&T) -> PubKey>(
    r: &mut Reader,
    verify_key: F,
) -> Result<Vec<CarriedObject<T>>, PackParseError> {
    let n = r.array_head()?;
    if n > r.remaining() as u64 {
        return Err(PackParseError::Decode(DecodeError::LengthExceedsInput {
            declared: n,
            remaining: r.remaining(),
        }));
    }
    let mut out = Vec::with_capacity(n as usize);
    for index in 0..n as usize {
        r.expect_array(2)?;
        let preimage = r.bytes()?.to_vec();
        let signature = Signature(r.fixed_bytes::<64>("carried object signature")?);

        let object = T::decode_preimage(&preimage).ok();
        let id = object.as_ref().map(Object::id);
        let check = match (&object, id) {
            (Some(o), Some(id)) => {
                if verify_id(verify_key(o), id, &signature).is_ok() {
                    SelfCheck::Ok
                } else {
                    SelfCheck::BadSignature
                }
            }
            _ => SelfCheck::Undecodable,
        };
        out.push(CarriedObject {
            index,
            object,
            id,
            signature,
            check,
        });
    }
    Ok(out)
}

/// Read envelope field 5: an array of bare `ForkProof` preimages. A proof that
/// does not decode, or does not pass [`ForkProof::check`], is dropped and
/// counted (`spec/03` §5 step 3).
fn read_fork_proofs(
    r: &mut Reader,
    out: &mut Vec<(usize, ForkProof)>,
    invalid: &mut usize,
) -> Result<(), PackParseError> {
    let n = r.array_head()?;
    if n > r.remaining() as u64 {
        return Err(PackParseError::Decode(DecodeError::LengthExceedsInput {
            declared: n,
            remaining: r.remaining(),
        }));
    }
    for index in 0..n as usize {
        let preimage = r.bytes()?.to_vec();
        match ForkProof::decode_preimage(&preimage) {
            Ok(proof) if proof.check().is_ok() => out.push((index, proof)),
            _ => *invalid += 1,
        }
    }
    Ok(())
}

/// Read envelope field 6: an array of 32-byte observation ids, which `spec/03`
/// §2.2 requires be strictly ascending and duplicate-free.
fn read_claims(r: &mut Reader) -> Result<Vec<Hash>, PackParseError> {
    let n = r.array_head()?;
    if n > r.remaining() as u64 {
        return Err(PackParseError::Decode(DecodeError::LengthExceedsInput {
            declared: n,
            remaining: r.remaining(),
        }));
    }
    let mut out: Vec<Hash> = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let h = Hash(r.fixed_bytes::<32>("claim observation id")?);
        if out.last().is_some_and(|prev| &h <= prev) {
            return Err(PackParseError::ClaimsNotAscending);
        }
        out.push(h);
    }
    Ok(out)
}
