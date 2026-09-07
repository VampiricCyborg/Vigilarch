//! Export-pack assembly and parsing (`spec/03-export-pack.md`).
//!
//! An **export pack** is the self-contained file a node produces so a third
//! party — with no database, no network, and no node — can independently check
//! the bracket claims the node makes about its own records (`spec/03` §1). It
//! carries no new object encoding: every observation, attestation and fork proof
//! inside it is one of the `spec/01-wire-format.md` §6 types in its existing
//! canonical form, wrapped in an unsigned CBOR envelope (`spec/03` §2).
//!
//! ## What [`export_pack`] puts in a pack (`spec/03` §3)
//!
//! For every claimed observation:
//!
//! - the claimed observation itself (§3.1);
//! - its author's chain segment, contiguous by `seq` as the store holds it, from
//!   the earliest held entry up to and including the furthest entry any carried
//!   attestation anchors on (§3.2). "Far enough" is read straight off
//!   [`Dag::build`]'s seal-edge anchoring — this module does not reimplement
//!   §4.5;
//! - every attestation reachable to or from the claim in that DAG (§3.3);
//! - every held [`ForkProof`](vigil_core::ForkProof) convicting any key that
//!   appears anywhere in the pack (§3.4).
//!
//! Nothing else. A pack is the smallest object set the stated claims follow from
//! (`spec/03` §4): records not named, unrelated attestations, and other authors'
//! chains are all left out. The one exception the spec makes — never drop
//! something that would *widen* a bracket — is why every reachable attestation
//! and every touching fork proof is mandatory.
//!
//! The "earliest held" marker (`spec/03` §3.5) is implicit: when an author's
//! segment does not start at `seq` 0, that shows up as the lowest carried `seq`
//! for that author being non-zero, and a verifier detects it directly. There is
//! no flag field.
//!
//! ## Determinism (`spec/03` §2.3)
//!
//! Two exporters with the same claims over the same held objects produce
//! byte-identical files. Every list is ordered by recomputed content address,
//! the envelope map obeys the `spec/01` §2.1 key ordering, and an empty
//! `fork_proofs` field is omitted rather than encoded as `[]`.
//!
//! ## [`parse_pack`] — the read side
//!
//! [`parse_pack`] performs `spec/03` §5 steps 1–3: it checks the file marker,
//! decodes the envelope with the `spec/01` §8 strict reader, and self-checks
//! every carried object (recompute id, decode, verify signature). An object
//! failing any check is kept as [`CarriedObject`] with `self_check_ok == false`
//! and contributes nothing further, exactly as §5 step 2 requires. The chain
//! check, DAG rebuild and bracket recomputation of §5 steps 4–6 are the caller's
//! to run over the surviving objects with the ordinary `vigil-ledger` APIs;
//! `vigil-verify` is what wires them into a verdict.

use std::collections::{BTreeMap, BTreeSet};

use vigil_core::cbor::{MapWriter, Reader, write_array_head, write_bytes, write_uint};
use vigil_core::{
    Attestation, DecodeError, ForkProof, Hash, Object, Observation, PubKey, Signature,
    WIRE_VERSION, verify_id,
};

use crate::dag::{Dag, DagNode};
use crate::fork::{Quarantine, detect_forks};
use crate::store::{Store, StoreError, StoredAttestation, StoredObservation};

/// The file marker every pack begins with: `"vigilarch/1/pack" || 0x00`
/// (`spec/03-export-pack.md` §2.1). It is a file-type tag and an explicit wire
/// version, never a hash preimage — nothing signs or hashes it.
pub const PACK_MARKER: &[u8] = b"vigilarch/1/pack\x00";

/// Why [`export_pack`] could not build a pack.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// A claim names an observation the store does not hold. A pack must carry
    /// every claimed observation (`spec/03` §3.1), so this cannot be papered
    /// over.
    #[error("claim names an observation the store does not hold: {0}")]
    ClaimNotHeld(Hash),

    /// The storage backend failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Assemble an export pack for `claims` from everything `store` holds
/// (`spec/03-export-pack.md` §2–§4).
///
/// `quarantine` is threaded into [`Dag::build`] so that a convicted witness's
/// seal edges are dropped before "far enough" (§3.2) is measured — a pack must
/// not be sized against evidence the exporter already knows is unsound. Pass
/// [`Quarantine::new`] for the ordinary case.
///
/// `org` is written into the envelope as a label (`spec/03` §2.4); it is not
/// checked against any certificate here, because key issuance is stubbed in v1.
///
/// The returned bytes are the complete pack file: [`PACK_MARKER`] followed by
/// the canonical-CBOR envelope.
///
/// # Errors
///
/// [`ExportError::ClaimNotHeld`] if any claimed id is not a stored observation;
/// [`ExportError::Store`] if the backend fails.
pub fn export_pack<S: Store + ?Sized>(
    store: &S,
    quarantine: &Quarantine,
    org: PubKey,
    claims: &[Hash],
) -> Result<Vec<u8>, ExportError> {
    // 1. Resolve claims. Every claimed id MUST be a held observation (§3.1);
    //    duplicates collapse (§2.2 field 6: duplicate-free).
    let mut claim_set: BTreeSet<Hash> = BTreeSet::new();
    let mut claimed: Vec<Observation> = Vec::new();
    for &c in claims {
        let so = store.observation(&c)?.ok_or(ExportError::ClaimNotHeld(c))?;
        if claim_set.insert(c) {
            claimed.push(so.observation);
        }
    }

    // 2. Build the DAG once. Its seal-edge construction *is* the anchoring rule
    //    of §4.5; reachability over it is what §3.2/§3.3 are defined against.
    let dag = Dag::build(store, quarantine)?;

    // 3. Per claim: the reachable attestation closure (§3.3), and the furthest
    //    `subject_seq` any of those attestations anchors on — which is how far
    //    the author's chain segment must reach (§3.2, "far enough").
    let mut carried_att_ids: BTreeSet<Hash> = BTreeSet::new();
    let mut segment_reach: BTreeMap<PubKey, u64> = BTreeMap::new();
    for obs in &claimed {
        let r = DagNode::Obs(obs.id());
        let mut k = obs.seq;
        for aid in dag.attestation_ids() {
            let x = DagNode::Att(aid);
            if !(dag.reaches(r, x) || dag.reaches(x, r)) {
                continue;
            }
            carried_att_ids.insert(aid);
            if let Some(att) = dag.attestation(&aid) {
                // In wire version 1 the DAG has no cross-author edge (ADR-0003
                // Part 2), so a reachable attestation always has
                // `subject == author`. Guard it anyway.
                if att.subject == obs.author {
                    k = k.max(att.subject_seq);
                }
            }
        }
        let entry = segment_reach.entry(obs.author).or_insert(0);
        *entry = (*entry).max(k);
    }

    // 4. Observations to carry: each involved author's chain segment as the
    //    store holds it, from earliest held up to `k`. Nothing else (§4). Every
    //    entry at a shared `seq` (equivocation) travels — fork context is
    //    evidence, not noise.
    let mut carried_obs: Vec<StoredObservation> = Vec::new();
    let mut seen_obs: BTreeSet<Hash> = BTreeSet::new();
    for (author, k) in &segment_reach {
        for so in store.chain(author)? {
            if so.observation.seq <= *k && seen_obs.insert(so.id) {
                carried_obs.push(so);
            }
        }
    }

    let mut carried_att: Vec<StoredAttestation> = Vec::new();
    for id in &carried_att_ids {
        if let Some(sa) = store.attestation(id)? {
            carried_att.push(sa);
        }
    }

    // 5. Fork proofs touching any key that appears as an author, subject or
    //    witness anywhere in the pack (§3.4). Omitting a held, relevant one is
    //    the single omission that lets a pack overstate, so it is mandatory.
    let mut keys: BTreeSet<PubKey> = BTreeSet::new();
    for so in &carried_obs {
        keys.insert(so.observation.author);
    }
    for sa in &carried_att {
        keys.insert(sa.attestation.subject);
        keys.insert(sa.attestation.witness);
    }
    let mut fork_proofs: Vec<(Hash, Vec<u8>)> = Vec::new();
    for proof in detect_forks(store)? {
        if keys.contains(&proof.key) {
            fork_proofs.push((proof.id(), proof.preimage()));
        }
    }

    // --- hand the parts to the encoder (§2.2) ---
    let observations = carried_obs
        .iter()
        .map(|so| CarriedBytes {
            id: so.id,
            preimage: so.observation.preimage(),
            signature: so.signature,
        })
        .collect();
    let attestations = carried_att
        .iter()
        .map(|sa| CarriedBytes {
            id: sa.id,
            preimage: sa.attestation.preimage(),
            signature: sa.signature,
        })
        .collect();

    Ok(encode_pack(
        org,
        observations,
        attestations,
        fork_proofs,
        &claim_set,
    ))
}

/// One object as it sits in a pack: its recomputed content address, its full
/// domain-separated preimage, and its detached signature (`spec/03` §2.2,
/// `carried_object`).
#[derive(Debug, Clone)]
pub struct CarriedBytes {
    pub id: Hash,
    pub preimage: Vec<u8>,
    pub signature: Signature,
}

/// Encode a pack file from parts already resolved (`spec/03-export-pack.md`
/// §2.2–§2.3).
///
/// Every list is sorted here by recomputed content address, the envelope map
/// obeys the `spec/01` §2.1 key ordering, `claims` is emitted ascending and
/// duplicate-free, and an empty `fork_proofs` is omitted rather than encoded as
/// `[]` — so the output is canonical regardless of the order the caller passes.
///
/// [`export_pack`] uses this after selecting the minimal object set. It is also
/// the seam a test or a fixture generator uses to build a *deliberately*
/// malformed pack (a tampered object, a dropped entry) while keeping the
/// envelope framing itself well-formed.
#[must_use]
pub fn encode_pack(
    org: PubKey,
    mut observations: Vec<CarriedBytes>,
    mut attestations: Vec<CarriedBytes>,
    mut fork_proofs: Vec<(Hash, Vec<u8>)>,
    claims: &BTreeSet<Hash>,
) -> Vec<u8> {
    observations.sort_by_key(|c| c.id);
    attestations.sort_by_key(|c| c.id);
    fork_proofs.sort_by_key(|(id, _)| *id);

    let carried = |c: &CarriedBytes, o: &mut Vec<u8>| {
        write_array_head(2, o);
        write_bytes(&c.preimage, o);
        write_bytes(c.signature.as_bytes(), o);
    };

    let mut env = MapWriter::new();
    env.field(1, |o| write_uint(u64::from(WIRE_VERSION), o));
    env.field(2, |o| write_bytes(org.as_bytes(), o));
    env.field(3, |o| {
        write_array_head(observations.len() as u64, o);
        for c in &observations {
            carried(c, o);
        }
    });
    env.field(4, |o| {
        write_array_head(attestations.len() as u64, o);
        for c in &attestations {
            carried(c, o);
        }
    });
    if !fork_proofs.is_empty() {
        env.field(5, |o| {
            write_array_head(fork_proofs.len() as u64, o);
            for (_, preimage) in &fork_proofs {
                write_bytes(preimage, o);
            }
        });
    }
    env.field(6, |o| {
        write_array_head(claims.len() as u64, o);
        for c in claims {
            write_bytes(c.as_bytes(), o);
        }
    });

    let mut out = PACK_MARKER.to_vec();
    env.finish(&mut out);
    out
}

// ---------------------------------------------------------------------------
// parse_pack
// ---------------------------------------------------------------------------

/// One object carried in a pack, after the `spec/03` §5 step 2 self-check.
///
/// `object` is `None` when the carried preimage did not decode as its declared
/// type (a non-canonical or malformed preimage — `spec/01` §8). `self_check_ok`
/// is `true` only when the object decoded *and* its detached signature verifies
/// under the appropriate key (`author` for an observation, `witness` for an
/// attestation). An object with `self_check_ok == false` is discarded by a
/// verifier and contributes nothing (`spec/03` §5 step 2).
#[derive(Debug, Clone)]
pub struct CarriedObject<T> {
    pub object: Option<T>,
    pub signature: Signature,
    pub self_check_ok: bool,
}

impl<T: Object> CarriedObject<T> {
    /// The recomputed content address, or `None` if the preimage did not decode.
    #[must_use]
    pub fn id(&self) -> Option<Hash> {
        self.object.as_ref().map(Object::id)
    }
}

/// The decoded contents of a pack file: the envelope fields plus every carried
/// object with its self-check verdict. Produced by [`parse_pack`].
#[derive(Debug, Clone)]
pub struct PackContents {
    pub wire_version: u64,
    pub org: PubKey,
    pub observations: Vec<CarriedObject<Observation>>,
    pub attestations: Vec<CarriedObject<Attestation>>,
    /// Fork proofs that decoded *and* passed [`ForkProof::check`]. A proof
    /// failing either is dropped here (`spec/03` §5 step 3).
    pub fork_proofs: Vec<ForkProof>,
    pub claims: Vec<Hash>,
    /// How many carried objects failed their self-check (`spec/03` §5 step 2).
    pub invalid_object_count: usize,
}

impl PackContents {
    /// Every carried observation that passed its self-check, in carried order.
    pub fn valid_observations(&self) -> impl Iterator<Item = (Hash, &Observation, &Signature)> {
        self.observations.iter().filter_map(|c| {
            c.self_check_ok
                .then(|| c.object.as_ref().map(|o| (o.id(), o, &c.signature)))
                .flatten()
        })
    }

    /// Every carried attestation that passed its self-check, in carried order.
    pub fn valid_attestations(&self) -> impl Iterator<Item = (Hash, &Attestation, &Signature)> {
        self.attestations.iter().filter_map(|c| {
            c.self_check_ok
                .then(|| c.object.as_ref().map(|o| (o.id(), o, &c.signature)))
                .flatten()
        })
    }
}

/// Why a pack file could not be parsed as far as its envelope structure
/// (`spec/03-export-pack.md` §5 step 1).
///
/// A *structural* failure — bad marker, non-canonical CBOR, trailing bytes,
/// unknown field. A carried object that fails its own id/signature check is
/// **not** one of these: it is retained in [`PackContents`] with
/// `self_check_ok == false` (§5 step 2).
#[derive(Debug, thiserror::Error)]
pub enum PackParseError {
    /// The file did not begin with [`PACK_MARKER`].
    #[error("not an export pack: missing the `vigilarch/1/pack` marker")]
    BadMarker,

    /// `wire_version` was absent or not `1`.
    #[error("wire version {0} is not 1 — a pack is tied to exactly one wire version")]
    WrongWireVersion(u64),

    /// A required envelope field was missing.
    #[error("required envelope field {0} is missing")]
    MissingField(u64),

    /// An envelope field number this version does not define.
    #[error("unknown envelope field number {0}")]
    UnknownField(u64),

    /// The envelope CBOR violated the `spec/01` §2.1 profile or §8 framing.
    #[error("envelope decode failed: {0}")]
    Decode(#[from] DecodeError),
}

/// Parse a pack file: check the marker, decode the envelope with the strict
/// `spec/01` §8 reader, and self-check every carried object (`spec/03` §5
/// steps 1–3).
///
/// This does not run the chain check, rebuild the DAG, or recompute brackets
/// (§5 steps 4–6). Those run over [`PackContents::valid_observations`] /
/// [`PackContents::valid_attestations`] with the ordinary `vigil-ledger` APIs.
///
/// # Errors
///
/// [`PackParseError`] on any structural failure. A carried object failing its
/// self-check is not an error — see [`PackContents::invalid_object_count`].
pub fn parse_pack(bytes: &[u8]) -> Result<PackContents, PackParseError> {
    let body = bytes
        .strip_prefix(PACK_MARKER)
        .ok_or(PackParseError::BadMarker)?;

    let mut r = Reader::new(body);
    let mut m = r.map()?;

    let mut wire_version: Option<u64> = None;
    let mut org: Option<PubKey> = None;
    let mut observations: Option<Vec<CarriedObject<Observation>>> = None;
    let mut attestations: Option<Vec<CarriedObject<Attestation>>> = None;
    let mut fork_proofs: Vec<ForkProof> = Vec::new();
    let mut claims: Option<Vec<Hash>> = None;

    while let Some(key) = m.next_uint_key(&mut r)? {
        match key {
            1 => wire_version = Some(r.uint()?),
            2 => org = Some(PubKey(r.fixed_bytes::<32>("org PubKey")?)),
            3 => observations = Some(read_carried(&mut r, |o: &Observation| o.author)?),
            4 => attestations = Some(read_carried(&mut r, |a: &Attestation| a.witness)?),
            5 => fork_proofs = read_fork_proofs(&mut r)?,
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
    let observations = observations.ok_or(PackParseError::MissingField(3))?;
    let attestations = attestations.ok_or(PackParseError::MissingField(4))?;
    let claims = claims.ok_or(PackParseError::MissingField(6))?;

    let invalid_object_count = observations.iter().filter(|c| !c.self_check_ok).count()
        + attestations.iter().filter(|c| !c.self_check_ok).count();

    Ok(PackContents {
        wire_version,
        org,
        observations,
        attestations,
        fork_proofs,
        claims,
        invalid_object_count,
    })
}

/// Read field 3 or 4: an array of `[preimage, sig]` pairs. Each is self-checked
/// (`spec/03` §5 step 2): recompute the id by decoding the preimage, then verify
/// the detached signature under the key `verify_key` extracts from the decoded
/// object.
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
    for _ in 0..n {
        r.expect_array(2)?;
        let preimage = r.bytes()?.to_vec();
        let signature = Signature(r.fixed_bytes::<64>("carried object signature")?);
        let object = T::decode_preimage(&preimage).ok();
        let self_check_ok = object
            .as_ref()
            .is_some_and(|o| verify_id(verify_key(o), o.id(), &signature).is_ok());
        out.push(CarriedObject {
            object,
            signature,
            self_check_ok,
        });
    }
    Ok(out)
}

/// Read field 5: an array of bare `ForkProof` preimages. A proof that does not
/// decode or does not pass [`ForkProof::check`] is dropped (`spec/03` §5
/// step 3).
fn read_fork_proofs(r: &mut Reader) -> Result<Vec<ForkProof>, PackParseError> {
    let n = r.array_head()?;
    if n > r.remaining() as u64 {
        return Err(PackParseError::Decode(DecodeError::LengthExceedsInput {
            declared: n,
            remaining: r.remaining(),
        }));
    }
    let mut out = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let preimage = r.bytes()?.to_vec();
        if let Ok(proof) = ForkProof::decode_preimage(&preimage) {
            if proof.check().is_ok() {
                out.push(proof);
            }
        }
    }
    Ok(out)
}

/// Read field 6: an array of 32-byte observation ids.
fn read_claims(r: &mut Reader) -> Result<Vec<Hash>, PackParseError> {
    let n = r.array_head()?;
    if n > r.remaining() as u64 {
        return Err(PackParseError::Decode(DecodeError::LengthExceedsInput {
            declared: n,
            remaining: r.remaining(),
        }));
    }
    let mut out = Vec::with_capacity(n as usize);
    for _ in 0..n {
        out.push(Hash(r.fixed_bytes::<32>("claim observation id")?));
    }
    Ok(out)
}
