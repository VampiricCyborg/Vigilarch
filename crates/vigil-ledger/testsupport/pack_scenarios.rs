//! The `spec/03-export-pack.md` §6 worked scenario and its tamper variants,
//! built once and shared by the fixture generator (`examples/gen_packs.rs`) and
//! the export tests (`tests/export.rs`).
//!
//! Every pack here is produced by `vigil-ledger`'s own encoder. The honest pack
//! is cross-checked byte-for-byte against the independently hand-built golden
//! vector `testdata/vectors/pack-worked-example.json` in `tests/export.rs`, so
//! "the encoder agreeing with itself" is not the only evidence on the record.

#![allow(dead_code)]

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use vigil_core::{
    Attestation, Hash, Hlc, Object, Observation, ObservationBody, PubKey, Signature, SignedObject,
    SiteId, public_key,
};
use vigil_ledger::{
    CarriedBytes, MemoryStore, Quarantine, Store, append, detect_forks, encode_pack, export_pack,
};

pub const SITE: SiteId = SiteId(*b"VIGILARCH-SITE-A");

/// A's signing-key seed — `0001…1f`, the `spec/01` §10 seed (`spec/03` §6.1).
pub fn seed_a() -> [u8; 32] {
    core::array::from_fn(|i| i as u8)
}

/// W's signing-key seed — `8081…9f` (`spec/03` §6.1).
pub fn seed_w() -> [u8; 32] {
    core::array::from_fn(|i| 0x80 ^ i as u8)
}

/// The org key seed — `11…11` (`spec/03` §6.1).
pub fn seed_org() -> [u8; 32] {
    [0x11; 32]
}

/// A third, unrelated key — used only by the minimisation test.
pub fn seed_stranger() -> [u8; 32] {
    [0x42; 32]
}

pub fn org_key() -> PubKey {
    public_key(&SigningKey::from_bytes(&seed_org()))
}

fn note(sk: &SigningKey, prev: Option<Hash>, seq: u64, wall_ms: u64, text: &str) -> Observation {
    Observation {
        author: public_key(sk),
        site: SITE,
        prev,
        seq,
        hlc: Hlc::new(wall_ms, 0),
        body: ObservationBody::Note {
            text: text.to_owned(),
        },
        geo: None,
        acks: BTreeSet::new(),
    }
}

fn attest(
    witness: &SigningKey,
    subject: PubKey,
    head: Hash,
    seq: u64,
    wall_ms: u64,
) -> Attestation {
    Attestation {
        witness: public_key(witness),
        subject,
        subject_head: head,
        subject_seq: seq,
        witness_hlc: Hlc::new(wall_ms, 0),
        nonce: core::array::from_fn(|i| 0xa0 ^ i as u8),
    }
}

/// The honest §6.2 objects: A's genesis note, A's second note extending the
/// chain to the witnessed head, and W's attestation `U` anchoring `A@1`.
pub struct Honest {
    pub a: SigningKey,
    pub w: SigningKey,
    pub a0: Observation,
    pub a0_sig: Signature,
    pub a1: Observation,
    pub a1_sig: Signature,
    pub u: Attestation,
    pub u_sig: Signature,
}

impl Honest {
    pub fn build() -> Self {
        let a = SigningKey::from_bytes(&seed_a());
        let w = SigningKey::from_bytes(&seed_w());
        let a0 = note(
            &a,
            None,
            0,
            1_700_000_000_000,
            "shoring on grid B4 is out of plumb",
        );
        let a1 = note(
            &a,
            Some(a0.id()),
            1,
            1_700_000_100_000,
            "grid B4 shoring re-checked, area now clear",
        );
        let u = attest(&w, public_key(&a), a1.id(), 1, 1_700_000_100_000);
        Self {
            a0_sig: a0.sign(&a),
            a1_sig: a1.sign(&a),
            u_sig: u.sign(&w),
            a0,
            a1,
            u,
            a,
            w,
        }
    }

    /// A store holding exactly the three honest objects.
    pub fn store(&self) -> MemoryStore {
        let mut s = MemoryStore::new();
        append(&mut s, &self.a0, &self.a0_sig).expect("A@0 genesis");
        append(&mut s, &self.a1, &self.a1_sig).expect("A@1 links onto A@0");
        s.put_attestation(&self.u, &self.u_sig).expect("store U");
        s
    }

    pub fn claim(&self) -> Hash {
        self.a0.id()
    }
}

fn carried(preimage: Vec<u8>, signature: Signature) -> CarriedBytes {
    // Every preimage used here is a well-formed observation/attestation, so this
    // decode always succeeds; it is how the tamper fixtures get a recomputed id
    // without a BLAKE3 dependency in this crate.
    let id = Observation::decode_preimage(&preimage)
        .map(|o| o.id())
        .or_else(|_| Attestation::decode_preimage(&preimage).map(|a| a.id()))
        .expect("fixture preimage decodes");
    CarriedBytes {
        id,
        preimage,
        signature,
    }
}

/// `spec/03` §6.3 — the honest pack, straight from the exporter.
pub fn honest_pack() -> Vec<u8> {
    let h = Honest::build();
    export_pack(&h.store(), &Quarantine::new(), org_key(), &[h.claim()]).expect("honest export")
}

/// `spec/03` §6.5 T1 — flip the final body byte of `A@0` (`0x62` → `0x63`). The
/// carried signature (over the original id) then fails, so the object is
/// discarded and the claim names an observation no surviving object has.
pub fn t1_flipped_byte() -> Vec<u8> {
    let h = Honest::build();
    let mut preimage = h.a0.preimage();
    let last = preimage.last_mut().expect("non-empty preimage");
    assert_eq!(*last, 0x62, "T1 targets the final 'b' of \"plumb\"");
    *last = 0x63;

    let observations = vec![
        carried(preimage, h.a0_sig),
        carried(h.a1.preimage(), h.a1_sig),
    ];
    let attestations = vec![carried(h.u.preimage(), h.u_sig)];
    encode_pack(
        org_key(),
        observations,
        attestations,
        Vec::new(),
        &BTreeSet::from([h.claim()]),
    )
}

/// `spec/03` §6.5 T2 — replace `A@0` with a validly re-signed genesis whose
/// `hlc` counter is `1` instead of `0`. Each object self-checks, but `A@1.prev`
/// no longer matches the held predecessor: a `BrokenLink`.
pub fn t2_resigned_genesis() -> Vec<u8> {
    let h = Honest::build();
    let mut a0pp = h.a0.clone();
    a0pp.hlc = Hlc::new(1_700_000_000_000, 1);
    let a0pp_sig = a0pp.sign(&h.a);

    let observations = vec![
        carried(a0pp.preimage(), a0pp_sig),
        carried(h.a1.preimage(), h.a1_sig),
    ];
    let attestations = vec![carried(h.u.preimage(), h.u_sig)];
    encode_pack(
        org_key(),
        observations,
        attestations,
        Vec::new(),
        &BTreeSet::from([h.claim()]),
    )
}

/// The id `spec/03` §6.5 T2 states for the re-signed genesis `A@0″`.
pub fn t2_resigned_genesis_id() -> Hash {
    let h = Honest::build();
    let mut a0pp = h.a0.clone();
    a0pp.hlc = Hlc::new(1_700_000_000_000, 1);
    a0pp.id()
}

/// `spec/03` §6.5 T3 — drop the anchor entry `A@1`. `U.subject_head` then names
/// an entry the verifier does not hold, so `U` produces no seal edge and `A@0`
/// is reported unwitnessed rather than sealed.
pub fn t3_dropped_anchor() -> Vec<u8> {
    let h = Honest::build();
    let observations = vec![carried(h.a0.preimage(), h.a0_sig)];
    let attestations = vec![carried(h.u.preimage(), h.u_sig)];
    encode_pack(
        org_key(),
        observations,
        attestations,
        Vec::new(),
        &BTreeSet::from([h.claim()]),
    )
}

/// A pack whose sealing witness `W` has equivocated on its own chain: the
/// exporter holds a `ForkProof` against `W` and MUST carry it (`spec/03` §3.4),
/// because a verifier without it would compute a seal the exporter knows is
/// unsound (`spec/02` §6.5).
pub fn fork_witness_pack() -> Vec<u8> {
    let h = Honest::build();
    let mut store = h.store();

    // W signs two irreconcilable genesis entries on its own chain.
    let w0 = note(
        &h.w,
        None,
        0,
        1_699_000_000_000,
        "night headcount: 6 on the north face",
    );
    let w0p = note(
        &h.w,
        None,
        0,
        1_699_000_000_000,
        "night headcount: 9, two crews merged",
    );
    append(&mut store, &w0, &w0.sign(&h.w)).expect("W@0");
    append(&mut store, &w0p, &w0p.sign(&h.w)).expect("W@0' — a sibling, stored not refused");

    export_pack(&store, &Quarantine::new(), org_key(), &[h.claim()]).expect("fork-witness export")
}

/// A pack whose author segment starts at `seq` 3: `A@0`–`A@2` were never held.
/// Its absence is the `spec/03` §3.5 "earliest held" marker — a verifier reports
/// `0…2` as `Incomplete`, and the unwitnessed window as open below to `A@3`.
pub fn earliest_held_pack() -> Vec<u8> {
    let a = SigningKey::from_bytes(&seed_a());
    let w = SigningKey::from_bytes(&seed_w());
    // A@3's `prev` points at an entry (A@2) the exporter never received.
    let phantom_a2 = Hash(*b"...A@2 was lost in the partition");
    let a3 = note(
        &a,
        Some(phantom_a2),
        3,
        1_700_000_300_000,
        "scaffold tag-out, bay 3",
    );
    let a4 = note(
        &a,
        Some(a3.id()),
        4,
        1_700_000_400_000,
        "bay 3 cleared, crew off",
    );
    let u = attest(&w, public_key(&a), a4.id(), 4, 1_700_000_450_000);

    let mut store = MemoryStore::new();
    append(&mut store, &a3, &a3.sign(&a)).expect("A@3 stored across a gap");
    append(&mut store, &a4, &a4.sign(&a)).expect("A@4 links onto A@3");
    store.put_attestation(&u, &u.sign(&w)).expect("store U");

    export_pack(&store, &Quarantine::new(), org_key(), &[a3.id()]).expect("earliest-held export")
}

/// The claimed id for [`earliest_held_pack`].
pub fn earliest_held_claim() -> Hash {
    let a = SigningKey::from_bytes(&seed_a());
    let phantom_a2 = Hash(*b"...A@2 was lost in the partition");
    note(
        &a,
        Some(phantom_a2),
        3,
        1_700_000_300_000,
        "scaffold tag-out, bay 3",
    )
    .id()
}

/// Every fixture as `(filename, bytes)`, in a fixed order.
pub fn all_fixtures() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("honest.vgl", honest_pack()),
        ("t1-flipped-byte.vgl", t1_flipped_byte()),
        ("t2-resigned-genesis.vgl", t2_resigned_genesis()),
        ("t3-dropped-anchor.vgl", t3_dropped_anchor()),
        ("fork-witness.vgl", fork_witness_pack()),
        ("earliest-held.vgl", earliest_held_pack()),
    ]
}

/// Detect the single fork proof the fork-witness scenario produces — shared by
/// the generator's sanity print and the test.
pub fn fork_witness_proof_key() -> PubKey {
    let h = Honest::build();
    let mut store = h.store();
    let w0 = note(
        &h.w,
        None,
        0,
        1_699_000_000_000,
        "night headcount: 6 on the north face",
    );
    let w0p = note(
        &h.w,
        None,
        0,
        1_699_000_000_000,
        "night headcount: 9, two crews merged",
    );
    append(&mut store, &w0, &w0.sign(&h.w)).unwrap();
    append(&mut store, &w0p, &w0p.sign(&h.w)).unwrap();
    let proofs = detect_forks(&store).unwrap();
    assert_eq!(proofs.len(), 1, "exactly one fork on W's chain");
    proofs[0].key
}
