//! `spec/03-export-pack.md` §5 step 6: recompute `bracket()`
//! (`spec/02-entanglement.md` §5) for each claim, from `vigil-verify`'s own DAG.
//!
//! An independent third traversal — after [`crate::chain`] and [`crate::dag`] —
//! of the same evidence. Where `⟶` does not establish an ordering the bound is
//! `None` and the window is open on that side. Nothing here interpolates:
//! overstating what the evidence forces is the defect invariant I5 forbids, and
//! a verifier that overstates "launders an unproven claim into an apparent
//! independent confirmation" (`spec/03` §1).
//!
//! The one place this differs from `vigil-ledger::bracket` is the lower window
//! edge: `spec/03` §5 step 6 requires `genesis` **only when `seq` 0 is held**,
//! and otherwise "open below to the earliest held entry (`seq` n)" — the §3.5
//! "earliest held" marker. [`WindowEdge`] carries that fourth case, which the
//! ledger's own enum does not need because its chain segments always start at
//! genesis.

use std::collections::BTreeSet;

use vigil_core::{Hash, PubKey, Seq};

use crate::dag::{Dag, DagNode};

/// One edge of an [`UnwitnessedWindow`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowEdge {
    /// Bounded here by an attestation.
    Attestation(Hash),
    /// Open below to the author's genesis — `seq` 0 is held and there is no
    /// lower-bound attestation (`spec/02` §5.1).
    Genesis,
    /// Open below only to the earliest entry the pack carries for this author,
    /// at `seq` n > 0 (`spec/03` §3.5). The verifier does **not** claim the
    /// window reaches genesis, because it has not seen `0..n`.
    EarliestHeld(Seq),
    /// Open above to the moment of verification — the record is unwitnessed
    /// (`spec/02` §5.1).
    VerificationMoment,
}

/// The span the system cannot vouch for. Its width is the record's witness
/// latency; a wide window is the honest output for a sparsely connected node,
/// not an alarm (`spec/02` §8.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnwitnessedWindow {
    pub lower: WindowEdge,
    pub upper: WindowEdge,
}

/// The recomputed bracket for one claimed observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bracket {
    pub observation: Hash,
    /// `L` — latest attestation provably preceding the record in its own chain
    /// via an ack edge, `None` if there is none. An ordering fact, not a
    /// timestamp (`spec/02` §5.3).
    pub lower_bound: Option<Hash>,
    /// `U` — earliest attestation sealing the record, `None` if unwitnessed.
    pub upper_bound: Option<Hash>,
    pub sealed: bool,
    /// Distinct witness keys among every sealing attestation (`spec/02` §5.1).
    pub witness_depth: u32,
    pub unwitnessed_window: UnwitnessedWindow,
    /// The record's author is quarantined and the record is unwitnessed
    /// (`spec/02` §6.4). A record of a quarantined key sealed by an honest
    /// witness stays valid and undisputed (§6.5).
    pub disputed: bool,
}

/// What the verifier holds about the claimed observation's own author chain
/// segment, needed for the lower window edge (`spec/03` §3.5).
#[derive(Debug, Clone, Copy)]
pub struct AuthorSegment {
    pub author: PubKey,
    /// The lowest `seq` the pack carries for this author. `0` means genesis is
    /// held.
    pub lowest_held_seq: Seq,
}

/// Recompute `bracket(id)` (`spec/02` §5) over `dag`. Returns `None` if `id` is
/// not an observation vertex — that is a claim the pack does not carry the
/// record for, reported separately by [`crate::verify`].
#[must_use]
pub fn bracket(dag: &Dag, id: Hash, segment: AuthorSegment) -> Option<Bracket> {
    let observation = dag.observation(id)?;
    let author = observation.author;
    let r_node = DagNode::Obs(id);

    // Sealing attestations: reachable from R, witness distinct from the author.
    let sealing: Vec<Hash> = dag
        .attestation_ids()
        .filter(|aid| {
            dag.attestation(*aid).is_some_and(|a| a.witness != author)
                && dag.reaches(r_node, DagNode::Att(*aid))
        })
        .collect();

    let witnesses: BTreeSet<PubKey> = sealing
        .iter()
        .filter_map(|aid| dag.attestation(*aid).map(|a| a.witness))
        .collect();
    let witness_depth = u32::try_from(witnesses.len()).unwrap_or(u32::MAX);
    let sealed = !sealing.is_empty();

    // U: minimal element of the sealing set in ⟶ — nothing else in the set
    // precedes it. Tie-break by id.
    let upper_bound = sealing
        .iter()
        .filter(|u| {
            !sealing
                .iter()
                .any(|other| other != *u && dag.reaches(DagNode::Att(*other), DagNode::Att(**u)))
        })
        .min()
        .copied();

    // L: attestations that provably precede R in its own chain (an ack edge on R
    // or an earlier entry). Witness distinct from the author.
    let preceding: Vec<Hash> = dag
        .attestation_ids()
        .filter(|aid| {
            dag.attestation(*aid).is_some_and(|a| a.witness != author)
                && dag.reaches(DagNode::Att(*aid), r_node)
        })
        .collect();

    // L: maximal element of the preceding set in ⟶. Tie-break by id.
    let lower_bound = preceding
        .iter()
        .filter(|l| {
            !preceding
                .iter()
                .any(|other| other != *l && dag.reaches(DagNode::Att(**l), DagNode::Att(*other)))
        })
        .min()
        .copied();

    let lower_edge = match lower_bound {
        Some(l) => WindowEdge::Attestation(l),
        None if segment.lowest_held_seq == 0 => WindowEdge::Genesis,
        None => WindowEdge::EarliestHeld(segment.lowest_held_seq),
    };
    let upper_edge = upper_bound.map_or(WindowEdge::VerificationMoment, WindowEdge::Attestation);

    let disputed = dag.is_quarantined(&author) && !sealed;

    Some(Bracket {
        observation: id,
        lower_bound,
        upper_bound,
        sealed,
        witness_depth,
        unwitnessed_window: UnwitnessedWindow {
            lower: lower_edge,
            upper: upper_edge,
        },
        disputed,
    })
}
