//! Bracketing: what the attestation DAG does and does not prove about when a
//! record was created (`spec/02-entanglement.md` §5).
//!
//! For an observation `R` by author `A` at `seq` r, [`Dag::bracket`] returns:
//!
//! - the **upper-bound attestation** `U` — the sealing attestation earliest in
//!   `⟶`, whose witness saw A's chain already past r. `U` present means `R` is
//!   **sealed**; absent means **unwitnessed** (`spec/02` §5.1).
//! - the **lower-bound attestation** `L` — the latest attestation that provably
//!   precedes `R` in `R`'s own chain via an ack edge. In v1 this is an
//!   *ordering* fact used to detect contradiction, **not** a wall-clock earliest
//!   time (`spec/02` §5.3, ADR-0002).
//! - **witness depth** — the number of *distinct* witness keys among every
//!   attestation that seals `R` (`spec/02` §5.1, §4.4). Distinct keys are not
//!   distinct parties (§8.9).
//! - the **unwitnessed window** — from `L` (or A's genesis, if there is no `L`)
//!   to `U` (or the verification moment, if there is no `U`). Its lower edge is
//!   never `R`'s own `hlc` (`spec/02` §5.1).
//!
//! ## Conservative by construction
//!
//! Where `⟶` does not establish an ordering, the corresponding bound is `None`
//! and the window is open on that side (`spec/02` §5.6). Nothing here
//! interpolates or guesses — overstating knowledge is the cardinal defect this
//! system must not have (invariant I5). Adding a valid attestation to the held
//! set can only *narrow* a bracket, never widen it (`spec/02` §5.5); a property
//! test asserts it.

use std::collections::BTreeSet;

use vigil_core::{Hash, PubKey};

use crate::dag::{Dag, DagNode};
use crate::fork::Quarantine;
use crate::store::{Store, StoreError};

/// One edge of an [`UnwitnessedWindow`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowEdge {
    /// The window is bounded here by an attestation.
    Attestation(Hash),
    /// The window is open below to the author's genesis — there is no lower-bound
    /// attestation (`spec/02-entanglement.md` §5.1).
    Genesis,
    /// The window is open above to the moment of verification — the record is
    /// unwitnessed (`spec/02-entanglement.md` §5.1).
    VerificationMoment,
}

/// The span the system cannot vouch for (`spec/02-entanglement.md` §5.1). Its
/// width is the record's witness latency; a wide window is the honest output for
/// a sparsely connected node, not an alarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnwitnessedWindow {
    pub lower: WindowEdge,
    pub upper: WindowEdge,
}

/// The result of [`Dag::bracket`] for one observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bracket {
    pub observation: Hash,
    /// `L` — latest attestation provably preceding the record in its own chain,
    /// `None` if there is none. An ordering fact, not a timestamp (`spec/02`
    /// §5.3).
    pub lower_bound: Option<Hash>,
    /// `U` — earliest attestation sealing the record, `None` if unwitnessed.
    pub upper_bound: Option<Hash>,
    /// Whether any attestation seals the record.
    pub sealed: bool,
    /// Distinct witness keys among every sealing attestation (`spec/02` §5.1).
    pub witness_depth: u32,
    pub unwitnessed_window: UnwitnessedWindow,
    /// Set when the record's author is quarantined and the record is
    /// unwitnessed (`spec/02` §6.4). A record of a quarantined key that was
    /// sealed by an honest witness stays valid and undisputed (§6.5).
    pub disputed: bool,
}

impl Dag {
    /// Bracket the observation `id` (`spec/02-entanglement.md` §5). Returns
    /// `None` if `id` is not an observation vertex.
    ///
    /// The result is a pure function of the held object set and is identical
    /// byte-for-byte across machines (`spec/02` §5.6, §4.7).
    #[must_use]
    pub fn bracket(&self, id: Hash) -> Option<Bracket> {
        let observation = self.observation(&id)?;
        let author = observation.author;
        let r_node = DagNode::Obs(id);

        // Sealing attestations: reachable from R, witness distinct from the
        // author (§4.4, §5.1).
        let sealing: Vec<Hash> = self
            .attestation_ids()
            .filter(|aid| {
                self.attestation(aid).is_some_and(|a| a.witness != author)
                    && self.reaches(r_node, DagNode::Att(*aid))
            })
            .collect();

        let witnesses: BTreeSet<PubKey> = sealing
            .iter()
            .filter_map(|aid| self.attestation(aid).map(|a| a.witness))
            .collect();
        let witness_depth = u32::try_from(witnesses.len()).unwrap_or(u32::MAX);
        let sealed = !sealing.is_empty();

        // U: the sealing attestation earliest in ⟶ — a minimal element, nothing
        // else in the set preceding it. Tie-break by id for determinism.
        let upper_bound = sealing
            .iter()
            .filter(|u| {
                !sealing
                    .iter()
                    .any(|other| other != *u && self.reaches(DagNode::Att(*other), DagNode::Att(**u)))
            })
            .min()
            .copied();

        // L: attestations that provably precede R in its own chain. An
        // attestation only reaches an observation through an ack edge into the
        // subject's chain, so `L ⟶ R` with `L.witness != author` already means
        // "ack edge on R or an earlier entry of A's chain" (`spec/02` §5.3).
        let preceding: Vec<Hash> = self
            .attestation_ids()
            .filter(|aid| {
                self.attestation(aid).is_some_and(|a| a.witness != author)
                    && self.reaches(DagNode::Att(*aid), r_node)
            })
            .collect();

        // L: the latest in ⟶ — a maximal element, nothing in the set following
        // it. Tie-break by id.
        let lower_bound = preceding
            .iter()
            .filter(|l| {
                !preceding
                    .iter()
                    .any(|other| other != *l && self.reaches(DagNode::Att(**l), DagNode::Att(*other)))
            })
            .min()
            .copied();

        let unwitnessed_window = UnwitnessedWindow {
            lower: lower_bound.map_or(WindowEdge::Genesis, WindowEdge::Attestation),
            upper: upper_bound.map_or(WindowEdge::VerificationMoment, WindowEdge::Attestation),
        };

        // A quarantined author's unwitnessed records are disputed (§6.4); its
        // honestly sealed records stay valid (§6.5).
        let disputed = self.is_quarantined(&author) && !sealed;

        Some(Bracket {
            observation: id,
            lower_bound,
            upper_bound,
            sealed,
            witness_depth,
            unwitnessed_window,
            disputed,
        })
    }
}

/// Bracket one observation straight from a [`Store`], building a DAG with no
/// quarantine — the common path (`spec/02-entanglement.md` §5.6).
///
/// For repeated queries over one store, build a [`Dag`] once and call
/// [`Dag::bracket`] on it.
///
/// # Errors
///
/// [`StoreError`] if the backend fails.
pub fn bracket<S: Store + ?Sized>(store: &S, id: Hash) -> Result<Option<Bracket>, StoreError> {
    Ok(Dag::build(store, &Quarantine::new())?.bracket(id))
}
