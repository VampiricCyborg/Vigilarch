//! Per-author hash chains: the guarded append path and the full-chain
//! verification pass (`spec/01-wire-format.md` §6.6).
//!
//! ## Two entry points, one rule
//!
//! [`append`] is the guarded write path. It checks the §6.6 join rule — `seq`
//! and `prev` **together**, never one on trust while the other looks consistent
//! — against what the store already holds, then persists the observation keyed
//! by its own content address.
//!
//! [`verify_chain`] is the assessment pass. Given everything the store holds for
//! one author it returns exactly one of three outcomes —
//! [`Verified`](ChainVerification::Verified),
//! [`Incomplete`](ChainVerification::Incomplete),
//! [`Violated`](ChainVerification::Violated) — and the middle one never
//! collapses into either neighbour. That is the whole point of §6.6: reporting a
//! slow link as tampering makes the fork alarm meaningless, and an alarm nobody
//! trusts protects nobody; reporting a partial chain as verified is the
//! overstatement invariant I5 forbids.
//!
//! ## An inconsistency is evidence, not an error
//!
//! A [`ChainMismatch`] or a [`ChainViolation`] is an *integrity finding*: the
//! bytes decoded and — by the caller's precondition — the signature verified
//! under `author`, but the chain claims contradict each other. Per §6.6 that is
//! the most valuable object the system can hold: attributable cryptographic
//! evidence of misconduct. So it is named — the offending key and both
//! conflicting entries — and handed back, never dropped and never dressed up as
//! an I/O fault. A malformed *frame* never reaches this module; `vigil-core`'s
//! decoder rejected it (`spec` §8) long before storage.
//!
//! ## `prev` is always the recomputed id
//!
//! §6.6 speaks of the "recomputed id" of a predecessor. There is no other kind
//! here: an `id` is never taken from the wire (`spec` §3.2), so the
//! [`StoredObservation::id`] a `Store` hands back is the value it computed from
//! the object itself on `put`. Comparing against it satisfies the rule.

use std::collections::BTreeMap;

use vigil_core::{Hash, Object, Observation, PubKey, Seq, Signature};

use crate::store::{Store, StoreError, StoredObservation};

/// How many missing sequence numbers [`verify_chain`] will enumerate before it
/// stops listing them.
///
/// `seq` is attacker-controlled (§6.6). A single ingested observation claiming
/// `seq = 10^18` must not make a verification pass allocate a billion-entry gap
/// list. Past the cap the outcome is still
/// [`Incomplete`](ChainVerification::Incomplete) and every listed entry is still
/// a real gap — the pass just stops counting.
const MISSING_LIST_CAP: usize = 4096;

// ---------------------------------------------------------------------------
// append
// ---------------------------------------------------------------------------

/// What `prev` was required to be at a given position (§6.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrevRequirement {
    /// `seq` 0: `prev` MUST be the zero-length byte string — [`Observation::prev`]
    /// of `None`. Genesis is a value, not an absence.
    Genesis,
    /// `seq` *n* > 0: `prev` MUST equal one of these, the recomputed id(s) held
    /// at `seq` *n* - 1. More than one id means the predecessor position is
    /// itself equivocated — still not a licence to point `prev` elsewhere.
    Predecessor(Vec<Hash>),
}

/// A refused [`append`]: the `seq`/`prev` pair is inconsistent with the author's
/// chain as the store holds it.
///
/// This is an attributable integrity finding, not a caller error and not a
/// backend fault. The rejected observation is handed back rather than stored so
/// the caller can retain it as evidence — a signed self-contradiction is never
/// discarded (§6.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainMismatch {
    /// The key that signed the inconsistent entry.
    pub author: PubKey,
    /// The entry's recomputed content address.
    pub entry: Hash,
    /// The `seq` it claimed.
    pub seq: Seq,
    /// The `prev` it carried; `None` is the genesis link.
    pub claimed_prev: Option<Hash>,
    /// What §6.6 required `prev` to be here.
    pub required: PrevRequirement,
}

/// Why an [`append`] did not complete.
#[derive(Debug, thiserror::Error)]
pub enum AppendError {
    /// The §6.6 join rule is broken. See [`ChainMismatch`].
    ///
    /// Boxed: this variant carries both conflicting positions and dwarfs the
    /// backend-fault variant, and `append` returns `Result` on its hot path.
    #[error(
        "chain integrity finding: author {} signed an entry at seq {} that breaks the \
         seq/prev join rule (spec/01-wire-format.md §6.6)",
        .0.author,
        .0.seq
    )]
    ChainMismatch(Box<ChainMismatch>),

    /// The storage backend failed — nothing to do with the caller's data.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Append an observation to its author's chain after checking the §6.6 join rule
/// against what the store already holds, then persist it.
///
/// # The check is deliberately one-sided
///
/// A *contradiction* is refused:
///
/// - `seq` 0 carrying a non-empty `prev`, or
/// - `seq` *n* > 0 whose `prev` matches no entry the store holds at *n* - 1.
///
/// A *gap* is not a contradiction. `seq` *n* > 0 with nothing held at *n* - 1 is
/// the ordinary state of a chain still arriving across a partition, so the entry
/// is stored and the unresolved link is left for [`verify_chain`] to report as
/// [`Incomplete`](ChainVerification::Incomplete). If `seq` *n* - 1 later arrives
/// and the link turns out not to match, that pass reports it as
/// [`Violated`](ChainVerification::Violated) — the safety net closes then.
///
/// Equivocation — a second, distinct entry at a `seq` already held — is likewise
/// not refused here. The store retains it (§6.6) and fork detection, not this
/// path, decides what to do about it.
///
/// # Preconditions
///
/// The caller has already decoded `observation` and verified `signature` under
/// `observation.author`. This function checks chain structure, not authenticity.
///
/// # Errors
///
/// [`AppendError::ChainMismatch`] if the join rule is broken (the observation is
/// **not** stored); [`AppendError::Store`] if the backend fails.
pub fn append<S: Store + ?Sized>(
    store: &mut S,
    observation: &Observation,
    signature: &Signature,
) -> Result<Hash, AppendError> {
    let author = observation.author;
    let seq = observation.seq;
    let claimed_prev = observation.prev;

    if seq == 0 {
        if claimed_prev.is_some() {
            return Err(AppendError::ChainMismatch(Box::new(ChainMismatch {
                author,
                entry: observation.id(),
                seq,
                claimed_prev,
                required: PrevRequirement::Genesis,
            })));
        }
    } else {
        let predecessors = store.observations_at(&author, seq - 1)?;
        if !predecessors.is_empty() {
            let linked = claimed_prev.is_some_and(|p| predecessors.iter().any(|so| so.id == p));
            if !linked {
                return Err(AppendError::ChainMismatch(Box::new(ChainMismatch {
                    author,
                    entry: observation.id(),
                    seq,
                    claimed_prev,
                    required: PrevRequirement::Predecessor(
                        predecessors.iter().map(|so| so.id).collect(),
                    ),
                })));
            }
        }
        // predecessors empty: a gap, not a contradiction. Store it; verify_chain
        // reports Incomplete until seq - 1 arrives.
    }

    Ok(store.put_observation(observation, signature)?)
}

// ---------------------------------------------------------------------------
// verify_chain
// ---------------------------------------------------------------------------

/// The result of a full-chain verification pass for one author (§6.6).
///
/// Exactly three outcomes, and the middle one never collapses into either
/// neighbour.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainVerification {
    /// Every sequence from 0 to the highest held is present exactly once, and
    /// every `prev` matches the recomputed id of its predecessor.
    Verified,
    /// One or more sequence numbers are missing and nothing held contradicts
    /// anything else held. The verifier does not have the whole chain. This is
    /// the *normal* state under partition and is not a problem.
    Incomplete {
        /// The missing sequence numbers, ascending, truncated at
        /// [`MISSING_LIST_CAP`]. Empty when the author is entirely unknown to
        /// the store.
        missing: Vec<Seq>,
    },
    /// At least one attributable integrity finding. Retained, never discarded;
    /// each names the offending key and the conflicting entries.
    Violated(Vec<ChainViolation>),
}

/// A single attributable chain-integrity finding (§6.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainViolation {
    /// `author` signed more than one distinct observation at `seq`.
    Equivocation {
        author: PubKey,
        seq: Seq,
        /// Every conflicting content address at this `seq`, ascending.
        entries: Vec<Hash>,
    },
    /// `entry`, at `seq`, carries a `prev` that does not match the predecessor
    /// the store holds.
    ///
    /// For `seq` 0 this means a non-empty `prev` on a genesis entry: `predecessor`
    /// is then empty and `claimed_prev` is the violation. For `seq` *n* > 0,
    /// `predecessor` holds the id(s) at *n* - 1 that `prev` failed to match.
    BrokenLink {
        author: PubKey,
        seq: Seq,
        entry: Hash,
        claimed_prev: Option<Hash>,
        predecessor: Vec<Hash>,
    },
}

/// Run a full-chain verification pass for one author over everything the store
/// holds (§6.6).
///
/// A [`ChainVerification::Violated`] result is a normal `Ok`: an integrity
/// finding is data to be surfaced, not an error to be propagated. Only a backend
/// failure produces `Err`.
///
/// # Errors
///
/// [`StoreError`] if the backend fails.
pub fn verify_chain<S: Store + ?Sized>(
    store: &S,
    author: &PubKey,
) -> Result<ChainVerification, StoreError> {
    let held = store.chain(author)?;
    if held.is_empty() {
        // Nothing held: the chain cannot be called verified, and there is no
        // known sequence range to enumerate gaps in.
        return Ok(ChainVerification::Incomplete {
            missing: Vec::new(),
        });
    }

    let mut by_seq: BTreeMap<Seq, Vec<StoredObservation>> = BTreeMap::new();
    for so in held {
        by_seq.entry(so.observation.seq).or_default().push(so);
    }

    // Pass 1: contradictions among what is held. Iterates only held positions,
    // so an absurd `seq` costs nothing.
    let mut violations = Vec::new();
    for (&seq, at_seq) in &by_seq {
        if at_seq.len() > 1 {
            violations.push(ChainViolation::Equivocation {
                author: *author,
                seq,
                entries: at_seq.iter().map(|so| so.id).collect(),
            });
        }
        for entry in at_seq {
            if let Some(v) = link_violation(*author, seq, entry, &by_seq) {
                violations.push(v);
            }
        }
    }
    if !violations.is_empty() {
        return Ok(ChainVerification::Violated(violations));
    }

    // Pass 2: nothing held contradicts anything held. Is the chain whole?
    let highest = *by_seq
        .keys()
        .next_back()
        .expect("by_seq is non-empty because held was non-empty");
    if by_seq.len() as u64 == highest.saturating_add(1) {
        return Ok(ChainVerification::Verified);
    }

    let mut missing = Vec::new();
    let mut next = 0u64;
    for &seq in by_seq.keys() {
        while next < seq && missing.len() < MISSING_LIST_CAP {
            missing.push(next);
            next += 1;
        }
        next = seq.saturating_add(1);
    }
    Ok(ChainVerification::Incomplete { missing })
}

/// Run [`verify_chain`] for every author the store knows, in key order.
///
/// # Errors
///
/// [`StoreError`] if the backend fails.
pub fn verify_all<S: Store + ?Sized>(
    store: &S,
) -> Result<Vec<(PubKey, ChainVerification)>, StoreError> {
    store
        .authors()?
        .into_iter()
        .map(|author| verify_chain(store, &author).map(|v| (author, v)))
        .collect()
}

/// The link check for one entry: does its `prev` match the predecessor the store
/// holds? `None` means the link is sound *or* uncheckable (a gap below it);
/// `Some` is an attributable [`ChainViolation::BrokenLink`].
fn link_violation(
    author: PubKey,
    seq: Seq,
    entry: &StoredObservation,
    by_seq: &BTreeMap<Seq, Vec<StoredObservation>>,
) -> Option<ChainViolation> {
    let claimed_prev = entry.observation.prev;

    if seq == 0 {
        // Genesis must carry the empty byte string.
        return claimed_prev.map(|_| ChainViolation::BrokenLink {
            author,
            seq,
            entry: entry.id,
            claimed_prev,
            predecessor: Vec::new(),
        });
    }

    // A gap below this entry makes the link uncheckable, not broken.
    let predecessors = by_seq.get(&(seq - 1))?;
    let linked = claimed_prev.is_some_and(|p| predecessors.iter().any(|so| so.id == p));
    if linked {
        None
    } else {
        Some(ChainViolation::BrokenLink {
            author,
            seq,
            entry: entry.id,
            claimed_prev,
            predecessor: predecessors.iter().map(|so| so.id).collect(),
        })
    }
}
