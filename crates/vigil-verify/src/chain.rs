//! `spec/03-export-pack.md` §5 step 4: the `spec/01-wire-format.md` §6.6
//! three-outcome chain check, run over exactly the carried segment.
//!
//! Reimplemented here from the §6.6 text, not shared with
//! `vigil-ledger::verify_chain`. The three outcomes and the rule that the middle
//! one never collapses into either neighbour are the point:
//!
//! - **Verified** — every `seq` from 0 to the highest held is present exactly
//!   once, and every `prev` recomputes to its predecessor's id.
//! - **Incomplete** — a `seq` is missing and nothing held contradicts anything
//!   else held. The normal state under partition; **not** a violation. A low
//!   `seq` missing because the pack's segment starts above 0 (`spec/03` §3.5,
//!   the "earliest held" marker) lands here — never in `Violated`.
//! - **Violated** — two entries at one `seq` with different ids, or a `prev`
//!   that does not match the held predecessor. Attributable to the author's key.

use std::collections::BTreeMap;

use vigil_core::{Hash, PubKey, Seq};

/// A held entry of one author's chain, as the verifier reconstructs it from the
/// pack's surviving observations.
#[derive(Debug, Clone, Copy)]
pub struct ChainEntry {
    pub id: Hash,
    pub seq: Seq,
    /// `None` is the genesis link — a zero-length `prev` (`spec/01` §6.1).
    pub prev: Option<Hash>,
}

/// The result of the §6.6 pass for one author.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainVerification {
    /// Complete from `seq` 0 to the highest held, every link sound.
    Verified,
    /// One or more `seq` numbers are missing; nothing held contradicts anything
    /// held. `missing` is ascending. Includes `0..n` when the segment's lowest
    /// held `seq` is `n > 0` (`spec/03` §3.5).
    Incomplete { missing: Vec<Seq> },
    /// One or more attributable integrity findings.
    Violated(Vec<ChainViolation>),
}

impl ChainVerification {
    #[must_use]
    pub fn is_violated(&self) -> bool {
        matches!(self, ChainVerification::Violated(_))
    }
}

/// A single attributable chain-integrity finding (`spec/01` §6.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainViolation {
    /// `author` signed more than one distinct observation at `seq`.
    Equivocation {
        author: PubKey,
        seq: Seq,
        /// Every conflicting content address at this `seq`, ascending.
        entries: Vec<Hash>,
    },
    /// `entry`, at `seq`, carries a `prev` that does not match the held
    /// predecessor. For `seq` 0 this means a non-empty `prev` on a genesis
    /// entry, and `predecessor` is then empty.
    BrokenLink {
        author: PubKey,
        seq: Seq,
        entry: Hash,
        claimed_prev: Option<Hash>,
        predecessor: Vec<Hash>,
    },
}

/// How many missing `seq` numbers to enumerate before stopping. `seq` is
/// attacker-controlled (`spec/01` §6.6): one entry claiming `seq = 10^18` must
/// not make the pass allocate a billion-entry gap list. Past the cap the outcome
/// is still `Incomplete` and every listed entry is still a real gap.
const MISSING_LIST_CAP: usize = 4096;

/// Run the §6.6 pass for one author over the entries the pack carries for it.
///
/// `entries` is every surviving observation whose `author` is this key. An empty
/// slice means the author has no carried segment — `Incomplete { missing: [] }`,
/// never `Verified`.
#[must_use]
pub fn verify_chain(author: PubKey, entries: &[ChainEntry]) -> ChainVerification {
    if entries.is_empty() {
        return ChainVerification::Incomplete {
            missing: Vec::new(),
        };
    }

    let mut by_seq: BTreeMap<Seq, Vec<ChainEntry>> = BTreeMap::new();
    for e in entries {
        by_seq.entry(e.seq).or_default().push(*e);
    }

    // Pass 1: contradictions among what is held. Iterates only held positions,
    // so an absurd `seq` costs nothing.
    let mut violations = Vec::new();
    for (&seq, at_seq) in &by_seq {
        let mut ids: Vec<Hash> = at_seq.iter().map(|e| e.id).collect();
        ids.sort_unstable();
        ids.dedup();
        if ids.len() > 1 {
            violations.push(ChainViolation::Equivocation {
                author,
                seq,
                entries: ids,
            });
        }
        for e in at_seq {
            if let Some(v) = link_violation(author, seq, e, &by_seq) {
                violations.push(v);
            }
        }
    }
    if !violations.is_empty() {
        return ChainVerification::Violated(violations);
    }

    // Pass 2: nothing held contradicts anything held. Is the chain whole from 0?
    let highest = *by_seq.keys().next_back().expect("entries is non-empty");
    if by_seq.len() as u64 == highest.saturating_add(1) {
        return ChainVerification::Verified;
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
    ChainVerification::Incomplete { missing }
}

/// The link check for one entry: does its `prev` match the held predecessor?
/// `None` means sound *or* uncheckable (a gap below it); `Some` is an
/// attributable [`ChainViolation::BrokenLink`].
fn link_violation(
    author: PubKey,
    seq: Seq,
    entry: &ChainEntry,
    by_seq: &BTreeMap<Seq, Vec<ChainEntry>>,
) -> Option<ChainViolation> {
    let claimed_prev = entry.prev;

    if seq == 0 {
        // Genesis must carry the zero-length byte string (`prev == None`).
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
    let linked = claimed_prev.is_some_and(|p| predecessors.iter().any(|e| e.id == p));
    if linked {
        None
    } else {
        let mut ids: Vec<Hash> = predecessors.iter().map(|e| e.id).collect();
        ids.sort_unstable();
        ids.dedup();
        Some(ChainViolation::BrokenLink {
            author,
            seq,
            entry: entry.id,
            claimed_prev,
            predecessor: ids,
        })
    }
}
