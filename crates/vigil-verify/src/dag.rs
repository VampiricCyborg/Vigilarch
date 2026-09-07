//! `spec/03-export-pack.md` §5 step 5: the attestation DAG
//! (`spec/02-entanglement.md` §4), rebuilt here with an independent traversal
//! over the pack's surviving objects.
//!
//! This is a second implementation of `vigil-ledger::dag` on purpose. If
//! `vigil-verify` imported the ledger's DAG it could only ever agree with it,
//! including where the ledger is wrong. The edge rules are `spec/02` §4.2:
//!
//! - **chain** — obs@(n−1) → obs@n when n's `prev` recomputes to (n−1)'s id and
//!   both are the same author.
//! - **ack** — attestation X → obs E when `X.id ∈ E.acks`, `X.subject == E.author`
//!   and `X.subject_seq < E.seq`.
//! - **seal** — obs S@m → attestation X for every held entry of the subject that
//!   is a **chain ancestor** of `X.subject_head` (walk `prev` from the anchored
//!   head — ADR-0003 Part 1), when the held entry at `X.subject_seq` recomputes
//!   to `X.subject_head` and `X.witness ≠ X.subject`. A quarantined witness
//!   contributes no seal edge (`spec/02` §6.5).
//!
//! `⟶` is the transitive closure. Every container is a `BTree*` so traversal is
//! in content-address order and the result does not depend on input order
//! (`spec/02` §4.7).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use vigil_core::{Attestation, Hash, Observation, PubKey};

/// A DAG vertex, named by content address. `Obs` sorts before `Att`; each sorts
/// by hash. That ordering is what every traversal iterates in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DagNode {
    Obs(Hash),
    Att(Hash),
}

/// Why a carried attestation drew no seal edge. Collected for the report: an
/// attestation that anchors nothing is either an invalid pack (a required entry
/// was left out, `spec/03` §3.2) or a probe to see whether the verifier will
/// seal on evidence it cannot check (`spec/03` §6.5 T3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealStatus {
    /// The witness saw the subject's head and it is held; seal edges were drawn.
    Anchored,
    /// `witness == subject`: a node attesting its own head proves nothing
    /// (`spec/02` §4.4). Retained, ignored for sealing.
    SelfAttestation,
    /// The witness key is quarantined by a validated fork proof (`spec/02` §6.5).
    WitnessQuarantined,
    /// `subject_head` names an entry the verifier does not hold, or the held
    /// entry at `subject_seq` does not match `subject`/`subject_seq`
    /// (`spec/02` §4.5).
    Unanchored,
}

/// The attestation DAG over one pack's surviving object set.
pub struct Dag {
    observations: BTreeMap<Hash, Observation>,
    attestations: BTreeMap<Hash, Attestation>,
    reach: BTreeMap<DagNode, BTreeSet<DagNode>>,
    seal_status: BTreeMap<Hash, SealStatus>,
    quarantined: BTreeSet<PubKey>,
}

impl Dag {
    /// Build the DAG from the pack's surviving observations and attestations,
    /// dropping seal edges from any witness in `quarantined` (`spec/02` §6.5).
    #[must_use]
    pub fn build(
        obs: &[(Hash, Observation)],
        att: &[(Hash, Attestation)],
        quarantined: &BTreeSet<PubKey>,
    ) -> Self {
        let observations: BTreeMap<Hash, Observation> = obs.iter().cloned().collect();
        let attestations: BTreeMap<Hash, Attestation> = att.iter().cloned().collect();

        let mut out: BTreeMap<DagNode, BTreeSet<DagNode>> = BTreeMap::new();
        for id in observations.keys() {
            out.entry(DagNode::Obs(*id)).or_default();
        }
        for id in attestations.keys() {
            out.entry(DagNode::Att(*id)).or_default();
        }

        // chain edges: obs@(n-1) -> obs@n
        for (id, o) in &observations {
            let Some(prev) = o.prev else { continue };
            let Some(p) = observations.get(&prev) else {
                continue;
            };
            if p.author == o.author && o.seq.checked_sub(1) == Some(p.seq) {
                out.entry(DagNode::Obs(prev))
                    .or_default()
                    .insert(DagNode::Obs(*id));
            }
        }

        // ack edges: att X -> obs E when X.id in E.acks, X.subject == E.author,
        // X.subject_seq < E.seq.
        for (id, o) in &observations {
            for ack_id in &o.acks {
                let Some(x) = attestations.get(ack_id) else {
                    continue;
                };
                if x.subject == o.author && x.subject_seq < o.seq {
                    out.entry(DagNode::Att(*ack_id))
                        .or_default()
                        .insert(DagNode::Obs(*id));
                }
            }
        }

        // seal edges: obs S@m -> att X for every chain ancestor of the anchored
        // head (walk `prev`), when the held entry at X.subject_seq recomputes to
        // X.subject_head and X.witness != X.subject.
        let mut seal_status: BTreeMap<Hash, SealStatus> = BTreeMap::new();
        for (xid, x) in &attestations {
            if x.witness == x.subject {
                seal_status.insert(*xid, SealStatus::SelfAttestation);
                continue;
            }
            if quarantined.contains(&x.witness) {
                seal_status.insert(*xid, SealStatus::WitnessQuarantined);
                continue;
            }
            let anchor_ok = observations
                .get(&x.subject_head)
                .is_some_and(|anchor| anchor.author == x.subject && anchor.seq == x.subject_seq);
            if !anchor_ok {
                seal_status.insert(*xid, SealStatus::Unanchored);
                continue;
            }
            seal_status.insert(*xid, SealStatus::Anchored);

            let mut cursor = Some(x.subject_head);
            let mut walked: BTreeSet<Hash> = BTreeSet::new();
            while let Some(cur) = cursor {
                if !walked.insert(cur) {
                    break; // defensive: a `prev` cycle in hostile input
                }
                let Some(entry) = observations.get(&cur) else {
                    break;
                };
                if entry.author != x.subject {
                    break;
                }
                out.entry(DagNode::Obs(cur))
                    .or_default()
                    .insert(DagNode::Att(*xid));
                cursor = entry.prev;
            }
        }

        // transitive closure: BFS from each vertex, in node order.
        let nodes: Vec<DagNode> = out.keys().copied().collect();
        let mut reach: BTreeMap<DagNode, BTreeSet<DagNode>> = BTreeMap::new();
        for &start in &nodes {
            let mut seen: BTreeSet<DagNode> = BTreeSet::new();
            let mut queue: VecDeque<DagNode> = out[&start].iter().copied().collect();
            for n in &queue {
                seen.insert(*n);
            }
            while let Some(cur) = queue.pop_front() {
                if let Some(nbrs) = out.get(&cur) {
                    for &n in nbrs {
                        if seen.insert(n) {
                            queue.push_back(n);
                        }
                    }
                }
            }
            reach.insert(start, seen);
        }

        Self {
            observations,
            attestations,
            reach,
            seal_status,
            quarantined: quarantined.clone(),
        }
    }

    /// `from ⟶ to`: `to` is reachable from `from` by one or more edges. False for
    /// `from == to`.
    #[must_use]
    pub fn reaches(&self, from: DagNode, to: DagNode) -> bool {
        self.reach.get(&from).is_some_and(|s| s.contains(&to))
    }

    /// The observation behind a vertex id, if it is one.
    #[must_use]
    pub fn observation(&self, id: Hash) -> Option<&Observation> {
        self.observations.get(&id)
    }

    /// The attestation behind a vertex id, if it is one.
    #[must_use]
    pub fn attestation(&self, id: Hash) -> Option<&Attestation> {
        self.attestations.get(&id)
    }

    /// Every attestation vertex id, ascending by content address.
    pub fn attestation_ids(&self) -> impl Iterator<Item = Hash> + '_ {
        self.attestations.keys().copied()
    }

    /// Why attestation `id` did or did not draw seal edges.
    #[must_use]
    pub fn seal_status(&self, id: Hash) -> Option<SealStatus> {
        self.seal_status.get(&id).copied()
    }

    /// Whether `key` is quarantined for this build.
    #[must_use]
    pub fn is_quarantined(&self, key: &PubKey) -> bool {
        self.quarantined.contains(key)
    }
}
