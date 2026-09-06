//! The attestation DAG (`spec/02-entanglement.md` §4).
//!
//! Given whatever set of objects a [`Store`] holds, [`Dag::build`] constructs a
//! directed acyclic graph with one vertex per valid observation and one per
//! valid attestation, and three kinds of edge — **chain**, **ack**, **seal** —
//! each meaning *the tail provably happened before the head*. The partial order
//! `⟶` that bracketing (`spec/02` §5) reads off is the transitive closure of
//! those edges.
//!
//! ## Determinism (`spec/02` §4.7)
//!
//! Construction is a pure function of the held object set: independent of
//! arrival order, of duplicates, and of the machine. Every container here is a
//! `BTree*`, so every traversal is in content-address order and no step depends
//! on insertion history. Two verifiers with the same held set produce the same
//! graph and therefore the same brackets. `vigil-sim` asserts this on every run.
//!
//! ## What "valid" means (`spec/02` §4.1)
//!
//! The id recomputes from the preimage — always true of a [`Store`], which
//! keys objects by the id it computed on `put` — and the signature verifies:
//! an observation under its `author`, an attestation under its `witness`. An
//! object whose signature does not verify is not a vertex and contributes no
//! edges. An *integrity finding* (a bad `acks` entry, `spec/02` §3.4) does not
//! exclude the observation — it enters the DAG and the finding is recorded.
//!
//! ## Every attestation is confined to its subject's chain
//!
//! An `Attestation` carries the *subject's* head, never the witness's. So its
//! seal edges arrive only from the subject's observations, and its one ack edge
//! leaves only to the subject's chain (`X.subject == E.author`, §4.2). A
//! consequence worth stating: this graph has **no edge between two different
//! authors' chains**. Bracketing (`spec/02` §5) reads an ordering off `⟶` and
//! never a heuristic (§4.3), so a record by author A and a record by author B
//! are `incomparable` unless one author's chain reaches the other's — which
//! these three edge rules never make happen. That is the honest, conservative
//! outcome under partition (invariant I5), not a gap to paper over.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use vigil_core::{Attestation, Hash, Observation, PubKey, Seq, verify_id};

use crate::fork::Quarantine;
use crate::store::{Store, StoreError, StoredAttestation, StoredObservation};

/// A vertex: either a valid observation or a valid attestation, named by its
/// content address.
///
/// `Ord` is derived, so `Obs` sorts before `Att` and each sorts by hash. That
/// ordering is what every traversal in this module iterates in, which is what
/// makes the results machine-independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DagNode {
    Obs(Hash),
    Att(Hash),
}

/// An integrity finding against an observation's `author`, raised when an `acks`
/// entry names an attestation that does not lawfully bind here
/// (`spec/02-entanglement.md` §3.4). The observation still enters the DAG; the
/// unlawful ack simply contributes no edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckFinding {
    /// The observation carrying the bad `acks` entry.
    pub observation: Hash,
    /// The key the finding is attributable to — the observation's `author`.
    pub author: PubKey,
    /// The attestation the `acks` entry named.
    pub attestation: Hash,
    pub reason: AckFindingReason,
}

/// Why an `acks` entry was rejected (`spec/02-entanglement.md` §3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckFindingReason {
    /// The attestation's `subject` is not the observation's `author`.
    SubjectMismatch { ack_subject: PubKey },
    /// The attestation's `subject_seq` is not strictly below the observation's
    /// `seq`, so it cannot precede this record in its own chain.
    SeqNotBelow { ack_subject_seq: Seq },
}

/// The attestation DAG over one held object set.
pub struct Dag {
    observations: BTreeMap<Hash, StoredObservation>,
    attestations: BTreeMap<Hash, StoredAttestation>,
    /// Direct edges, tail -> heads. Every vertex has an entry, possibly empty.
    out: BTreeMap<DagNode, BTreeSet<DagNode>>,
    /// Transitive closure of `out`: `reach[n]` is every node reachable from `n`
    /// by one or more edges (never `n` itself — a record does not precede
    /// itself).
    reach: BTreeMap<DagNode, BTreeSet<DagNode>>,
    findings: Vec<AckFinding>,
}

impl Dag {
    /// Build the DAG from everything `store` holds, disregarding seal edges from
    /// any witness in `quarantine` (`spec/02-entanglement.md` §6.5). Pass
    /// [`Quarantine::new`] for the ordinary case.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the backend fails.
    pub fn build<S: Store + ?Sized>(
        store: &S,
        quarantine: &Quarantine,
    ) -> Result<Self, StoreError> {
        // --- vertices: valid observations, valid attestations ---
        let mut observations = BTreeMap::new();
        for author in store.authors()? {
            for so in store.chain(&author)? {
                if verify_id(so.observation.author, so.id, &so.signature).is_ok() {
                    observations.insert(so.id, so);
                }
            }
        }
        let mut attestations = BTreeMap::new();
        for sa in store.all_attestations()? {
            if verify_id(sa.attestation.witness, sa.id, &sa.signature).is_ok() {
                attestations.insert(sa.id, sa);
            }
        }

        let mut by_author: BTreeMap<PubKey, BTreeMap<Seq, BTreeSet<Hash>>> = BTreeMap::new();
        for so in observations.values() {
            by_author
                .entry(so.observation.author)
                .or_default()
                .entry(so.observation.seq)
                .or_default()
                .insert(so.id);
        }

        let mut out: BTreeMap<DagNode, BTreeSet<DagNode>> = BTreeMap::new();
        for id in observations.keys() {
            out.entry(DagNode::Obs(*id)).or_default();
        }
        for id in attestations.keys() {
            out.entry(DagNode::Att(*id)).or_default();
        }

        // --- chain edges (§4.2): obs@(n-1) -> obs@n when n.prev recomputes to
        // (n-1)'s id and both are held for the same author. ---
        for so in observations.values() {
            let Some(prev) = so.observation.prev else {
                continue;
            };
            let Some(p) = observations.get(&prev) else {
                continue;
            };
            if p.observation.author == so.observation.author
                && so.observation.seq.checked_sub(1) == Some(p.observation.seq)
            {
                out.entry(DagNode::Obs(prev))
                    .or_default()
                    .insert(DagNode::Obs(so.id));
            }
        }

        // --- ack edges (§4.2) + integrity findings (§3.4): att X -> obs E when
        // X.id in E.acks, X.subject == E.author, X.subject_seq < E.seq. ---
        let mut findings = Vec::new();
        for so in observations.values() {
            for ack_id in &so.observation.acks {
                let Some(x) = attestations.get(ack_id) else {
                    // Not held (or not valid) — no edge, and no finding: it may
                    // simply not have arrived (§4.5 analogue).
                    continue;
                };
                let a = &x.attestation;
                if a.subject != so.observation.author {
                    findings.push(AckFinding {
                        observation: so.id,
                        author: so.observation.author,
                        attestation: *ack_id,
                        reason: AckFindingReason::SubjectMismatch {
                            ack_subject: a.subject,
                        },
                    });
                    continue;
                }
                if a.subject_seq >= so.observation.seq {
                    findings.push(AckFinding {
                        observation: so.id,
                        author: so.observation.author,
                        attestation: *ack_id,
                        reason: AckFindingReason::SeqNotBelow {
                            ack_subject_seq: a.subject_seq,
                        },
                    });
                    continue;
                }
                out.entry(DagNode::Att(*ack_id))
                    .or_default()
                    .insert(DagNode::Obs(so.id));
            }
        }

        // --- seal edges (§4.2): obs S@m -> att X for every held observation of
        // X.subject at seq m <= X.subject_seq, when the held entry at
        // X.subject_seq recomputes to X.subject_head and X.witness != X.subject.
        // A quarantined witness contributes no seal edge (§6.5). ---
        for x in attestations.values() {
            let a = &x.attestation;
            if a.witness == a.subject {
                // A node attesting its own head proves nothing (§4.4).
                continue;
            }
            if quarantine.contains(&a.witness) {
                continue;
            }
            let anchored = observations.get(&a.subject_head).is_some_and(|anchor| {
                anchor.observation.author == a.subject && anchor.observation.seq == a.subject_seq
            });
            if !anchored {
                // Unanchored: the verifier cannot confirm the head (§4.5).
                continue;
            }
            if let Some(seqs) = by_author.get(&a.subject) {
                for ids in seqs.range(..=a.subject_seq).map(|(_, ids)| ids) {
                    for sid in ids {
                        out.entry(DagNode::Obs(*sid))
                            .or_default()
                            .insert(DagNode::Att(x.id));
                    }
                }
            }
        }

        // --- transitive closure: BFS from each vertex, in node order ---
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

        Ok(Self {
            observations,
            attestations,
            out,
            reach,
            findings,
        })
    }

    /// Whether `node` is a vertex (a valid observation or attestation).
    #[must_use]
    pub fn is_vertex(&self, node: DagNode) -> bool {
        match node {
            DagNode::Obs(h) => self.observations.contains_key(&h),
            DagNode::Att(h) => self.attestations.contains_key(&h),
        }
    }

    /// `from ⟶ to`: `to` is reachable from `from` by one or more edges — "from
    /// provably happened before to". False for `from == to`.
    #[must_use]
    pub fn reaches(&self, from: DagNode, to: DagNode) -> bool {
        self.reach.get(&from).is_some_and(|s| s.contains(&to))
    }

    /// The direct out-edges of `node`, in node order.
    pub fn out_edges(&self, node: DagNode) -> impl Iterator<Item = DagNode> + '_ {
        self.out.get(&node).into_iter().flatten().copied()
    }

    /// Every observation vertex id, ascending by content address.
    pub fn observation_ids(&self) -> impl Iterator<Item = Hash> + '_ {
        self.observations.keys().copied()
    }

    /// Every attestation vertex id, ascending by content address.
    pub fn attestation_ids(&self) -> impl Iterator<Item = Hash> + '_ {
        self.attestations.keys().copied()
    }

    /// The observation behind a vertex id, if it is one.
    #[must_use]
    pub fn observation(&self, id: &Hash) -> Option<&Observation> {
        self.observations.get(id).map(|so| &so.observation)
    }

    /// The attestation behind a vertex id, if it is one.
    #[must_use]
    pub fn attestation(&self, id: &Hash) -> Option<&Attestation> {
        self.attestations.get(id).map(|sa| &sa.attestation)
    }

    /// Integrity findings against `acks` entries (`spec/02-entanglement.md`
    /// §3.4), in discovery order.
    #[must_use]
    pub fn ack_findings(&self) -> &[AckFinding] {
        &self.findings
    }
}
