//! Running `spec/03-export-pack.md` §5 end to end, and rendering the verdict a
//! stranger reads.
//!
//! [`verify`] is the whole procedure: parse the envelope, self-check every
//! carried object, validate fork proofs, run the `spec/01` §6.6 chain check per
//! author, rebuild the DAG, and recompute every bracket. It never calls
//! `vigil-ledger`.
//!
//! [`Report`] carries every intermediate result, not just a pass/fail bit,
//! because §5 requires the failure to be *named*: which object failed its
//! self-check, which chain was `Violated` and why, which claim is unverifiable
//! and why. [`Report::passed`] is the load-bearing exit condition.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use vigil_core::{Attestation, Hash, Observation, PubKey};

use crate::bracket::{AuthorSegment, Bracket, WindowEdge, bracket};
use crate::chain::{ChainEntry, ChainVerification, ChainViolation, verify_chain};
use crate::dag::{Dag, SealStatus};
use crate::pack::{PackContents, PackParseError, SelfCheck, parse_pack};

/// The outcome of trying to reproduce one bracket claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// The bracket was recomputed from the DAG. Carries the full result.
    Bracketed(Bracket),
    /// No surviving observation in the pack has the claimed id, so there is
    /// nothing to bracket (`spec/03` §6.5 T1/T2). `pack_had_discards` is `true`
    /// when the pack carried an object that failed its self-check and was
    /// discarded (a flipped byte — T1), and `false` when every carried object
    /// self-checked and the id is simply absent (a re-signed chain — T2).
    Unverifiable { pack_had_discards: bool },
}

/// One claim's entry in the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimReport {
    pub observation: Hash,
    pub outcome: ClaimOutcome,
    /// Keys convicted by a carried fork proof that also appear in this claim's
    /// closure — its author, or the witness of an upper/lower-bound attestation
    /// (`spec/03` §5 step 6: "any fork proof touching a key in the claim").
    pub fork_proofs_touching: Vec<PubKey>,
}

/// A carried object that failed its `spec/03` §5 step 2 self-check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidObject {
    pub kind: ObjectKind,
    pub index: usize,
    pub id: Option<Hash>,
    pub check: SelfCheck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    Observation,
    Attestation,
}

/// A carried attestation that drew no seal edge and is not a self-attestation
/// (`spec/03` §6.5 T3): its `subject_head` names an entry the pack does not
/// carry, so the verifier cannot confirm the head and refuses to seal on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnanchoredAttestation {
    pub id: Hash,
    pub subject: PubKey,
    pub subject_seq: u64,
    pub subject_head: Hash,
}

/// How a carried fork proof bears on the pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkKind {
    /// The convicted key witnesses one or more attestations in the pack — its
    /// seals are dropped (`spec/02` §6.5).
    Witness,
    /// The convicted key authors a carried chain — its unwitnessed records are
    /// `disputed` (`spec/02` §6.4).
    Author,
    /// The convicted key appears in the pack but neither witnesses nor authors a
    /// carried object. Still carried and reported (`spec/03` §3.4).
    Other,
}

/// Everything `vigil-verify` derived from a pack. Rendered by [`fmt::Display`];
/// [`Report::passed`] is the exit-0 condition.
#[derive(Debug, Clone)]
pub struct Report {
    pub pack_len: usize,
    pub org: PubKey,
    pub wire_version: u64,
    pub observation_count: usize,
    pub attestation_count: usize,
    pub invalid_objects: Vec<InvalidObject>,
    pub invalid_fork_proofs: usize,
    /// Validated fork proofs carried in the pack, and the key each convicts.
    pub fork_proofs: Vec<(PubKey, ForkKind)>,
    pub chains: Vec<(PubKey, ChainVerification)>,
    pub unanchored_attestations: Vec<UnanchoredAttestation>,
    pub claims: Vec<ClaimReport>,
}

impl Report {
    /// The exit-0 condition (`spec/03` §5): every claim reproduced cleanly.
    ///
    /// Nonzero when any carried object failed its self-check, any fork-proof
    /// entry was malformed, the pack carries a *valid* fork proof (a convicted
    /// key the pack depends on), any author chain is `Violated`, any carried
    /// attestation anchors nothing, or any claim could not be bracketed.
    ///
    /// A chain reported `Incomplete` does **not** fail — that is the normal
    /// state under partition, and the `spec/03` §3.5 "earliest held" segment
    /// lands there by design.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.invalid_objects.is_empty()
            && self.invalid_fork_proofs == 0
            && self.fork_proofs.is_empty()
            && !self.chains.iter().any(|(_, v)| v.is_violated())
            && self.unanchored_attestations.is_empty()
            && self
                .claims
                .iter()
                .all(|c| matches!(c.outcome, ClaimOutcome::Bracketed(_)))
    }

    /// `0` if [`passed`](Self::passed), else `1`. The load-bearing behaviour:
    /// `vigil-verify` runs in someone else's CI against a pack we did not
    /// produce.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        i32::from(!self.passed())
    }

    fn failure_summary(&self) -> String {
        let mut reasons = Vec::new();
        if !self.invalid_objects.is_empty() {
            reasons.push(format!(
                "{} carried object(s) failed the self-check and were discarded",
                self.invalid_objects.len()
            ));
        }
        if self.invalid_fork_proofs > 0 {
            reasons.push(format!(
                "{} malformed fork proof(s) in the pack",
                self.invalid_fork_proofs
            ));
        }
        if !self.fork_proofs.is_empty() {
            reasons.push(format!(
                "{} key(s) convicted of equivocation by a carried fork proof",
                self.fork_proofs.len()
            ));
        }
        if self.chains.iter().any(|(_, v)| v.is_violated()) {
            reasons.push("a chain integrity finding is attributable to an author key".to_owned());
        }
        if !self.unanchored_attestations.is_empty() {
            reasons.push(
                "the pack carries an attestation whose anchor entry it does not include".to_owned(),
            );
        }
        let unver = self
            .claims
            .iter()
            .filter(|c| matches!(c.outcome, ClaimOutcome::Unverifiable { .. }))
            .count();
        if unver > 0 {
            reasons.push(format!("{unver} claim(s) could not be bracketed"));
        }
        reasons.join("; ")
    }
}

/// Run `spec/03-export-pack.md` §5 steps 1–6 over `pack_bytes`, checking the
/// envelope's `org` against `org`.
///
/// # Errors
///
/// [`PackParseError`] only for a *structural* failure (bad marker, non-canonical
/// envelope CBOR, wrong wire version, wrong org, trailing bytes). Every
/// data-level finding — an object that failed its self-check, a broken chain, an
/// unverifiable claim — is recorded in the returned [`Report`], which then does
/// not [`passed`](Report::passed).
pub fn verify(pack_bytes: &[u8], org: PubKey) -> Result<Report, PackParseError> {
    let pack = parse_pack(pack_bytes, org)?;

    // --- step 2 residue: which objects failed, for the report ---
    let mut invalid_objects = Vec::new();
    for c in &pack.observations {
        if !c.check.is_ok() {
            invalid_objects.push(InvalidObject {
                kind: ObjectKind::Observation,
                index: c.index,
                id: c.id,
                check: c.check,
            });
        }
    }
    for c in &pack.attestations {
        if !c.check.is_ok() {
            invalid_objects.push(InvalidObject {
                kind: ObjectKind::Attestation,
                index: c.index,
                id: c.id,
                check: c.check,
            });
        }
    }

    // --- step 3: quarantine set from validated fork proofs ---
    let mut quarantined: BTreeSet<PubKey> = BTreeSet::new();
    for (_, proof) in &pack.fork_proofs {
        if let Ok(checked) = proof.check() {
            quarantined.insert(checked.key);
        }
    }

    // --- surviving objects (those that passed step 2) ---
    let survivor_obs: Vec<(Hash, Observation)> = pack
        .valid_observations()
        .map(|(id, o, _)| (id, o.clone()))
        .collect();
    let survivor_att: Vec<(Hash, Attestation)> = pack
        .valid_attestations()
        .map(|(id, a, _)| (id, *a))
        .collect();

    // --- step 4: chain check per author over the carried segment ---
    let mut by_author: BTreeMap<PubKey, Vec<ChainEntry>> = BTreeMap::new();
    for (id, o) in &survivor_obs {
        by_author.entry(o.author).or_default().push(ChainEntry {
            id: *id,
            seq: o.seq,
            prev: o.prev,
        });
    }
    let chains: Vec<(PubKey, ChainVerification)> = by_author
        .iter()
        .map(|(author, entries)| (*author, verify_chain(*author, entries)))
        .collect();

    // --- step 5: the DAG ---
    let dag = Dag::build(&survivor_obs, &survivor_att, &quarantined);

    let mut unanchored_attestations = Vec::new();
    for aid in dag.attestation_ids() {
        if dag.seal_status(aid) == Some(SealStatus::Unanchored) {
            if let Some(a) = dag.attestation(aid) {
                unanchored_attestations.push(UnanchoredAttestation {
                    id: aid,
                    subject: a.subject,
                    subject_seq: a.subject_seq,
                    subject_head: a.subject_head,
                });
            }
        }
    }

    // --- step 6: brackets per claim ---
    let pack_had_discards = !invalid_objects.is_empty();
    let claims = pack
        .claims
        .iter()
        .map(|claim| bracket_one(&dag, &by_author, &quarantined, *claim, pack_had_discards))
        .collect();

    Ok(Report {
        pack_len: pack_bytes.len(),
        org,
        wire_version: pack.wire_version,
        observation_count: pack.observations.len(),
        attestation_count: pack.attestations.len(),
        invalid_objects,
        invalid_fork_proofs: pack.invalid_fork_proofs,
        fork_proofs: classify_fork_proofs(&pack, &survivor_obs, &survivor_att),
        chains,
        unanchored_attestations,
        claims,
    })
}

fn classify_fork_proofs(
    pack: &PackContents,
    obs: &[(Hash, Observation)],
    att: &[(Hash, Attestation)],
) -> Vec<(PubKey, ForkKind)> {
    let authors: BTreeSet<PubKey> = obs.iter().map(|(_, o)| o.author).collect();
    let witnesses: BTreeSet<PubKey> = att.iter().map(|(_, a)| a.witness).collect();
    pack.fork_proofs
        .iter()
        .filter_map(|(_, p)| p.check().ok().map(|c| c.key))
        .map(|key| {
            let kind = if witnesses.contains(&key) {
                ForkKind::Witness
            } else if authors.contains(&key) {
                ForkKind::Author
            } else {
                ForkKind::Other
            };
            (key, kind)
        })
        .collect()
}

fn bracket_one(
    dag: &Dag,
    by_author: &BTreeMap<PubKey, Vec<ChainEntry>>,
    quarantined: &BTreeSet<PubKey>,
    claim: Hash,
    pack_had_discards: bool,
) -> ClaimReport {
    let Some(obs) = dag.observation(claim) else {
        return ClaimReport {
            observation: claim,
            outcome: ClaimOutcome::Unverifiable { pack_had_discards },
            fork_proofs_touching: Vec::new(),
        };
    };

    let author = obs.author;
    let lowest_held_seq = by_author
        .get(&author)
        .and_then(|v| v.iter().map(|e| e.seq).min())
        .unwrap_or(0);

    let br = bracket(
        dag,
        claim,
        AuthorSegment {
            author,
            lowest_held_seq,
        },
    )
    .expect("claim is an observation vertex");

    // Keys in this claim's closure: the author, the witness of every bounding
    // attestation, and — so a quarantine that *removed* a bound still shows up
    // here — the witness of any carried attestation about this author.
    let mut keys: BTreeSet<PubKey> = BTreeSet::from([author]);
    for a in br.upper_bound.into_iter().chain(br.lower_bound) {
        if let Some(att) = dag.attestation(a) {
            keys.insert(att.witness);
        }
    }
    for aid in dag.attestation_ids() {
        if let Some(att) = dag.attestation(aid) {
            if att.subject == author {
                keys.insert(att.witness);
            }
        }
    }
    let fork_proofs_touching: Vec<PubKey> = quarantined
        .iter()
        .copied()
        .filter(|k| keys.contains(k))
        .collect();

    ClaimReport {
        observation: claim,
        outcome: ClaimOutcome::Bracketed(br),
        fork_proofs_touching,
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn short(h: &Hash) -> String {
    let s = h.to_string();
    format!("{}…{}", &s[..8], &s[s.len() - 5..])
}

fn short_key(k: &PubKey) -> String {
    let s = k.to_string();
    format!("{}…{}", &s[..8], &s[s.len() - 5..])
}

fn window_edge(e: &WindowEdge) -> String {
    match e {
        WindowEdge::Attestation(h) => format!("attestation {}", short(h)),
        WindowEdge::Genesis => "genesis".to_owned(),
        WindowEdge::EarliestHeld(n) => {
            format!("open below to the earliest held entry (seq {n})")
        }
        WindowEdge::VerificationMoment => "verification moment".to_owned(),
    }
}

fn fmt_seqs(seqs: &[u64]) -> String {
    seqs.iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn fmt_violation(v: &ChainViolation) -> String {
    match v {
        ChainViolation::Equivocation { seq, entries, .. } => format!(
            "Equivocation at seq {seq}: {}",
            entries.iter().map(short).collect::<Vec<_>>().join(", ")
        ),
        ChainViolation::BrokenLink {
            seq,
            entry,
            claimed_prev,
            predecessor,
            ..
        } => {
            let cp = claimed_prev.map_or_else(|| "genesis".to_owned(), |h| short(&h));
            let pred = if predecessor.is_empty() {
                "(none — a genesis entry must carry an empty prev)".to_owned()
            } else {
                predecessor.iter().map(short).collect::<Vec<_>>().join(", ")
            };
            format!(
                "BrokenLink at seq {seq}: entry {} claims prev {cp}, held predecessor is {pred}",
                short(entry)
            )
        }
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "vigil-verify — spec/03-export-pack.md §5")?;
        writeln!(f)?;
        writeln!(f, "  pack   {} bytes", self.pack_len)?;
        writeln!(f, "  org    {}  (matches argument)", short_key(&self.org))?;
        writeln!(f, "  wire   {}", self.wire_version)?;
        writeln!(f)?;

        // [1] envelope — reaching here means it decoded.
        writeln!(f, "  [1] envelope            OK")?;

        // [2] object self-check
        let total = self.observation_count + self.attestation_count;
        let ok = total - self.invalid_objects.len();
        writeln!(f, "  [2] object self-check   {ok}/{total} passed")?;
        for io in &self.invalid_objects {
            let kind = match io.kind {
                ObjectKind::Observation => "observation",
                ObjectKind::Attestation => "attestation",
            };
            let reason = match io.check {
                SelfCheck::Undecodable => "preimage is not a canonical object",
                SelfCheck::BadSignature => "signature does not verify",
                SelfCheck::Ok => "ok",
            };
            let id = io.id.map_or_else(|| "?".to_owned(), |h| short(&h));
            writeln!(
                f,
                "        {kind} #{} ({id}): {reason} — discarded",
                io.index
            )?;
        }

        // [3] fork proofs
        if self.fork_proofs.is_empty() && self.invalid_fork_proofs == 0 {
            writeln!(f, "  [3] fork proofs         none")?;
        } else {
            writeln!(
                f,
                "  [3] fork proofs         {} valid, {} malformed",
                self.fork_proofs.len(),
                self.invalid_fork_proofs
            )?;
            for (key, kind) in &self.fork_proofs {
                let role = match kind {
                    ForkKind::Witness => {
                        "convicts a sealing witness — its attestations are dropped from sealing"
                    }
                    ForkKind::Author => {
                        "convicts a carried author — its unwitnessed records are disputed"
                    }
                    ForkKind::Other => "convicts a key present in the pack",
                };
                writeln!(f, "        {} — {role}", short_key(key))?;
            }
        }

        // [4] chains
        writeln!(f, "  [4] chains")?;
        for (author, v) in &self.chains {
            match v {
                ChainVerification::Verified => {
                    writeln!(f, "        {} Verified", short_key(author))?;
                }
                ChainVerification::Incomplete { missing } => {
                    writeln!(
                        f,
                        "        {} Incomplete — missing seq {} (normal under partition)",
                        short_key(author),
                        fmt_seqs(missing)
                    )?;
                }
                ChainVerification::Violated(vs) => {
                    writeln!(f, "        {} VIOLATED", short_key(author))?;
                    for viol in vs {
                        writeln!(f, "          {}", fmt_violation(viol))?;
                    }
                }
            }
        }

        // [5] DAG
        writeln!(
            f,
            "  [5] attestation DAG     {} attestation(s) carried",
            self.attestation_count
        )?;
        for u in &self.unanchored_attestations {
            writeln!(
                f,
                "        attestation {} anchors nothing: subject_head {} \
                 (subject {}, seq {}) is not carried in the pack — the verifier \
                 refuses to seal on evidence it cannot check",
                short(&u.id),
                short(&u.subject_head),
                short_key(&u.subject),
                u.subject_seq
            )?;
        }

        // [6] claims
        writeln!(f, "  [6] claims")?;
        for c in &self.claims {
            writeln!(f)?;
            writeln!(f, "    {}", short(&c.observation))?;
            match &c.outcome {
                ClaimOutcome::Unverifiable { pack_had_discards } => {
                    let why = if *pack_had_discards {
                        "no surviving observation has this id — the pack carried an object \
                         that failed its self-check and was discarded (spec/03 §6.5 T1)"
                    } else {
                        "no carried observation has this id, and every carried object \
                         self-checked — the chain was re-signed (spec/03 §6.5 T2)"
                    };
                    writeln!(f, "      status       UNVERIFIABLE — {why}")?;
                }
                ClaimOutcome::Bracketed(b) => {
                    writeln!(
                        f,
                        "      status       {}",
                        if b.sealed { "SEALED" } else { "UNWITNESSED" }
                    )?;
                    match b.upper_bound {
                        Some(h) => writeln!(
                            f,
                            "      upper bound  attestation {}  (witness depth {})",
                            short(&h),
                            b.witness_depth
                        )?,
                        None => writeln!(f, "      upper bound  none")?,
                    }
                    match b.lower_bound {
                        Some(h) => writeln!(f, "      lower bound  attestation {}", short(&h))?,
                        None => writeln!(f, "      lower bound  none")?,
                    }
                    writeln!(
                        f,
                        "      window       [{}, {}]",
                        window_edge(&b.unwitnessed_window.lower),
                        window_edge(&b.unwitnessed_window.upper)
                    )?;
                    if b.disputed {
                        writeln!(
                            f,
                            "      disputed     YES — author is quarantined and this record is unwitnessed"
                        )?;
                    }
                }
            }
            for k in &c.fork_proofs_touching {
                writeln!(f, "      fork proof   convicts {}", short_key(k))?;
            }
        }

        writeln!(f)?;
        if self.passed() {
            writeln!(
                f,
                "RESULT: PASS — every claim reproduced from the pack's own evidence."
            )?;
        } else {
            writeln!(f, "RESULT: FAIL — {}", self.failure_summary())?;
        }
        Ok(())
    }
}
