//! `vigil-node` as a library: one process, one in-memory ledger, four loopback
//! HTTP endpoints.
//!
//! This is **not** a multi-node system. There is no peer, no sync, no role
//! distinction — those need `vigil-sync`, which is a v2 item and is not built.
//! What a node does here is:
//!
//! - hold one [`MemoryStore`] and one Ed25519 device key;
//! - append its own observations to its own chain on `POST /obs`;
//! - report, read-only, what [`vigil_ledger`] already computes about a record's
//!   provenance on `GET /obs/{id}/provenance` — the endpoint `docs/VIGILARCH.md`
//!   §15 calls "the product";
//! - assemble an export pack for a set of claimed records on `POST /export`, the
//!   file a person hands to `vigil-verify`;
//! - answer `GET /health`.
//!
//! ## A single node in isolation seals nothing
//!
//! Sealing a record requires an attestation from a *different* key that saw this
//! chain (`spec/02-entanglement.md` §5). A lone node has no such witness, so
//! every record it holds brackets as **unwitnessed**, with the window open above
//! to the verification moment. That is the correct, honest output (invariants
//! I5, I6), not a limitation to paper over — and the tests assert exactly it.
//!
//! ## Capture never blocks (a project invariant, not a local nicety)
//!
//! [`Node::capture`] touches only the in-process store behind a `Mutex` and the
//! signing key. It performs no I/O, opens no socket, and calls nothing that
//! could grow into a blocking call. "Capture is always available" is a
//! whole-project invariant (`docs/VIGILARCH.md` §2); keeping this path free of
//! anything external is how it stays true here.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use ed25519_dalek::SigningKey;
use vigil_core::{
    Hash, Hlc, Observation, ObservationBody, PubKey, Seq, SignedObject, SiteId, public_key,
};
use vigil_ledger::{
    Bracket, ChainVerification, ExportError, MemoryStore, Quarantine, Store, WindowEdge, append,
    bracket, export_pack, verify_chain,
};

mod http;
pub use http::{HttpResponse, dispatch, serve};

/// The site every observation this node writes is stamped with. A real
/// deployment would provision this; for a self-contained demo it is a constant.
const SITE: SiteId = SiteId(*b"VIGILARCH-NODE-A");

/// One running node: an in-memory ledger, a device key, and a logical clock,
/// all behind a single lock.
pub struct Node {
    inner: Mutex<Inner>,
}

struct Inner {
    store: MemoryStore,
    key: SigningKey,
    pubkey: PubKey,
    hlc: Hlc,
    /// A monotonically increasing counter fed to [`Hlc::tick`] in place of a
    /// wall clock. The HLC is a merge hint and never evidence
    /// (`spec/01-wire-format.md` §5.1), and a lone node never merges, so its
    /// absolute value carries no meaning — only that it advances. A counter
    /// rather than `SystemTime::now()` also keeps this crate clear of the
    /// workspace clock ban (`clippy.toml`).
    tick: u64,
}

impl Node {
    /// A node with a freshly generated device key.
    ///
    /// # Errors
    ///
    /// If the OS randomness source is unavailable.
    pub fn new() -> anyhow::Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)
            .map_err(|e| anyhow::anyhow!("OS randomness unavailable: {e}"))?;
        Ok(Self::from_seed(seed))
    }

    /// A node whose device key is derived deterministically from `seed`. For
    /// tests that want a reproducible node identity; not exposed on the CLI.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&seed);
        let pubkey = public_key(&key);
        Self {
            inner: Mutex::new(Inner {
                store: MemoryStore::new(),
                key,
                pubkey,
                hlc: Hlc::default(),
                tick: 0,
            }),
        }
    }

    /// This node's public key — the identity a verifier checks a pack against.
    #[must_use]
    pub fn pubkey(&self) -> PubKey {
        self.lock().pubkey
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Capture: append a text observation to this node's own chain and return
    /// its content address and sequence number.
    ///
    /// The next `seq`/`prev` come from the store's view of the chain, the object
    /// is signed with the device key, and [`append`] enforces the
    /// `spec/01-wire-format.md` §6.6 join rule before it is stored. No step here
    /// blocks on anything external — see the module docs.
    ///
    /// # Errors
    ///
    /// [`CaptureError::Empty`] if `text` is blank; [`CaptureError::Ledger`] if
    /// the append is refused or the backend fails (neither happens for a
    /// well-formed single-node chain).
    pub fn capture(&self, text: &str) -> Result<Captured, CaptureError> {
        if text.trim().is_empty() {
            return Err(CaptureError::Empty);
        }
        let mut g = self.lock();

        let (seq, prev) = match g
            .store
            .chain_head(&g.pubkey)
            .map_err(CaptureError::ledger)?
        {
            Some(head) => (head.seq + 1, Some(head.id)),
            None => (0, None),
        };

        g.tick += 1000;
        let now = g.tick;
        g.hlc = g.hlc.tick(now);

        let obs = Observation {
            author: g.pubkey,
            site: SITE,
            prev,
            seq,
            hlc: g.hlc,
            body: ObservationBody::Note {
                text: text.to_owned(),
            },
            geo: None,
            acks: BTreeSet::new(),
        };
        let sig = obs.sign(&g.key);
        let id = append(&mut g.store, &obs, &sig).map_err(CaptureError::ledger)?;
        Ok(Captured { id, seq })
    }

    /// Provenance: everything `vigil-ledger` computes about one held record — its
    /// chain-verification state and its bracket (`docs/VIGILARCH.md` §15,
    /// `spec/02-entanglement.md` §5). Read-only; adds no logic of its own.
    ///
    /// Returns `Ok(None)` if the id is not a record this node holds.
    ///
    /// # Errors
    ///
    /// If the storage backend fails.
    pub fn provenance(&self, id: Hash) -> anyhow::Result<Option<Provenance>> {
        let g = self.lock();
        let Some(so) = g.store.observation(&id)? else {
            return Ok(None);
        };
        let author = so.observation.author;
        let chain = verify_chain(&g.store, &author)?;
        let bracket =
            bracket(&g.store, id)?.expect("a held observation always brackets (spec/02 §5)");
        Ok(Some(Provenance {
            id,
            author,
            seq: so.observation.seq,
            chain,
            bracket,
        }))
    }

    /// Export: assemble the `spec/03-export-pack.md` file for `claims` from
    /// everything this node holds. The node's own key is written as the pack's
    /// `org` label (`spec/03` §2.4); `vigil-verify <pack> <this pubkey>` checks
    /// it.
    ///
    /// This is the only place in the crate that touches `export.rs`.
    ///
    /// # Errors
    ///
    /// [`ExportError::ClaimNotHeld`] if a claimed id is not held;
    /// [`ExportError::Store`] on a backend failure.
    pub fn export(&self, claims: &[Hash]) -> Result<Vec<u8>, ExportError> {
        let g = self.lock();
        export_pack(&g.store, &Quarantine::new(), g.pubkey, claims)
    }

    /// A liveness snapshot: the node's key and how many records it holds on its
    /// own chain.
    #[must_use]
    pub fn health(&self) -> Health {
        let g = self.lock();
        let chain_len = g.store.chain(&g.pubkey).map(|c| c.len()).unwrap_or(0);
        Health {
            pubkey: g.pubkey,
            chain_len,
        }
    }
}

/// The result of a successful [`Node::capture`].
#[derive(Debug, Clone, Copy)]
pub struct Captured {
    pub id: Hash,
    pub seq: Seq,
}

/// Why a [`Node::capture`] did not complete.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    /// The request body was empty or whitespace. v1 captures text; there was
    /// nothing to record.
    #[error("capture body is empty")]
    Empty,
    /// The ledger refused the append or the backend failed. The string is a log
    /// line, not something to branch on.
    #[error("ledger error: {0}")]
    Ledger(String),
}

impl CaptureError {
    fn ledger(e: impl std::fmt::Display) -> Self {
        Self::Ledger(e.to_string())
    }
}

/// The read-only provenance of one record (`docs/VIGILARCH.md` §15).
#[derive(Debug, Clone)]
pub struct Provenance {
    pub id: Hash,
    pub author: PubKey,
    pub seq: Seq,
    pub chain: ChainVerification,
    pub bracket: Bracket,
}

/// A [`Node::health`] snapshot.
#[derive(Debug, Clone, Copy)]
pub struct Health {
    pub pubkey: PubKey,
    pub chain_len: usize,
}

/// Wrap a bare [`Node`] in the [`Arc`] the HTTP layer holds.
#[must_use]
pub fn shared(node: Node) -> Arc<Node> {
    Arc::new(node)
}

// -- serde_json helpers shared with the http module --------------------------

pub(crate) fn window_edge_json(e: &WindowEdge) -> serde_json::Value {
    match e {
        WindowEdge::Attestation(h) => serde_json::json!({ "attestation": h.to_string() }),
        WindowEdge::Genesis => serde_json::json!("genesis"),
        WindowEdge::VerificationMoment => serde_json::json!("verification-moment"),
    }
}

pub(crate) fn chain_json(c: &ChainVerification) -> serde_json::Value {
    match c {
        ChainVerification::Verified => serde_json::json!("verified"),
        ChainVerification::Incomplete { missing } => {
            serde_json::json!({ "incomplete": { "missing": missing } })
        }
        ChainVerification::Violated(violations) => {
            serde_json::json!({ "violated": format!("{violations:?}") })
        }
    }
}
