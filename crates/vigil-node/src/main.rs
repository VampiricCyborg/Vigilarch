//! # vigil-node
//!
//! The node binary. One executable, several roles: `--role edge|hub|mule`.
//! Exposes the loopback HTTP API that the field PWA and the ops console consume
//! (`docs/VIGILARCH.md` §15).
//!
//! **Architectural invariant #1: no node is the source of truth.** The hub is a
//! well-connected peer with lots of storage and nothing else. It holds no
//! authority the edge nodes lack, and its Postgres is a materialized view only.
//! If this invariant is ever violated for expedience, the project's entire
//! thesis collapses. Guard it in code review.

fn main() {
    println!("vigil-node: scaffold only — see docs/VIGILARCH.md §14 for the roadmap");
}
