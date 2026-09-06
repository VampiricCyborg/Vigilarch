//! `vigil-sim` as a library: the deterministic scenario and its PRNG, exposed so
//! integration tests can assert on a run without going through the binary.
//!
//! See [`sim::run`] and the crate-level docs in `main.rs`.

#![forbid(unsafe_code)]

pub mod rng;
pub mod sim;
