//! # vigil-wasm
//!
//! wasm-bindgen wrapper exposing L0–L3 to the field PWA.
//!
//! Milestone: **M4**. See `docs/VIGILARCH.md` §12.
//!
//! This crate is a *binding surface only*. It must contain no ledger or sync
//! logic of its own. Architectural invariant #2: the phone, the edge box, the
//! mule and the hub run byte-identical L0–L3 code. A second implementation of
//! consensus-adjacent protocol logic guarantees divergence bugs that appear
//! only under partition and only in the field. Do not write a JavaScript
//! ledger, and do not let one grow here by accident.

#![forbid(unsafe_code)]
