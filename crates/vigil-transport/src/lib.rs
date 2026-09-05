//! # vigil-transport — L1
//!
//! One `Link` trait and the transports that sit behind it.
//!
//! Milestone: **M2** — QUIC plus mDNS discovery on a LAN, and sneakernet bundle
//! import/export. That is the whole of the in-scope surface.
//!
//! ## Physical radios are out of scope — model them, do not drive them
//!
//! `claude.md` rules out BLE, LoRa, Wi-Fi Direct and real mule hardware. They
//! are represented instead as **link profiles in `vigil-sim`** — bandwidth,
//! latency, loss and MTU — and the mule is demonstrated as a simulated node.
//! This costs the project nothing it needs: the interesting claim is that a
//! narrow, intermittent link still carries priority classes 0 and 1, and that is
//! provable against a simulated 50 byte/s profile without owning a radio.
//!
//! So: keep the `Link` trait honest enough that a real radio *could* implement
//! it, and resist adding one. If a task seems to require a physical transport,
//! say so and propose the simulated profile instead.
//!
//! ## What every link must carry
//!
//! However narrow the link, classes 0 and 1 always fit — alarms, fork proofs,
//! revocations, attestations, checkpoints and heartbeats, all around 100–150
//! bytes. That is what keeps a barely-connected site inside the ordering graph
//! and inside the coverage model. Knowledge degrades gracefully rather than
//! failing binary: a starved link still conveys *that* something happened,
//! *where*, and *when relative to what*, long before it can convey *what*.

#![forbid(unsafe_code)]
