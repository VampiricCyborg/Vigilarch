//! # vigil-sim
//!
//! A seeded, fully reproducible discrete-event simulator that runs N virtual
//! nodes on the *real* ledger and sync code over a scriptable virtual network.
//!
//! Milestone: built **alongside M1**, not after. See `docs/VIGILARCH.md` §16.1.
//!
//! Conventional testing will not find the bugs in this system. The failures
//! live in partition topology, message reordering and clock adversariality —
//! regions unit tests do not reach and manual QA cannot reproduce.
//!
//! Scriptable: partition topology over time, per-link bandwidth/latency/loss and
//! MTU including a LoRa profile, clock skew and adversarial rollback, mule
//! movement schedules, node loss and re-provisioning, and adversarial node
//! behaviour — backdating, equivocation, withholding, replay.
//!
//! Every run asserts the system invariants: convergence, order preservation,
//! tamper detection attributed to the correct key, coverage soundness (asserted
//! one-sidedly — overstating knowledge is the cardinal sin), and no panics or
//! unbounded growth.

fn main() {
    println!("vigil-sim: scaffold only — see docs/VIGILARCH.md §16.1 for the design");
}
