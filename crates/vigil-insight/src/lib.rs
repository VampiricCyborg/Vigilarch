//! # vigil-insight — L5
//!
//! Coverage math, silence detection, signature extraction, and the federated
//! sketch index.
//!
//! See `docs/VIGILARCH.md` §10 and §11 — but read `claude.md` first, which
//! corrects two defects in that section and wins where they disagree.
//!
//! ## Coverage weighting — do not implement §10.1 as written
//!
//! The design document weights each node by its *own historical event rate*.
//! That is gameable and inverts the pillar this crate exists to serve: a node
//! that suppresses reports lowers its own weight, which makes its absence cheap,
//! which means a withholder mechanically *inflates* coverage. Expected rate must
//! instead be derived from crew size, shift pattern and work phase — inputs the
//! node cannot quietly deflate by reporting less.
//!
//! ## Two absolutes
//!
//! Not targets to tune toward. Any nonzero result is a top-severity defect,
//! because each is a claim the project rests on.
//!
//! - **Coverage is never overstated.** Computed coverage must be less than or
//!   equal to true coverage, one-sidedly, and every simulator run asserts it.
//!   No API here returns a bare aggregate; everything is wrapped in
//!   `Covered<T>`, carrying the coverage fraction, who contributed, and who is
//!   dark and for how long.
//! - **Zero bytes of raw incident content cross a site boundary.** Only
//!   sketches, counters and k-anonymised signature statistics federate. The
//!   motivation is legal and industrial-relations survivability, not bandwidth.
//!
//! ## Silence detection
//!
//! The inversion this crate exists to correct: on every dashboard in this
//! industry, a site that goes quiet looks like a safe site, because no incumbent
//! can tell "nobody reported" from "nobody connected". Vigilarch can, because
//! partition is modelled. Zero reports with a live heartbeat is the dangerous
//! quadrant and it raises an alert (§10.3).
//!
//! ## Federated output is reported honestly or not at all
//!
//! The design document's demo line — "median lead time 19 days" from two
//! observations — violates the honesty pillar it is meant to showcase. Report
//! counts only ("seen at 6 sites, escalated at 2"), and put federated outputs
//! behind `Covered<T>` like everything else. The credible part of that demo is
//! the wire capture showing zero content crossed, not the statistic.

#![forbid(unsafe_code)]
