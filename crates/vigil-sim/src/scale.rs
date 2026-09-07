//! Scale-up: run every scenario across a range of seeds and aggregate, so the
//! README's measured evaluation table is fed by counted runs rather than a
//! hand-wave.
//!
//! The one rule this module exists to enforce: **a failing seed is never lost.**
//! Every `(scenario, seed)` pair is run exactly once, its result recorded, and
//! the per-scenario `pass + fail` is checked to equal the seed count before any
//! summary is produced. A runner that swallows a failure and reports 100% is
//! worse than no runner, so the counting is defended with an assertion, not left
//! to trust.
//!
//! Each scenario here is pure in-memory computation with no I/O and no sleep
//! (invariant I4 — no wall-clock read in the evidence path either). The work per
//! run is a handful of Ed25519 sign/verify operations and one or two small DAG
//! builds, so a run costs low single-digit milliseconds in release and a scale
//! of a few thousand finishes in a few seconds. [`ScaleReport::over_budget`]
//! flags a run that is *much* slower than that — the sign of an algorithmic
//! regression, most often a query path that rebuilds the attestation DAG from
//! scratch instead of reusing one — so it is investigated rather than accepted.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

use crate::{equivocation, sealing_ablation, sim};

/// The scenarios a scale-up run covers, each reduced to "did this seed pass".
///
/// The closure returns the scenario's own pass/fail bool. A panic inside a
/// scenario (an `expect` tripping on some seed) is caught and counted as a
/// failure for that seed — loud, but still attributed to the exact seed rather
/// than aborting the whole run.
type ScenarioFn = fn(u64) -> bool;

/// `(name, runner)` for every scenario, in run order.
#[must_use]
pub fn scenarios() -> Vec<(&'static str, ScenarioFn)> {
    vec![
        ("minimal", (|s| sim::run(s).sealed_ok) as ScenarioFn),
        ("equivocation", |s| equivocation::run(s).passed),
        ("sealing-ablation", |s| sealing_ablation::run(s).passed),
    ]
}

/// One scenario's result over the whole seed range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioOutcome {
    pub name: &'static str,
    /// Seeds that passed.
    pub pass: u64,
    /// Seeds that failed, in ascending order — the full list, so any regression
    /// is reproducible from an exact seed.
    pub failing_seeds: Vec<u64>,
}

impl ScenarioOutcome {
    #[must_use]
    pub fn fail(&self) -> u64 {
        self.failing_seeds.len() as u64
    }

    #[must_use]
    pub fn first_failing_seed(&self) -> Option<u64> {
        self.failing_seeds.first().copied()
    }
}

/// The aggregate of a scale-up run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaleReport {
    /// Seeds covered: `0..seeds`.
    pub seeds: u64,
    pub outcomes: Vec<ScenarioOutcome>,
    /// Wall time the run took. Monotonic ([`Instant`]), never a wall clock, and
    /// never fed back into a scenario — it is a diagnostic, nothing more.
    pub elapsed: Duration,
}

impl ScaleReport {
    /// Total `(scenario, seed)` runs performed.
    #[must_use]
    pub fn total_runs(&self) -> u64 {
        self.seeds * self.outcomes.len() as u64
    }

    /// Runs that passed.
    #[must_use]
    pub fn total_pass(&self) -> u64 {
        self.outcomes.iter().map(|o| o.pass).sum()
    }

    /// Whether every scenario passed every seed.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.outcomes.iter().all(|o| o.failing_seeds.is_empty())
    }

    /// The first failure in run order — scenario order, then ascending seed.
    /// `None` when everything passed.
    #[must_use]
    pub fn first_failure(&self) -> Option<(&'static str, u64)> {
        self.outcomes
            .iter()
            .find_map(|o| o.first_failing_seed().map(|s| (o.name, s)))
    }

    /// Whether the run took much longer than these scenarios should — a signal
    /// of an algorithmic regression rather than normal variance.
    ///
    /// Budget: 10 ms per `(scenario, seed)` run. A run does a few signature
    /// operations and one or two DAG builds over stores holding under a dozen
    /// objects; in release that is ~1–2 ms, and even an unoptimised debug build
    /// stays well under 10 ms. Crossing this line means something is doing work
    /// that does not scale with the (tiny) object count — the case worth a look.
    #[must_use]
    pub fn over_budget(&self) -> bool {
        let budget = Duration::from_millis(self.total_runs().saturating_mul(10).max(10));
        self.elapsed > budget
    }
}

/// Run every scenario once per seed in `0..seeds` and aggregate.
///
/// # Panics
///
/// If the per-scenario `pass + fail` count does not equal `seeds` — that would
/// mean a run was lost, which is the one thing this module must not do.
#[must_use]
pub fn run_scale_up(seeds: u64) -> ScaleReport {
    let start = Instant::now();
    let mut outcomes = Vec::new();

    for (name, run) in scenarios() {
        let mut pass = 0u64;
        let mut failing_seeds = Vec::new();
        for seed in 0..seeds {
            let ok = catch_unwind(AssertUnwindSafe(|| run(seed))).unwrap_or(false);
            if ok {
                pass += 1;
            } else {
                failing_seeds.push(seed);
            }
        }
        assert_eq!(
            pass + failing_seeds.len() as u64,
            seeds,
            "scale-up lost a run for scenario {name}: {pass} pass + {} fail != {seeds} seeds",
            failing_seeds.len()
        );
        outcomes.push(ScenarioOutcome {
            name,
            pass,
            failing_seeds,
        });
    }

    ScaleReport {
        seeds,
        outcomes,
        elapsed: start.elapsed(),
    }
}

/// Render a [`ScaleReport`] as a flat, greppable table.
///
/// Every scenario line carries `pass=` and `fail=` tokens; a failing scenario
/// additionally carries `first_fail=` and a bounded `failing_seeds=` list. The
/// last line is `scale-up: PASS` or `scale-up: FAIL …`, the latter naming the
/// first failing scenario and seed.
#[must_use]
pub fn render(report: &ScaleReport) -> String {
    use std::fmt::Write as _;

    // How many failing seeds to spell out per scenario before truncating.
    const SEED_LIST_CAP: usize = 20;

    let mut s = String::new();
    let _ = writeln!(
        s,
        "scale-up: seeds=0..{} scenarios={}",
        report.seeds,
        report.outcomes.len()
    );

    let width = report
        .outcomes
        .iter()
        .map(|o| o.name.len())
        .max()
        .unwrap_or(0);

    for o in &report.outcomes {
        let _ = write!(s, "{:<width$}  pass={} fail={}", o.name, o.pass, o.fail());
        if let Some(first) = o.first_failing_seed() {
            let shown: Vec<String> = o
                .failing_seeds
                .iter()
                .take(SEED_LIST_CAP)
                .map(u64::to_string)
                .collect();
            let more = o.failing_seeds.len().saturating_sub(SEED_LIST_CAP);
            let _ = write!(s, " first_fail={first} failing_seeds={}", shown.join(","));
            if more > 0 {
                let _ = write!(s, ",+{more}");
            }
        }
        let _ = writeln!(s);
    }

    let elapsed = report.elapsed.as_secs_f64();
    match report.first_failure() {
        None => {
            let _ = writeln!(
                s,
                "scale-up: PASS {}/{} runs in {elapsed:.3}s",
                report.total_pass(),
                report.total_runs()
            );
        }
        Some((name, seed)) => {
            let _ = writeln!(
                s,
                "scale-up: FAIL first failure scenario={name} seed={seed} — {}/{} runs passed in {elapsed:.3}s",
                report.total_pass(),
                report.total_runs()
            );
        }
    }

    if report.over_budget() {
        let _ = writeln!(
            s,
            "scale-up: WARNING {elapsed:.3}s for {} runs is far slower than these scenarios warrant \
             — suspect an algorithmic regression (e.g. a query path rebuilding the attestation DAG \
             from scratch), not machine variance",
            report.total_runs()
        );
    }

    s
}
