//! [`DriftMonitor`] — serving-time feature distribution against the training
//! snapshot (§20.5, Sprint 18 t5).
//!
//! §20.5 asks for "serving-time feature distributions monitored against the
//! training snapshot ... drift past threshold raises an alert ... visible
//! before precision decays, not after". This module is the measurement half of
//! that: a pure, windowed accumulator over the vectors a model is actually
//! served, scored against the [`FeatureBaseline`] that model was exported
//! with. The alerting half (metrics, thresholds, the log line an operator
//! reads) is the `inference` crate's `DriftEngine`, which owns the
//! synchronisation and the single metrics call site.
//!
//! It lives here, next to [`FeatureBaseline`], for the reason the baseline
//! itself does: the serving-side explainer and this monitor key off the *same*
//! numbers, and two owners of "what normal was for feature version *N*" would
//! drift apart in exactly the situation both exist to detect.
//!
//! # What is measured, and why it is not a PSI
//!
//! The textbook drift statistic is a population-stability index: bin the
//! training distribution, bin the serving distribution, sum
//! `(p - q)·ln(p/q)`. That needs the training distribution's *shape* — a
//! histogram. A [`FeatureBaseline`] carries robust summary statistics (median
//! centre, MAD spread) and deliberately not a histogram, because the export
//! must stay small, comparable across versions, and hashable into a
//! deployment's identity. Binning against an *assumed* shape would be worse
//! than useless here: §20.1 features are heavy-tailed by construction, so a
//! normality assumption would report drift on the quietest possible day.
//!
//! So the statistic is the robust two-sample analogue of what the baseline can
//! actually support. Each observed vector is turned into the same clamped
//! z-scores [`FeatureBaseline::deviations`] already produces — the serving
//! window expressed in training-spread units — and each feature's window is
//! summarised by the same pair of robust statistics the baseline itself uses:
//!
//! - [`shift`](FeatureDrift::shift) — the **median** deviation. `0` means the
//!   serving window sits exactly where training did; `±2` means it has moved
//!   two training spreads.
//! - [`spread`](FeatureDrift::spread) — the window's own σ-scaled **MAD**, in
//!   training-spread units. `1` means it varies exactly as much as training
//!   did; `0.1` means it has collapsed; `5` means it has fanned out.
//!
//! [`magnitude`](FeatureDrift::magnitude) folds the pair into the one number a
//! threshold is set on: `max(|shift|, |ln spread|)`. Both terms are already in
//! log/σ units, so the maximum is a comparable "how many units has this
//! feature moved, in its worst respect" — and taking the max rather than a sum
//! keeps a feature that moved *one* way from being reported as twice as
//! drifted as it is.
//!
//! # Windows are tumbling, not sliding
//!
//! [`observe`](DriftMonitor::observe) accumulates until the window is full,
//! yields one [`DriftReport`], and starts over. A sliding window would
//! re-report the same drift on every subsequent vector, turning one condition
//! into a continuous stream of identical alerts; a tumbling one makes each
//! report an independent sample of the serving distribution, which is also
//! what makes a rate over the breach counter meaningful.
//!
//! # Degenerate features
//!
//! A feature that never varied in training (`is_contract_creation` in a window
//! with no deployments) has a MAD of zero, which [`MIN_SPREAD`] floors. Its
//! *scale* is then not a measurable quantity — the ratio's denominator is a
//! floor, not an observation — so [`magnitude`](FeatureDrift::magnitude)
//! reports `|shift|` alone for it. That is not a softening: any movement at
//! all in such a feature is already amplified to [`MAX_DEVIATION`] by the
//! z-score, so a degenerate feature that moves is *maximally* drifted, and one
//! that stays put reports exactly zero instead of a spurious `|ln 0|`.

use std::time::{Duration, Instant};

use crate::baseline::{FeatureBaseline, MAD_TO_SIGMA, MAX_DEVIATION, MIN_SPREAD};
use crate::schema::{FeatureDef, FeatureKind, FeatureVersion, Granularity};
use crate::stats::{mad, median};
use crate::vector::FeatureVector;

/// Floor applied to a window's own spread before taking its logarithm.
///
/// Same role as [`MIN_SPREAD`] one level down: a serving window in which a
/// feature never moved has a MAD of exactly zero, and `ln 0` is not a number a
/// gauge can carry. `1e-3` puts a fully collapsed feature at `|ln| ≈ 6.9` —
/// far past any sane threshold, and finite.
pub const MIN_WINDOW_SPREAD: f64 = 1e-3;

/// Smallest window a [`DriftMonitor`] will accept.
///
/// A median and a MAD over a handful of samples are noise, and a drift alert
/// that fires on noise is worse than no alert: it trains an operator to ignore
/// the one that matters. 32 is not a tuned number — it is the point below
/// which the statistics stop meaning anything.
pub const MIN_WINDOW: usize = 32;

/// The default window: how many served vectors one drift reading covers.
///
/// At one block-level vector per block that is roughly an hour of Ethereum;
/// at one vector per transaction it is a couple of blocks. Both are the right
/// order of magnitude for a signal whose job is to be visible *before*
/// precision decays rather than within one block.
pub const DEFAULT_WINDOW: usize = 512;

/// The default age bound: how long a partly-filled window may stay open before
/// it reports anyway (given at least [`MIN_WINDOW`] samples).
///
/// Chosen for *latency to first signal*, not for statistical comfort. The
/// count bound alone leaves a block-granularity model silent for roughly the
/// first 100 minutes after a deploy — the exact window in which a bad retrain
/// is most likely to be discovered by its damage rather than by its drift.
/// Fifteen minutes puts a reading on the dashboard well inside the alert's own
/// `for:` clause while still being long enough that a quiet chain accumulates
/// a usable sample.
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(900);

/// One feature's serving-time distribution relative to its training window.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FeatureDrift {
    /// Position in the schema — the deterministic tie-break when two features
    /// drift equally, matching [`crate::Deviation::index`].
    pub index: usize,
    /// The feature's name and statistical kind.
    pub def: FeatureDef,
    /// Median deviation across the window, in training-spread units. `0.0`
    /// means the window sits exactly on the training centre.
    pub shift: f64,
    /// The window's own σ-scaled MAD of those deviations, floored at
    /// [`MIN_WINDOW_SPREAD`]. `1.0` means it varies exactly as training did.
    pub spread: f64,
    /// Whether training saw this feature vary at all (spread above
    /// [`MIN_SPREAD`]). `false` means [`spread`](Self::spread) is measured
    /// against a floor rather than an observation, so
    /// [`magnitude`](Self::magnitude) ignores it — see the module docs.
    pub measurable_spread: bool,
}

impl FeatureDrift {
    pub fn name(&self) -> &'static str {
        self.def.name
    }

    pub fn kind(&self) -> FeatureKind {
        self.def.kind
    }

    /// The single number a threshold is set on: `max(|shift|, |ln spread|)`,
    /// or `|shift|` alone for a feature training never saw vary.
    ///
    /// Always finite, and bounded by [`MAX_DEVIATION`] — the z-scores it is
    /// built from are clamped, so a runaway feature saturates rather than
    /// swamping every other number on the dashboard.
    pub fn magnitude(&self) -> f64 {
        let shift = self.shift.abs();
        if !self.measurable_spread {
            return shift;
        }
        shift.max(self.spread.max(MIN_WINDOW_SPREAD).ln().abs())
    }
}

/// One completed window's reading, per feature in schema order.
///
/// Carries the identity of the baseline it was measured against so a report
/// can be attributed to the exact training snapshot that defined "normal" —
/// the same reason `AnomalyDetail` carries `baseline_hash` (§20.2: re-deriving
/// a baseline changes what an explanation means).
#[derive(Debug, Clone, PartialEq)]
pub struct DriftReport {
    /// The feature schema the observed vectors were extracted under.
    pub feature_version: FeatureVersion,
    pub granularity: Granularity,
    /// The measured-against baseline's [`FeatureBaseline::content_hash`].
    pub baseline_hash: String,
    /// How many vectors this reading covers. Equal to the configured window
    /// for a [`WindowClose::Full`] reading, and somewhere between
    /// [`MIN_WINDOW`] and it for a [`WindowClose::Aged`] one.
    pub samples: usize,
    /// Why this window closed — worth carrying because it changes how much a
    /// reading is worth: a full window is the configured sample size, an aged
    /// one is "the most we had within the latency bound".
    pub closed_by: WindowClose,
    /// Per-feature readings, in schema order.
    pub features: Vec<FeatureDrift>,
}

/// Why a window closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowClose {
    /// It reached the configured vector count.
    Full,
    /// It hit [`DriftMonitor::max_age`] with at least [`MIN_WINDOW`] samples.
    ///
    /// The reason this exists at all: at one block-level vector per block, a
    /// 512-vector window is roughly 100 minutes of Ethereum — so a purely
    /// count-bounded monitor is blind for the first hour and a half after every
    /// deploy, which is precisely when new weights are most likely to be wrong
    /// (§20.5 wants drift visible *before* precision decays).
    Aged,
}

impl WindowClose {
    /// Low-cardinality label/wire form.
    pub fn as_str(self) -> &'static str {
        match self {
            WindowClose::Full => "full",
            WindowClose::Aged => "aged",
        }
    }
}

impl DriftReport {
    /// The most-drifted feature, magnitude-desc with schema index as the
    /// tie-break (so two equally drifted features always report in the same
    /// order — the determinism rule the explainer follows too). `None` only
    /// for an empty schema.
    pub fn worst(&self) -> Option<&FeatureDrift> {
        self.features.iter().max_by(|a, b| {
            a.magnitude()
                .total_cmp(&b.magnitude())
                // Reversed: on a tie the *lower* schema index wins, and
                // `max_by` keeps the last maximum it sees.
                .then(b.index.cmp(&a.index))
        })
    }

    /// The worst feature's magnitude — the model-level drift gauge. `0.0` for
    /// an empty schema.
    pub fn max_magnitude(&self) -> f64 {
        self.worst().map_or(0.0, FeatureDrift::magnitude)
    }

    /// Every feature at or past `threshold`, worst first — what an alert
    /// enumerates. Ties break by schema index, as [`worst`](Self::worst) does.
    pub fn breaches(&self, threshold: f64) -> Vec<&FeatureDrift> {
        let mut over: Vec<&FeatureDrift> = self
            .features
            .iter()
            .filter(|f| f.magnitude() >= threshold)
            .collect();
        over.sort_by(|a, b| {
            b.magnitude()
                .total_cmp(&a.magnitude())
                .then(a.index.cmp(&b.index))
        });
        over
    }
}

/// Accumulates served feature vectors and reports one [`DriftReport`] per
/// completed window.
///
/// Not `Sync` and not internally synchronised on purpose: it is a plain
/// `&mut self` accumulator so the arithmetic is testable without a lock, and
/// the *one* consumer that needs it across threads (`inference::DriftEngine`)
/// owns that decision explicitly rather than paying for it everywhere.
#[derive(Debug)]
pub struct DriftMonitor {
    baseline: FeatureBaseline,
    window: usize,
    max_age: Duration,
    /// `columns[i]` holds this window's deviations for feature `i`. Preallocated
    /// to `window` at construction so a steady-state window allocates nothing.
    columns: Vec<Vec<f64>>,
    /// Vectors observed so far in the current window.
    filled: usize,
    /// When the current window took its first vector. `None` between windows.
    opened_at: Option<Instant>,
    /// Vectors this monitor refused because they were not shaped like the
    /// baseline's schema — a serving/training skew (§20.5), reported as its
    /// own counter rather than folded into the statistics.
    rejected: u64,
    /// Windows completed since construction.
    windows: u64,
    /// Scratch buffer reused by every summarise, so a completed window does
    /// not allocate per feature.
    scratch: Vec<f64>,
    /// Scratch buffer for one observed vector's deviations, so the per-vector
    /// path allocates nothing (see [`FeatureBaseline::fill_deviations`]).
    incoming: Vec<f64>,
}

impl DriftMonitor {
    /// Bind a monitor to the baseline a model was exported with.
    ///
    /// `window` is clamped up to [`MIN_WINDOW`] rather than rejected: a
    /// too-small window is a configuration mistake whose only sound response
    /// is to measure over enough samples anyway, and refusing to boot over it
    /// would take a *serving* path down for a *monitoring* misconfiguration.
    pub fn new(baseline: FeatureBaseline, window: usize, max_age: Duration) -> Self {
        let window = window.max(MIN_WINDOW);
        let features = baseline.stats().len();
        Self {
            baseline,
            window,
            max_age,
            columns: vec![Vec::with_capacity(window); features],
            filled: 0,
            opened_at: None,
            rejected: 0,
            windows: 0,
            scratch: Vec::with_capacity(window),
            incoming: Vec::with_capacity(features),
        }
    }

    /// The age at which a partly-filled window closes early, provided it has
    /// at least [`MIN_WINDOW`] samples.
    pub fn max_age(&self) -> Duration {
        self.max_age
    }

    /// Discard the partial window and start over.
    ///
    /// For a caller recovering from a panic mid-`observe` (a poisoned lock):
    /// the columns may hold a half-written vector, and half a vector is not a
    /// sample. Counters (`windows`, `rejected`) are cumulative facts about the
    /// process and survive.
    pub fn reset(&mut self) {
        for column in &mut self.columns {
            column.clear();
        }
        self.filled = 0;
        self.opened_at = None;
    }

    /// The baseline this monitor measures against.
    pub fn baseline(&self) -> &FeatureBaseline {
        &self.baseline
    }

    /// How many vectors one reading covers.
    pub fn window(&self) -> usize {
        self.window
    }

    /// Vectors accumulated into the current, incomplete window.
    pub fn pending(&self) -> usize {
        self.filled
    }

    /// Vectors refused for not matching the baseline's schema (serving/training
    /// skew, §20.5) since construction.
    pub fn rejected(&self) -> u64 {
        self.rejected
    }

    /// Windows completed since construction.
    pub fn windows(&self) -> u64 {
        self.windows
    }

    /// Fold one served vector in; `Some` exactly on the vector that completes
    /// a window, which also resets the accumulator for the next one.
    ///
    /// A vector the baseline does not accept is counted as
    /// [`rejected`](Self::rejected) and otherwise ignored: mixing a foreign
    /// schema's values into the columns would corrupt every subsequent
    /// reading, and the skew itself is the more urgent signal anyway.
    pub fn observe_at(&mut self, features: &FeatureVector, now: Instant) -> Option<DriftReport> {
        if !self.baseline.fill_deviations(features, &mut self.incoming) {
            self.rejected += 1;
            return None;
        }

        if self.filled == 0 {
            self.opened_at = Some(now);
        }
        for (column, &deviation) in self.columns.iter_mut().zip(&self.incoming) {
            column.push(deviation);
        }
        self.filled += 1;

        self.close_reason(now)
            .map(|closed_by| self.close_window(closed_by))
    }

    /// [`observe_at`](Self::observe_at) with no clock: the window can then only
    /// close by count.
    ///
    /// For a caller with no meaningful "now" — a replay, a backtest, a unit
    /// test. A serving path should pass the clock, or a low-traffic model
    /// publishes nothing for hours after a deploy (§20.5's whole point is
    /// being visible *early*).
    pub fn observe(&mut self, features: &FeatureVector) -> Option<DriftReport> {
        // `Instant::now()` is not called here: with `opened_at` set to the
        // same instant every vector, the age bound can never trip, which is
        // exactly the count-only behaviour this method promises.
        let now = self.opened_at.unwrap_or_else(Instant::now);
        self.observe_at(features, now)
    }

    /// [`observe_at`](Self::observe_at) over a batch, returning every report
    /// the batch completed — more than one when the batch is larger than the
    /// window (a big block through a per-transaction model).
    ///
    /// One clock read for the whole batch: a block's vectors are observed
    /// together, and reading the clock per vector would cost more than the
    /// arithmetic it is timing.
    pub fn observe_all_at(&mut self, features: &[FeatureVector], now: Instant) -> Vec<DriftReport> {
        features
            .iter()
            .filter_map(|vector| self.observe_at(vector, now))
            .collect()
    }

    /// [`observe_all_at`](Self::observe_all_at) with no clock — see
    /// [`observe`](Self::observe).
    pub fn observe_all(&mut self, features: &[FeatureVector]) -> Vec<DriftReport> {
        features
            .iter()
            .filter_map(|vector| self.observe(vector))
            .collect()
    }

    /// Whether the current window should close, and why.
    ///
    /// The age bound is gated on [`MIN_WINDOW`] and not on `window`: closing
    /// early is about *latency to first signal*, never about publishing
    /// statistics over too few samples. A model quiet enough that it cannot
    /// reach `MIN_WINDOW` within `max_age` keeps accumulating until it can —
    /// which is the honest answer, and is visible as a flat
    /// `model_drift_windows_total`.
    fn close_reason(&self, now: Instant) -> Option<WindowClose> {
        if self.filled >= self.window {
            return Some(WindowClose::Full);
        }
        let aged = self.filled >= MIN_WINDOW
            && self
                .opened_at
                .is_some_and(|opened| now.duration_since(opened) >= self.max_age);
        aged.then_some(WindowClose::Aged)
    }

    /// Summarise the filled columns and start the next window.
    fn close_window(&mut self, closed_by: WindowClose) -> DriftReport {
        let samples = self.filled;
        let defs = self.baseline.schema().defs();
        let stats = self.baseline.stats();

        let mut drifted = Vec::with_capacity(self.columns.len());
        for (index, column) in self.columns.iter_mut().enumerate() {
            self.scratch.clear();
            self.scratch.extend_from_slice(column);
            let shift = median(&mut self.scratch);
            let spread = mad(&mut self.scratch, shift) * MAD_TO_SIGMA;
            column.clear();

            drifted.push(FeatureDrift {
                index,
                def: defs[index],
                // Clamped for the same reason the z-scores are: the median of
                // clamped values is already bounded, but stating the bound
                // here keeps `magnitude`'s range a property of this type
                // rather than of its inputs.
                shift: shift.clamp(-MAX_DEVIATION, MAX_DEVIATION),
                spread: spread.max(MIN_WINDOW_SPREAD),
                measurable_spread: stats[index].spread > MIN_SPREAD,
            });
        }

        self.filled = 0;
        self.opened_at = None;
        self.windows += 1;

        DriftReport {
            feature_version: self.baseline.feature_version(),
            granularity: self.baseline.granularity(),
            baseline_hash: self.baseline.content_hash(),
            samples,
            closed_by,
            features: drifted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use detector_api::test_util::{addr, b256, swap, CtxBuilder};

    /// The nine [`training`] samples, four times each.
    ///
    /// A multiple of the sample count, not [`MIN_WINDOW`]: a window that cuts
    /// mid-cycle carries a *different* distribution from the one the baseline
    /// was derived from, and the assertions below are about the two agreeing
    /// exactly. (Discovered the hard way — a 32-vector window over 9 samples
    /// drops the ninth and reads a spurious 0.22 shift.)
    const WINDOW: usize = 36;

    /// An age bound no test can reach, so the count-bounded assertions below
    /// stay about counts. The age bound gets its own tests, which drive the
    /// clock explicitly.
    const NO_AGE_BOUND: Duration = Duration::from_secs(86_400);

    /// Nine blocks whose *shape* varies — a different transaction count,
    /// sender census and swap size each — so most features have a real spread
    /// rather than every one being constant (which would leave the
    /// interesting assertions below vacuous).
    fn training() -> Vec<FeatureVector> {
        (1..=9u8)
            .map(|n| {
                let mut builder = CtxBuilder::new()
                    .priced_token(addr(0xAA), 18, 2000.0)
                    .priced_token(addr(0xBB), 18, 1.0)
                    .pool(addr(0xCC), addr(0xAA), addr(0xBB), 1_000, 1_000);
                for i in 0..n {
                    builder = builder.tx(
                        b256(n * 16 + i),
                        addr(i),
                        vec![swap(
                            addr(0xCC),
                            addr(0xAA),
                            addr(0xBB),
                            u128::from(i + 1) * 1_000_000_000_000_000_000,
                            u128::from(n) * 90,
                        )],
                    );
                }
                crate::extract_block(&builder.build())
            })
            .collect()
    }

    fn baseline() -> FeatureBaseline {
        FeatureBaseline::from_samples(&training()).expect("uniform block vectors")
    }

    /// A whole window drawn from `samples`, each repeated `repeats` times, so
    /// the window reproduces the sample distribution *exactly* rather than
    /// approximately — which is what lets the quiet case assert `0.0` instead
    /// of "small".
    fn window_of(samples: &[FeatureVector], repeats: usize) -> Vec<FeatureVector> {
        samples
            .iter()
            .flat_map(|v| std::iter::repeat_n(v.clone(), repeats))
            .collect()
    }

    /// Every sample with feature `index` moved by `by` (in raw feature units),
    /// leaving the rest of the distribution untouched — a pure location shift.
    fn shifted(samples: &[FeatureVector], index: usize, by: f64) -> Vec<FeatureVector> {
        samples
            .iter()
            .map(|v| {
                let mut values = v.values().to_vec();
                values[index] += by;
                vector_like(v, values)
            })
            .collect()
    }

    /// Rebuild a vector with the same stamp and different values.
    ///
    /// Round-tripped through serde because `FeatureVector`'s constructor is
    /// crate-private to the version modules — a drift test needs to state
    /// exact values, and this is the narrowest way to do it without widening
    /// that constructor's visibility for a test's convenience.
    fn vector_like(model: &FeatureVector, values: Vec<f64>) -> FeatureVector {
        let json = serde_json::json!({
            "feature_version": model.feature_version(),
            "granularity": model.granularity(),
            "values": values,
        });
        serde_json::from_value(json).expect("a well-formed vector")
    }

    /// The first feature training saw vary, and the first it never did — the
    /// two cases `magnitude` treats differently.
    fn measurable(baseline: &FeatureBaseline) -> usize {
        baseline
            .stats()
            .iter()
            .position(|s| s.spread > MIN_SPREAD)
            .expect("at least one feature varied across the sample blocks")
    }

    fn degenerate(baseline: &FeatureBaseline) -> usize {
        baseline
            .stats()
            .iter()
            .position(|s| s.spread <= MIN_SPREAD)
            .expect("at least one feature is constant across the sample blocks")
    }

    #[test]
    fn no_report_until_the_window_fills() {
        let samples = training();
        let mut monitor = DriftMonitor::new(baseline(), WINDOW, NO_AGE_BOUND);

        for i in 1..WINDOW {
            assert!(
                monitor.observe(&samples[i % samples.len()]).is_none(),
                "vector {i}"
            );
            assert_eq!(monitor.pending(), i);
        }
        let report = monitor.observe(&samples[0]).expect("the window closes");
        assert_eq!(report.samples, WINDOW);
        assert_eq!(monitor.pending(), 0, "the next window starts empty");
        assert_eq!(monitor.windows(), 1);
    }

    #[test]
    fn serving_the_training_distribution_back_reports_no_drift_at_all() {
        // The property the whole alert rests on. Replaying the exact
        // distribution the baseline was derived from must read *zero*, not
        // "small": the deviations then have median 0 and a σ-scaled MAD of 1
        // by construction, so both terms of `magnitude` vanish. Anything else
        // would mean the statistic disagrees with the baseline that defines it.
        let samples = training();
        let mut monitor = DriftMonitor::new(baseline(), WINDOW, NO_AGE_BOUND);

        let report = monitor
            .observe_all(&window_of(&samples, 4))
            .pop()
            .expect("four copies of nine samples close one window");

        assert!(
            report.max_magnitude() < 1e-9,
            "quiet traffic must not drift: {:#?}",
            report.worst()
        );
        assert!(report.breaches(0.5).is_empty());
    }

    #[test]
    fn a_shifted_feature_reports_its_shift_in_training_spreads() {
        let samples = training();
        let base = baseline();
        let target = measurable(&base);
        let moved = shifted(&samples, target, 2.0 * base.stats()[target].spread);

        let mut monitor = DriftMonitor::new(base, WINDOW, NO_AGE_BOUND);
        let report = monitor
            .observe_all(&window_of(&moved, 4))
            .pop()
            .expect("one completed window");

        let worst = report.worst().expect("a non-empty schema");
        assert_eq!(worst.index, target);
        assert!(
            (worst.shift - 2.0).abs() < 1e-9,
            "expected a 2-spread shift, got {}",
            worst.shift
        );
        assert!(
            (worst.magnitude() - 2.0).abs() < 1e-9,
            "a pure location shift must not also report a scale change"
        );
        assert_eq!(report.breaches(1.5).len(), 1, "only the moved feature");
    }

    #[test]
    fn a_collapsed_feature_reports_the_lost_variance_as_drift() {
        // A feature that varied in training and is now pinned is a real
        // distribution change — upstream data went missing, or a source
        // started reporting a constant. It must be visible even though its
        // *location* never moved.
        let samples = training();
        let base = baseline();
        let target = measurable(&base);
        let centre = base.stats()[target].center;
        let pinned: Vec<FeatureVector> = samples
            .iter()
            .map(|v| {
                let mut values = v.values().to_vec();
                values[target] = centre;
                vector_like(v, values)
            })
            .collect();

        let mut monitor = DriftMonitor::new(base, WINDOW, NO_AGE_BOUND);
        let report = monitor
            .observe_all(&window_of(&pinned, 4))
            .pop()
            .expect("one completed window");

        let drift = report.features[target];
        assert_eq!(drift.shift, 0.0, "it sits exactly on the training centre");
        assert_eq!(drift.spread, MIN_WINDOW_SPREAD, "floored, not zero");
        assert!(
            (drift.magnitude() - MIN_WINDOW_SPREAD.ln().abs()).abs() < 1e-9,
            "the collapse alone carries the magnitude: {drift:?}"
        );
    }

    #[test]
    fn a_feature_constant_in_training_reports_shift_only_never_a_collapsed_spread() {
        // The false-alarm trap this guards: an indicator that was 0 throughout
        // training and is still 0 has zero window spread. Reading `ln 0` there
        // would page on the quietest possible traffic.
        let samples = training();
        let base = baseline();
        let target = degenerate(&base);

        let mut monitor = DriftMonitor::new(base, WINDOW, NO_AGE_BOUND);
        let report = monitor
            .observe_all(&window_of(&samples, 4))
            .pop()
            .expect("one completed window");

        let drift = report.features[target];
        assert!(!drift.measurable_spread);
        assert_eq!(drift.spread, MIN_WINDOW_SPREAD, "floored — and ignored");
        assert_eq!(drift.magnitude(), 0.0);
    }

    #[test]
    fn a_constant_in_training_feature_that_moves_is_maximally_drifted() {
        let samples = training();
        let base = baseline();
        let target = degenerate(&base);
        let moved = shifted(&samples, target, 1.0);

        let mut monitor = DriftMonitor::new(base, WINDOW, NO_AGE_BOUND);
        let report = monitor
            .observe_all(&window_of(&moved, 4))
            .pop()
            .expect("one completed window");

        assert_eq!(report.features[target].magnitude(), MAX_DEVIATION);
        assert_eq!(report.max_magnitude(), MAX_DEVIATION);
    }

    #[test]
    fn a_foreign_vector_is_rejected_not_folded_into_the_statistics() {
        // Serving/training skew (§20.5): the wrong granularity must not
        // silently corrupt every subsequent reading.
        let ctx = CtxBuilder::new().tx(b256(1), addr(1), vec![]).build();
        let tx_vector = crate::extract_all_txs(&ctx)
            .pop()
            .expect("one transaction")
            .1;

        let mut monitor = DriftMonitor::new(baseline(), WINDOW, NO_AGE_BOUND);
        assert!(monitor.observe(&tx_vector).is_none());
        assert_eq!(monitor.rejected(), 1);
        assert_eq!(monitor.pending(), 0, "nothing entered the window");
    }

    #[test]
    fn a_batch_larger_than_the_window_completes_more_than_one() {
        let samples = training();
        let mut monitor = DriftMonitor::new(baseline(), WINDOW, NO_AGE_BOUND);
        let batch = window_of(&samples, 9); // 81 vectors = two 36-windows + 9

        let reports = monitor.observe_all(&batch);
        assert_eq!(reports.len(), 2);
        assert_eq!(monitor.pending(), 9, "the remainder starts the next window");
    }

    #[test]
    fn an_aged_window_reports_early_rather_than_staying_blind() {
        // The cold-start property: a block-granularity model takes ~100 minutes
        // to fill a 512-vector window, and a bad retrain should not get that
        // long unwatched. With the clock driven past `max_age`, a window that
        // has cleared MIN_WINDOW closes on its own.
        let samples = training();
        let mut monitor = DriftMonitor::new(baseline(), 4096, Duration::from_secs(900));
        let start = Instant::now();

        // MIN_WINDOW vectors, all "instantly" — far short of 4096.
        for i in 0..MIN_WINDOW {
            assert!(monitor
                .observe_at(&samples[i % samples.len()], start)
                .is_none());
        }

        let report = monitor
            .observe_at(&samples[0], start + Duration::from_secs(901))
            .expect("past max_age with enough samples, the window closes");
        assert_eq!(report.closed_by, WindowClose::Aged);
        assert_eq!(report.samples, MIN_WINDOW + 1);
        assert_eq!(monitor.pending(), 0, "the next window starts clean");
    }

    #[test]
    fn an_aged_window_still_refuses_to_report_over_too_few_samples() {
        // Latency to first signal must not become "publish statistics over
        // three vectors". A model quiet enough to miss MIN_WINDOW inside
        // max_age keeps accumulating, and its silence is visible as a flat
        // `model_drift_windows_total`.
        let samples = training();
        let mut monitor = DriftMonitor::new(baseline(), 4096, Duration::from_secs(900));
        let start = Instant::now();

        for i in 0..MIN_WINDOW - 1 {
            assert!(
                monitor
                    .observe_at(
                        &samples[i % samples.len()],
                        start + Duration::from_secs(3600)
                    )
                    .is_none(),
                "vector {i} is an hour past max_age and still not enough"
            );
        }
        assert_eq!(monitor.pending(), MIN_WINDOW - 1);
        assert_eq!(monitor.windows(), 0);
    }

    #[test]
    fn the_age_clock_starts_at_the_windows_first_vector_not_at_construction() {
        // Otherwise a monitor built at boot and first fed hours later would
        // close its very first window on one vector.
        let samples = training();
        let mut monitor = DriftMonitor::new(baseline(), 4096, Duration::from_secs(900));
        let boot = Instant::now();
        let first_traffic = boot + Duration::from_secs(7200);

        for i in 0..MIN_WINDOW {
            assert!(
                monitor
                    .observe_at(&samples[i % samples.len()], first_traffic)
                    .is_none(),
                "vector {i}"
            );
        }
        assert_eq!(monitor.windows(), 0, "two idle hours are not window age");
    }

    #[test]
    fn a_clockless_observe_can_only_close_by_count() {
        // `observe` is for replay/backtest, where "now" means nothing. It must
        // never close a window early on wall-clock time that has no bearing on
        // the data being replayed.
        let samples = training();
        let mut monitor = DriftMonitor::new(baseline(), WINDOW, Duration::from_nanos(1));

        for i in 0..WINDOW - 1 {
            assert!(
                monitor.observe(&samples[i % samples.len()]).is_none(),
                "vector {i}"
            );
        }
        let report = monitor.observe(&samples[0]).expect("closes on the count");
        assert_eq!(report.closed_by, WindowClose::Full);
    }

    #[test]
    fn reset_discards_the_partial_window_but_keeps_the_cumulative_counters() {
        // What a caller does after recovering from a poisoned lock: half a
        // written vector is not a sample, but "how many windows has this
        // process published" is still true.
        let samples = training();
        let mut monitor = DriftMonitor::new(baseline(), WINDOW, NO_AGE_BOUND);
        monitor.observe_all(&window_of(&samples, 4));
        assert_eq!(monitor.windows(), 1);

        monitor.observe(&samples[0]);
        assert_eq!(monitor.pending(), 1);
        monitor.reset();

        assert_eq!(monitor.pending(), 0);
        assert_eq!(monitor.windows(), 1, "cumulative facts survive a reset");
    }

    #[test]
    fn a_window_below_the_floor_is_raised_not_honoured() {
        let monitor = DriftMonitor::new(baseline(), 1, NO_AGE_BOUND);
        assert_eq!(monitor.window(), MIN_WINDOW);
    }

    #[test]
    fn breaches_and_worst_break_ties_by_schema_index() {
        // Determinism: two features that moved identically must always be
        // reported in the same order, or a dashboard reshuffles per scrape.
        let samples = training();
        let base = baseline();
        let movable: Vec<usize> = base
            .stats()
            .iter()
            .enumerate()
            .filter(|(_, s)| s.spread > MIN_SPREAD)
            .map(|(i, _)| i)
            .take(2)
            .collect();
        assert_eq!(movable.len(), 2, "need two features that varied");

        let mut moved = samples;
        for &i in &movable {
            moved = shifted(&moved, i, 3.0 * base.stats()[i].spread);
        }

        let mut monitor = DriftMonitor::new(base, WINDOW, NO_AGE_BOUND);
        let report = monitor
            .observe_all(&window_of(&moved, 4))
            .pop()
            .expect("one completed window");

        let breaches = report.breaches(2.5);
        assert_eq!(breaches.len(), 2, "{breaches:#?}");
        assert_eq!(breaches[0].index, movable[0], "lower index first on a tie");
        assert_eq!(report.worst().unwrap().index, movable[0]);
    }

    #[test]
    fn the_report_names_the_baseline_it_was_measured_against() {
        let samples = training();
        let base = baseline();
        let mut monitor = DriftMonitor::new(base.clone(), WINDOW, NO_AGE_BOUND);
        let report = monitor
            .observe_all(&window_of(&samples, 4))
            .pop()
            .expect("one completed window");

        assert_eq!(report.baseline_hash, base.content_hash());
        assert_eq!(report.feature_version, base.feature_version());
        assert_eq!(report.granularity, base.granularity());
    }
}
