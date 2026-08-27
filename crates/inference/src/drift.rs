//! [`DriftEngine`] — the §20.5 drift monitor, wired as a second decorator over
//! the serving seam (Sprint 18 t5).
//!
//! `ml_features::DriftMonitor` measures; this wires. It is a decorator for the
//! same reason [`ObservedEngine`](crate::ObservedEngine) is: the vectors a
//! model is *actually served* are visible at exactly one place, and a
//! monitor bolted onto a detector instead would miss any future call path and
//! would have to be re-implemented for the next model.
//!
//! ```text
//! DriftEngine  ─ observes the input vectors, per completed window
//!   └ ObservedEngine ─ latency / throughput / failures / score histogram
//!       └ OrtEngine  ─ the runtime
//! ```
//!
//! **Drift wraps observation, not the other way round.** The
//! `model_inference_duration_seconds` histogram is the number the < 1s
//! fast-path budget (§6, §20.2) is checked against, so it must measure
//! inference and not inference-plus-bookkeeping. Drift's own cost is still
//! paid on the fast path and still measured — it lands inside the detector's
//! `detector_detect_duration_seconds`, which is where a monitor that has grown
//! too expensive should show up.
//!
//! # What one window costs
//!
//! Per served vector: one `FeatureBaseline::deviations` pass (a
//! subtract/divide/clamp per feature) and one push per feature into a
//! preallocated column. Per completed window (512 vectors by default): a
//! median and a MAD per feature, each a sort of the window — microseconds,
//! amortised over hundreds of blocks.
//!
//! `deviations` returns an owned `Vec`, so there is one allocation per
//! observed vector — order a kilobyte, immediately dropped. That is a
//! deliberate trade, not an oversight: the alternative is re-deriving the
//! z-score arithmetic here, which would give the workspace two owners of "how
//! far is this from normal" — the exact divergence this monitor exists to
//! detect. The columns themselves are allocated once at boot and reused.
//!
//! # Why a `Mutex` and not something cleverer
//!
//! [`InferenceEngine`] takes `&self` (it is held as `Arc<dyn …>`), and the
//! accumulator is inherently stateful, so the state needs interior mutability.
//! A `Mutex` is right rather than conservative: detection processes one block
//! at a time and the rayon fan-out gives each *detector* its own task, so a
//! given engine sees one caller at a time in practice — and if that ever stops
//! being true, serialising a few microseconds of bookkeeping is the correct
//! outcome, not a reason to reach for a lock-free structure whose failure mode
//! is a silently wrong statistic.
//!
//! A poisoned lock disables monitoring rather than failing the inference: a
//! panic in the accumulator must not take down the fast path it is watching.

use std::collections::VecDeque;
use std::sync::{Mutex, TryLockError};
use std::time::{Duration, Instant};

use ml_features::{
    DriftMonitor, DriftReport, FeatureBaseline, FeatureVector, DEFAULT_MAX_AGE, DEFAULT_WINDOW,
};
use serde::{Deserialize, Serialize};

use crate::descriptor::ModelDescriptor;
use crate::engine::{InferenceEngine, InferenceError, Score};
use crate::metrics::{record_drift, record_drift_rejected, record_drift_skipped};

/// Default drift magnitude at which a feature is reported as breached.
///
/// In the units `ml_features::FeatureDrift::magnitude` reports: a serving
/// window whose median has moved three training spreads, or whose variance has
/// changed by a factor of `e³ ≈ 20`. Both are far outside ordinary traffic
/// variation and well inside the clamp, so a breach is a statement and not a
/// rounding artefact.
///
/// It is a *default*, not an SLO: §20.5 wants drift visible before precision
/// decays, and where that line sits depends on the model. The gauge is
/// exported unconditionally, so the Prometheus rule can pick a different
/// number without a redeploy — this one only decides when the service itself
/// says something.
pub const DEFAULT_DRIFT_THRESHOLD: f64 = 3.0;

/// How a deployment configures drift monitoring for one model.
///
/// `deny_unknown_fields` and defaults throughout, like every other config in
/// this workspace: a misspelled key is a refused boot, and an omitted section
/// means the shipped behaviour rather than "monitoring silently off".
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriftConfig {
    /// Served vectors per drift reading. Raised to
    /// `ml_features::MIN_WINDOW` if smaller.
    #[serde(default = "default_window")]
    pub window: usize,
    /// Seconds after which a partly-filled window reports anyway, provided it
    /// has at least `ml_features::MIN_WINDOW` samples.
    ///
    /// The count bound alone decides how *good* a reading is; this decides how
    /// *soon* there is one. At one block-level vector per block a 512-vector
    /// window is ~100 minutes, and a model is at its most dangerous in the
    /// hour after its weights change — so the two bounds answer different
    /// questions and a deployment sets both.
    #[serde(default = "default_max_age_seconds")]
    pub max_age_seconds: u64,
    /// Magnitude at or past which a feature is logged and counted as a
    /// breach.
    #[serde(default = "default_threshold")]
    pub threshold: f64,
    /// Turn monitoring off entirely for this model.
    ///
    /// Present because "no drift section" must mean *monitored with the
    /// defaults* — the safe reading — which leaves no way to express the
    /// opposite without saying it out loud. A deployment that disables it is
    /// making a visible choice in the config file, not omitting a line.
    #[serde(default)]
    pub disabled: bool,
}

fn default_window() -> usize {
    DEFAULT_WINDOW
}

fn default_max_age_seconds() -> u64 {
    DEFAULT_MAX_AGE.as_secs()
}

fn default_threshold() -> f64 {
    DEFAULT_DRIFT_THRESHOLD
}

impl Default for DriftConfig {
    fn default() -> Self {
        Self {
            window: DEFAULT_WINDOW,
            max_age_seconds: DEFAULT_MAX_AGE.as_secs(),
            threshold: DEFAULT_DRIFT_THRESHOLD,
            disabled: false,
        }
    }
}

impl DriftConfig {
    fn max_age(&self) -> Duration {
        Duration::from_secs(self.max_age_seconds)
    }
}

/// The read side of a [`DriftEngine`]: completed readings, drained by whatever
/// layer is allowed to publish them.
///
/// Object-safe and free of any event/broker type on purpose. This crate is
/// forbidden `event-bus` by the architecture rules (a serving seam that could
/// publish would be a serving seam with an opinion about topology), so drift
/// leaves through a plain trait and the *composing service* — which already
/// owns an `EventSink`, a retry policy and a DLQ — decides what a reading
/// becomes. Metrics still go out from inside the engine, because a gauge is
/// not a message.
pub trait DriftSource: Send + Sync + std::fmt::Debug {
    /// The model these readings describe.
    fn model_id(&self) -> &str;

    /// The magnitude at which this deployment calls a feature drifted.
    ///
    /// On the trait rather than left to the reader because a reading is only
    /// interpretable against the threshold it was judged by, and that is
    /// per-model config — a consumer that supplied its own would be answering
    /// a different question from the one the alert and the log line answered.
    fn threshold(&self) -> f64;

    /// Take every reading completed since the last call, oldest first.
    fn drain(&self) -> Vec<DriftReport>;
}

/// An [`InferenceEngine`] that folds every vector it is asked to score into a
/// windowed drift reading against the model's training baseline (§20.5).
///
/// Wrap **once**, outside [`ObservedEngine`](crate::ObservedEngine), at the
/// boot site that owns the engine.
#[derive(Debug)]
pub struct DriftEngine<E> {
    inner: E,
    monitor: Mutex<DriftMonitor>,
    /// Completed readings waiting to be drained by the publishing layer.
    /// Separate lock from the accumulator: draining is done by the scheduler
    /// between blocks and must never contend with the observation path.
    pending: Mutex<VecDeque<DriftReport>>,
    threshold: f64,
}

/// How many undrained readings are kept before the oldest is discarded.
///
/// A bound, not a capacity estimate. The publishing layer drains after every
/// block, so in a healthy service this holds at most one; the cap exists for
/// the unhealthy case, where an unbounded queue behind a stalled consumer is
/// how a monitor turns a degradation into an outage. Dropping the *oldest* is
/// deliberate — if only some readings survive, the recent ones describe the
/// distribution the model is serving now.
const MAX_PENDING_REPORTS: usize = 32;

impl<E: InferenceEngine> DriftEngine<E> {
    /// Monitor `inner`'s inputs against `baseline` — the snapshot exported by
    /// the training run that produced `inner`'s artifact.
    ///
    /// The baseline is *not* checked against the engine's descriptor here, and
    /// deliberately so: a mismatch is not a boot-time wiring assertion this
    /// layer can make honestly (a descriptor names a schema, a baseline binds
    /// to one, and either could legitimately be a version behind — §20.5). It
    /// shows up instead as
    /// [`rejected`](ml_features::DriftMonitor::rejected), which is exported as
    /// its own counter precisely so serving/training skew reads as skew rather
    /// than as a plausible-looking statistic.
    pub fn new(inner: E, baseline: FeatureBaseline, config: DriftConfig) -> Self {
        Self {
            inner,
            monitor: Mutex::new(DriftMonitor::new(baseline, config.window, config.max_age())),
            pending: Mutex::new(VecDeque::new()),
            threshold: config.threshold,
        }
    }

    /// The wrapped engine.
    pub fn inner(&self) -> &E {
        &self.inner
    }

    /// The magnitude at which this engine reports a breach.
    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    /// Windows completed since boot — `0` while the first is still filling.
    /// Exposed for tests and for a caller that wants to know whether the
    /// gauges mean anything yet.
    pub fn windows(&self) -> u64 {
        self.monitor
            .try_lock()
            .map_or(0, |monitor| monitor.windows())
    }

    /// Fold `features` in and publish whatever windows they completed.
    ///
    /// **Fails open, loudly.** The accumulator is a watcher, and a watcher must
    /// never be the reason the fast path stops scoring blocks — so a contended
    /// or poisoned lock drops the observation rather than blocking or
    /// panicking. What it does *not* do is drop it silently: every skipped
    /// observation lands on `model_drift_skipped_total` by reason, because a
    /// monitor that quietly stopped monitoring reads exactly like a model with
    /// no drift.
    ///
    /// `try_lock` rather than `lock` even though today's scheduler processes
    /// one block at a time and cannot contend: that is a property of the
    /// current scheduler, not a guarantee of the seam, and the failure mode of
    /// getting it wrong later is a lock on the < 1s path.
    fn observe(&self, features: &[FeatureVector]) {
        let model = self.inner.descriptor().model_id();
        let mut monitor = match self.monitor.try_lock() {
            Ok(monitor) => monitor,
            Err(TryLockError::WouldBlock) => {
                record_drift_skipped(model, "contended", features.len() as u64);
                return;
            }
            // A panic inside `observe_all` can leave the columns holding a
            // half-written vector, and half a vector is not a sample — so the
            // partial window is discarded and accumulation resumes. Recovering
            // beats the alternative (monitoring dead for the process's life
            // after one bad vector), and the counter says it happened.
            Err(TryLockError::Poisoned(poisoned)) => {
                record_drift_skipped(model, "poisoned", features.len() as u64);
                let mut monitor = poisoned.into_inner();
                monitor.reset();
                self.monitor.clear_poison();
                return;
            }
        };

        let before = monitor.rejected();
        let reports = monitor.observe_all_at(features, Instant::now());
        let rejected = monitor.rejected() - before;
        // Drop the lock before touching metrics, tracing or the pending queue:
        // none of them is fast, and none of them needs the accumulator.
        drop(monitor);

        if rejected > 0 {
            record_drift_rejected(model, rejected);
        }
        for report in &reports {
            self.publish(model, report);
        }
        self.enqueue(model, reports);
    }

    /// Hand completed readings to the publishing layer, oldest first, bounded.
    fn enqueue(&self, model: &str, reports: Vec<DriftReport>) {
        if reports.is_empty() {
            return;
        }
        let Ok(mut pending) = self.pending.try_lock() else {
            // Same rule as the accumulator: never block the fast path over
            // bookkeeping, and never lose the fact that a reading was lost.
            record_drift_skipped(model, "undrained", reports.len() as u64);
            return;
        };
        for report in reports {
            if pending.len() == MAX_PENDING_REPORTS {
                pending.pop_front();
                record_drift_skipped(model, "undrained", 1);
            }
            pending.push_back(report);
        }
    }

    /// One completed window: gauges for every feature, and a log line naming
    /// the ones past the threshold.
    fn publish(&self, model: &str, report: &DriftReport) {
        record_drift(model, report, self.threshold);

        let breaches = report.breaches(self.threshold);
        if breaches.is_empty() {
            return;
        }
        // One line for the window, not one per feature: a drifted model
        // usually moves several correlated features at once, and an operator
        // wants "this model drifted, here is the shape of it" rather than a
        // burst that buries the rest of the log.
        let worst = breaches[0];
        tracing::warn!(
            model,
            baseline = %report.baseline_hash,
            window = report.closed_by.as_str(),
            feature_version = %report.feature_version,
            granularity = ?report.granularity,
            samples = report.samples,
            threshold = self.threshold,
            breached = breaches.len(),
            worst_feature = worst.name(),
            worst_magnitude = worst.magnitude(),
            worst_shift = worst.shift,
            worst_spread = worst.spread,
            features = %breaches
                .iter()
                .map(|f| format!("{}={:.2}", f.name(), f.magnitude()))
                .collect::<Vec<_>>()
                .join(" "),
            "serving-time feature distribution has drifted from the training snapshot (§20.5)"
        );
    }
}

impl<E: InferenceEngine> DriftSource for DriftEngine<E> {
    fn model_id(&self) -> &str {
        self.inner.descriptor().model_id()
    }

    fn threshold(&self) -> f64 {
        self.threshold
    }

    fn drain(&self) -> Vec<DriftReport> {
        self.pending
            .try_lock()
            .map(|mut pending| pending.drain(..).collect())
            .unwrap_or_default()
    }
}

impl<E: InferenceEngine> InferenceEngine for DriftEngine<E> {
    fn descriptor(&self) -> &ModelDescriptor {
        self.inner.descriptor()
    }

    fn infer(&self, features: &FeatureVector) -> Result<Score, InferenceError> {
        self.observe(std::slice::from_ref(features));
        self.inner.infer(features)
    }

    fn infer_batch(&self, features: &[FeatureVector]) -> Result<Vec<Score>, InferenceError> {
        self.observe(features);
        self.inner.infer_batch(features)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{block_descriptor, StubEngine};

    use detector_api::test_util::{addr, b256, swap, CtxBuilder};
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::CompositeKey;

    type Series = Vec<(
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    )>;

    fn captured(f: impl FnOnce()) -> Series {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, f);
        snapshotter.snapshot().into_vec()
    }

    fn counter(series: &Series, name: &str) -> Option<u64> {
        series
            .iter()
            .find(|(ck, _, _, _)| ck.key().name() == name)
            .and_then(|(_, _, _, v)| match v {
                DebugValue::Counter(n) => Some(*n),
                _ => None,
            })
    }

    fn gauges(series: &Series, name: &str) -> Vec<f64> {
        series
            .iter()
            .filter(|(ck, _, _, _)| ck.key().name() == name)
            .filter_map(|(_, _, _, v)| match v {
                DebugValue::Gauge(g) => Some(g.into_inner()),
                _ => None,
            })
            .collect()
    }

    /// Nine block vectors of varying shape — the same construction
    /// `ml_features::drift`'s own tests use, so a baseline derived from them
    /// reads exactly zero when they are served back.
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
                ml_features::extract_block(&builder.build())
            })
            .collect()
    }

    fn baseline() -> FeatureBaseline {
        FeatureBaseline::from_samples(&training()).expect("uniform block vectors")
    }

    /// A window that is an exact multiple of the nine samples — see
    /// `ml_features::drift`'s tests for why the cycle has to close.
    const WINDOW: usize = 36;

    fn config() -> DriftConfig {
        DriftConfig {
            window: WINDOW,
            // Effectively no age bound: these tests are about the count path,
            // and a wall-clock trigger would make them flaky under load. The
            // age bound is tested in `ml_features::drift`, where the clock is
            // injected instead of read.
            max_age_seconds: 86_400,
            ..DriftConfig::default()
        }
    }

    fn engine() -> DriftEngine<StubEngine> {
        DriftEngine::new(
            StubEngine::constant(
                block_descriptor("anomaly-iforest"),
                Score::new(0.5).unwrap(),
            ),
            baseline(),
            config(),
        )
    }

    fn full_window(samples: &[FeatureVector]) -> Vec<FeatureVector> {
        samples
            .iter()
            .flat_map(|v| std::iter::repeat_n(v.clone(), WINDOW / samples.len()))
            .collect()
    }

    #[test]
    fn scores_are_passed_through_untouched() {
        // The decorator must be invisible to the caller: same descriptor, same
        // scores, same errors. Anything else and monitoring would be changing
        // what the detector sees.
        let engine = engine();
        let samples = training();

        assert_eq!(engine.descriptor().model_id(), "anomaly-iforest");
        assert_eq!(engine.infer(&samples[0]).unwrap().get(), 0.5);
        let batch = engine.infer_batch(&samples).unwrap();
        assert_eq!(batch.len(), samples.len());
        assert!(batch.iter().all(|s| s.get() == 0.5));
    }

    #[test]
    fn nothing_is_published_until_a_window_closes() {
        let engine = engine();
        let series = captured(|| {
            engine.infer_batch(&training()).unwrap(); // 9 of 36
        });

        assert_eq!(engine.windows(), 0);
        assert_eq!(counter(&series, crate::metrics::DRIFT_WINDOWS_TOTAL), None);
        assert!(gauges(&series, crate::metrics::FEATURE_DRIFT).is_empty());
    }

    #[test]
    fn a_quiet_window_publishes_gauges_and_no_breach() {
        let engine = engine();
        let quiet = full_window(&training());

        let series = captured(|| {
            engine.infer_batch(&quiet).unwrap();
        });

        assert_eq!(engine.windows(), 1);
        assert_eq!(
            counter(&series, crate::metrics::DRIFT_WINDOWS_TOTAL),
            Some(1)
        );
        assert_eq!(
            counter(&series, crate::metrics::DRIFT_BREACHES_TOTAL),
            None,
            "serving the training distribution back is not a breach"
        );
        let per_feature = gauges(&series, crate::metrics::FEATURE_DRIFT);
        assert_eq!(
            per_feature.len(),
            ml_features::block_schema().len(),
            "one gauge per feature, always — an unmoved feature reads 0, it is not absent"
        );
        assert!(per_feature.iter().all(|g| *g < 1e-9), "{per_feature:?}");
        let max = gauges(&series, crate::metrics::DRIFT_MAX);
        assert_eq!(max.len(), 1);
        assert!(max[0] < 1e-9, "the model-level gauge is quiet too: {max:?}");
    }

    #[test]
    fn a_drifted_window_counts_a_breach_per_feature_and_raises_the_max_gauge() {
        let base = baseline();
        let target = base
            .stats()
            .iter()
            .position(|s| s.spread > ml_features::MIN_SPREAD)
            .expect("a feature that varied in training");
        // Move it well past the threshold, leaving its shape alone.
        let drifted: Vec<FeatureVector> = training()
            .iter()
            .map(|v| {
                let mut values = v.values().to_vec();
                values[target] += 5.0 * base.stats()[target].spread;
                let json = serde_json::json!({
                    "feature_version": v.feature_version(),
                    "granularity": v.granularity(),
                    "values": values,
                });
                serde_json::from_value(json).expect("a well-formed vector")
            })
            .collect();

        let engine = engine();
        let series = captured(|| {
            engine.infer_batch(&full_window(&drifted)).unwrap();
        });

        assert_eq!(
            counter(&series, crate::metrics::DRIFT_BREACHES_TOTAL),
            Some(1),
            "exactly the moved feature"
        );
        let max = gauges(&series, crate::metrics::DRIFT_MAX);
        assert_eq!(max.len(), 1);
        assert!((max[0] - 5.0).abs() < 1e-9, "{max:?}");
    }

    #[test]
    fn a_foreign_vector_counts_as_skew_and_never_reaches_the_statistics() {
        // §20.5 serving/training skew: a tx-granularity vector against a
        // block baseline must read as skew, not quietly corrupt the window.
        let ctx = CtxBuilder::new().tx(b256(1), addr(1), vec![]).build();
        let tx_vectors: Vec<FeatureVector> = ml_features::extract_all_txs(&ctx)
            .into_iter()
            .map(|(_, v)| v)
            .collect();

        let engine = engine();
        let series = captured(|| {
            // The stub rejects it too (`accepts` is enforced by the double),
            // which is the point: both layers see the same skew.
            let _ = engine.infer_batch(&tx_vectors);
        });

        assert_eq!(
            counter(&series, crate::metrics::DRIFT_REJECTED_TOTAL),
            Some(tx_vectors.len() as u64)
        );
        assert_eq!(counter(&series, crate::metrics::DRIFT_WINDOWS_TOTAL), None);
    }

    #[test]
    fn windows_keep_closing_across_calls() {
        // The accumulator spans calls — a block-granularity model sees one
        // vector per block, so a window is hundreds of separate `infer` calls
        // and would never close if state were per-call.
        let engine = engine();
        let samples = training();
        for i in 0..WINDOW {
            engine.infer(&samples[i % samples.len()]).unwrap();
        }
        assert_eq!(engine.windows(), 1);
    }

    #[test]
    fn a_completed_window_is_queued_for_the_publishing_layer_and_drains_once() {
        // The durable half of §20.5: the metrics fire *and* the reading is
        // kept for whoever turns it into a `ModelDriftDetected`. A monitor
        // that only moved a gauge would leave nothing to audit after
        // Prometheus retention expires.
        let engine = engine();
        engine.infer_batch(&full_window(&training())).unwrap();

        let drained = engine.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].samples, WINDOW);
        assert!(
            engine.drain().is_empty(),
            "draining is destructive — one reading must never publish twice"
        );
    }

    #[test]
    fn undrained_readings_are_bounded_and_the_loss_is_counted() {
        // A stalled publisher must not turn a monitor into a memory leak. The
        // *oldest* readings go, because the recent ones describe the
        // distribution the model is serving now — and the drop is counted, so
        // "we lost readings" never looks like "there were none".
        let engine = engine();
        let window = full_window(&training());
        let series = captured(|| {
            for _ in 0..super::MAX_PENDING_REPORTS + 3 {
                engine.infer_batch(&window).unwrap();
            }
        });

        assert_eq!(engine.drain().len(), super::MAX_PENDING_REPORTS);
        assert_eq!(
            counter(&series, crate::metrics::DRIFT_SKIPPED_TOTAL),
            Some(3),
            "three readings were evicted, and said so"
        );
    }

    #[test]
    fn a_poisoned_monitor_recovers_instead_of_going_silent_forever() {
        // Fail open, loudly. The old behaviour — return on a poisoned lock —
        // meant one panic disabled monitoring for the process's life while the
        // dashboard kept showing a confident zero.
        let engine = std::sync::Arc::new(engine());
        let samples = training();

        let poisoner = std::sync::Arc::clone(&engine);
        let vector = samples[0].clone();
        std::thread::spawn(move || {
            let _guard = poisoner.monitor.lock().unwrap();
            let _ = &vector;
            panic!("poison the monitor");
        })
        .join()
        .expect_err("the thread panicked on purpose");
        assert!(engine.monitor.is_poisoned());

        let series = captured(|| {
            engine.infer_batch(&samples).unwrap();
        });
        assert_eq!(
            counter(&series, crate::metrics::DRIFT_SKIPPED_TOTAL),
            Some(samples.len() as u64),
            "the skipped observations are counted, not swallowed"
        );

        // And monitoring resumes: the next full window still reports.
        assert!(!engine.monitor.is_poisoned(), "the poison was cleared");
        engine.infer_batch(&full_window(&training())).unwrap();
        assert_eq!(engine.windows(), 1);
    }

    #[test]
    fn the_threshold_is_exported_beside_the_readings_it_judges() {
        // So an alert rule compares against it (`model_drift_max > on(model)
        // model_drift_threshold`) instead of restating the number in PromQL,
        // where a per-model override could never reach it.
        let engine = engine();
        let series = captured(|| {
            engine.infer_batch(&full_window(&training())).unwrap();
        });
        assert_eq!(
            gauges(&series, crate::metrics::DRIFT_THRESHOLD),
            vec![DEFAULT_DRIFT_THRESHOLD]
        );
    }

    #[test]
    fn the_documented_config_shape_parses_and_omissions_take_the_defaults() {
        let full: DriftConfig =
            serde_json::from_str(r#"{"window": 1024, "threshold": 2.5, "max_age_seconds": 300}"#)
                .unwrap();
        assert_eq!(full.window, 1024);
        assert_eq!(full.threshold, 2.5);
        assert_eq!(full.max_age_seconds, 300);
        assert!(!full.disabled);

        let empty: DriftConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(empty, DriftConfig::default());
        assert!(
            !empty.disabled,
            "an omitted drift section means monitored-with-defaults, never off"
        );

        assert!(
            serde_json::from_str::<DriftConfig>(r#"{"windows": 1024}"#).is_err(),
            "a typo must be a refused boot, not a silent default"
        );
    }
}
