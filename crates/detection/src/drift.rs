//! Turning drift readings into domain events (§20.5) — the publishing half of
//! the drift monitor.
//!
//! `ml-features` measures, `inference::DriftEngine` accumulates and exports
//! metrics, and this decides what a completed reading *becomes*. The split is
//! not ceremony: the arch-conformance rules forbid `inference` from depending
//! on `event-bus` or `rdkafka`, because a model-serving seam that could publish
//! would be a serving seam with an opinion about topology — and a detector
//! cannot publish either, being a pure function of its context (§6). So the
//! reading leaves the seam through the plain [`DriftSource`] trait and lands
//! here, in the service that already owns an `EventSink`, a retry policy and a
//! DLQ.
//!
//! # Why a gauge was not enough
//!
//! The metrics answer "is this model drifting right now?". They cannot answer
//! the question an incident review actually asks months later: *which weights
//! were serving when it drifted, and could anyone have known?* Prometheus
//! retention is days; the event store is the audit trail (§4). §20.5 asks for
//! drift to "flag the model version in the registry" — the durable, queryable
//! flag is a [`ModelDriftDetected`] keyed by the exact `(id, version,
//! config_hash)` triple that model's findings were stamped with, which is what
//! makes the two joinable.
//!
//! # Where the events are emitted from
//!
//! The scheduler, on the block boundary, appended to the events it was
//! publishing anyway ([`crate::scheduler::Scheduler`]). That reuses the whole
//! existing publish path — the same `publish_resilient` retry, the same
//! ordering, the same shutdown behaviour — rather than standing up a second
//! producer with its own failure modes for a handful of events per hour. A
//! drift reading is not urgent to the millisecond; it is urgent to the hour,
//! and the block boundary is well inside that.

use std::sync::Arc;

use chrono::Utc;
use events::primitives::DetectorRef;
use events::system::{DriftedFeature, ModelDriftDetected};
use events::DomainEvent;
use inference::DriftSource;
use ml_features::DriftReport;

use crate::scheduler::BlockBoundaryEvents;

/// Drains the drift monitors of one detector's served models and renders their
/// readings as [`ModelDriftDetected`] events.
///
/// Holds the detector's *resolved* [`DetectorRef`] — the triple `link_roster`
/// produced at boot, not one rebuilt here — so a drift record and the
/// `DetectorTriggered`s produced under the same weights carry byte-identical
/// identity and join without a heuristic.
#[derive(Debug)]
pub struct DriftPublisher {
    detector: DetectorRef,
    sources: Vec<Arc<dyn DriftSource>>,
}

impl DriftPublisher {
    /// Wire the publisher to the detector triple and the per-model monitors.
    ///
    /// Returns `None` when there are no sources: an ML deployment with drift
    /// monitoring disabled, or no ML deployment at all. `None` rather than an
    /// empty publisher so the scheduler's "is there anything to drain?" is a
    /// type-level question, not a length check it could forget.
    pub fn new(detector: DetectorRef, sources: Vec<Arc<dyn DriftSource>>) -> Option<Self> {
        (!sources.is_empty()).then_some(Self { detector, sources })
    }

    /// How many monitors this publisher drains.
    pub fn len(&self) -> usize {
        self.sources.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Drain every monitor and render the readings that breached.
    ///
    /// **Quiet windows produce nothing.** A window in which no feature reached
    /// the deployment's threshold is the normal case and has no business in an
    /// audit log — the gauges already carry the continuous signal. One event
    /// per breaching *window*, not per breaching feature: a drifted model
    /// usually moves several correlated features at once, and fanning that out
    /// would multiply one condition into a burst that buries the rest of the
    /// stream.
    pub fn drift_events(&self) -> Vec<DomainEvent> {
        let observed_at = Utc::now();
        let mut events = Vec::new();
        for source in &self.sources {
            let threshold = source.threshold();
            for report in source.drain() {
                if let Some(event) =
                    self.render_report(source.model_id(), threshold, &report, observed_at)
                {
                    crate::metrics::record_drift_event(source.model_id());
                    events.push(DomainEvent::ModelDriftDetected(event));
                }
            }
        }
        events
    }

    fn render_report(
        &self,
        model_id: &str,
        threshold: f64,
        report: &DriftReport,
        observed_at: chrono::DateTime<Utc>,
    ) -> Option<ModelDriftDetected> {
        let breaches = report.breaches(threshold);
        if breaches.is_empty() {
            return None;
        }
        Some(ModelDriftDetected {
            model_id: model_id.to_owned(),
            detector: self.detector.clone(),
            feature_version: report.feature_version.0,
            granularity: report.granularity.as_str().to_owned(),
            baseline_hash: report.baseline_hash.clone(),
            samples: report.samples as u64,
            window_closed_by: report.closed_by.as_str().to_owned(),
            threshold,
            // The worst feature overall, not the worst *breach* — they are the
            // same number here, but stating it from the report keeps the
            // headline honest if the threshold is ever raised above every
            // reading.
            max_magnitude: report.max_magnitude(),
            drifted: breaches
                .iter()
                .map(|f| DriftedFeature {
                    feature: f.name().to_owned(),
                    magnitude: f.magnitude(),
                    shift: f.shift,
                    spread: f.spread,
                })
                .collect(),
            observed_at,
        })
    }
}

impl BlockBoundaryEvents for DriftPublisher {
    fn events(&self) -> Vec<DomainEvent> {
        self.drift_events()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_features::{DriftMonitor, FeatureBaseline, FeatureVector, MIN_WINDOW};
    use std::sync::Mutex;

    /// A `DriftSource` that hands out prepared readings — the seam's own double,
    /// so these tests are about *rendering*, not about the statistics (which
    /// `ml-features` tests) or the accumulator (which `inference` tests).
    #[derive(Debug)]
    struct StubSource {
        model_id: String,
        threshold: f64,
        reports: Mutex<Vec<DriftReport>>,
    }

    impl DriftSource for StubSource {
        fn model_id(&self) -> &str {
            &self.model_id
        }
        fn threshold(&self) -> f64 {
            self.threshold
        }
        fn drain(&self) -> Vec<DriftReport> {
            std::mem::take(&mut self.reports.lock().unwrap())
        }
    }

    fn a_ref() -> DetectorRef {
        DetectorRef {
            id: "anomaly".into(),
            version: "1.0.0".into(),
            config_hash: "cafebabe".into(),
        }
    }

    /// Block vectors of varying shape, and a baseline over them.
    fn training() -> Vec<FeatureVector> {
        use detector_api::test_util::{addr, b256, swap, CtxBuilder};
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

    /// One completed window over `samples`, produced by the real monitor so
    /// these tests can never drift from the statistic they render.
    fn report_over(samples: &[FeatureVector]) -> DriftReport {
        let baseline = FeatureBaseline::from_samples(&training()).unwrap();
        let mut monitor = DriftMonitor::new(baseline, 36, std::time::Duration::from_secs(86_400));
        let window: Vec<FeatureVector> = samples
            .iter()
            .flat_map(|v| std::iter::repeat_n(v.clone(), 36 / samples.len()))
            .collect();
        monitor
            .observe_all(&window)
            .pop()
            .expect("36 vectors close one window")
    }

    /// The training distribution, with one measurable feature moved far.
    fn drifted_samples() -> Vec<FeatureVector> {
        let baseline = FeatureBaseline::from_samples(&training()).unwrap();
        let target = baseline
            .stats()
            .iter()
            .position(|s| s.spread > ml_features::MIN_SPREAD)
            .expect("a feature that varied");
        training()
            .iter()
            .map(|v| {
                let mut values = v.values().to_vec();
                values[target] += 6.0 * baseline.stats()[target].spread;
                serde_json::from_value(serde_json::json!({
                    "feature_version": v.feature_version(),
                    "granularity": v.granularity(),
                    "values": values,
                }))
                .expect("a well-formed vector")
            })
            .collect()
    }

    fn publisher(threshold: f64, reports: Vec<DriftReport>) -> DriftPublisher {
        DriftPublisher::new(
            a_ref(),
            vec![Arc::new(StubSource {
                model_id: "anomaly-iforest".into(),
                threshold,
                reports: Mutex::new(reports),
            })],
        )
        .expect("one source")
    }

    #[test]
    fn a_quiet_window_produces_no_event() {
        // The rule that keeps this out of the audit log's way: normal is not a
        // fact worth recording forever.
        let publisher = publisher(3.0, vec![report_over(&training())]);
        assert!(publisher.drift_events().is_empty());
    }

    #[test]
    fn a_breaching_window_becomes_one_event_carrying_the_detector_triple() {
        let publisher = publisher(3.0, vec![report_over(&drifted_samples())]);
        let events = publisher.drift_events();

        assert_eq!(events.len(), 1, "one event per window, not per feature");
        let DomainEvent::ModelDriftDetected(drift) = &events[0] else {
            panic!("expected ModelDriftDetected, got {:?}", events[0]);
        };
        assert_eq!(drift.model_id, "anomaly-iforest");
        // The join key: identical to what this detector's findings carry.
        assert_eq!(drift.detector, a_ref());
        assert_eq!(drift.threshold, 3.0);
        assert_eq!(drift.samples, 36);
        assert_eq!(drift.window_closed_by, "full");
        assert_eq!(drift.granularity, "block");
        assert_eq!(drift.feature_version, ml_features::FEATURE_VERSION.0);
        assert!(!drift.baseline_hash.is_empty());
        assert!(drift.max_magnitude >= 3.0);
    }

    #[test]
    fn only_the_breached_features_are_carried_worst_first() {
        // The full vector lives on the gauges. An audit record wants the
        // finding, not the telemetry — and a 24-entry array per event would be
        // most of the payload.
        let publisher = publisher(3.0, vec![report_over(&drifted_samples())]);
        let events = publisher.drift_events();
        let DomainEvent::ModelDriftDetected(drift) = &events[0] else {
            unreachable!()
        };

        assert!(!drift.drifted.is_empty());
        assert!(
            drift.drifted.len() < ml_features::block_schema().len(),
            "a quiet feature must not be reported as drifted"
        );
        assert!(
            drift.drifted.iter().all(|f| f.magnitude >= 3.0),
            "{:?}",
            drift.drifted
        );
        assert!(
            drift
                .drifted
                .windows(2)
                .all(|w| w[0].magnitude >= w[1].magnitude),
            "worst first"
        );
    }

    #[test]
    fn draining_is_destructive_so_one_reading_is_never_published_twice() {
        let publisher = publisher(3.0, vec![report_over(&drifted_samples())]);
        assert_eq!(publisher.drift_events().len(), 1);
        assert!(
            publisher.drift_events().is_empty(),
            "the second drain has nothing left"
        );
    }

    #[test]
    fn every_served_model_is_drained_not_just_the_first() {
        // Two slots is the shipped deployment (supervised + novelty), and a
        // publisher that stopped at the first would silently un-monitor one.
        let publisher = DriftPublisher::new(
            a_ref(),
            vec![
                Arc::new(StubSource {
                    model_id: "anomaly-gbdt".into(),
                    threshold: 3.0,
                    reports: Mutex::new(vec![report_over(&drifted_samples())]),
                }),
                Arc::new(StubSource {
                    model_id: "anomaly-iforest".into(),
                    threshold: 3.0,
                    reports: Mutex::new(vec![report_over(&drifted_samples())]),
                }),
            ],
        )
        .expect("two sources");

        let models: Vec<String> = publisher
            .events()
            .iter()
            .map(|e| match e {
                DomainEvent::ModelDriftDetected(d) => d.model_id.clone(),
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(models, vec!["anomaly-gbdt", "anomaly-iforest"]);
    }

    #[test]
    fn a_deployment_with_no_monitors_has_no_publisher() {
        assert!(DriftPublisher::new(a_ref(), Vec::new()).is_none());
    }

    #[test]
    fn the_threshold_comes_from_the_source_not_from_this_layer() {
        // A reading is only interpretable against the threshold it was judged
        // by. Raising it must silence the event, not merely relabel it.
        let quiet = publisher(64.0, vec![report_over(&drifted_samples())]);
        assert!(
            quiet.drift_events().is_empty(),
            "past the clamp, nothing can breach"
        );
    }

    #[test]
    fn an_aged_window_is_labelled_as_one() {
        // A reader has to be able to tell "512 samples" from "the most we had
        // inside the latency bound" — they are not equally strong readings.
        let baseline = FeatureBaseline::from_samples(&training()).unwrap();
        let mut monitor = DriftMonitor::new(baseline, 4096, std::time::Duration::from_secs(900));
        let drifted = drifted_samples();
        let start = std::time::Instant::now();
        for i in 0..MIN_WINDOW {
            monitor.observe_at(&drifted[i % drifted.len()], start);
        }
        let report = monitor
            .observe_at(&drifted[0], start + std::time::Duration::from_secs(901))
            .expect("closes on age");

        let publisher = publisher(3.0, vec![report]);
        let events = publisher.drift_events();
        let DomainEvent::ModelDriftDetected(drift) = &events[0] else {
            unreachable!()
        };
        assert_eq!(drift.window_closed_by, "aged");
        assert_eq!(drift.samples, MIN_WINDOW as u64 + 1);
    }
}
