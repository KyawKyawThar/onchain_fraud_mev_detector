//! [`ObservedReadModel`] — the §19 metrics for a rebuild, as a decorator.
//!
//! Conventions §14: a cross-cutting concern is a wrapper plus an `_inner`
//! split, never a metric call scattered across every return site. This is the
//! same shape `inference::ObservedEngine` takes over the serving seam, and for
//! the same reason — the wrapped type stays free of bookkeeping and there is
//! exactly one place where a counter can be forgotten.
//!
//! Everything is a no-op until a binary installs the Prometheus exporter
//! (`telemetry::metrics::init`), so linking this costs nothing.
//!
//! ## Why a rebuild needs metrics at all
//!
//! Because the drill is only worth something if a failing one is *noticed*. A
//! divergence printed into an operator's terminal is a number somebody read
//! once; `projection_rebuild_divergence_rows` on a dashboard is an alertable
//! SLO signal, which is what turns "we proved projections are derived in
//! September" into a standing guarantee. The three classes are separate label
//! values on purpose: `lost` is an audit-completeness hole and should page,
//! while `gained` on the analytics model has a known benign cause and should
//! only trend.
//!
//! | metric | type | labels | what it says |
//! |---|---|---|---|
//! | `projection_rebuild_runs_total` | counter | `model`, `outcome` | a run finished (`promoted`/`discarded`/`failed`) |
//! | `projection_rebuild_events_total` | counter | `model` | events replayed and folded |
//! | `projection_rebuild_duration_seconds` | histogram | `model` | how long a rebuild takes — the Epic B RTO input |
//! | `projection_rebuild_rows` | gauge | `model`, `side` | rows `live` vs `staged` |
//! | `projection_rebuild_divergence_rows` | gauge | `model`, `class` | `lost` / `gained` / `changed` |
//! | `projection_rebuild_apply_errors_total` | counter | `model` | folds that failed mid-replay |

use std::sync::Arc;

use async_trait::async_trait;
use events::EventEnvelope;

use crate::digest::{Divergence, ModelDigest};
use crate::driver::{Outcome, RebuildReport};
use crate::model::{ModelError, Projector, Scope, ScopeSupport, Snapshotter, Stageable, Staging};

/// Metric names, as constants so a dashboard and an alert rule can be grepped
/// back to their producer.
pub mod names {
    pub const RUNS: &str = "projection_rebuild_runs_total";
    pub const EVENTS: &str = "projection_rebuild_events_total";
    pub const DURATION: &str = "projection_rebuild_duration_seconds";
    pub const ROWS: &str = "projection_rebuild_rows";
    pub const DIVERGENCE: &str = "projection_rebuild_divergence_rows";
    pub const APPLY_ERRORS: &str = "projection_rebuild_apply_errors_total";
}

/// Record a finished run. Called by the CLI once the driver returns, rather
/// than from inside the driver, so the driver stays a pure procedure and the
/// binary owns its own observability (the same split every other service uses).
pub fn record_report(report: &RebuildReport) {
    let model = report.model;
    let outcome = match report.outcome {
        Outcome::Promoted => "promoted",
        Outcome::Discarded => "discarded",
    };
    metrics::counter!(names::RUNS, "model" => model, "outcome" => outcome).increment(1);
    metrics::counter!(names::EVENTS, "model" => model).increment(report.events_replayed);
    metrics::histogram!(names::DURATION, "model" => model).record(report.elapsed.as_secs_f64());
    metrics::gauge!(names::ROWS, "model" => model, "side" => "live").set(report.live_rows as f64);
    metrics::gauge!(names::ROWS, "model" => model, "side" => "staged")
        .set(report.staged_rows as f64);
    record_divergence(model, &report.divergence);
}

/// Record a run that never produced a report.
pub fn record_failure(model: &'static str) {
    metrics::counter!(names::RUNS, "model" => model, "outcome" => "failed").increment(1);
}

/// Publish the three divergence classes as separate series.
///
/// Always set, including to zero: a gauge that is only written when non-zero
/// holds its last value forever, so a model that started passing would keep
/// alerting — the same "monitoring the monitor" trap §15 names.
fn record_divergence(model: &'static str, divergence: &Divergence) {
    metrics::gauge!(names::DIVERGENCE, "model" => model, "class" => "lost")
        .set(divergence.lost.len() as f64);
    metrics::gauge!(names::DIVERGENCE, "model" => model, "class" => "gained")
        .set(divergence.gained.len() as f64);
    metrics::gauge!(names::DIVERGENCE, "model" => model, "class" => "changed")
        .set(divergence.changed.len() as f64);
}

/// Wraps a read model so its fold failures are counted.
///
/// The per-run numbers come from [`record_report`]; what this decorator adds is
/// the one signal the report cannot carry — a run that *died* mid-replay, which
/// by definition never produces a report.
pub struct ObservedReadModel<M> {
    inner: M,
}

impl<M> ObservedReadModel<M> {
    pub fn new(inner: M) -> Self {
        Self { inner }
    }

    /// The wrapped model, for callers that need the concrete type back.
    pub fn into_inner(self) -> M {
        self.inner
    }
}

#[async_trait]
impl<M: Snapshotter> Snapshotter for ObservedReadModel<M> {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn scope_support(&self) -> ScopeSupport {
        self.inner.scope_support()
    }

    async fn digest(&self, scope: &Scope) -> Result<ModelDigest, ModelError> {
        self.inner.digest(scope).await
    }
}

#[async_trait]
impl<M: Snapshotter + Stageable> Stageable for ObservedReadModel<M> {
    async fn stage(&self, staging: &Staging) -> Result<Arc<dyn Projector>, ModelError> {
        Ok(Arc::new(ObservedProjector {
            inner: self.inner.stage(staging).await?,
            model: self.inner.name(),
        }))
    }

    async fn digest_staged(
        &self,
        staging: &Staging,
        scope: &Scope,
    ) -> Result<ModelDigest, ModelError> {
        self.inner.digest_staged(staging, scope).await
    }

    async fn promote(&self, staging: &Staging) -> Result<u64, ModelError> {
        self.inner.promote(staging).await
    }

    async fn discard(&self, staging: &Staging) -> Result<(), ModelError> {
        self.inner.discard(staging).await
    }
}

/// The projector half of the decorator: counts folds that failed.
struct ObservedProjector {
    inner: Arc<dyn Projector>,
    model: &'static str,
}

#[async_trait]
impl Projector for ObservedProjector {
    fn event_types(&self) -> Vec<String> {
        self.inner.event_types()
    }

    async fn apply(&self, envelope: EventEnvelope) -> Result<(), ModelError> {
        match self.inner.apply(envelope).await {
            Ok(()) => Ok(()),
            Err(err) => {
                metrics::counter!(names::APPLY_ERRORS, "model" => self.model).increment(1);
                Err(err)
            }
        }
    }

    async fn flush(&self) -> Result<(), ModelError> {
        self.inner.flush().await
    }
}

#[cfg(test)]
mod tests {
    use metrics_util::debugging::DebuggingRecorder;

    use super::*;
    use crate::digest::{ModelDigest, RowEncoder};

    /// A gauge that is only written when non-zero holds its last value forever,
    /// so a model that started passing would keep alerting. All three classes
    /// must be published every run, zeros included.
    #[test]
    fn every_divergence_class_is_published_even_when_zero() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        metrics::with_local_recorder(&recorder, || {
            record_divergence(
                "sum",
                &Divergence {
                    lost: vec!["a".into()],
                    ..Default::default()
                },
            );
        });

        let snapshot = snapshotter.snapshot().into_vec();
        let classes: Vec<String> = snapshot
            .iter()
            .filter(|(key, _, _, _)| key.key().name() == names::DIVERGENCE)
            .filter_map(|(key, _, _, _)| {
                key.key()
                    .labels()
                    .find(|label| label.key() == "class")
                    .map(|label| label.value().to_string())
            })
            .collect();
        assert_eq!(classes.len(), 3, "lost, gained and changed: {classes:?}");
        for class in ["lost", "gained", "changed"] {
            assert!(classes.iter().any(|c| c == class), "missing {class}");
        }
    }

    /// A digest with no rows still produces a root, and a report over it still
    /// records — the "nothing diverged" path must not be silent.
    #[test]
    fn a_clean_run_still_records_its_classes() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            record_divergence("sum", &Divergence::default());
        });
        let snapshot = snapshotter.snapshot().into_vec();
        assert_eq!(
            snapshot
                .iter()
                .filter(|(key, _, _, _)| key.key().name() == names::DIVERGENCE)
                .count(),
            3
        );
    }

    #[test]
    fn an_empty_model_digest_is_not_an_error() {
        let mut digest = ModelDigest::new();
        digest
            .insert("a", RowEncoder::new().float(1.0).finish())
            .unwrap();
        assert_eq!(digest.len(), 1);
    }
}
