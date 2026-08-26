//! Prometheus metrics for the export (§17/§19).
//!
//! Recorded through the shared [`metrics`] facade, never a recorder of this
//! crate's own — `telemetry::metrics::init` owns the global recorder, and the
//! facade is a near-free no-op until something installs one. So an export run
//! without `METRICS_ADDR` set pays nothing and still compiles the call sites
//! in, which is the workspace's standing arrangement.
//!
//! # What is worth a series here, and why
//!
//! A batch job's metrics are not the same as a service's. There is no request
//! rate and no latency SLO; what an operator (and an alert) wants is **whether
//! the dataset that came out is trustworthy**:
//!
//! - `dataset_binding_conflicts_total` is the one to alert on. A non-zero
//!   value means `IncidentCreated` contradicted a binding the join was
//!   confident about — the events disagree with each other. That is a signal
//!   about the *upstream emitter*, and it would otherwise sit unread in a JSON
//!   blob.
//! - `dataset_context_drop_fraction` is the selection-bias measure (see
//!   `ExportError::ExcessiveDrop`). The export already refuses above a
//!   threshold; the gauge is what shows the trend *before* it trips.
//! - the outcome and fidelity histograms explain a small dataset without
//!   re-running anything.
//!
//! Every series is stamped with `dataset_id`, so two exports of different
//! specs never blur together on a dashboard.

use crate::manifest::DatasetManifest;

/// A page request that failed transiently and was retried. A rising count
/// means the event store is flapping; the export survived it.
pub fn record_replay_retry() {
    metrics::counter!("dataset_replay_retries_total").increment(1);
}

/// Publish everything one finished export learned.
///
/// Called once, at the end, from the manifest — rather than incrementally from
/// inside the pipeline — because the pipeline is a pure function and keeping it
/// that way is what makes the export reproducible. Metrics are an observation
/// *of* the run, not a participant in it.
pub fn record_export(manifest: &DatasetManifest) {
    let id = manifest.dataset_id.clone();
    let labels = [("dataset_id", id)];

    metrics::gauge!("dataset_rows_written", &labels).set(manifest.rows.written as f64);
    metrics::gauge!("dataset_findings_labeled", &labels).set(manifest.rows.labeled as f64);
    metrics::gauge!("dataset_findings_unlabeled", &labels).set(manifest.rows.unlabeled as f64);

    // The bias measure — the gauge that shows a drop-rate trend before the
    // export starts refusing.
    metrics::gauge!("dataset_context_drop_fraction", &labels).set(manifest.rows.drop_fraction());
    metrics::gauge!("dataset_context_dropped", &labels)
        .set(manifest.rows.dropped_for_context() as f64);

    // Join health. `binding_conflicts` is the alertable one: it means the
    // stored events contradict each other, not that this tool is unlucky.
    metrics::counter!("dataset_binding_conflicts_total", &labels)
        .increment(manifest.join.binding_conflicts);
    metrics::counter!("dataset_ambiguous_bindings_total", &labels)
        .increment(manifest.join.ambiguous_bindings);
    metrics::counter!("dataset_corrected_bindings_total", &labels)
        .increment(manifest.join.corrected_bindings);
    metrics::gauge!("dataset_triggers_seen", &labels).set(manifest.join.triggers as f64);

    // Why a dataset is the size it is: outcome and fidelity distributions.
    for (outcome, count) in &manifest.rows.by_outcome {
        metrics::gauge!(
            "dataset_findings_by_outcome",
            "dataset_id" => manifest.dataset_id.clone(),
            "outcome" => outcome.clone(),
        )
        .set(*count as f64);
    }
    for (fidelity, count) in &manifest.rows.by_fidelity {
        metrics::gauge!(
            "dataset_findings_by_fidelity",
            "dataset_id" => manifest.dataset_id.clone(),
            "fidelity" => fidelity.clone(),
        )
        .set(*count as f64);
    }
    for (label, count) in &manifest.rows.by_label {
        metrics::gauge!(
            "dataset_rows_by_label",
            "dataset_id" => manifest.dataset_id.clone(),
            "label" => label.clone(),
        )
        .set(*count as f64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ctx::Fidelity;
    use crate::join::JoinStats;
    use crate::manifest::RowCounts;
    use crate::row::RowDigest;
    use crate::spec::{DatasetSpec, DEFAULT_LOOKAHEAD_SECS};
    use chrono::DateTime;
    use metrics_util::debugging::DebuggingRecorder;
    use ml_features::Granularity;

    fn manifest() -> DatasetManifest {
        let spec = DatasetSpec {
            chain: events::primitives::Chain::ETHEREUM,
            from: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            to: DateTime::from_timestamp(1_700_003_600, 0).unwrap(),
            feature_version: ml_features::FEATURE_VERSION,
            granularity: Granularity::Tx,
            min_fidelity: Fidelity::HeaderOnly,
            include_ambiguous: false,
            lookahead_secs: DEFAULT_LOOKAHEAD_SECS,
        };
        let mut counts = RowCounts {
            written: 10,
            labeled: 8,
            no_extractable_tx: 2,
            ..Default::default()
        };
        RowCounts::bump(&mut counts.by_outcome, "confirmed");
        DatasetManifest::new(
            &spec,
            "0123".to_owned(),
            vec!["a".to_owned()],
            RowDigest::new(),
            counts,
            JoinStats {
                binding_conflicts: 3,
                ..Default::default()
            },
        )
    }

    #[test]
    fn an_export_publishes_the_series_an_operator_alerts_on() {
        // `with_local_recorder` is thread-local, which is all this needs — the
        // recording here is synchronous and single-threaded (the rayon caveat
        // that forces a global recorder elsewhere does not apply).
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || record_export(&manifest()));

        // `snapshot()` drains, so take it once and assert against that.
        let snapshot = snapshotter.snapshot().into_vec();
        let names: Vec<String> = snapshot
            .iter()
            .map(|(key, _, _, _)| key.key().name().to_owned())
            .collect();

        for expected in [
            "dataset_rows_written",
            "dataset_context_drop_fraction",
            "dataset_binding_conflicts_total",
            "dataset_findings_by_outcome",
        ] {
            assert!(
                names.iter().any(|n| n == expected),
                "{expected} must be published; got {names:?}"
            );
        }
    }

    #[test]
    fn the_drop_fraction_is_the_bias_measure_not_a_raw_count() {
        let m = manifest();
        // 2 of 8 labeled findings had no usable context.
        assert!((m.rows.drop_fraction() - 0.25).abs() < f64::EPSILON);
        assert_eq!(m.rows.dropped_for_context(), 2);
    }

    #[test]
    fn an_empty_window_is_not_a_biased_one() {
        let counts = RowCounts::default();
        assert_eq!(counts.drop_fraction(), 0.0);
    }
}
