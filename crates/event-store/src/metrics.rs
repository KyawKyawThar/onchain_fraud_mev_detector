//! Event-store metrics (§19, Sprint 13 t4): append latency, throughput, and
//! error rate.
//!
//! One call site, [`crate::store::EventStore::append_batch`] — the single write
//! path both ingress adapters (HTTP append API, Kafka consumer) share, mirroring
//! the single-call-site discipline `detection::metrics` uses. Deliberately does
//! **not** attempt event-sequence-gap detection — that's a correctness feature
//! (Epic A, `production_readiness.md`), tracked separately from this
//! observability wire-up.

use std::time::Duration;

use crate::store::StoreError;

/// Histogram: one `append_batch` call's wall-clock latency.
pub const APPEND_DURATION_SECONDS: &str = "event_store_append_duration_seconds";
/// Counter: envelopes successfully appended (summed across batches).
pub const ROWS_APPENDED_TOTAL: &str = "event_store_rows_appended_total";
/// Counter: failed append attempts, labeled `kind` (`transient`/`permanent`) via
/// [`event_bus::Transience`].
pub const APPEND_ERRORS_TOTAL: &str = "event_store_append_errors_total";

/// Record a successful append of `rows` envelopes, including its latency.
pub fn record_append_success(elapsed: Duration, rows: usize) {
    metrics::histogram!(APPEND_DURATION_SECONDS).record(elapsed.as_secs_f64());
    metrics::counter!(ROWS_APPENDED_TOTAL).increment(rows as u64);
}

/// Record a failed append attempt, classified transient/permanent via
/// [`event_bus::Transience`] so a dashboard can tell "ClickHouse is down"
/// (transient, retried) apart from "an encode bug" (permanent, needs a fix).
pub fn record_append_error(elapsed: Duration, err: &StoreError) {
    use event_bus::Transience;
    metrics::histogram!(APPEND_DURATION_SECONDS).record(elapsed.as_secs_f64());
    let kind = if err.is_transient() {
        "transient"
    } else {
        "permanent"
    };
    metrics::counter!(APPEND_ERRORS_TOTAL, "kind" => kind).increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn value<'a>(series: &'a Series, name: &str) -> Option<&'a DebugValue> {
        series
            .iter()
            .find(|(ck, _, _, _)| ck.key().name() == name)
            .map(|(_, _, _, v)| v)
    }

    #[test]
    fn a_success_records_latency_and_row_count() {
        let series = captured(|| record_append_success(Duration::from_millis(3), 5));
        match value(&series, APPEND_DURATION_SECONDS) {
            Some(DebugValue::Histogram(samples)) => assert_eq!(samples.len(), 1),
            other => panic!("expected a histogram, got {other:?}"),
        }
        match value(&series, ROWS_APPENDED_TOTAL) {
            Some(DebugValue::Counter(n)) => assert_eq!(*n, 5),
            other => panic!("expected a counter, got {other:?}"),
        }
    }

    #[test]
    fn an_encode_error_is_classified_permanent_not_transient() {
        let err = StoreError::Encode(serde_json::from_str::<()>("not json").unwrap_err());
        let series = captured(|| record_append_error(Duration::from_millis(1), &err));
        let has_permanent = series.iter().any(|(ck, _, _, _)| {
            ck.key().name() == APPEND_ERRORS_TOTAL
                && ck.key().labels().any(|l| l.value() == "permanent")
        });
        assert!(has_permanent, "an Encode error is permanent, not transient");
    }
}
