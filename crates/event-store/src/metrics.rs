//! Event-store metrics (§19, Sprint 13 t4): append latency, throughput, and
//! error rate.
//!
//! One call site, [`crate::store::EventStore::append_batch`] — the single write
//! path both ingress adapters (HTTP append API, Kafka consumer) share, mirroring
//! the single-call-site discipline `detection::metrics` uses. Deliberately does
//! **not** attempt event-sequence-gap detection — that's a correctness feature
//! (Epic A, `production_readiness.md`), tracked separately from this
//! observability wire-up.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::store::{EventRow, StoreError};

/// Histogram: one `append_batch` call's wall-clock latency.
pub const APPEND_DURATION_SECONDS: &str = "event_store_append_duration_seconds";
/// Counter: envelopes successfully appended (summed across batches).
pub const ROWS_APPENDED_TOTAL: &str = "event_store_rows_appended_total";
/// Counter: failed append attempts, labeled `kind` (`transient`/`permanent`) via
/// [`event_bus::Transience`].
pub const APPEND_ERRORS_TOTAL: &str = "event_store_append_errors_total";

/// Gauge, days: the regulatory evidence window this deployment is enforcing on
/// the `events` table (engineering conventions §18).
///
/// A gauge and not a log line because the question it answers is comparative:
/// the copilot's audit reports narratives whose evidence is gone, and the first
/// thing to check is whether this number moved. Set once, at boot, from the
/// resolved policy — including on the path where reconciliation *refuses*, so
/// what the deployment believes is always visible next to what the store does.
pub const EVIDENCE_RETENTION_DAYS: &str = "event_store_evidence_retention_days";

/// Publish the configured evidence window. One call site, in the binary's
/// retention reconciliation.
pub fn set_evidence_retention_days(days: u32) {
    metrics::gauge!(EVIDENCE_RETENTION_DAYS).set(f64::from(days));
}

/// Counter (labeled `event_type`): `payload` bytes appended, uncompressed.
///
/// The measured side of the capacity plan. `crates/capacity` projects payload
/// bytes per day from `model.json`, and `EventStoreGrowthAboveCapacityPlan`
/// compares this counter's daily rate against that projection — the threshold
/// is pinned to the model by a test, so the alert and the plan cannot drift.
/// Labeled by event type (a closed set of ~40) so the dashboard answers *which*
/// type outgrew its rate, which is the question the alert raises.
pub const PAYLOAD_BYTES_APPENDED_TOTAL: &str = "event_store_appended_payload_bytes_total";

/// Counter (labeled `event_type`): envelopes the Kafka ingest could not encode
/// and parked on the DLQ. Any non-zero rate is a bug in the event types.
pub const INGEST_REJECTED_TOTAL: &str = "event_store_ingest_rejected_total";

/// Gauge: rows in an `events` table still on the pre-capacity-plan partition
/// key, waiting for `event-store repartition run`. Zero once the table is
/// current. `EventStoreRepartitionPending` fires on it.
pub const REPARTITION_PENDING_ROWS: &str = "event_store_repartition_pending_rows";

/// Record a successful append of `rows`, including its latency and the payload
/// bytes it added per event type.
pub fn record_append_success(elapsed: Duration, rows: &[EventRow]) {
    metrics::histogram!(APPEND_DURATION_SECONDS).record(elapsed.as_secs_f64());
    metrics::counter!(ROWS_APPENDED_TOTAL).increment(rows.len() as u64);
    let mut bytes: BTreeMap<&str, u64> = BTreeMap::new();
    for row in rows {
        *bytes.entry(row.event_type.as_str()).or_default() += row.payload.len() as u64;
    }
    for (event_type, n) in bytes {
        metrics::counter!(PAYLOAD_BYTES_APPENDED_TOTAL, "event_type" => event_type.to_owned())
            .increment(n);
    }
}

/// Record one envelope the ingest rejected before it reached a batch.
pub fn record_ingest_rejected(event_type: &str) {
    metrics::counter!(INGEST_REJECTED_TOTAL, "event_type" => event_type.to_owned()).increment(1);
}

/// Publish how many rows still wait for the repartition Job.
pub fn set_repartition_pending_rows(rows: u64) {
    metrics::gauge!(REPARTITION_PENDING_ROWS).set(rows as f64);
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

    fn rows(n: usize) -> Vec<EventRow> {
        use alloy_primitives::B256;
        use events::chain::BlockAssembled;
        use events::primitives::{BlockRef, Chain};
        use events::{DomainEvent, EventEnvelope};
        (0..n)
            .map(|_| {
                EventRow::try_from(&EventEnvelope::new(
                    Chain::ETHEREUM,
                    DomainEvent::BlockAssembled(BlockAssembled {
                        block: BlockRef::new(1, B256::repeat_byte(0xab)),
                        tx_count: 1,
                        trace_available: true,
                    }),
                ))
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn a_success_records_latency_row_count_and_payload_bytes_by_type() {
        let batch = rows(5);
        let expected_bytes: u64 = batch.iter().map(|r| r.payload.len() as u64).sum();
        let series = captured(|| record_append_success(Duration::from_millis(3), &batch));
        match value(&series, APPEND_DURATION_SECONDS) {
            Some(DebugValue::Histogram(samples)) => assert_eq!(samples.len(), 1),
            other => panic!("expected a histogram, got {other:?}"),
        }
        match value(&series, ROWS_APPENDED_TOTAL) {
            Some(DebugValue::Counter(n)) => assert_eq!(*n, 5),
            other => panic!("expected a counter, got {other:?}"),
        }
        let bytes = series
            .iter()
            .find(|(ck, _, _, _)| {
                ck.key().name() == PAYLOAD_BYTES_APPENDED_TOTAL
                    && ck.key().labels().any(|l| l.value() == "BlockAssembled")
            })
            .map(|(_, _, _, v)| v);
        assert_eq!(bytes, Some(&DebugValue::Counter(expected_bytes)));
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
