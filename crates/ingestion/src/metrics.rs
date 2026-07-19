//! Ingestion service metrics (§19, Sprint 13 t4): head-to-wall-clock lag,
//! per-head assembly latency, and reorg depth/frequency.
//!
//! Three call sites, all in [`crate::pipeline::Pipeline::ingest`] — the one seam
//! every observed head passes through, mirroring the single-call-site discipline
//! `detection::metrics::record_detector_run` uses. These go through the
//! [`metrics`] facade, a near-free no-op until the binary installs the
//! Prometheus exporter ([`telemetry::metrics::init_labeled`]).

use std::time::Duration;

use crate::tree::CanonicalUpdate;

/// Gauge: how far behind wall clock the most recently observed head's own
/// timestamp is — chain propagation lag plus this instance's poll interval.
/// A gauge (not a histogram) because a dashboard wants the *current* lag, the
/// same convention as `event_bus::lag`'s `kafka_consumer_lag`.
pub const INGESTION_LAG_SECONDS: &str = "ingestion_lag_seconds";
/// Histogram: one `Pipeline::ingest` call's wall-clock latency — back-fill
/// RPC fetches and publish retries included, since those are exactly what
/// make assembling a head into the canonical tree slow.
pub const ASSEMBLY_DURATION_SECONDS: &str = "assembly_duration_seconds";
/// Counter: every canonical update that orphaned at least one block — the
/// reorg-frequency signal.
pub const REORGS_TOTAL: &str = "reorgs_total";
/// Histogram: a reorg's depth (`reverted.len()`), sampled only on updates
/// that are actually reorgs.
pub const REORG_DEPTH: &str = "reorg_depth";

/// Record how far behind wall clock `head_timestamp_unix_secs` (the chain's own
/// block timestamp) is right now. Clamped at zero — clock skew between this
/// host and the chain's timestamp source shouldn't render as negative lag.
pub fn record_ingestion_lag(head_timestamp_unix_secs: u64) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    let lag = (now - head_timestamp_unix_secs as f64).max(0.0);
    metrics::gauge!(INGESTION_LAG_SECONDS).set(lag);
}

/// Record one `ingest()` call's total wall-clock duration.
pub fn record_assembly_duration(elapsed: Duration) {
    metrics::histogram!(ASSEMBLY_DURATION_SECONDS).record(elapsed.as_secs_f64());
}

/// Record one canonical update's reorg shape. A no-op for a plain extension
/// (`update.is_reorg()` false) — frequency is a fraction of updates, not a
/// fraction of blocks.
pub fn record_canonical_update(update: &CanonicalUpdate) {
    if update.is_reorg() {
        metrics::counter!(REORGS_TOTAL).increment(1);
        metrics::histogram!(REORG_DEPTH).record(update.reverted.len() as f64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::ChainHead;
    use alloy_primitives::B256;
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

    fn a_head(number: u64) -> ChainHead {
        ChainHead {
            number,
            hash: B256::from([number as u8; 32]),
            parent_hash: B256::from([(number.saturating_sub(1)) as u8; 32]),
            timestamp: 0,
            tx_count: 0,
        }
    }

    #[test]
    fn lag_is_the_gap_between_now_and_the_head_timestamp() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let series = captured(|| record_ingestion_lag(now - 5));
        match value(&series, INGESTION_LAG_SECONDS) {
            Some(DebugValue::Gauge(g)) => assert!(
                (f64::from(*g) - 5.0).abs() < 1.0,
                "expected ~5s lag, got {g:?}"
            ),
            other => panic!("expected a gauge, got {other:?}"),
        }
    }

    #[test]
    fn a_future_timestamp_clamps_lag_to_zero_not_negative() {
        let far_future = u64::MAX / 2;
        let series = captured(|| record_ingestion_lag(far_future));
        match value(&series, INGESTION_LAG_SECONDS) {
            Some(DebugValue::Gauge(g)) => assert_eq!(f64::from(*g), 0.0),
            other => panic!("expected a gauge, got {other:?}"),
        }
    }

    #[test]
    fn assembly_duration_records_one_sample() {
        let series = captured(|| record_assembly_duration(Duration::from_millis(7)));
        match value(&series, ASSEMBLY_DURATION_SECONDS) {
            Some(DebugValue::Histogram(samples)) => assert_eq!(samples.len(), 1),
            other => panic!("expected a histogram, got {other:?}"),
        }
    }

    #[test]
    fn a_plain_extension_touches_neither_reorg_metric() {
        let update = CanonicalUpdate {
            reverted: vec![],
            canonicalized: vec![a_head(2)],
        };
        let series = captured(|| record_canonical_update(&update));
        assert!(value(&series, REORGS_TOTAL).is_none());
        assert!(value(&series, REORG_DEPTH).is_none());
    }

    #[test]
    fn a_reorg_counts_once_and_samples_its_depth() {
        let update = CanonicalUpdate {
            reverted: vec![a_head(3), a_head(2)],
            canonicalized: vec![a_head(2), a_head(3)],
        };
        let series = captured(|| record_canonical_update(&update));
        match value(&series, REORGS_TOTAL) {
            Some(DebugValue::Counter(n)) => assert_eq!(*n, 1),
            other => panic!("expected a counter, got {other:?}"),
        }
        match value(&series, REORG_DEPTH) {
            Some(DebugValue::Histogram(samples)) => {
                assert_eq!(samples.len(), 1);
                assert_eq!(f64::from(samples[0]), 2.0, "reverted.len() == 2");
            }
            other => panic!("expected a histogram, got {other:?}"),
        }
    }
}
