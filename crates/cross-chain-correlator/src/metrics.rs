//! Correlator metrics (§19) — through the shared `metrics` facade, a
//! near-free no-op until `telemetry::metrics::init` installs the exporter, so
//! `buffer`'s own tests stay exporter-agnostic (that module records nothing
//! itself — see its docs — so only `actor`, its effectful shell, calls into
//! this module; mirrors `predictive::metrics`'s "measure at the seam"
//! discipline).

use crate::leg::BridgeOrPair;

/// Counter (labeled `bridge_or_pair`): every candidate leg folded into a
/// correlation actor's buffer — the buffered-leg-rate denominator, once a
/// real [`crate::leg::LegExtractor`] starts producing legs (task 2).
pub const LEGS_BUFFERED_TOTAL: &str = "cross_chain_correlator_legs_buffered_total";

/// Gauge (labeled `bridge_or_pair`): current size of one bridge/pair's
/// candidate-leg buffer — the memory-DoS signal ops watches, same spirit as
/// `simulation`'s cache/orphan-buffer size gauges.
pub const LEG_BUFFER_SIZE: &str = "cross_chain_correlator_leg_buffer_size";

/// Counter (labeled `bridge_or_pair`, `reason`): legs dropped from a buffer —
/// `reason = "window"` for a normal age-out, `reason = "capacity"` for the
/// hard backstop firing (a burst arriving faster than the window drains, or a
/// misconfigured capacity — worth alerting on, unlike a window eviction).
pub const LEGS_EVICTED_TOTAL: &str = "cross_chain_correlator_legs_evicted_total";

pub fn record_leg_buffered(bridge_or_pair: &BridgeOrPair) {
    metrics::counter!(LEGS_BUFFERED_TOTAL, "bridge_or_pair" => bridge_or_pair.0.clone())
        .increment(1);
}

pub fn record_buffer_size(bridge_or_pair: &BridgeOrPair, size: usize) {
    metrics::gauge!(LEG_BUFFER_SIZE, "bridge_or_pair" => bridge_or_pair.0.clone()).set(size as f64);
}

pub fn record_legs_evicted(bridge_or_pair: &BridgeOrPair, reason: &'static str, count: u64) {
    if count == 0 {
        return;
    }
    metrics::counter!(
        LEGS_EVICTED_TOTAL,
        "bridge_or_pair" => bridge_or_pair.0.clone(),
        "reason" => reason,
    )
    .increment(count);
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
    fn buffer_size_records_a_gauge() {
        let bridge = BridgeOrPair("usdc-eth-base".to_owned());
        let series = captured(|| record_buffer_size(&bridge, 7));
        match value(&series, LEG_BUFFER_SIZE) {
            Some(DebugValue::Gauge(v)) => assert_eq!(f64::from(*v), 7.0),
            other => panic!("expected a gauge, got {other:?}"),
        }
    }

    #[test]
    fn zero_evictions_records_nothing() {
        let bridge = BridgeOrPair("usdc-eth-base".to_owned());
        let series = captured(|| record_legs_evicted(&bridge, "window", 0));
        assert!(series.is_empty());
    }

    #[test]
    fn evictions_count_by_reason() {
        let bridge = BridgeOrPair("usdc-eth-base".to_owned());
        let series = captured(|| {
            record_legs_evicted(&bridge, "window", 3);
            record_legs_evicted(&bridge, "capacity", 1);
        });
        let counters: Vec<u64> = series
            .iter()
            .filter(|(ck, _, _, _)| ck.key().name() == LEGS_EVICTED_TOTAL)
            .filter_map(|(_, _, _, v)| match v {
                DebugValue::Counter(n) => Some(*n),
                _ => None,
            })
            .collect();
        assert_eq!(counters.iter().sum::<u64>(), 4);
    }
}
