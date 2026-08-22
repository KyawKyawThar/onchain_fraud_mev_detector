//! Reflexivity-walk metrics (§19), part of Sprint 16 task 3's production-
//! observability pass: one function, [`record_cascade_walk`], called once per
//! [`crate::reflexivity::detect_cascade`] invocation from its single call site
//! in `main.rs::run_cascade` — mirrors `detection::metrics`'s "measure at the
//! seam, not inside the algorithm" discipline, so a walk that forgot to
//! record itself can't silently vanish from the dashboard.
//!
//! Goes through the [`metrics`] facade, a near-free no-op until the binary
//! installs the Prometheus exporter (`telemetry::metrics::init_labeled`), so
//! `reflexivity`'s own tests stay exporter-agnostic.

use crate::reflexivity::CascadeOutcome;

/// Counter: every `detect_cascade` call, regardless of outcome — the
/// walk-rate denominator.
pub const WALKS_TOTAL: &str = "predictive_cascade_walks_total";
/// Counter: calls that found a genuine reflexive cascade (§16.3 — growth
/// beyond the naive at-risk seed set).
pub const WARNINGS_TOTAL: &str = "predictive_cascade_warnings_total";
/// Counter: calls whose walk reached a degree-capped hub asset (§8.2),
/// *regardless* of whether a warning ultimately fired — tracks how often
/// `ReflexivityLimits::degree_cap` binds, including the "walk gave up early
/// and found nothing" case a warnings-only signal would miss entirely.
pub const HUB_CAPPED_TOTAL: &str = "predictive_cascade_hub_capped_total";
/// Histogram: `reflexive_depth` of every emitted warning.
pub const REFLEXIVE_DEPTH: &str = "predictive_cascade_reflexive_depth";

/// Record one `detect_cascade` call's outcome.
pub fn record_cascade_walk(outcome: &CascadeOutcome) {
    metrics::counter!(WALKS_TOTAL).increment(1);
    if outcome.hub_capped {
        metrics::counter!(HUB_CAPPED_TOTAL).increment(1);
    }
    if let Some(warning) = &outcome.warning {
        metrics::counter!(WARNINGS_TOTAL).increment(1);
        metrics::histogram!(REFLEXIVE_DEPTH).record(f64::from(warning.reflexive_depth));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reflexivity::CascadeWarning;
    use alloy_primitives::Address;
    use events::primitives::UsdAmount;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::CompositeKey;

    type Series = Vec<(
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    )>;

    /// Run `f` under a scoped in-memory recorder and return the captured
    /// series — no global install (so tests don't contend), and one
    /// `snapshot()` only (it drains the recorder).
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

    fn counter(series: &Series, name: &str) -> Option<u64> {
        match value(series, name) {
            Some(DebugValue::Counter(n)) => Some(*n),
            _ => None,
        }
    }

    fn warning(reflexive_depth: u32) -> CascadeWarning {
        CascadeWarning {
            trigger_asset: Address::repeat_byte(0xE0),
            trigger_price: 1_500.0,
            reflexive_depth,
            accounts: vec![Address::repeat_byte(0x11)],
            aggregate_at_risk_usd: UsdAmount::new(40_000_000.0),
        }
    }

    #[test]
    fn a_walk_with_no_cascade_counts_only_the_walk() {
        let series = captured(|| {
            record_cascade_walk(&CascadeOutcome {
                warning: None,
                hub_capped: false,
            });
        });
        assert_eq!(counter(&series, WALKS_TOTAL), Some(1));
        assert_eq!(counter(&series, WARNINGS_TOTAL), None);
        assert_eq!(counter(&series, HUB_CAPPED_TOTAL), None);
    }

    #[test]
    fn a_hub_capped_walk_counts_even_without_a_warning() {
        let series = captured(|| {
            record_cascade_walk(&CascadeOutcome {
                warning: None,
                hub_capped: true,
            });
        });
        assert_eq!(counter(&series, WALKS_TOTAL), Some(1));
        assert_eq!(
            counter(&series, HUB_CAPPED_TOTAL),
            Some(1),
            "hub-capping must be visible even when no warning fired"
        );
        assert_eq!(counter(&series, WARNINGS_TOTAL), None);
    }

    #[test]
    fn a_cascade_warning_counts_the_walk_the_warning_and_its_depth() {
        let series = captured(|| {
            record_cascade_walk(&CascadeOutcome {
                warning: Some(warning(2)),
                hub_capped: false,
            });
        });
        assert_eq!(counter(&series, WALKS_TOTAL), Some(1));
        assert_eq!(counter(&series, WARNINGS_TOTAL), Some(1));
        match value(&series, REFLEXIVE_DEPTH) {
            Some(DebugValue::Histogram(samples)) => {
                assert_eq!(samples.len(), 1);
                assert_eq!(samples[0], 2.0);
            }
            other => panic!("expected a histogram, got {other:?}"),
        }
    }

    #[test]
    fn repeated_walks_accumulate_on_the_monotonic_counters() {
        let series = captured(|| {
            record_cascade_walk(&CascadeOutcome {
                warning: Some(warning(1)),
                hub_capped: false,
            });
            record_cascade_walk(&CascadeOutcome {
                warning: None,
                hub_capped: false,
            });
            record_cascade_walk(&CascadeOutcome {
                warning: Some(warning(3)),
                hub_capped: true,
            });
        });
        assert_eq!(counter(&series, WALKS_TOTAL), Some(3));
        assert_eq!(counter(&series, WARNINGS_TOTAL), Some(2));
        assert_eq!(counter(&series, HUB_CAPPED_TOTAL), Some(1));
        match value(&series, REFLEXIVE_DEPTH) {
            Some(DebugValue::Histogram(samples)) => {
                assert_eq!(samples.len(), 2, "one sample per warning, not per walk");
            }
            other => panic!("expected a histogram, got {other:?}"),
        }
    }
}
