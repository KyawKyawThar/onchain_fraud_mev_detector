//! Fill `ModelCard::Performance` from a backtest [`Report`] (§18, Sprint 10 t4) —
//! the writer side of the bridge `detection::model` defines the wire types for.
//!
//! `save`/`load`/the wire types themselves ([`PerformanceRecord`],
//! [`PerformanceStore`]) live in `detection::model`, not duplicated here: both
//! `detection`'s boot (the reader) and this module (the writer) need the exact
//! same schema, so it's defined once, next to [`detection::model::ModelCard`]
//! itself.

use chrono::Utc;
use detection::{PerformanceRecord, PerformanceStore};
use std::num::NonZeroU64;

use crate::Report;

/// Derive a performance store from a fresh [`Report`], one entry per linked
/// detector with *both* a measured precision and recall — mirroring
/// [`crate::baseline::from_report`]'s "skip rather than fabricate" rule. A
/// detector that never fired (or has no ground-truthed incident) stays
/// `Performance::Unmeasured` in the live catalogue, which is correct: nothing
/// was actually verified about it yet.
///
/// Each record is keyed on the build the report measured; `detection`'s boot
/// shows it only for that exact `(id, version, config_hash)`.
///
/// `sample_size` is `total_blocks` (not the tp/fp/fn count) — the scale a
/// precision/recall/hit_rate reading was taken over, per
/// `Performance::Measured::sample_size`'s own doc ("a precision over 3 blocks
/// is not the precision over 30k").
pub fn from_report(report: &Report) -> PerformanceStore {
    let Some(sample_size) = NonZeroU64::new(report.total_blocks) else {
        return PerformanceStore::new();
    };
    let measured_at = Utc::now();

    report
        .linked()
        .filter_map(|(id, build, stats)| {
            let record = PerformanceRecord::try_new(
                stats.precision()?,
                stats.recall()?,
                report.hit_rate(id).unwrap_or(0.0),
                sample_size,
                measured_at,
            )
            .expect("ratios of non-negative counts are within [0, 1]");
            Some((build.clone(), record))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_build, test_report, DetectorStats};
    use detection::Lookup;

    fn measured() -> DetectorStats {
        DetectorStats {
            true_positives: 3,
            false_positives: 1,
            false_negatives: 0,
            blocks_hit: 3,
            unadjudicated: 0,
        }
    }

    #[test]
    fn from_report_fills_a_detector_with_both_precision_and_recall() {
        let report = test_report(100, &[("sandwich", measured())]);
        let store = from_report(&report);

        let Lookup::Current(record) = store.lookup(&test_build("sandwich", "1.0.0", "cfg")) else {
            panic!("sandwich was measured on exactly this build");
        };
        assert_eq!(record.precision(), 0.75);
        assert_eq!(record.recall(), 1.0);
        assert_eq!(record.hit_rate(), 0.03);
        assert_eq!(record.sample_size().get(), 100);
    }

    #[test]
    fn from_report_skips_a_detector_with_no_ground_truthed_recall() {
        // Raised alerts but no ground-truthed incident for it at all: recall is
        // `None`, so it must not be recorded at a fabricated number.
        let report = test_report(
            100,
            &[(
                "brand-new",
                DetectorStats {
                    true_positives: 0,
                    false_positives: 2,
                    false_negatives: 0,
                    blocks_hit: 2,
                    unadjudicated: 0,
                },
            )],
        );
        assert!(from_report(&report).is_empty());
    }

    #[test]
    fn from_report_skips_an_unlinked_detector() {
        let mut report = test_report(100, &[("sandwich", measured())]);
        report.detectors.get_mut("sandwich").unwrap().build = None;
        assert!(from_report(&report).is_empty());
    }

    #[test]
    fn from_report_is_empty_over_an_empty_fixture_set() {
        assert!(from_report(&test_report(0, &[])).is_empty());
    }

    #[test]
    fn from_report_round_trips_through_the_shared_store_io() {
        let store = from_report(&test_report(100, &[("sandwich", measured())]));

        let path = std::env::temp_dir().join(format!(
            "backtest-model-performance-test-{}",
            std::process::id()
        ));
        detection::save_performance_store(&store, &path).unwrap();
        let reloaded = detection::load_performance_store(&path).unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(store, reloaded);
    }
}
