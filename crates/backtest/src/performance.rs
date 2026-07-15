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

/// Derive a performance store from a fresh [`Report`], one entry per detector
/// with *both* a measured precision and recall — mirroring
/// [`crate::baseline::from_report`]'s "skip rather than fabricate" rule. A
/// detector that never fired (or has no ground-truthed incident) stays
/// `Performance::Unmeasured` in the live catalogue, which is correct: nothing
/// was actually verified about it yet.
///
/// `sample_size` is `total_blocks` (not the tp/fp/fn count) — the scale a
/// precision/recall/hit_rate reading was taken over, per
/// `Performance::Measured::sample_size`'s own doc ("a precision over 3 blocks
/// is not the precision over 30k").
pub fn from_report(report: &Report) -> PerformanceStore {
    let Some(sample_size) = NonZeroU64::new(report.total_blocks) else {
        return PerformanceStore::new();
    };

    report
        .detectors
        .iter()
        .filter_map(|(id, stats)| {
            let precision = stats.precision()?;
            let recall = stats.recall()?;
            let hit_rate = report.hit_rate(id).unwrap_or(0.0);
            Some((
                id.clone(),
                PerformanceRecord {
                    precision,
                    recall,
                    hit_rate,
                    sample_size,
                    measured_at: Utc::now(),
                },
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DetectorStats;

    fn report_of(total_blocks: u64, entries: &[(&str, DetectorStats)]) -> Report {
        Report {
            fixtures: Vec::new(),
            detectors: entries
                .iter()
                .map(|(id, stats)| (id.to_string(), *stats))
                .collect(),
            total_blocks,
        }
    }

    fn measured() -> DetectorStats {
        DetectorStats {
            true_positives: 3,
            false_positives: 1,
            false_negatives: 0,
            blocks_hit: 3,
        }
    }

    #[test]
    fn from_report_fills_a_detector_with_both_precision_and_recall() {
        let report = report_of(100, &[("sandwich", measured())]);
        let store = from_report(&report);

        let record = store.get("sandwich").expect("sandwich was measured");
        assert_eq!(record.precision, 0.75);
        assert_eq!(record.recall, 1.0);
        assert_eq!(record.hit_rate, 0.03);
        assert_eq!(record.sample_size.get(), 100);
    }

    #[test]
    fn from_report_skips_a_detector_with_no_ground_truthed_recall() {
        // Raised alerts but no ground-truthed incident for it at all: recall is
        // `None`, so it must not be baselined at a fabricated number.
        let report = report_of(
            100,
            &[(
                "brand-new",
                DetectorStats {
                    true_positives: 0,
                    false_positives: 2,
                    false_negatives: 0,
                    blocks_hit: 2,
                },
            )],
        );
        assert!(from_report(&report).is_empty());
    }

    #[test]
    fn from_report_is_empty_over_an_empty_fixture_set() {
        let report = report_of(0, &[]);
        assert!(from_report(&report).is_empty());
    }

    #[test]
    fn from_report_round_trips_through_the_shared_store_io() {
        let report = report_of(100, &[("sandwich", measured())]);
        let store = from_report(&report);

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
