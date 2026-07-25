//! Safe-block-timing recommendation (§ safe-block-timing) — the pure fold
//! from a `(chain, severity)` pair's raw
//! [`TimingBucketRow`](crate::store::TimingBucketRow) rows (as read by
//! [`TimingStore::timing_buckets`](crate::store::TimingStore::timing_buckets))
//! into the `GET /v1/timing/recommendation` response ([`crate::http`]).
//!
//! No I/O, no async — a deterministic function of the rows it's given, so
//! it's `assert_eq!`-testable without ClickHouse, mirroring
//! [`crate::exposure`]'s outcome→summary fold.
//!
//! "Slot" here is a derived [`SLOT_MINUTES`]-wide UTC time-of-day bucket, not
//! an on-chain/beacon slot — `incident_analytics` carries no block/slot
//! number today. The `incident_timing_rollup_mv` materialized view
//! (`migrations/0004_create_incident_timing_rollup_mv.up.sql`) computes the
//! same bucket independently in SQL (it can't `use` a Rust const): if
//! `SLOT_MINUTES` ever changes here, that migration's `intDiv(..., 10)`
//! literal must change with it, or the two sides silently drift.
//!
//! "Size" is [`SizeBand`] — the incident's `severity` band, reused as-is
//! rather than inventing a second USD-threshold scheme.

use events::primitives::{Chain, Severity};

use crate::store::TimingBucketRow;

/// The "size" a caller queries by. Literally [`Severity`] — the confirmed-
/// incident data already carries a USD-impact band
/// (`events::scoring::severity_band`), and "how large a trade is" maps onto
/// "what severity of historical incident happened at that impact level"
/// closely enough to reuse it rather than invent a second banding scheme. A
/// plain alias, not a newtype, so every existing `Severity` API keeps
/// working — named here so the coupling is visible at the type level: a
/// future change to `severity_band`'s thresholds (an alert-scoring concern)
/// also silently redefines what "size" means on this endpoint.
pub type SizeBand = Severity;

/// 10-minute buckets across a UTC day: `24 * 60 / 10`.
pub const SLOT_MINUTES: u16 = 10;
pub const SLOTS_PER_DAY: u16 = 24 * 60 / SLOT_MINUTES;

/// How many ranked windows the recommendation surfaces — a top-N, not a full
/// 144-row dump (mirrors [`crate::store`]'s `Limit`-style bounded reads).
pub const RECOMMENDED_WINDOWS: usize = 5;

/// The fixed disclaimer every response carries — this is a heuristic over
/// historical patterns, never a promise. Stated once here so the wording
/// can't drift between call sites.
pub const TIMING_CAVEAT: &str =
    "Historical pattern only — a guide, not a guarantee of protection from MEV.";

/// One ranked low-MEV window in a [`TimingRecommendation`], safest first.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct TimingWindow {
    /// 1-based rank, safest window first.
    pub rank: u32,
    /// Inclusive UTC start of the window, `"HH:MM"`.
    pub slot_start: String,
    /// Exclusive UTC end of the window, `"HH:MM"`.
    pub slot_end: String,
    pub incident_count: u64,
    /// `incident_count / sample_size`; `0.0` when `sample_size` is zero
    /// (no historical data yet) rather than `NaN`.
    pub share_of_incidents: f64,
}

/// The full `GET /v1/timing/recommendation` response body.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct TimingRecommendation {
    pub chain: u64,
    /// The "size" band the caller queried, as its wire string.
    pub size: &'static str,
    /// Total confirmed incidents observed for this chain/size across every
    /// slot — the sample the ranking is drawn from. `0` is a valid, honest
    /// answer (no history yet), not hidden: paired with [`Self::caveat`] it
    /// tells the caller not to over-trust a ranking with no data behind it.
    pub sample_size: u64,
    /// Ranked ascending by historical incident intensity, safest first.
    pub windows: Vec<TimingWindow>,
    pub caveat: &'static str,
}

/// Format a slot index (`0..SLOTS_PER_DAY`) as its UTC `"HH:MM"` start time.
fn format_slot_start(slot_of_day: u16) -> String {
    let minutes = slot_of_day * SLOT_MINUTES;
    format!("{:02}:{:02}", minutes / 60, minutes % 60)
}

/// Fold a chain/severity's raw rollup rows into the ranked recommendation.
///
/// A slot absent from `rows` had zero confirmed incidents — the *safest*
/// kind of window — so every slot in `0..SLOTS_PER_DAY` is a ranking
/// candidate, not just the ones the sparse rollup happened to write a row
/// for. Ties (most commonly every slot, when `sample_size == 0`) break on
/// `slot_of_day` ascending for a deterministic, reproducible order (mirrors
/// `leaderboard.rs`'s stable tiebreak).
pub fn rank_windows(
    chain: Chain,
    severity: SizeBand,
    rows: Vec<TimingBucketRow>,
) -> TimingRecommendation {
    let mut counts = vec![0u64; SLOTS_PER_DAY as usize];
    for row in rows {
        if let Some(slot) = counts.get_mut(row.slot_of_day as usize) {
            *slot += row.incident_count;
        }
    }
    let sample_size: u64 = counts.iter().sum();

    let mut slots: Vec<(u16, u64)> = counts
        .into_iter()
        .enumerate()
        .map(|(slot, count)| (slot as u16, count))
        .collect();
    slots.sort_by_key(|&(slot, count)| (count, slot));

    let windows = slots
        .into_iter()
        .take(RECOMMENDED_WINDOWS)
        .enumerate()
        .map(|(index, (slot_of_day, incident_count))| TimingWindow {
            rank: index as u32 + 1,
            slot_start: format_slot_start(slot_of_day),
            slot_end: format_slot_start((slot_of_day + 1) % SLOTS_PER_DAY),
            incident_count,
            share_of_incidents: if sample_size == 0 {
                0.0
            } else {
                incident_count as f64 / sample_size as f64
            },
        })
        .collect();

    TimingRecommendation {
        chain: chain.id(),
        size: <&'static str>::from(severity),
        sample_size,
        windows,
        caveat: TIMING_CAVEAT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(slot_of_day: u16, incident_count: u64) -> TimingBucketRow {
        TimingBucketRow {
            slot_of_day,
            incident_count,
            total_victim_loss_usd: 0.0,
        }
    }

    #[test]
    fn no_rows_yields_zero_sample_size_but_still_five_windows() {
        let rec = rank_windows(Chain::ETHEREUM, Severity::High, vec![]);
        assert_eq!(rec.sample_size, 0);
        assert_eq!(rec.windows.len(), RECOMMENDED_WINDOWS);
        // Every slot ties at zero, so the deterministic tiebreak picks the
        // first N slots in order.
        assert_eq!(rec.windows[0].slot_start, "00:00");
        assert_eq!(rec.windows[0].incident_count, 0);
        assert_eq!(rec.windows[0].share_of_incidents, 0.0);
        assert_eq!(rec.caveat, TIMING_CAVEAT);
        assert_eq!(rec.size, "high");
        assert_eq!(rec.chain, Chain::ETHEREUM.id());
    }

    #[test]
    fn a_zero_incident_slot_absent_from_rows_still_ranks_as_safest() {
        // Slot 5 (00:50) has one incident; every other slot (including ones
        // never written to the sparse rollup) has none and must outrank it.
        let rec = rank_windows(Chain::ETHEREUM, Severity::Medium, vec![row(5, 1)]);
        assert_eq!(rec.sample_size, 1);
        assert!(
            rec.windows.iter().all(|w| w.incident_count == 0),
            "a single incident among 144 slots must not appear in the top 5 safest"
        );
    }

    #[test]
    fn windows_rank_ascending_by_incident_count_with_deterministic_tiebreak() {
        let rows = vec![row(0, 10), row(1, 0), row(2, 5), row(3, 0)];
        let rec = rank_windows(Chain::ETHEREUM, Severity::Low, rows);
        // Slots 1 and 3 tie at zero; slot 1 sorts first (lower slot index).
        assert_eq!(rec.windows[0].slot_start, "00:10");
        assert_eq!(rec.windows[0].incident_count, 0);
        assert_eq!(rec.windows[1].slot_start, "00:30");
        assert_eq!(rec.windows[1].incident_count, 0);
        // Every other untouched slot also ties at zero and sorts before the
        // slots with actual incidents.
        assert_eq!(rec.windows[2].incident_count, 0);
        assert_eq!(rec.windows[2].rank, 3);
    }

    #[test]
    fn share_of_incidents_divides_by_the_full_sample() {
        // Every slot carries exactly one incident, so all 144 tie and the
        // sample is the full slot count — a clean, checkable division.
        let rows: Vec<TimingBucketRow> = (0..SLOTS_PER_DAY).map(|slot| row(slot, 1)).collect();
        let rec = rank_windows(Chain::ETHEREUM, Severity::Critical, rows);
        assert_eq!(rec.sample_size, u64::from(SLOTS_PER_DAY));
        assert_eq!(rec.windows[0].incident_count, 1);
        assert_eq!(
            rec.windows[0].share_of_incidents,
            1.0 / f64::from(SLOTS_PER_DAY)
        );
    }

    #[test]
    fn a_mid_day_slot_formats_and_ranks_correctly() {
        // Every slot but 90 has an incident, so slot 90 (minute 900 ->
        // 15:00) is the unique safest window and ranks first.
        let rows: Vec<TimingBucketRow> = (0..SLOTS_PER_DAY)
            .filter(|&slot| slot != 90)
            .map(|slot| row(slot, 1))
            .collect();
        let rec = rank_windows(Chain::ETHEREUM, Severity::Low, rows);
        let slot90 = &rec.windows[0];
        assert_eq!(slot90.slot_start, "15:00");
        assert_eq!(slot90.slot_end, "15:10");
        assert_eq!(slot90.incident_count, 0);
    }

    #[test]
    fn the_last_slot_of_the_day_wraps_its_end_to_midnight_not_24_00() {
        // Every slot but the last (143, 23:50) has an incident, so it's the
        // unique safest window; its end must read "00:00", not "24:00" -
        // exercises the `% SLOTS_PER_DAY` wraparound `rank_windows` applies,
        // not just the private `format_slot_start` helper in isolation.
        let rows: Vec<TimingBucketRow> = (0..SLOTS_PER_DAY - 1).map(|slot| row(slot, 1)).collect();
        let rec = rank_windows(Chain::ETHEREUM, Severity::Low, rows);
        let last = &rec.windows[0];
        assert_eq!(last.slot_start, "23:50");
        assert_eq!(last.slot_end, "00:00");
    }
}
