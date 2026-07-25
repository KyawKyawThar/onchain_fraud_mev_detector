//! The scheduled §25 exposure-report push (Sprint 15 t5): once per cycle,
//! every opted-in [`MonitoredWallet`] gets a fresh `WalletExposureReportReady`
//! published for notification to deliver, plus one `WalletMonitored`
//! [`UsageFact`] — the "per customer-configured address" §13 metering, fired
//! recurringly (once per wallet per cycle) rather than once at opt-in, since
//! it bills the ongoing act of monitoring, not the one-time opt-in call.
//!
//! **Reorg-safety by construction, not by new machinery**: [`run_cycle`] calls
//! the exact same [`WalletExposureStore::mev_exposure`] the on-demand `GET
//! /v1/wallet/{addr}/mev-exposure` endpoint uses, live, every cycle — never a
//! cached snapshot. That store already folds each incident to its latest
//! `IncidentRetracted`-aware state (§15), so a reorg that withdrew an
//! incident between cycles is excluded here for free, the same way it's
//! excluded from the live endpoint.
//!
//! **Scale**: [`run_cycle`] pages through [`MonitoredWalletStore::list_all`]
//! (never loads every monitored wallet into memory at once) and processes
//! each page with up to [`MAX_CONCURRENCY`] wallets in flight at a time
//! (`futures_util::stream::StreamExt::buffer_unordered`), rather than one
//! `.await` at a time — at real scale a serial loop can't finish a cycle
//! before the next one is due. `shutdown` is checked between pages so a
//! graceful drain doesn't have to walk an entire large table first.

use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use event_bus::usage::UsageFact;
use event_bus::EventSink;
use events::simulation::WalletExposureReportReady;
use events::system::UsageEventType;
use events::{DomainEvent, EventEnvelope};
use futures_util::stream::{self, StreamExt};
use tokio_util::sync::CancellationToken;

use crate::exposure::{self, MevExposureSummary};
use crate::monitored_wallet_store::{MonitoredWallet, MonitoredWalletCursor, MonitoredWalletStore};
use crate::store::{PersistError, WalletExposureStore};

/// Rows per [`MonitoredWalletStore::list_all`] page. Small enough that one
/// page comfortably fits in memory and a page-boundary shutdown check has
/// low latency; large enough that pagination overhead is negligible next to
/// the per-wallet work.
const PAGE_LIMIT: u64 = 500;

/// Max wallets processed concurrently within a page. Bounds the fan-out
/// against both the exposure store and the event sink — this is I/O
/// concurrency (interleaved polling on one task), not OS parallelism, which
/// is exactly what's wanted for network-bound work like this.
const MAX_CONCURRENCY: usize = 16;

/// Histogram: one sample per completed [`run_cycle`] call, spanning every
/// page and every wallet — the cycle's total wall-clock cost.
pub const EXPOSURE_REPORT_CYCLE_DURATION_SECONDS: &str = "exposure_report_cycle_duration_seconds";
/// Counter: one increment per wallet processed this cycle, labeled `outcome`
/// (`published`/`exposure_fetch_failed`) — mirrors `SIMULATION_JOBS_TOTAL`'s
/// outcome-label convention (`crate::metrics`).
pub const EXPOSURE_REPORT_WALLETS_TOTAL: &str = "exposure_report_wallets_total";

/// One human-readable line summarizing a wallet's exposure over the report
/// period — what `Notice::from_exposure_report` delivers verbatim as the
/// notice's message, so notification never has to know
/// [`MevExposureSummary`]'s field shape.
fn headline(summary: &MevExposureSummary) -> String {
    if summary.incident_count == 0 {
        "no MEV exposure this period".to_owned()
    } else {
        format!(
            "${:.2} lost across {} incident{} this period (worst: ${:.2})",
            summary.total_usd_lost,
            summary.incident_count,
            if summary.incident_count == 1 { "" } else { "s" },
            summary.worst_usd_lost,
        )
    }
}

/// How one wallet's processing resolved this cycle — what [`run_cycle`]
/// tallies into [`CycleStats`]/metrics, and what an exposure-fetch fault
/// degrades to rather than aborting the whole cycle (see the module docs).
enum WalletOutcome {
    Published,
    ExposureFetchFailed,
}

/// What one [`run_cycle`] call did — logged by the caller (`bin/projection.rs`)
/// and folded into [`EXPOSURE_REPORT_WALLETS_TOTAL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CycleStats {
    pub wallets_published: usize,
    pub wallets_failed: usize,
}

/// Compute one wallet's exposure and publish it (plus the `WalletMonitored`
/// usage fact) — the unit of work [`run_cycle`] fans out with bounded
/// concurrency. A fault fetching this wallet's exposure is logged and
/// downgraded to [`WalletOutcome::ExposureFetchFailed`] rather than
/// propagated — one ClickHouse hiccup on one wallet must not withhold every
/// other customer's report in the same page.
async fn process_wallet(
    wallet: MonitoredWallet,
    exposure_store: &dyn WalletExposureStore,
    sink: &dyn EventSink,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
    backoff: Duration,
    shutdown: &CancellationToken,
) -> WalletOutcome {
    let rows = match exposure_store
        .mev_exposure(&wallet.address, Some(period_start))
        .await
    {
        Ok(rows) => rows,
        Err(err) => {
            tracing::warn!(
                error = %err,
                owner = %wallet.owner,
                address = %wallet.address,
                "fetching this cycle's exposure failed for one monitored wallet; skipping it this cycle"
            );
            return WalletOutcome::ExposureFetchFailed;
        }
    };
    let summary = exposure::summarize(rows);
    let headline = headline(&summary);

    let event = WalletExposureReportReady {
        customer_id: wallet.owner,
        address: wallet.address,
        period_start,
        period_end,
        headline,
        summary: serde_json::to_value(&summary).unwrap_or(serde_json::Value::Null),
    };
    event_bus::publish_resilient(
        sink,
        EventEnvelope::new(wallet.chain, DomainEvent::WalletExposureReportReady(event)),
        backoff,
        shutdown,
    )
    .await;

    UsageFact::new(UsageEventType::WalletMonitored, 1)
        .for_customer(wallet.owner)
        .record(sink, wallet.chain, backoff, shutdown)
        .await;

    WalletOutcome::Published
}

/// One scheduled cycle — the core, free of the interval loop that drives it
/// (`bin/projection.rs`), so it's testable with no `tokio::time` involved.
///
/// Every opted-in wallet is a candidate regardless of owner (`list_all`
/// deliberately crosses owners, see its docs), paged and processed with
/// bounded concurrency (see the module docs on scale). A fault listing a page
/// of wallets is fatal to the cycle and propagated, so the caller can log it
/// and simply try again next tick — unlike a single wallet's exposure fetch,
/// there's no partial result to salvage from a broken listing.
pub async fn run_cycle(
    monitored: &dyn MonitoredWalletStore,
    exposure_store: &dyn WalletExposureStore,
    sink: &dyn EventSink,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
    backoff: Duration,
    shutdown: &CancellationToken,
) -> Result<CycleStats, PersistError> {
    let cycle_started = Instant::now();
    let mut cursor: Option<MonitoredWalletCursor> = None;
    let mut stats = CycleStats::default();

    loop {
        let page = monitored.list_all(cursor, PAGE_LIMIT).await?;
        cursor = page.next_cursor;

        let outcomes: Vec<WalletOutcome> = stream::iter(page.wallets)
            .map(|wallet| {
                process_wallet(
                    wallet,
                    exposure_store,
                    sink,
                    period_start,
                    period_end,
                    backoff,
                    shutdown,
                )
            })
            .buffer_unordered(MAX_CONCURRENCY)
            .collect()
            .await;

        for outcome in outcomes {
            match outcome {
                WalletOutcome::Published => stats.wallets_published += 1,
                WalletOutcome::ExposureFetchFailed => stats.wallets_failed += 1,
            }
        }

        // Between pages, not mid-page: bounds a graceful drain's latency to
        // one page's worth of in-flight work rather than abandoning it, while
        // still not walking the rest of a large table once shutdown fires.
        if cursor.is_none() || shutdown.is_cancelled() {
            break;
        }
    }

    record_cycle(cycle_started.elapsed(), &stats);
    Ok(stats)
}

/// Record one completed cycle's duration and per-wallet outcome tally. A
/// plain sync function (not folded into [`run_cycle`] itself) so it's
/// `metrics::with_local_recorder`-testable in isolation, the same split
/// `notification::delivery`'s `count_delivery` uses.
fn record_cycle(elapsed: Duration, stats: &CycleStats) {
    metrics::histogram!(EXPOSURE_REPORT_CYCLE_DURATION_SECONDS).record(elapsed.as_secs_f64());
    metrics::counter!(EXPOSURE_REPORT_WALLETS_TOTAL, "outcome" => "published")
        .increment(stats.wallets_published as u64);
    metrics::counter!(EXPOSURE_REPORT_WALLETS_TOTAL, "outcome" => "exposure_fetch_failed")
        .increment(stats.wallets_failed as u64);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{
        InMemoryMonitoredWalletStore, InMemoryWalletExposure, RecordingEventSink,
    };
    use events::primitives::{AccountAddress, Chain, CustomerId};
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::CompositeKey;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    #[test]
    fn headline_reports_zero_exposure_plainly() {
        let summary = exposure::summarize(vec![]);
        assert_eq!(headline(&summary), "no MEV exposure this period");
    }

    #[test]
    fn headline_singularizes_one_incident() {
        let summary = exposure::summarize(vec![InMemoryWalletExposure::row(
            uuid::Uuid::from_u128(1),
            "sandwich",
            100.0,
            at(1),
        )]);
        let line = headline(&summary);
        assert!(line.contains("1 incident"), "{line}");
        assert!(!line.contains("1 incidents"), "{line}");
    }

    #[tokio::test]
    async fn run_cycle_publishes_one_report_and_meters_wallet_monitored_per_wallet() {
        let monitored = InMemoryMonitoredWalletStore::new();
        let owner = CustomerId::new();
        let address = AccountAddress::repeat_byte(7);
        monitored
            .add(owner, Chain::ETHEREUM, address, Utc::now())
            .await
            .unwrap();

        let exposure_store = InMemoryWalletExposure::new(vec![InMemoryWalletExposure::row(
            uuid::Uuid::from_u128(1),
            "sandwich",
            250.0,
            at(1),
        )]);
        let sink = RecordingEventSink::default();
        let shutdown = CancellationToken::new();

        let stats = run_cycle(
            &monitored,
            &exposure_store,
            &sink,
            at(0),
            at(100),
            Duration::from_millis(1),
            &shutdown,
        )
        .await
        .unwrap();
        assert_eq!(stats.wallets_published, 1);
        assert_eq!(stats.wallets_failed, 0);

        let published = sink.events();
        let reports: Vec<_> = published
            .iter()
            .filter_map(|e| match e {
                DomainEvent::WalletExposureReportReady(r) => Some(r),
                _ => None,
            })
            .collect();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].customer_id, owner);
        assert_eq!(reports[0].address, address);
        assert!(reports[0].headline.contains("250.00"));

        let usage: Vec<_> = published
            .iter()
            .filter_map(|e| match e {
                DomainEvent::UsageRecorded(u) => Some(u),
                _ => None,
            })
            .collect();
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].customer_id, Some(owner));
        assert_eq!(
            usage[0].event_type,
            UsageEventType::WalletMonitored.as_wire_str()
        );
    }

    /// The reorg-safety claim, exercised end to end through this module's own
    /// entry point (not just the underlying store, which already has its own
    /// coverage): a wallet whose only incident was retracted must produce a
    /// zero-exposure report, never the pre-retraction loss.
    #[tokio::test]
    async fn run_cycle_excludes_a_retracted_incidents_loss() {
        let monitored = InMemoryMonitoredWalletStore::new();
        let owner = CustomerId::new();
        let address = AccountAddress::repeat_byte(9);
        monitored
            .add(owner, Chain::ETHEREUM, address, Utc::now())
            .await
            .unwrap();

        // A `WalletExposureStore` only ever hands back rows for incidents that
        // are still `confirmed` (§15's exclusion happens inside the store, see
        // `store::WalletExposureStore::mev_exposure`'s docs) — a retracted
        // incident never reaches this call in the first place, so the double
        // below stands in for "already retracted, so no rows".
        let exposure_store = InMemoryWalletExposure::new(vec![]);
        let sink = RecordingEventSink::default();
        let shutdown = CancellationToken::new();

        run_cycle(
            &monitored,
            &exposure_store,
            &sink,
            at(0),
            at(100),
            Duration::from_millis(1),
            &shutdown,
        )
        .await
        .unwrap();

        let published = sink.events();
        let report = published
            .iter()
            .find_map(|e| match e {
                DomainEvent::WalletExposureReportReady(r) => Some(r),
                _ => None,
            })
            .expect("a report is still published for a zero-exposure period");
        assert_eq!(report.headline, "no MEV exposure this period");
    }

    /// Regression guard for the concurrency fix itself: with `MAX_CONCURRENCY`
    /// wallets or more all blocked in-flight at once, more than one must be
    /// mid-`mev_exposure` at the same time — a plain sequential loop would
    /// never let the observed peak rise above 1.
    #[tokio::test]
    async fn run_cycle_processes_wallets_concurrently_not_one_at_a_time() {
        struct ConcurrencyTrackingExposure {
            in_flight: AtomicUsize,
            peak: AtomicUsize,
        }

        #[async_trait::async_trait]
        impl WalletExposureStore for ConcurrencyTrackingExposure {
            async fn mev_exposure(
                &self,
                _victim_address: &AccountAddress,
                _since: Option<DateTime<Utc>>,
            ) -> Result<Vec<crate::store::ExposureRow>, PersistError> {
                let now_in_flight = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                self.peak.fetch_max(now_in_flight, Ordering::SeqCst);
                // Yield long enough that, if wallets ran strictly one at a
                // time, every other in-flight task would already have
                // finished before this one even started.
                tokio::time::sleep(Duration::from_millis(20)).await;
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                Ok(vec![])
            }
        }

        let monitored = InMemoryMonitoredWalletStore::new();
        for i in 0..(MAX_CONCURRENCY as u8 * 2) {
            monitored
                .add(
                    CustomerId::new(),
                    Chain::ETHEREUM,
                    AccountAddress::repeat_byte(i),
                    Utc::now(),
                )
                .await
                .unwrap();
        }

        let exposure_store = Arc::new(ConcurrencyTrackingExposure {
            in_flight: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        });
        let sink = RecordingEventSink::default();
        let shutdown = CancellationToken::new();

        run_cycle(
            &monitored,
            exposure_store.as_ref(),
            &sink,
            at(0),
            at(100),
            Duration::from_millis(1),
            &shutdown,
        )
        .await
        .unwrap();

        let peak = exposure_store.peak.load(Ordering::SeqCst);
        assert!(
            peak > 1,
            "expected concurrent in-flight calls, saw peak {peak}"
        );
        assert!(
            peak <= MAX_CONCURRENCY,
            "must never exceed the concurrency bound, saw peak {peak}"
        );
    }

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

    fn has_series(series: &Series, name: &str) -> bool {
        series.iter().any(|(ck, ..)| ck.key().name() == name)
    }

    #[test]
    fn record_cycle_emits_duration_and_per_outcome_counts() {
        let stats = CycleStats {
            wallets_published: 3,
            wallets_failed: 1,
        };
        let series = captured(|| record_cycle(Duration::from_millis(250), &stats));

        assert!(has_series(&series, EXPOSURE_REPORT_CYCLE_DURATION_SECONDS));
        assert!(has_series(&series, EXPOSURE_REPORT_WALLETS_TOTAL));

        let published = series
            .iter()
            .find(|(ck, ..)| {
                ck.key().name() == EXPOSURE_REPORT_WALLETS_TOTAL
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "outcome" && l.value() == "published")
            })
            .map(|(.., value)| value);
        assert_eq!(published, Some(&DebugValue::Counter(3)));

        let failed = series
            .iter()
            .find(|(ck, ..)| {
                ck.key().name() == EXPOSURE_REPORT_WALLETS_TOTAL
                    && ck
                        .key()
                        .labels()
                        .any(|l| l.key() == "outcome" && l.value() == "exposure_fetch_failed")
            })
            .map(|(.., value)| value);
        assert_eq!(failed, Some(&DebugValue::Counter(1)));
    }
}
