//! The **scheduled** half of the §20.3 embedding job (Sprint 19 t1).
//!
//! This is the primary path, and the one §20.3 actually names. Cadence
//! features change with *time passing*, not with any event: an address that
//! stops transacting becomes dormant without anything being published about
//! it, so no invalidation stream can notice. Only a schedule can.
//!
//! It is also where the counterparty-distribution drift that
//! [`crate::embedding_consumer`] deliberately refuses to fan out on gets
//! picked up — see that module for why that refusal is the right one.
//!
//! ## Bounded, resumable, and shardable — in that order
//!
//! Each tick walks the addresses the graph has seen in a trailing window,
//! **cursor-paged** by address. Three properties follow from that shape:
//!
//! - **Bounded:** a per-tick address budget caps the work one tick does,
//!   whatever the graph did that hour.
//! - **Resumable:** on hitting the budget the cursor is *kept*, so the next
//!   tick continues the same window instead of restarting at the
//!   lowest-sorting address — which is the starvation this design exists to
//!   prevent, and the reason the budget is safe to set low.
//! - **Shardable:** because the cursor is a position in an ordered keyspace,
//!   [`Shard`] partitions that keyspace with no coordination and no
//!   rebalancing protocol. Each replica owns the addresses that hash into its
//!   index, reads only those rows, and keeps its own cursor.
//!
//! Sharding is the answer to "one pod cannot embed mainnet". Declaring the
//! key up front matters more than using it: an unsharded deployment is just
//! [`Shard::SINGLE`], while retrofitting a shard key onto a keyspace already
//! being walked is a flag day.

use std::time::Duration;

use chrono::{DateTime, Utc};
use event_bus::Transience;
use events::primitives::AccountAddress;
use tokio_util::sync::CancellationToken;

use crate::adjacency::Shard;
use crate::embedding_job::{Embedder, EmbeddingError, Trigger};

/// Ticks that ran out of address budget before finishing their window (§15 —
/// the monitoring path fails open, and counts that it did). A non-zero rate
/// means the sweep is not keeping up with graph activity: raise the budget,
/// shorten the interval, or add shards.
pub const SWEEP_BUDGET_EXHAUSTED_TOTAL: &str =
    "intelligence_embedding_sweep_budget_exhausted_total";
/// Candidate pages read from the adjacency store.
pub const SWEEP_PAGES_TOTAL: &str = "intelligence_embedding_sweep_pages_total";
/// Seconds to walk one window end to end — the **staleness SLI**. Not "did a
/// tick run" but "how long until an address is looked at again", which is
/// exactly the bound the similarity search (t2) and the clustering signal (t3)
/// inherit from this job. Recorded only when a window completes, so a stalled
/// window shows up as a *missing* observation next to a rising
/// `..._budget_exhausted_total`.
pub const SWEEP_LAP_SECONDS: &str = "intelligence_embedding_sweep_lap_seconds";

/// Operator-tunable bounds for the schedule.
#[derive(Debug, Clone, Copy)]
pub struct SweepLimits {
    /// How often the sweep ticks.
    pub interval: Duration,
    /// How far back a window reaches. Should comfortably exceed `interval` so
    /// a slow or restarted tick cannot leave a gap of addresses that were
    /// active but never swept.
    pub lookback: Duration,
    /// Candidate addresses per adjacency page.
    pub page_size: u32,
    /// Most addresses one tick will recompute. On hitting it the tick stops,
    /// counts [`SWEEP_BUDGET_EXHAUSTED_TOTAL`], and the *next* tick resumes
    /// from the same cursor in the same window.
    pub budget: usize,
    /// Which slice of the keyspace this replica owns.
    pub shard: Shard,
}

impl Default for SweepLimits {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(3_600),
            lookback: Duration::from_secs(3 * 3_600),
            page_size: 500,
            budget: 20_000,
            shard: Shard::SINGLE,
        }
    }
}

/// Where the sweep is in its walk. Carried across ticks so an unfinished
/// window resumes instead of restarting.
///
/// In-process by design, and cheap to lose: a restart re-opens a fresh window,
/// which at worst re-embeds addresses that were about to be skipped anyway
/// (and change detection makes that nearly free). Persisting it would buy
/// little and add a store dependency to the one component that has no
/// correctness stake in its own progress.
#[derive(Debug, Clone, Default)]
pub struct SweepState {
    /// The recency floor of the window currently being walked.
    pub window_start: DateTime<Utc>,
    /// When that window was opened — the lap-time baseline.
    pub window_opened_at: Option<DateTime<Utc>>,
    /// The last address fully computed in this window; `None` means "no window
    /// in progress, open a fresh one on the next tick".
    pub cursor: Option<AccountAddress>,
}

/// What one tick did — returned so a caller (and the tests) can assert on
/// progress without reading metrics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepReport {
    pub pages: usize,
    pub addresses: usize,
    /// The tick stopped on its budget with the window unfinished.
    pub budget_exhausted: bool,
    /// The window finished on this tick.
    pub window_completed: bool,
}

/// The scheduled sweep: a ticker over an [`Embedder`].
#[derive(Clone)]
pub struct EmbeddingSweep {
    embedder: Embedder,
    limits: SweepLimits,
}

impl EmbeddingSweep {
    pub fn new(embedder: Embedder, limits: SweepLimits) -> Self {
        Self { embedder, limits }
    }

    /// The bounds this sweep runs under.
    pub fn limits(&self) -> SweepLimits {
        self.limits
    }

    /// Run until shutdown.
    ///
    /// The tick is `MissedTickBehavior::Skip` — a sweep that overruns its
    /// interval must not queue a backlog of catch-up ticks that all read the
    /// same window (the ingestion pipeline's finalize ticker takes the same
    /// stance).
    pub async fn run(self, shutdown: CancellationToken) {
        let mut ticker = tokio::time::interval(self.limits.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut state = SweepState::default();

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    tracing::info!("embedding sweep shutting down");
                    return;
                }
                _ = ticker.tick() => {}
            }

            match self.tick(&mut state, Utc::now(), &shutdown).await {
                Ok(report) => {
                    if report.addresses > 0 || report.budget_exhausted {
                        tracing::info!(
                            pages = report.pages,
                            addresses = report.addresses,
                            budget_exhausted = report.budget_exhausted,
                            window_completed = report.window_completed,
                            shard = %self.limits.shard,
                            "embedding sweep tick"
                        );
                    }
                }
                Err(err) => {
                    // A failed sweep is not fatal: the cursor advanced only for
                    // completed pages, so the next tick resumes rather than
                    // repeating or skipping. The job degrades to "late", never
                    // to "stopped" (§15).
                    tracing::warn!(
                        error = %err,
                        transient = err.is_transient(),
                        shard = %self.limits.shard,
                        "embedding sweep tick failed; retrying on the next tick"
                    );
                }
            }
        }
    }

    /// One tick, factored out of the timer loop so it is testable against the
    /// in-memory doubles with no clock involved.
    pub async fn tick(
        &self,
        state: &mut SweepState,
        now: DateTime<Utc>,
        shutdown: &CancellationToken,
    ) -> Result<SweepReport, EmbeddingError> {
        // A cursor left over from a budget-exhausted tick means "finish that
        // window first"; otherwise open a fresh one.
        if state.cursor.is_none() {
            state.window_start = now
                - chrono::Duration::from_std(self.limits.lookback)
                    .unwrap_or_else(|_| chrono::Duration::hours(3));
            state.window_opened_at = Some(now);
        }

        let mut report = SweepReport::default();
        let mut budget = self.limits.budget;

        loop {
            if shutdown.is_cancelled() {
                return Ok(report);
            }
            let page = self
                .embedder
                .graph_active_addresses(
                    state.window_start,
                    state.cursor,
                    self.limits.page_size,
                    self.limits.shard,
                )
                .await?;
            metrics::counter!(SWEEP_PAGES_TOTAL).increment(1);
            report.pages += 1;

            if page.is_empty() {
                // Window exhausted — record the lap and open a fresh one next
                // tick.
                if let Some(opened_at) = state.window_opened_at {
                    let lap = now.signed_duration_since(opened_at);
                    if let Ok(lap) = lap.to_std() {
                        metrics::histogram!(SWEEP_LAP_SECONDS).record(lap.as_secs_f64());
                    }
                }
                state.cursor = None;
                state.window_opened_at = None;
                report.window_completed = true;
                return Ok(report);
            }

            let last = *page.last().expect("a non-empty page has a last address");
            let count = page.len();
            self.embedder.compute(&page, now, Trigger::Sweep).await?;

            // Advance only after the page is fully computed: a cursor moved
            // past addresses that failed would silently skip them until the
            // window rolled over.
            state.cursor = Some(last);
            report.addresses += count;
            budget = budget.saturating_sub(count);
            if budget == 0 {
                metrics::counter!(SWEEP_BUDGET_EXHAUSTED_TOTAL).increment(1);
                report.budget_exhausted = true;
                tracing::warn!(
                    window_start = %state.window_start,
                    cursor = %last,
                    shard = %self.limits.shard,
                    "embedding sweep hit its per-tick address budget; \
                     resuming from this cursor on the next tick"
                );
                return Ok(report);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adjacency::AdjacencyStore;
    use crate::embedding_job::tests::{
        addr, adjacency_edge, at, harness, harness_with, EmbeddingsExt, Harness,
    };
    use crate::embedding_job::EmbeddingLimits;
    use std::collections::BTreeSet;

    const HOUR: i64 = 3_600;

    fn sweep(h: &Harness, limits: SweepLimits) -> EmbeddingSweep {
        EmbeddingSweep::new(h.embedder.clone(), limits)
    }

    #[tokio::test]
    async fn the_sweep_embeds_every_recently_active_address() {
        let h = harness();
        h.graph
            .append(&[adjacency_edge(1, 2, 0), adjacency_edge(3, 4, HOUR)])
            .await
            .unwrap();

        let mut state = SweepState::default();
        let report = sweep(&h, SweepLimits::default())
            .tick(&mut state, at(2 * HOUR), &CancellationToken::new())
            .await
            .unwrap();

        let mut swept: Vec<_> = h.sink.embeddings().into_iter().map(|e| e.address).collect();
        swept.sort();
        assert_eq!(swept, vec![addr(1), addr(2), addr(3), addr(4)]);
        assert!(report.window_completed);
        assert!(!report.budget_exhausted);
        assert_eq!(
            state.cursor, None,
            "an exhausted window leaves no cursor behind"
        );
    }

    /// The lookback is what bounds the sweep's work: addresses whose last
    /// observation predates the window are not re-embedded every tick.
    #[tokio::test]
    async fn the_sweep_ignores_addresses_outside_its_lookback_window() {
        let h = harness();
        h.graph
            .append(&[adjacency_edge(1, 2, 0), adjacency_edge(3, 4, 10 * HOUR)])
            .await
            .unwrap();

        let mut state = SweepState::default();
        sweep(
            &h,
            SweepLimits {
                lookback: Duration::from_secs(HOUR as u64),
                ..Default::default()
            },
        )
        .tick(&mut state, at(10 * HOUR), &CancellationToken::new())
        .await
        .unwrap();

        let swept: BTreeSet<_> = h.sink.embeddings().into_iter().map(|e| e.address).collect();
        assert_eq!(swept, BTreeSet::from([addr(3), addr(4)]));
    }

    /// A graph busier than one tick's budget must fall behind *evenly*: the
    /// next tick resumes from the cursor rather than re-embedding the same
    /// lowest-sorting addresses forever while the rest starve. This is the
    /// property that makes a low budget safe.
    #[tokio::test]
    async fn a_budget_exhausted_sweep_resumes_from_its_cursor() {
        let h = harness();
        h.graph
            .append(&[
                adjacency_edge(1, 2, 0),
                adjacency_edge(3, 4, 0),
                adjacency_edge(5, 6, 0),
            ])
            .await
            .unwrap();

        let sweep = sweep(
            &h,
            SweepLimits {
                page_size: 2,
                budget: 2,
                ..Default::default()
            },
        );
        let shutdown = CancellationToken::new();
        let mut state = SweepState::default();

        let first_report = sweep.tick(&mut state, at(HOUR), &shutdown).await.unwrap();
        let first: Vec<_> = h.sink.embeddings().into_iter().map(|e| e.address).collect();
        assert_eq!(first, vec![addr(1), addr(2)]);
        assert!(first_report.budget_exhausted);
        assert!(!first_report.window_completed);
        assert_eq!(
            state.cursor,
            Some(addr(2)),
            "the window is left in progress"
        );
        let window = state.window_start;

        sweep
            .tick(&mut state, at(2 * HOUR), &shutdown)
            .await
            .unwrap();
        assert_eq!(
            state.window_start, window,
            "an unfinished window is resumed, not reopened at a later floor"
        );
        let second: Vec<_> = h
            .sink
            .embeddings()
            .into_iter()
            .skip(first.len())
            .map(|e| e.address)
            .collect();
        assert_eq!(second, vec![addr(3), addr(4)]);
    }

    #[tokio::test]
    async fn a_finished_window_reopens_at_a_fresh_floor_on_the_next_tick() {
        let h = harness();
        let sweep = sweep(
            &h,
            SweepLimits {
                lookback: Duration::from_secs(HOUR as u64),
                ..Default::default()
            },
        );
        let mut state = SweepState::default();
        let shutdown = CancellationToken::new();

        sweep
            .tick(&mut state, at(10 * HOUR), &shutdown)
            .await
            .unwrap();
        let first_floor = state.window_start;
        sweep
            .tick(&mut state, at(11 * HOUR), &shutdown)
            .await
            .unwrap();

        assert!(state.window_start > first_floor);
    }

    #[tokio::test]
    async fn a_cancelled_sweep_stops_between_pages() {
        let h = harness();
        h.graph
            .append(&[adjacency_edge(1, 2, 0), adjacency_edge(3, 4, 0)])
            .await
            .unwrap();

        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let mut state = SweepState::default();
        sweep(
            &h,
            SweepLimits {
                page_size: 1,
                ..Default::default()
            },
        )
        .tick(&mut state, at(HOUR), &shutdown)
        .await
        .unwrap();

        assert!(h.sink.embeddings().is_empty());
    }

    /// Change detection means a second tick over an unchanged graph does no
    /// writes at all — the property that makes an hourly sweep affordable.
    #[tokio::test]
    async fn a_second_tick_over_an_unchanged_graph_writes_nothing() {
        let h = harness_with(EmbeddingLimits {
            refresh_interval: Duration::from_secs(365 * 24 * 3_600),
            ..Default::default()
        });
        h.graph.append(&[adjacency_edge(1, 2, 0)]).await.unwrap();
        let sweep = sweep(&h, SweepLimits::default());
        let shutdown = CancellationToken::new();

        let mut state = SweepState::default();
        sweep.tick(&mut state, at(HOUR), &shutdown).await.unwrap();
        let after_first = h.embeddings.appended().len();

        let mut state = SweepState::default();
        sweep
            .tick(&mut state, at(2 * HOUR), &shutdown)
            .await
            .unwrap();

        assert_eq!(
            h.embeddings.appended().len(),
            after_first,
            "an unchanged second pass appends nothing"
        );
    }

    // ── Sharding ─────────────────────────────────────────────────────

    #[test]
    fn a_shard_index_outside_its_total_is_refused_at_construction() {
        use crate::adjacency::{Shard, ShardError};
        assert_eq!(Shard::new(0, 0), Err(ShardError::ZeroTotal));
        assert_eq!(
            Shard::new(4, 4),
            Err(ShardError::IndexOutOfRange { index: 4, total: 4 })
        );
        assert!(Shard::new(3, 4).is_ok());
        assert!(Shard::SINGLE.is_single());
        assert!(!Shard::new(0, 2).unwrap().is_single());
    }

    /// The sharding contract: shards **partition** the active set — every
    /// address is swept by exactly one shard, and together they cover
    /// everything. That is what lets replicas be added with no coordination
    /// and no rebalancing protocol.
    #[tokio::test]
    async fn shards_partition_the_active_set_with_no_overlap_and_no_gaps() {
        use crate::adjacency::Shard;

        let total = 3;
        let edges: Vec<_> = (1..=24u8).map(|n| adjacency_edge(n, 0xFF, 0)).collect();
        let expected: BTreeSet<_> = edges
            .iter()
            .flat_map(|e| [e.src, e.dst])
            .collect::<BTreeSet<_>>();

        let mut all: Vec<Vec<AccountAddress>> = Vec::new();
        for index in 0..total {
            let h = harness();
            h.graph.append(&edges).await.unwrap();
            let mut state = SweepState::default();
            sweep(
                &h,
                SweepLimits {
                    shard: Shard::new(index, total).unwrap(),
                    ..Default::default()
                },
            )
            .tick(&mut state, at(HOUR), &CancellationToken::new())
            .await
            .unwrap();

            let swept: Vec<_> = h.sink.embeddings().into_iter().map(|e| e.address).collect();
            all.push(swept);
        }

        // No overlap.
        for a in 0..all.len() {
            for b in (a + 1)..all.len() {
                let left: BTreeSet<_> = all[a].iter().copied().collect();
                let right: BTreeSet<_> = all[b].iter().copied().collect();
                assert!(
                    left.is_disjoint(&right),
                    "shards {a} and {b} both swept the same address"
                );
            }
        }
        // No gaps.
        let covered: BTreeSet<_> = all.iter().flatten().copied().collect();
        assert_eq!(covered, expected, "the shards must cover the whole set");
    }

    /// An unsharded deployment is just `Shard::SINGLE` — the whole keyspace.
    #[tokio::test]
    async fn the_single_shard_covers_everything() {
        let h = harness();
        let edges: Vec<_> = (1..=8u8).map(|n| adjacency_edge(n, 0xFF, 0)).collect();
        h.graph.append(&edges).await.unwrap();

        let all = h
            .graph
            .active_addresses(
                crate::embedding_job::tests::CHAIN,
                at(0),
                None,
                1_000,
                crate::adjacency::Shard::SINGLE,
            )
            .await
            .unwrap();
        assert_eq!(all.len(), 9, "eight sources plus the shared counterparty");
    }
}
