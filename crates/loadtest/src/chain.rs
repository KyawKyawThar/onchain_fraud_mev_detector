//! The synthetic chain: `BlockAssembled` at a target rate.
//!
//! ## The timestamp is the scheduled time, not the send time
//!
//! The fast path is measured from the block's `occurred_at`, which this
//! generator stamps. Stamping it at the moment of the send would hide the
//! harness's own lateness: when the broker back-pressures and a send takes
//! 400ms, the next block goes out late *and* carries a late timestamp, so its
//! measured latency is as short as if nothing had happened. That is coordinated
//! omission — the system slows down, the load generator politely slows down with
//! it, and the histogram reports the latency of a system under light load.
//!
//! So each block is stamped with the wall-clock time it was *due*, computed once
//! from an absolute schedule (`start + n × interval`), never by accumulating
//! sleeps. A generator that falls behind therefore inflates its own blocks'
//! measured latency, which is the honest direction: the pipeline really did
//! deliver that block's alert that long after the block was supposed to exist.
//!
//! ## What this load is and is not
//!
//! `BlockAssembled` carries a block ref, a tx count and a trace flag — no
//! transactions (§6's "header-only context today"). So `txs_per_block` sets the
//! *declared* chain tps and the event's payload size, and does not make the
//! detector fan-out do more work per block. This harness therefore measures the
//! pipeline — broker, consumer, queue, fan-out, publish — at chain rate, not the
//! per-transaction cost of a full bundle. That is the right subject for the §6
//! claim (the fast path is the plumbing) and it is a real limit on what a green
//! run proves; the report says so rather than leaving it to be discovered.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use event_bus::EventSink;
use events::chain::BlockAssembled;
use events::primitives::BlockRef;
use events::{DomainEvent, EventEnvelope};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::profile::Profile;
use crate::source::{self, LoadSource, Offered, Window};

/// The synthetic chain as a [`LoadSource`].
pub struct ChainLoad {
    sink: Arc<dyn EventSink>,
    profile: Profile,
    first_block: u64,
}

impl ChainLoad {
    pub fn new(sink: Arc<dyn EventSink>, profile: Profile) -> Self {
        Self {
            sink,
            profile,
            first_block: FIRST_BLOCK,
        }
    }
}

#[async_trait]
impl LoadSource for ChainLoad {
    fn name(&self) -> &'static str {
        source::CHAIN
    }

    async fn offer(&self, window: Window, shutdown: CancellationToken) -> Result<Offered> {
        generate(
            Arc::clone(&self.sink),
            &self.profile,
            window,
            self.first_block,
            shutdown,
        )
        .await
    }
}

/// Where the synthetic chain starts.
///
/// High enough that it cannot collide with a real chain's height in a shared
/// staging store, and constant so a rerun reuses the same block ids and the
/// event store dedups a repeat rather than accumulating one synthetic chain per
/// run.
const FIRST_BLOCK: u64 = 900_000_000;

/// Publish synthetic `BlockAssembled` events across `window` on an absolute
/// schedule, starting at block `first_block`.
///
/// The run's length comes from `window`, not from the profile: the orchestrator
/// owns the clock, so a shortened run shortens every source together (see
/// [`Window`]).
///
/// Returns early on cancellation, reporting what it managed — a cancelled run is
/// a short run, and the caller decides whether that is enough to judge.
async fn generate(
    sink: Arc<dyn EventSink>,
    profile: &Profile,
    window: Window,
    first_block: u64,
    shutdown: CancellationToken,
) -> Result<Offered> {
    let total = (window.total().as_secs_f64() * profile.blocks_per_second).round() as u64;
    let interval = Duration::from_secs_f64(1.0 / profile.blocks_per_second);
    let pattern = AlertPattern::new(profile.alerting_block_fraction);

    // The two clocks are anchored together once, so a scheduled monotonic
    // deadline can be named as the wall-clock timestamp a consumer will
    // subtract from. Re-deriving `Utc::now()` per block would reintroduce
    // exactly the send-time stamping the module docs rule out.
    let start_instant = Instant::now();
    let start_utc = Utc::now();

    let mut report = Offered {
        scheduled: total,
        target_rate: profile.blocks_per_second,
        // A published event has no status code, and a block's latency is the
        // *subject's* to report — that is the entire point of the fast-path
        // metric. So this source measures neither, and says so with `None`
        // rather than reporting a zero that would read as a measurement.
        ..Offered::none(source::CHAIN, "blocks/s", profile.blocks_per_second)
    };
    let mut alerting_blocks = 0u64;

    for n in 0..total {
        let due_in = interval.mul_f64(n as f64);
        let due_at = start_instant + due_in;
        let due_utc: DateTime<Utc> = start_utc
            + chrono::Duration::from_std(due_in).expect("a run's length fits in a chrono Duration");

        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            () = tokio::time::sleep_until(due_at) => {}
        }
        report.max_lateness = Some(
            report
                .max_lateness
                .unwrap_or_default()
                .max(due_at.elapsed()),
        );

        let number = first_block + n;
        let alerting = pattern.alerts(n);
        let envelope = EventEnvelope::with_metadata(
            uuid_for(number),
            due_utc,
            profile.chain(),
            DomainEvent::BlockAssembled(BlockAssembled {
                block: BlockRef::new(block_number(number, alerting), block_hash(number)),
                tx_count: profile.txs_per_block,
                trace_available: false,
            }),
        );

        match sink.publish(envelope).await {
            Ok(()) => {
                report.delivered += 1;
                alerting_blocks += u64::from(alerting);
            }
            Err(err) => {
                report.failed += 1;
                tracing::warn!(error = %err, block = number, "block publish failed");
            }
        }
    }

    report.elapsed = start_instant.elapsed();
    tracing::info!(
        delivered = report.delivered,
        alerting_blocks,
        "block generator finished"
    );
    Ok(report)
}

/// Which generated blocks should provoke an alert.
///
/// The only detector that can fire on a header-only `BlockAssembled` is
/// `demo-v0.1`, so "peak alert volume" is controlled by choosing block numbers
/// it fires on, not by synthesising evidence.
///
/// The *rule* is not duplicated here: [`block_number`] asks
/// [`demo_detector::fires_on`] which numbers qualify. Reimplementing the parity
/// test would mean a change to the detector's schedule silently desyncs the
/// harness — it would keep generating the old pattern, offer the wrong alert
/// volume, and report an inconclusive run whose message points at the wrong
/// cause.
///
/// A build under test must link `detection`'s `demo` feature; a run against a
/// build without it collects no alerting samples and is reported inconclusive
/// rather than passing on the `no_alert` series.
#[derive(Debug, Clone, Copy)]
struct AlertPattern {
    fraction: f64,
}

impl AlertPattern {
    fn new(fraction: f64) -> Self {
        Self { fraction }
    }

    /// Should the `n`-th generated block alert? A deterministic spread rather
    /// than a random draw, so two runs of the same profile offer the same load
    /// and their p99s are comparable.
    fn alerts(&self, n: u64) -> bool {
        if self.fraction <= 0.0 {
            return false;
        }
        if self.fraction >= 1.0 {
            return true;
        }
        // Bresenham-style: the count of alerting blocks up to `n` tracks
        // `n * fraction`, so the pattern is evenly spread instead of bursting at
        // the front — a front-loaded burst would measure a cold pipeline.
        let before = (n as f64 * self.fraction).floor();
        let after = ((n + 1) as f64 * self.fraction).floor();
        after > before
    }
}

/// Pick a block number that the demo detector will, or will not, fire on.
///
/// The candidate pair `2n` / `2n+1` guarantees a unique number per ordinal;
/// which of the two is the alerting one is [`demo_detector::fires_on`]'s to say,
/// not this module's. If that schedule ever changes to something parity cannot
/// express, this assertion fails loudly here rather than silently offering the
/// wrong alert volume.
fn block_number(n: u64, alerting: bool) -> u64 {
    let (even, odd) = (n * 2, n * 2 + 1);
    debug_assert!(
        demo_detector::fires_on(even) != demo_detector::fires_on(odd),
        "the demo detector's schedule must distinguish consecutive block numbers, \
         or this generator cannot control alert volume"
    );
    if demo_detector::fires_on(even) == alerting {
        even
    } else {
        odd
    }
}

/// Deterministic per-block hash — same profile, same bytes, so a rerun is a
/// rerun.
fn block_hash(n: u64) -> alloy_primitives::B256 {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&n.to_be_bytes());
    alloy_primitives::B256::from(bytes)
}

/// Deterministic per-block event id, so a redelivery of the same synthetic
/// block dedups in the event store the way a real one would (§7).
fn uuid_for(n: u64) -> uuid::Uuid {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&n.to_be_bytes());
    bytes[8..].copy_from_slice(b"loadtest");
    uuid::Uuid::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_alert_fraction_spreads_evenly_rather_than_bursting() {
        let half = AlertPattern::new(0.5);
        let first_ten: Vec<bool> = (0..10).map(|n| half.alerts(n)).collect();
        assert_eq!(first_ten.iter().filter(|a| **a).count(), 5);
        // Alternating, not five-then-five.
        assert_ne!(first_ten[0], first_ten[1]);
    }

    #[test]
    fn the_extremes_are_all_or_nothing() {
        assert!((0..5).all(|n| AlertPattern::new(1.0).alerts(n)));
        assert!((0..5).all(|n| !AlertPattern::new(0.0).alerts(n)));
    }

    #[test]
    fn a_quarter_fraction_alerts_a_quarter_of_the_time() {
        let p = AlertPattern::new(0.25);
        assert_eq!((0..100).filter(|n| p.alerts(*n)).count(), 25);
    }

    /// The coupling is one-directional now: the harness asks the detector,
    /// rather than both hard-coding "even".
    #[test]
    fn an_alerting_block_gets_a_number_the_demo_detector_actually_fires_on() {
        assert!(demo_detector::fires_on(block_number(3, true)));
        assert!(!demo_detector::fires_on(block_number(3, false)));
    }

    #[test]
    fn block_numbers_are_unique_across_the_parity_choice() {
        let mut seen = std::collections::HashSet::new();
        for n in 0..1000 {
            let alerting = AlertPattern::new(0.5).alerts(n);
            assert!(
                seen.insert(block_number(n, alerting)),
                "block numbers must not repeat — a repeat is a different block to the \
                 cross-block state and a duplicate to the event store"
            );
        }
    }

    #[test]
    fn the_block_generator_reports_no_latency_of_its_own() {
        let empty = Offered::none(source::CHAIN, "blocks/s", 1.0);
        assert!(
            empty.latency.is_none() && empty.outcomes.is_none(),
            "a block's latency is the subject's to report — that is what the \
             fast-path metric is for"
        );
    }
}
