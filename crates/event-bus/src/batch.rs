//! The micro-batching consume loop — for sinks whose downstream store wants
//! few large writes, not many small ones (ClickHouse's parts economics: every
//! insert is an on-disk part, and per-record inserts hit `TOO_MANY_PARTS` long
//! before CPU matters).
//!
//! The shape mirrors [`crate::run_consumer`] (subscribe, shutdown-aware
//! receive, decode-or-skip poison, trace continuation) with one structural
//! difference: **offsets are committed per flush, not per record**. The loop
//! accumulates handler-accepted items until either [`BatchConfig::max_items`]
//! or [`BatchConfig::max_wait`] is reached, calls the handler's `flush` once,
//! and only then commits the high-water offset of every partition the batch
//! touched. At-least-once is preserved: a crash between flush and commit
//! redelivers the whole batch, so — exactly as with `run_consumer` — the
//! flush must be idempotent (the usage sink's `ReplacingMergeTree` key, the
//! event-store's dedupe-by-`event_id` posture).
//!
//! Failure policy per flush, mirroring the per-record [`crate::handled`]
//! discipline: a *transient* flush error (store unreachable) retries the same
//! batch over [`BatchConfig::retry_backoff`] until it succeeds or shutdown —
//! nothing is committed, nothing is lost; a *permanent* one (an encode bug
//! that fails identically on every retry) drops the batch loudly and commits,
//! so one poison batch can't wedge the stream. Records the handler rejects
//! up front ([`Accepted::Skip`]) are parked on the [`DeadLetterQueue`] (when
//! one is wired) and committed with the batch.
//!
//! On shutdown the loop drains what it holds: one final flush attempt bounded
//! by [`BatchConfig::shutdown_flush_grace`], so a broker/store that is down
//! *at* shutdown can't hang the process — anything the deadline cuts off is
//! left uncommitted for redelivery on restart, and logged with a count.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use events::EventEnvelope;
use rdkafka::consumer::{CommitMode, Consumer, ConsumerContext, StreamConsumer};
use rdkafka::{Message, Offset, TopicPartitionList};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::dlq::DeadLetterQueue;
use crate::Transience;

/// Counter (labeled by `consumer` and `outcome`): batch flushes.
/// `outcome="committed"` is the healthy path; `outcome="dropped_permanent"`
/// means a whole batch was discarded on a permanent flush error (alert);
/// `outcome="abandoned_shutdown"` means a shutdown deadline cut a final flush
/// off (redelivered on restart, not lost — but worth watching).
pub const BATCH_FLUSH_TOTAL: &str = "batch_flush_total";

/// How a batch loop sizes and paces its flushes.
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Flush when this many items have accumulated.
    pub max_items: usize,
    /// Flush when the oldest buffered record has waited this long — bounds
    /// end-to-end latency on a quiet stream.
    pub max_wait: Duration,
    /// Back-off between retries of a transiently-failed flush.
    pub retry_backoff: Duration,
    /// Ceiling on the final drain-flush at shutdown.
    pub shutdown_flush_grace: Duration,
}

/// The handler's verdict on one decoded record, made *before* it enters the
/// batch — the cheap, per-record half of a batching sink.
pub enum Accepted<T> {
    /// Mapped to the batch item type; will be flushed with the batch.
    Item(T),
    /// Can never be processed (a misrouted event type, a mapping bug that is
    /// identical on every retry). Parked on the DLQ when one is wired, then
    /// committed with the batch so it can't wedge the stream.
    Skip {
        /// Why — lands in the DLQ record's `dlq.error` header and the log.
        error: String,
    },
}

/// A batching sink's two decisions: the per-record mapping and the per-batch
/// write. Everything else — pacing, offsets, retries, the DLQ, shutdown
/// draining — is the loop's ([`run_batch_consumer`]).
#[async_trait]
pub trait BatchHandler: Send + Sync {
    /// What a record becomes inside a batch.
    type Item: Send;
    /// Why a flush failed; its [`Transience`] drives retry-vs-drop.
    type FlushError: Transience + std::fmt::Display + Send;

    /// Map one decoded envelope, or reject it as unprocessable. Must be cheap
    /// and side-effect-free — it runs inline in the consume loop.
    fn accept(&self, envelope: EventEnvelope) -> Accepted<Self::Item>;

    /// Write one batch. Called with the same slice again on a transient
    /// failure, so it must be safe to re-run (at-least-once).
    async fn flush(&self, items: &[Self::Item]) -> Result<(), Self::FlushError>;
}

/// The pure batching bookkeeping — what to buffer, when to flush, what to
/// commit — split from the I/O loop so the interesting decisions are unit
/// tested without a broker (the `TopicSpec`-vs-`ensure_topics` split).
struct BatchState<T> {
    items: Vec<T>,
    /// Per-partition high-water mark: the *next* offset to consume (Kafka
    /// commit semantics: last handled + 1).
    watermarks: HashMap<(String, i32), i64>,
    /// When the oldest pending work arrived — the max_wait clock. Set on the
    /// first buffered item *or* skipped record (a poison-only stretch must
    /// still get its offsets committed, not wait forever for a real item).
    since: Option<Instant>,
}

impl<T> BatchState<T> {
    fn new() -> Self {
        Self {
            items: Vec::new(),
            watermarks: HashMap::new(),
            since: None,
        }
    }

    /// Record that `(topic, partition)` is handled through `offset` — called
    /// for accepted, skipped, and poison records alike (all three advance the
    /// stream once the surrounding batch commits).
    fn note_handled(&mut self, topic: &str, partition: i32, offset: i64) {
        self.watermarks
            .insert((topic.to_owned(), partition), offset + 1);
        self.since.get_or_insert_with(Instant::now);
    }

    fn push(&mut self, item: T) {
        self.items.push(item);
    }

    /// Nothing buffered *and* nothing to commit.
    fn is_empty(&self) -> bool {
        self.watermarks.is_empty()
    }

    /// The instant the max_wait clock expires, if it is running.
    fn deadline(&self, max_wait: Duration) -> Option<Instant> {
        self.since.map(|since| since + max_wait)
    }

    fn is_full(&self, max_items: usize) -> bool {
        self.items.len() >= max_items
    }

    /// The offsets to commit for this batch, as rdkafka wants them.
    fn commit_list(&self) -> TopicPartitionList {
        let mut list = TopicPartitionList::new();
        for ((topic, partition), next_offset) in &self.watermarks {
            // Building a TPL from known-good coordinates cannot fail; if it
            // ever does, skipping the commit is safe (redelivery, not loss).
            let _ = list.add_partition_offset(topic, *partition, Offset::Offset(*next_offset));
        }
        list
    }

    fn clear(&mut self) {
        self.items.clear();
        self.watermarks.clear();
        self.since = None;
    }
}

/// Drive a [`BatchHandler`] over `topics` until shutdown — the batching
/// counterpart of [`crate::run_consumer`]; see the module docs for the commit
/// and failure discipline. Generic over the consumer's context so callers can
/// pass a metrics-reporting one ([`crate::lag::LagReporting`]).
pub async fn run_batch_consumer<C, H>(
    consumer: StreamConsumer<C>,
    topics: &[&str],
    name: &str,
    cfg: BatchConfig,
    handler: H,
    dlq: Option<&DeadLetterQueue>,
    shutdown: &CancellationToken,
) -> Result<()>
where
    C: ConsumerContext + 'static,
    H: BatchHandler,
{
    consumer
        .subscribe(topics)
        .with_context(|| format!("{name}: subscribing to {topics:?}"))?;
    tracing::info!(
        consumer = name,
        topics = topics.len(),
        max_items = cfg.max_items,
        max_wait_ms = cfg.max_wait.as_millis() as u64,
        "batch consumer subscribed"
    );

    let mut state: BatchState<H::Item> = BatchState::new();

    loop {
        // Three wake-ups: shutdown (drain + exit), the max_wait deadline
        // (flush what we hold), a new record (buffer it). `biased` prefers
        // shutdown, then the deadline, so a saturated stream can't starve
        // either.
        let msg = {
            let deadline = state.deadline(cfg.max_wait);
            tokio::select! {
                biased;
                () = shutdown.cancelled() => {
                    drain_on_shutdown(&consumer, name, &cfg, &handler, &mut state).await;
                    tracing::info!(consumer = name, "batch consumer stopping");
                    return Ok(());
                }
                () = async { tokio::time::sleep_until(deadline.expect("guarded")).await }, if deadline.is_some() => {
                    flush_and_commit(&consumer, name, &cfg, &handler, &mut state, shutdown).await;
                    continue;
                }
                received = consumer.recv() => match received {
                    Ok(msg) => msg,
                    Err(err) => {
                        tracing::error!(consumer = name, error = %err, "Kafka receive error");
                        continue;
                    }
                },
            }
        };

        // Poison (no payload / undecodable / future schema version) can never
        // be handled: park it (best-effort) and advance the watermark past it.
        match crate::decode(&msg, name) {
            None => {
                if let Some(dlq) = dlq {
                    dlq.publish(&msg, "undecodable event envelope").await;
                }
                state.note_handled(msg.topic(), msg.partition(), msg.offset());
            }
            Some(envelope) => match handler.accept(envelope) {
                Accepted::Item(item) => {
                    state.push(item);
                    state.note_handled(msg.topic(), msg.partition(), msg.offset());
                }
                Accepted::Skip { error } => {
                    tracing::error!(
                        consumer = name,
                        error = %error,
                        "permanent fault; skipping record so it cannot wedge the stream"
                    );
                    if let Some(dlq) = dlq {
                        dlq.publish(&msg, &error).await;
                    }
                    state.note_handled(msg.topic(), msg.partition(), msg.offset());
                }
            },
        }

        if state.is_full(cfg.max_items) {
            flush_and_commit(&consumer, name, &cfg, &handler, &mut state, shutdown).await;
        }
    }
}

/// Flush the buffered items (retrying transient failures until success or
/// shutdown), then commit the batch's watermarks. On a permanent flush error
/// the batch is dropped loudly and the offsets still commit — the batch
/// analogue of skip-don't-wedge. On shutdown-during-retry nothing commits, so
/// the whole batch redelivers on restart.
async fn flush_and_commit<C, H>(
    consumer: &StreamConsumer<C>,
    name: &str,
    cfg: &BatchConfig,
    handler: &H,
    state: &mut BatchState<H::Item>,
    shutdown: &CancellationToken,
) where
    C: ConsumerContext + 'static,
    H: BatchHandler,
{
    if state.is_empty() {
        return;
    }

    while !state.items.is_empty() {
        match handler.flush(&state.items).await {
            Ok(()) => break,
            Err(err) if err.is_transient() => {
                tracing::warn!(
                    consumer = name,
                    error = %err,
                    items = state.items.len(),
                    "transient flush failure; retrying the same batch after backoff"
                );
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => {
                        // Nothing committed: the whole batch redelivers on restart.
                        tracing::warn!(
                            consumer = name,
                            items = state.items.len(),
                            "shutdown during flush retry; batch left for redelivery"
                        );
                        return;
                    }
                    () = tokio::time::sleep(cfg.retry_backoff) => {}
                }
            }
            Err(err) => {
                metrics::counter!(BATCH_FLUSH_TOTAL, "consumer" => name.to_owned(), "outcome" => "dropped_permanent").increment(1);
                tracing::error!(
                    consumer = name,
                    error = %err,
                    items = state.items.len(),
                    "permanent flush failure; dropping batch so it cannot wedge the stream"
                );
                break;
            }
        }
    }

    if let Err(err) = consumer.commit(&state.commit_list(), CommitMode::Async) {
        // A commit failure is redelivery, not loss (the flush is idempotent).
        tracing::error!(consumer = name, error = %err, "batch offset commit failed");
    } else {
        metrics::counter!(BATCH_FLUSH_TOTAL, "consumer" => name.to_owned(), "outcome" => "committed").increment(1);
    }
    state.clear();
}

/// The final drain: one flush attempt bounded by `shutdown_flush_grace`, so a
/// store that is down at shutdown can't hang exit. `shutdown` is already
/// cancelled here, so the retry loop inside [`flush_and_commit`] gives up on
/// the first transient failure — the deadline is the ceiling on one slow
/// (but succeeding) flush, and whatever it cuts off redelivers on restart.
async fn drain_on_shutdown<C, H>(
    consumer: &StreamConsumer<C>,
    name: &str,
    cfg: &BatchConfig,
    handler: &H,
    state: &mut BatchState<H::Item>,
) where
    C: ConsumerContext + 'static,
    H: BatchHandler,
{
    if state.is_empty() {
        return;
    }
    let items = state.items.len();
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let drain = flush_and_commit(consumer, name, cfg, handler, state, &cancelled);
    if tokio::time::timeout(cfg.shutdown_flush_grace, drain)
        .await
        .is_err()
    {
        metrics::counter!(BATCH_FLUSH_TOTAL, "consumer" => name.to_owned(), "outcome" => "abandoned_shutdown").increment(1);
        tracing::warn!(
            consumer = name,
            items,
            "shutdown flush grace expired; batch left for redelivery"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watermarks_track_the_next_offset_per_partition() {
        let mut state: BatchState<u32> = BatchState::new();
        state.note_handled("t", 0, 41);
        state.note_handled("t", 0, 42); // later record on the same partition wins
        state.note_handled("t", 1, 7);

        let list = state.commit_list();
        let offsets: HashMap<(String, i32), Offset> = list
            .elements()
            .iter()
            .map(|e| ((e.topic().to_owned(), e.partition()), e.offset()))
            .collect();
        // Kafka commit semantics: the *next* offset to consume, not the last handled.
        assert_eq!(offsets[&("t".to_owned(), 0)], Offset::Offset(43));
        assert_eq!(offsets[&("t".to_owned(), 1)], Offset::Offset(8));
    }

    #[test]
    fn skipped_records_arm_the_flush_clock_even_with_no_items() {
        // A poison-only stretch buffers no items but must still get its
        // offsets committed — the deadline has to arm on note_handled alone.
        let mut state: BatchState<u32> = BatchState::new();
        assert!(state.is_empty());
        assert!(state.deadline(Duration::from_secs(1)).is_none());

        state.note_handled("t", 0, 0);
        assert!(!state.is_empty());
        assert!(state.deadline(Duration::from_secs(1)).is_some());
        assert!(!state.is_full(1), "a skip is not an item");
    }

    #[test]
    fn size_trigger_counts_items_and_clear_resets_everything() {
        let mut state: BatchState<u32> = BatchState::new();
        state.push(1);
        state.note_handled("t", 0, 0);
        state.push(2);
        state.note_handled("t", 0, 1);
        assert!(state.is_full(2));

        state.clear();
        assert!(state.is_empty());
        assert!(state.deadline(Duration::from_secs(1)).is_none());
        assert_eq!(state.commit_list().count(), 0);
    }
}
