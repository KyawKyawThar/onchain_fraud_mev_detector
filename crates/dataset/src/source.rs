//! The [`EventSource`] seam — reading a replay window out of the event store.
//!
//! The store's `GET /v1/replay` *is* the §16 replay source: rows come back in
//! the table's own `(occurred_at, event_id)` sort order, and pagination is
//! keyset on that same total order, so following cursors to exhaustion
//! reproduces the window exactly, every time. This module is the client for it
//! plus an in-memory double, so the whole export pipeline is testable without a
//! ClickHouse.
//!
//! # Narrowing, and why the merge is sound
//!
//! The join reads seven event types out of a log that also carries every
//! `RawBlockReceived` and `UsageRecorded` on the chain, so dragging the whole
//! window across the wire would be mostly waste. But `/v1/replay` narrows to
//! *one* `event_type` at a time.
//!
//! [`replay_window`] therefore makes one paginated pass per type and merges the
//! results on `(occurred_at, event_id)`. That reconstructs the global order
//! restricted to those types **exactly**: each per-type stream is already
//! sorted by the same total key, and the key is unique (`event_id` is the
//! table's tie-breaker), so a sort of the concatenation is the same sequence
//! the store would have returned unfiltered, minus the types nobody reads.
//!
//! # Memory
//!
//! The window is materialised in memory: the export needs two passes over it
//! (once to reconstruct each block's context, once to join), and a dataset
//! export is a batch job, not a streaming service. [`replay_window`] takes an
//! explicit ceiling and *fails* when a window exceeds it rather than growing
//! until the OOM killer decides — a refusal that names the knob is a better
//! failure than a dead process.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use events::primitives::Chain;
use events::EventEnvelope;
use serde::Deserialize;

/// One page request against the replay API.
#[derive(Debug, Clone)]
pub struct ReplayQuery {
    pub chain: Chain,
    /// Restrict to one `DomainEvent` variant name. `None` reads every type.
    pub event_type: Option<String>,
    /// Inclusive lower bound on `occurred_at`.
    pub from: DateTime<Utc>,
    /// Exclusive upper bound.
    pub to: DateTime<Utc>,
    /// Opaque cursor from the previous page; resume after it.
    pub cursor: Option<String>,
    /// Rows per page. The server clamps this to its own ceiling.
    pub limit: u64,
}

/// One page of the replay stream.
#[derive(Debug, Clone, Deserialize)]
pub struct EventPage {
    pub events: Vec<EventEnvelope>,
    /// `Some` iff more rows may follow — so a caller can always tell a
    /// complete result from a truncated one.
    pub next_cursor: Option<String>,
}

/// A failure reading the replay stream.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    /// The request never got an answer (unreachable, timeout, TLS).
    #[error("event-store replay request failed")]
    Transport(#[from] reqwest::Error),

    /// The store answered, but not with a page.
    #[error("event-store replay returned {status}: {body}")]
    Status { status: u16, body: String },

    /// The window is larger than the configured ceiling.
    #[error(
        "replay window yielded more than {limit} events — narrow the window or raise \
         --max-events (a dataset export materialises its window in memory)"
    )]
    WindowTooLarge { limit: usize },

    /// The store handed back a cursor it then refused to honour, or a page
    /// loop failed to advance. Guards against spinning forever on a server
    /// bug.
    #[error("replay pagination stalled after {pages} pages without advancing")]
    PaginationStalled { pages: usize },
}

impl SourceError {
    /// Whether retrying the *same* request could plausibly succeed later.
    ///
    /// This mirrors the contract of `event_bus::Transience`, which every
    /// consumer on the backbone classifies through, but does not implement the
    /// trait: `event-bus` links `rdkafka`'s vendored C build, and pulling a
    /// broker client into an offline batch tool to gain one method is a bad
    /// trade. If a third non-broker crate ever needs the vocabulary, the trait
    /// is worth lifting out of `event-bus` into its own leaf crate — the
    /// `bounded-map` rule of three.
    ///
    /// A 5xx or a transport fault is a blip worth retrying; a 4xx is our own
    /// malformed request and will fail identically forever, as will a window
    /// that is simply too large or a server that mis-paginates.
    pub fn is_transient(&self) -> bool {
        match self {
            SourceError::Transport(_) => true,
            SourceError::Status { status, .. } => *status >= 500,
            SourceError::WindowTooLarge { .. } | SourceError::PaginationStalled { .. } => false,
        }
    }
}

/// How hard to try a failed page request before giving up.
///
/// An export replays for minutes to hours; without this, a single transient
/// 503 five hours in throws away the whole run. Bounded attempts with a linear
/// backoff, because the failure we expect is a restarting event-store pod, not
/// a thundering herd we could make worse.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Total attempts per page, including the first. `1` disables retrying.
    pub attempts: u32,
    /// Base delay; attempt *n* waits `backoff * n`.
    pub backoff: std::time::Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            attempts: 5,
            backoff: std::time::Duration::from_secs(1),
        }
    }
}

/// Per-request timeout. Without one, a half-open connection to a dead pod
/// hangs the export indefinitely — the failure mode a retry policy cannot see.
pub const DEFAULT_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Reads pages of the replay stream. Object-safe so the export holds a `&dyn
/// EventSource` and a test swaps in [`VecEventSource`] with no HTTP.
#[async_trait]
pub trait EventSource: Send + Sync {
    async fn page(&self, query: &ReplayQuery) -> Result<EventPage, SourceError>;
}

/// Default rows per page. The store clamps to its own `MAX_LIMIT` (10 000), so
/// asking for that much is asking for the largest page it will serve.
pub const DEFAULT_PAGE_SIZE: u64 = 10_000;

/// The real client: `GET {base_url}/v1/replay`.
///
/// The replay endpoint is unauthenticated (only the *append* half of the
/// event-store API sits behind the write token), so this carries no
/// credentials — it is an internal-network read, the same posture the API
/// service's proxy takes.
#[derive(Debug, Clone)]
pub struct HttpEventSource {
    client: reqwest::Client,
    base_url: String,
    retry: RetryPolicy,
}

impl HttpEventSource {
    /// `base_url` is the event-store service root, e.g.
    /// `http://event-store:8080`; a trailing slash is tolerated.
    pub fn new(client: reqwest::Client, base_url: impl Into<String>) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        Self {
            client,
            base_url,
            retry: RetryPolicy::default(),
        }
    }

    /// Override the retry policy (tests use `attempts: 1` to assert the
    /// no-retry path without waiting on backoffs).
    pub fn with_retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// One page request, no retry — the unit [`EventSource::page`] retries.
    async fn page_once(&self, query: &ReplayQuery) -> Result<EventPage, SourceError> {
        let mut params: Vec<(&str, String)> = vec![
            ("chain", query.chain.id().to_string()),
            ("from", query.from.to_rfc3339()),
            ("to", query.to.to_rfc3339()),
            ("limit", query.limit.to_string()),
        ];
        if let Some(event_type) = &query.event_type {
            params.push(("event_type", event_type.clone()));
        }
        if let Some(cursor) = &query.cursor {
            params.push(("cursor", cursor.clone()));
        }

        let response = self
            .client
            .get(format!("{}/v1/replay", self.base_url))
            .query(&params)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            // Read the body for the store's own error text — a 400 from a bad
            // cursor says exactly what is wrong, and swallowing it would turn a
            // one-line fix into a debugging session.
            let body = response.text().await.unwrap_or_default();
            return Err(SourceError::Status {
                status: status.as_u16(),
                body,
            });
        }
        Ok(response.json().await?)
    }
}

#[async_trait]
impl EventSource for HttpEventSource {
    /// Fetch one page, retrying transient failures per [`RetryPolicy`].
    ///
    /// Retrying at the *page* level is what makes it safe: a page request is a
    /// pure read of an immutable, keyset-paginated store, so re-issuing it
    /// returns the same rows. Nothing is skipped and nothing is duplicated by a
    /// retry, which is exactly why this belongs here and not around the whole
    /// export.
    async fn page(&self, query: &ReplayQuery) -> Result<EventPage, SourceError> {
        let attempts = self.retry.attempts.max(1);
        for attempt in 1..=attempts {
            match self.page_once(query).await {
                Ok(page) => return Ok(page),
                Err(err) if attempt < attempts && err.is_transient() => {
                    let wait = self.retry.backoff * attempt;
                    tracing::warn!(
                        attempt,
                        of = attempts,
                        backoff_ms = wait.as_millis() as u64,
                        error = %err,
                        "replay page failed transiently; retrying"
                    );
                    crate::metrics::record_replay_retry();
                    tokio::time::sleep(wait).await;
                }
                Err(err) => return Err(err),
            }
        }
        unreachable!("the loop returns on the final attempt")
    }
}

/// Drain every page of one query, following cursors to exhaustion.
///
/// `budget` is the *remaining* allowance across every type in this window;
/// `max_events` is the original ceiling, carried separately so the error names
/// the knob an operator would actually raise rather than whatever was left.
async fn drain(
    source: &dyn EventSource,
    mut query: ReplayQuery,
    budget: &mut usize,
    max_events: usize,
) -> Result<Vec<EventEnvelope>, SourceError> {
    let mut collected = Vec::new();
    let mut pages = 0usize;
    loop {
        let page = source.page(&query).await?;
        pages += 1;
        let was_empty = page.events.is_empty();
        if page.events.len() > *budget {
            return Err(SourceError::WindowTooLarge { limit: max_events });
        }
        *budget -= page.events.len();
        collected.extend(page.events);

        match page.next_cursor {
            // A cursor with nothing to show for it would loop forever.
            Some(_) if was_empty => return Err(SourceError::PaginationStalled { pages }),
            Some(cursor) => query.cursor = Some(cursor),
            None => return Ok(collected),
        }
    }
}

/// Replay a window, narrowed to `event_types`, in the store's total order.
///
/// `max_events` is the in-memory ceiling across all types; exceeding it is
/// [`SourceError::WindowTooLarge`], never a silent truncation — a dataset
/// missing its tail is not the dataset its spec describes.
pub async fn replay_window(
    source: &dyn EventSource,
    chain: Chain,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    event_types: &[&str],
    max_events: usize,
) -> Result<Vec<EventEnvelope>, SourceError> {
    let mut budget = max_events;
    let mut all = Vec::new();

    if event_types.is_empty() {
        all = drain(
            source,
            ReplayQuery {
                chain,
                event_type: None,
                from,
                to,
                cursor: None,
                limit: DEFAULT_PAGE_SIZE,
            },
            &mut budget,
            max_events,
        )
        .await?;
    } else {
        for event_type in event_types {
            let page = drain(
                source,
                ReplayQuery {
                    chain,
                    event_type: Some((*event_type).to_owned()),
                    from,
                    to,
                    cursor: None,
                    limit: DEFAULT_PAGE_SIZE,
                },
                &mut budget,
                max_events,
            )
            .await?;
            all.extend(page);
        }
    }

    // Restore the store's own total order across the per-type streams. The key
    // is unique, so this is a re-derivation of the global order, not a
    // heuristic re-ordering.
    all.sort_by_key(|envelope| (envelope.occurred_at, envelope.event_id));
    Ok(all)
}

/// Replay exactly the window a [`DatasetSpec`] names, narrowed to the event
/// types the join reads — the sequence [`crate::run_export`] folds, and the
/// same one [`crate::ctx::ReplayCtxSource`] reconstructs block contexts from.
///
/// [`DatasetSpec`]: crate::DatasetSpec
pub async fn replay_window_types(
    source: &dyn EventSource,
    spec: &crate::DatasetSpec,
    max_events: usize,
) -> Result<Vec<EventEnvelope>, SourceError> {
    replay_window(
        source,
        spec.chain,
        spec.from,
        // Past `to`, not up to it: the tail is what resolves the outcomes of
        // findings near the end of the window. Reading only `[from, to)` is the
        // truncation bug `DatasetSpec::lookahead_secs` documents.
        spec.replay_end(),
        crate::join::JOINED_EVENT_TYPES,
        max_events,
    )
    .await
}

/// In-memory replay source: an ordered window plus real keyset pagination, so
/// the paging and merge logic is exercised without a store.
#[derive(Debug, Clone, Default)]
pub struct VecEventSource {
    events: Vec<EventEnvelope>,
    /// Rows per page, overriding the query's own limit — how a test forces
    /// multi-page behaviour without a 10 000-event fixture.
    page_size: Option<usize>,
}

impl VecEventSource {
    /// Sorts into the store's total order on construction, so a fixture can be
    /// written in whatever order reads best.
    pub fn new(mut events: Vec<EventEnvelope>) -> Self {
        events.sort_by_key(|e| (e.occurred_at, e.event_id));
        Self {
            events,
            page_size: None,
        }
    }

    /// Force a small page size to exercise cursor-following.
    pub fn with_page_size(mut self, size: usize) -> Self {
        self.page_size = Some(size.max(1));
        self
    }

    /// Encode a cursor the way `event_store::query::Cursor::token` does.
    fn token(envelope: &EventEnvelope) -> String {
        format!(
            "{}:{}",
            envelope.occurred_at.timestamp_millis(),
            envelope.event_id
        )
    }
}

#[async_trait]
impl EventSource for VecEventSource {
    async fn page(&self, query: &ReplayQuery) -> Result<EventPage, SourceError> {
        let after: Option<(i64, uuid::Uuid)> = match &query.cursor {
            None => None,
            Some(token) => {
                let (millis, id) = token.split_once(':').ok_or_else(|| SourceError::Status {
                    status: 400,
                    body: format!("invalid cursor `{token}`"),
                })?;
                Some((
                    millis.parse().map_err(|_| SourceError::Status {
                        status: 400,
                        body: format!("invalid cursor `{token}`"),
                    })?,
                    id.parse().map_err(|_| SourceError::Status {
                        status: 400,
                        body: format!("invalid cursor `{token}`"),
                    })?,
                ))
            }
        };

        let limit = self.page_size.unwrap_or(query.limit as usize).max(1);
        let matching: Vec<EventEnvelope> = self
            .events
            .iter()
            .filter(|e| e.chain == query.chain)
            .filter(|e| e.occurred_at >= query.from && e.occurred_at < query.to)
            .filter(|e| {
                query
                    .event_type
                    .as_ref()
                    .is_none_or(|ty| e.event_type() == ty)
            })
            .filter(|e| {
                after.is_none_or(|(millis, id)| {
                    (e.occurred_at.timestamp_millis(), e.event_id) > (millis, id)
                })
            })
            .take(limit + 1)
            .cloned()
            .collect();

        let has_more = matching.len() > limit;
        let events: Vec<EventEnvelope> = matching.into_iter().take(limit).collect();
        let next_cursor = has_more.then(|| Self::token(events.last().expect("non-empty page")));
        Ok(EventPage {
            events,
            next_cursor,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::TimeZone;
    use events::chain::{BlockAssembled, BlockFinalized};
    use events::primitives::BlockRef;
    use events::DomainEvent;
    use uuid::Uuid;

    const CHAIN: Chain = Chain::ETHEREUM;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    fn assembled(seq: u32) -> EventEnvelope {
        EventEnvelope::with_metadata(
            Uuid::from_u128(u128::from(seq)),
            at(1_700_000_000 + i64::from(seq)),
            CHAIN,
            DomainEvent::BlockAssembled(BlockAssembled {
                block: BlockRef::new(u64::from(seq), alloy_primitives::B256::repeat_byte(1)),
                tx_count: 1,
                trace_available: false,
            }),
        )
    }

    fn finalized(seq: u32) -> EventEnvelope {
        EventEnvelope::with_metadata(
            Uuid::from_u128(u128::from(seq)),
            at(1_700_000_000 + i64::from(seq)),
            CHAIN,
            DomainEvent::BlockFinalized(BlockFinalized {
                block: BlockRef::new(u64::from(seq), alloy_primitives::B256::repeat_byte(2)),
            }),
        )
    }

    fn window() -> (DateTime<Utc>, DateTime<Utc>) {
        (at(1_700_000_000), at(1_700_001_000))
    }

    #[tokio::test]
    async fn draining_follows_cursors_to_exhaustion() {
        let events: Vec<EventEnvelope> = (0..25).map(assembled).collect();
        let source = VecEventSource::new(events).with_page_size(4);
        let (from, to) = window();

        let replayed = replay_window(&source, CHAIN, from, to, &["BlockAssembled"], 1_000)
            .await
            .expect("drains");
        assert_eq!(replayed.len(), 25, "every page followed, nothing truncated");
        assert!(
            replayed
                .windows(2)
                .all(|w| (w[0].occurred_at, w[0].event_id) < (w[1].occurred_at, w[1].event_id)),
            "pages come back in the store's total order"
        );
    }

    #[tokio::test]
    async fn per_type_passes_merge_back_into_the_stores_total_order() {
        // Interleave two types on alternating seconds; a merged replay must
        // read as if one unfiltered pass had returned them.
        let mut events = Vec::new();
        for seq in 0..10 {
            if seq % 2 == 0 {
                events.push(assembled(seq));
            } else {
                events.push(finalized(seq));
            }
        }
        let expected: Vec<Uuid> = {
            let mut sorted = events.clone();
            sorted.sort_by_key(|e| (e.occurred_at, e.event_id));
            sorted.iter().map(|e| e.event_id).collect()
        };

        let source = VecEventSource::new(events).with_page_size(3);
        let (from, to) = window();
        let merged = replay_window(
            &source,
            CHAIN,
            from,
            to,
            &["BlockAssembled", "BlockFinalized"],
            1_000,
        )
        .await
        .expect("merges");

        assert_eq!(
            merged.iter().map(|e| e.event_id).collect::<Vec<_>>(),
            expected
        );
    }

    #[tokio::test]
    async fn narrowing_to_a_type_excludes_the_others() {
        let events = vec![assembled(1), finalized(2), assembled(3)];
        let source = VecEventSource::new(events);
        let (from, to) = window();
        let only = replay_window(&source, CHAIN, from, to, &["BlockAssembled"], 1_000)
            .await
            .unwrap();
        assert_eq!(only.len(), 2);
        assert!(only.iter().all(|e| e.event_type() == "BlockAssembled"));
    }

    #[tokio::test]
    async fn the_window_bound_is_half_open() {
        let events: Vec<EventEnvelope> = (0..5).map(assembled).collect();
        let source = VecEventSource::new(events);
        let replayed = replay_window(
            &source,
            CHAIN,
            at(1_700_000_001),
            at(1_700_000_003),
            &["BlockAssembled"],
            1_000,
        )
        .await
        .unwrap();
        assert_eq!(
            replayed.len(),
            2,
            "[from, to) selects seconds 1 and 2, never 3 — so adjacent windows tile"
        );
    }

    #[tokio::test]
    async fn an_oversized_window_is_refused_rather_than_truncated() {
        let events: Vec<EventEnvelope> = (0..20).map(assembled).collect();
        let source = VecEventSource::new(events).with_page_size(5);
        let (from, to) = window();
        let err = replay_window(&source, CHAIN, from, to, &["BlockAssembled"], 8)
            .await
            .expect_err("must refuse");
        assert!(
            matches!(err, SourceError::WindowTooLarge { limit: 8 }),
            "{err}"
        );
    }

    #[tokio::test]
    async fn the_budget_spans_every_type_not_each_one_separately() {
        let mut events: Vec<EventEnvelope> = (0..6).map(assembled).collect();
        events.extend((10..16).map(finalized));
        let source = VecEventSource::new(events);
        let (from, to) = window();
        let err = replay_window(
            &source,
            CHAIN,
            from,
            to,
            &["BlockAssembled", "BlockFinalized"],
            8,
        )
        .await
        .expect_err("6 + 6 exceeds 8");
        assert!(matches!(err, SourceError::WindowTooLarge { .. }), "{err}");
    }

    #[tokio::test]
    async fn events_from_other_chains_are_not_in_the_window() {
        let mut foreign = assembled(1);
        foreign.chain = Chain(8453);
        let source = VecEventSource::new(vec![foreign, assembled(2)]);
        let (from, to) = window();
        let replayed = replay_window(&source, CHAIN, from, to, &["BlockAssembled"], 1_000)
            .await
            .unwrap();
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].chain, CHAIN);
    }
}
