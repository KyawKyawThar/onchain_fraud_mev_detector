//! The replay side of a rebuild: pulling the event store's deterministic stream
//! back out, oldest first (§4 query API / §18 replay source).
//!
//! ## Why HTTP and not a ClickHouse client
//!
//! The event store already publishes `GET /v1/replay` as the replay source, and
//! it is the surface an operator has. Reading its ClickHouse table directly
//! would give a rebuild a second, unversioned definition of "the log" —
//! bypassing [`EventEnvelope::from_json_slice`], and with it the
//! `schema_version` check and the [`events::upcast`] seam that migrates an
//! envelope written under an older schema up to today's shape (§17). A rebuild
//! that skipped upcasting would silently mis-fold exactly the historical events
//! it exists to re-fold. So: HTTP, through the published endpoint, decoded
//! through the one decode seam.
//!
//! ## The watermark: a consistent cut of the log
//!
//! [`ReplaySource::watermark`] pins the point a rebuild is "as of", and every
//! page then carries [`PageRequest::appended_before`]. The bound is on
//! **ingest** time, not event time, because `occurred_at` is not monotonic with
//! respect to arrival: an event whose `occurred_at` is an hour old can be
//! appended right now, and an event-time bound would let it slip through a
//! replay that had already passed that timestamp. `appended_at` is the store's
//! own server-side stamp, so bounding on it is a genuine cut — see
//! [`crate::driver`] for the residual in-flight race and why idempotent
//! catch-up rather than a longer lock is what closes it.
//!
//! The watermark comes from the **store's** clock, never the caller's. A
//! rebuild host whose clock runs fast would otherwise pin a cut in the store's
//! future and silently include part of the tail it meant to exclude.
//!
//! ## Ordering
//!
//! One stream (`event_type: None`) is returned in the store's own
//! `(occurred_at, event_id)` total order — the order a live consumer would have
//! seen if Kafka had delivered perfectly. [`MergedReplay`] over several
//! per-type streams reproduces that order **up to the tie-break between events
//! sharing a millisecond**: within a millisecond it orders by the client's UUID
//! comparison, which is not necessarily the store's. That is only safe for a
//! fold that is commutative over the types it consumes — which the incident
//! projection documents itself to be, and which is the property a projection
//! needs anyway to survive at-least-once Kafka delivery. A read model whose
//! fold is *not* order-independent must replay the single unfiltered stream
//! instead (declare no event types).

use std::collections::VecDeque;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use events::EventEnvelope;

/// Hard ceiling the event store clamps a page to (`event_store::query::MAX_LIMIT`).
/// Duplicated as a const rather than depended on: this crate deliberately does
/// not link the event-store service. Asking for more is not an error — the
/// server clamps — but a caller that means "as big as allowed" should say so.
pub const MAX_PAGE: u64 = 10_000;

/// Default page size for a rebuild: large enough that a long replay is not
/// dominated by round-trips, small enough that one page is a bounded allocation.
pub const DEFAULT_PAGE: u64 = 2_000;

/// The ingest-time point a rebuild is "as of" — the upper bound of its cut of
/// the log.
///
/// A newtype rather than a bare `DateTime` because the distinction that matters
/// is *which clock and which column*: this is the event store's own
/// `appended_at`, read from the store's clock, and it must never be confused
/// with an `occurred_at` bound (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Watermark(DateTime<Utc>);

impl Watermark {
    /// Pin a watermark at an instant on the store's clock.
    pub fn at(at: DateTime<Utc>) -> Self {
        Self(at)
    }

    /// The instant, for building a query bound.
    pub fn as_datetime(self) -> DateTime<Utc> {
        self.0
    }
}

impl std::fmt::Display for Watermark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.to_rfc3339())
    }
}

/// A failure pulling the replay stream.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    /// The HTTP round-trip failed (unreachable, timeout, TLS).
    #[error("event-store request failed")]
    Transport(#[from] reqwest::Error),

    /// The event store answered, but not with a page.
    #[error("event store returned {status}: {body}")]
    Status {
        status: reqwest::StatusCode,
        body: String,
    },

    /// A page decoded as JSON but an envelope in it did not decode as an event —
    /// a schema the running build cannot read (§17). Fatal for a rebuild: the
    /// resulting read model would be missing whatever that event carried, and
    /// silently skipping it would produce a *plausible but wrong* projection.
    #[error("event {event_id} could not be decoded (schema the running build cannot read)")]
    Undecodable {
        event_id: String,
        #[source]
        source: events::EventError,
    },

    /// The response body was not the page shape.
    #[error("event-store response was not a replay page")]
    Malformed(#[from] serde_json::Error),
}

/// One request for a page of the replay stream. `from` is mandatory (unlike the
/// endpoint's optional filters) because the store refuses an entirely
/// unnarrowed replay: a full rebuild passes the Unix epoch and means it.
#[derive(Debug, Clone)]
pub struct PageRequest {
    /// Restrict to one chain id, or every chain.
    pub chain: Option<u64>,
    /// Restrict to one event type, or the whole log.
    pub event_type: Option<String>,
    /// Inclusive lower bound on `occurred_at`.
    pub from: DateTime<Utc>,
    /// Exclusive upper bound on `occurred_at`; `None` means "up to the end".
    pub to: Option<DateTime<Utc>>,
    /// Exclusive upper bound on **ingest** time — the rebuild's cut of the log.
    /// `None` replays to whatever the tail is when this lane drains, which is
    /// only correct against a log that is not being appended to.
    pub appended_before: Option<Watermark>,
    /// Opaque cursor from a previous page.
    pub cursor: Option<String>,
    /// Rows per page (server-clamped to [`MAX_PAGE`]).
    pub limit: u64,
}

/// A page of the stream plus where to resume. `next_cursor: None` means the
/// stream is exhausted — a rebuild must not stop on an empty page alone, since
/// the store distinguishes "no more rows" from "this page happened to be full".
#[derive(Debug)]
pub struct ReplayPage {
    pub events: Vec<EventEnvelope>,
    pub next_cursor: Option<String>,
}

/// The seam a rebuild reads through. Object-safe so the driver takes
/// `&dyn ReplaySource` and tests hand it a canned stream with no event store.
#[async_trait]
pub trait ReplaySource: Send + Sync {
    /// Pin the current ingest-time cut, read from the **store's** clock.
    ///
    /// Called once at the start of a rebuild; every page of that rebuild is
    /// then bounded by it, so all replay lanes stop at the same point in the
    /// log rather than at whatever the tail happened to be when each drained.
    async fn watermark(&self) -> Result<Watermark, ReplayError>;

    /// Fetch one page. Implementations return events in
    /// `(occurred_at, event_id)` order, oldest first.
    async fn page(&self, request: &PageRequest) -> Result<ReplayPage, ReplayError>;
}

/// The production source: the event-store service's read API.
///
/// The read endpoints are unauthenticated by design (internal network only; the
/// bearer gate is on `append`), so this carries no credential.
#[derive(Debug, Clone)]
pub struct EventStoreReplay {
    base_url: String,
    client: reqwest::Client,
}

impl EventStoreReplay {
    /// `base_url` is the event store's origin, e.g. `http://event-store:8080`;
    /// a trailing slash is tolerated.
    pub fn new(base_url: impl Into<String>) -> Result<Self, ReplayError> {
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            // No global timeout: a wide page over a large window is legitimately
            // slow, and a rebuild that gave up mid-stream would leave a wiped
            // read model half-filled. Connect timeouts still apply.
            client: reqwest::Client::builder().build()?,
        })
    }

    /// Build from an existing client (shares the connection pool).
    pub fn with_client(base_url: impl Into<String>, client: reqwest::Client) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client,
        }
    }
}

/// The wire shape of `GET /v1/replay`. Envelopes are held as raw JSON values so
/// each one can be handed to [`EventEnvelope::from_json_slice`] — the version
/// dispatch seam — rather than deserialized straight into the current struct.
#[derive(serde::Deserialize)]
struct WirePage {
    events: Vec<serde_json::Value>,
    next_cursor: Option<String>,
}

/// The wire shape of `GET /v1/watermark`.
#[derive(serde::Deserialize)]
struct WireWatermark {
    watermark: DateTime<Utc>,
}

#[async_trait]
impl ReplaySource for EventStoreReplay {
    async fn watermark(&self) -> Result<Watermark, ReplayError> {
        let response = self
            .client
            .get(format!("{}/v1/watermark", self.base_url))
            .send()
            .await?;
        let status = response.status();
        let body = response.bytes().await?;
        if !status.is_success() {
            return Err(ReplayError::Status {
                status,
                body: String::from_utf8_lossy(&body).chars().take(512).collect(),
            });
        }
        let wire: WireWatermark = serde_json::from_slice(&body)?;
        Ok(Watermark::at(wire.watermark))
    }

    async fn page(&self, request: &PageRequest) -> Result<ReplayPage, ReplayError> {
        let mut query: Vec<(&str, String)> = vec![
            ("from", request.from.to_rfc3339()),
            ("limit", request.limit.min(MAX_PAGE).to_string()),
        ];
        if let Some(chain) = request.chain {
            query.push(("chain", chain.to_string()));
        }
        if let Some(event_type) = &request.event_type {
            query.push(("event_type", event_type.clone()));
        }
        if let Some(to) = request.to {
            query.push(("to", to.to_rfc3339()));
        }
        if let Some(watermark) = request.appended_before {
            query.push(("appended_before", watermark.as_datetime().to_rfc3339()));
        }
        if let Some(cursor) = &request.cursor {
            query.push(("cursor", cursor.clone()));
        }

        let response = self
            .client
            .get(format!("{}/v1/replay", self.base_url))
            .query(&query)
            .send()
            .await?;

        let status = response.status();
        let body = response.bytes().await?;
        if !status.is_success() {
            return Err(ReplayError::Status {
                status,
                body: String::from_utf8_lossy(&body).chars().take(512).collect(),
            });
        }

        let page: WirePage = serde_json::from_slice(&body)?;
        let mut events = Vec::with_capacity(page.events.len());
        for value in page.events {
            // Name the event in the error before consuming it, so an undecodable
            // envelope is identifiable in the store rather than just "one of
            // this page".
            let event_id = value
                .get("event_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("<unknown>")
                .to_string();
            let bytes = serde_json::to_vec(&value)?;
            events.push(
                EventEnvelope::from_json_slice(&bytes)
                    .map_err(|source| ReplayError::Undecodable { event_id, source })?,
            );
        }

        Ok(ReplayPage {
            events,
            next_cursor: page.next_cursor,
        })
    }
}

/// A paging cursor over one narrowing of the stream: buffers a page at a time
/// and yields events one by one.
struct Lane {
    request: PageRequest,
    buffer: VecDeque<EventEnvelope>,
    exhausted: bool,
}

impl Lane {
    fn new(request: PageRequest) -> Self {
        Self {
            request,
            buffer: VecDeque::new(),
            exhausted: false,
        }
    }

    /// Ensure the buffer holds at least one event, fetching pages until one
    /// arrives non-empty or the stream ends. (A page can legitimately come back
    /// empty while `next_cursor` is set — the store pages by keyset, not by
    /// match count.)
    async fn fill(&mut self, source: &dyn ReplaySource) -> Result<(), ReplayError> {
        while self.buffer.is_empty() && !self.exhausted {
            let page = source.page(&self.request).await?;
            self.buffer.extend(page.events);
            match page.next_cursor {
                Some(cursor) => self.request.cursor = Some(cursor),
                None => self.exhausted = true,
            }
        }
        Ok(())
    }

    /// The sort key of the next event, if any.
    fn head_key(&self) -> Option<(DateTime<Utc>, uuid::Uuid)> {
        self.buffer
            .front()
            .map(|event| (event.occurred_at, event.event_id))
    }
}

/// A k-way merge over several per-event-type replay lanes, yielding the union in
/// `(occurred_at, event_id)` order.
///
/// Memory is bounded by `lanes × page size`, not by the length of the replay —
/// which is the point: a rebuild over years of history must not accumulate.
///
/// See the module docs for the tie-break caveat within a single millisecond.
pub struct MergedReplay<'a> {
    source: &'a dyn ReplaySource,
    lanes: Vec<Lane>,
    yielded: u64,
}

impl<'a> MergedReplay<'a> {
    /// One lane per `event_type`; an empty `event_types` makes a single
    /// unfiltered lane over the whole log (exact store order, no tie-break
    /// caveat).
    pub fn new(
        source: &'a dyn ReplaySource,
        template: PageRequest,
        event_types: &[String],
    ) -> Self {
        let lanes = if event_types.is_empty() {
            vec![Lane::new(PageRequest {
                event_type: None,
                ..template
            })]
        } else {
            event_types
                .iter()
                .map(|event_type| {
                    Lane::new(PageRequest {
                        event_type: Some(event_type.clone()),
                        ..template.clone()
                    })
                })
                .collect()
        };
        Self {
            source,
            lanes,
            yielded: 0,
        }
    }

    /// How many events have been yielded so far.
    pub fn yielded(&self) -> u64 {
        self.yielded
    }

    /// The next event in merged order, or `None` when every lane is drained.
    pub async fn next(&mut self) -> Result<Option<EventEnvelope>, ReplayError> {
        for lane in &mut self.lanes {
            lane.fill(self.source).await?;
        }
        let winner = self
            .lanes
            .iter()
            .enumerate()
            .filter_map(|(index, lane)| lane.head_key().map(|key| (key, index)))
            .min()
            .map(|(_, index)| index);

        Ok(match winner {
            None => None,
            Some(index) => {
                self.yielded += 1;
                self.lanes[index].buffer.pop_front()
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use events::primitives::Chain;
    use events::DomainEvent;

    /// A canned source: each `(event_type → events)` lane hands back its whole
    /// list as one page. Also records the requests it saw, so the tests can
    /// assert the driver narrowed the way it claimed to.
    struct CannedSource {
        lanes: Vec<(Option<String>, Vec<EventEnvelope>)>,
        seen: Mutex<Vec<PageRequest>>,
    }

    #[async_trait]
    impl ReplaySource for CannedSource {
        async fn watermark(&self) -> Result<Watermark, ReplayError> {
            Ok(Watermark::at(
                DateTime::<Utc>::from_timestamp(9_999, 0).unwrap(),
            ))
        }

        async fn page(&self, request: &PageRequest) -> Result<ReplayPage, ReplayError> {
            self.seen.lock().unwrap().push(request.clone());
            // A cursor means "the second call on this lane" — always empty, so
            // the lane terminates.
            if request.cursor.is_some() {
                return Ok(ReplayPage {
                    events: vec![],
                    next_cursor: None,
                });
            }
            let events = self
                .lanes
                .iter()
                .find(|(event_type, _)| *event_type == request.event_type)
                .map(|(_, events)| events.clone())
                .unwrap_or_default();
            Ok(ReplayPage {
                events,
                next_cursor: None,
            })
        }
    }

    fn event(secs: i64, byte: u8) -> EventEnvelope {
        EventEnvelope::with_metadata(
            uuid::Uuid::from_bytes([byte; 16]),
            DateTime::<Utc>::from_timestamp(secs, 0).unwrap(),
            Chain::ETHEREUM,
            DomainEvent::SimulationCompleted(events::simulation::SimulationCompleted {
                alert_id: events::primitives::AlertId(uuid::Uuid::from_bytes([byte; 16])),
                profit: secs as f64,
                victim_loss: 0.0,
                confirmed: true,
            }),
        )
    }

    fn template() -> PageRequest {
        PageRequest {
            chain: None,
            event_type: None,
            from: DateTime::<Utc>::UNIX_EPOCH,
            to: None,
            appended_before: None,
            cursor: None,
            limit: DEFAULT_PAGE,
        }
    }

    #[tokio::test]
    async fn a_merge_interleaves_lanes_by_event_time() {
        let source = CannedSource {
            lanes: vec![
                (Some("A".into()), vec![event(10, 1), event(30, 3)]),
                (Some("B".into()), vec![event(20, 2), event(40, 4)]),
            ],
            seen: Mutex::new(vec![]),
        };
        let types = vec!["A".to_string(), "B".to_string()];
        let mut merged = MergedReplay::new(&source, template(), &types);

        let mut order = vec![];
        while let Some(event) = merged.next().await.unwrap() {
            order.push(event.occurred_at.timestamp());
        }
        assert_eq!(order, vec![10, 20, 30, 40]);
        assert_eq!(merged.yielded(), 4);
    }

    #[tokio::test]
    async fn no_event_types_makes_one_unfiltered_lane() {
        let source = CannedSource {
            lanes: vec![(None, vec![event(10, 1), event(20, 2)])],
            seen: Mutex::new(vec![]),
        };
        let mut merged = MergedReplay::new(&source, template(), &[]);
        let mut count = 0;
        while merged.next().await.unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 2);
        let seen = source.seen.lock().unwrap();
        assert!(
            seen.iter().all(|request| request.event_type.is_none()),
            "the unfiltered lane must not narrow by type"
        );
    }

    #[tokio::test]
    async fn an_empty_lane_does_not_stall_the_merge() {
        let source = CannedSource {
            lanes: vec![
                (Some("A".into()), vec![]),
                (Some("B".into()), vec![event(5, 9)]),
            ],
            seen: Mutex::new(vec![]),
        };
        let types = vec!["A".to_string(), "B".to_string()];
        let mut merged = MergedReplay::new(&source, template(), &types);
        assert!(merged.next().await.unwrap().is_some());
        assert!(merged.next().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn the_window_is_pushed_down_to_every_lane() {
        let source = CannedSource {
            lanes: vec![(Some("A".into()), vec![])],
            seen: Mutex::new(vec![]),
        };
        let from = DateTime::<Utc>::from_timestamp(1_000, 0).unwrap();
        let to = DateTime::<Utc>::from_timestamp(2_000, 0).unwrap();
        let types = vec!["A".to_string()];
        let mut merged = MergedReplay::new(
            &source,
            PageRequest {
                chain: Some(1),
                from,
                to: Some(to),
                ..template()
            },
            &types,
        );
        while merged.next().await.unwrap().is_some() {}

        let seen = source.seen.lock().unwrap();
        assert!(!seen.is_empty());
        for request in seen.iter() {
            assert_eq!(request.chain, Some(1));
            assert_eq!(request.from, from);
            assert_eq!(request.to, Some(to));
        }
    }
}
