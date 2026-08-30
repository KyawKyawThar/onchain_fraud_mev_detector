//! Reading an incident's audit stream out of event-store (§4).
//!
//! This is the copilot's *grounding* input: the narrative a reviewer files a
//! SAR from must be derivable from events the system already recorded, so the
//! model is shown the incident's event sequence and nothing else.
//!
//! # Why an HTTP client and not a store edge
//!
//! event-store's `GET /v1/audit/incident/{id}` returns the incident's events
//! oldest-first with keyset pagination. Reading them by querying ClickHouse
//! directly would be faster and would also be a cross-service join — the one
//! thing §14 forbids without exception. The cost of the rule is one HTTP hop
//! on a path where nobody is waiting; the benefit is that event-store can
//! change its schema without breaking this service.
//!
//! # The window is bounded, and a truncation is visible
//!
//! An incident's stream is small (single-digit to low-hundreds of events),
//! but "small" is an assumption about a system under attack, and the reader
//! is what feeds a *billed* prompt. [`AuditStream::truncated`] records when
//! the ceiling cut the read short, so a draft built on a partial stream can
//! say so rather than silently omitting the tail — the same stance
//! `dataset::source` takes, differing only in the remedy: an export refuses,
//! a narrative degrades and admits it.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use events::primitives::{Chain, IncidentId};
use events::{DomainEvent, EventEnvelope};
use serde::Deserialize;

/// Default events per page. The store clamps to its own ceiling.
pub const DEFAULT_PAGE_SIZE: u64 = 1_000;

/// Default ceiling on one incident's stream. Generous relative to a real
/// incident, low enough that a pathological one cannot turn into a
/// six-figure-token prompt.
pub const DEFAULT_MAX_EVENTS: usize = 2_000;

/// Per-request timeout. Without one, a half-open connection to a dead
/// event-store pod parks a worker until its lease expires.
pub const DEFAULT_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// One incident's event sequence, oldest first.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AuditStream {
    pub incident_id: Option<IncidentId>,
    pub events: Vec<EventEnvelope>,
    /// Whether the ceiling cut the read short. Carried into the prompt, never
    /// swallowed: a narrative drafted from a truncated stream is a different
    /// claim than one drafted from a complete one.
    pub truncated: bool,
}

impl AuditStream {
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// The ids the model was shown — the seed of §20.4's `grounded_event_ids`.
    /// t3 narrows this to the ids a claim actually cites; recording the window
    /// is what makes that narrowing checkable.
    pub fn event_ids(&self) -> Vec<uuid::Uuid> {
        self.events.iter().map(|e| e.event_id).collect()
    }
}

/// One page of the audit endpoint.
#[derive(Debug, Clone, Deserialize)]
struct EventPage {
    events: Vec<EventEnvelope>,
    next_cursor: Option<String>,
}

/// A failure reading the audit stream.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// The request never got an answer (unreachable, timeout, TLS).
    #[error("event-store audit request failed")]
    Transport(#[from] reqwest::Error),
    /// The store answered, but not with a page.
    #[error("event-store audit returned {status}: {body}")]
    Status { status: u16, body: String },
    /// A cursor the store handed back that did not advance. Guards against
    /// spinning forever on a server bug.
    #[error("audit pagination stalled after {pages} pages without advancing")]
    PaginationStalled { pages: usize },
}

impl event_bus::Transience for AuditError {
    /// A 5xx or a transport fault is a blip the queue should re-run later; a
    /// 4xx is our own malformed request and a stalled paginator is a server
    /// bug — both fail identically on every retry.
    fn is_transient(&self) -> bool {
        match self {
            AuditError::Transport(_) => true,
            AuditError::Status { status, .. } => *status >= 500,
            AuditError::PaginationStalled { .. } => false,
        }
    }
}

/// Reads an incident's audit stream. Object-safe so the worker holds an
/// `Arc<dyn AuditSource>` and a test swaps in [`VecAuditSource`] with no HTTP.
#[async_trait]
pub trait AuditSource: Send + Sync + std::fmt::Debug {
    async fn audit_stream(
        &self,
        incident_id: IncidentId,
        max_events: usize,
    ) -> Result<AuditStream, AuditError>;
}

/// The real client: `GET {base_url}/v1/audit/incident/{incident_id}`.
///
/// The read half of event-store's API is unauthenticated by design (only
/// *append* sits behind the write token) — an internal-network read, the same
/// posture `dataset::source::HttpEventSource` and the API service's proxy
/// take.
#[derive(Debug, Clone)]
pub struct HttpAuditSource {
    client: reqwest::Client,
    base_url: String,
    page_size: u64,
}

impl HttpAuditSource {
    /// `base_url` is the event-store service root, e.g.
    /// `http://event-store:8080`; a trailing slash is tolerated.
    pub fn new(client: reqwest::Client, base_url: impl Into<String>) -> Self {
        Self {
            client,
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            page_size: DEFAULT_PAGE_SIZE,
        }
    }

    pub fn with_page_size(mut self, page_size: u64) -> Self {
        self.page_size = page_size.max(1);
        self
    }

    async fn page(
        &self,
        incident_id: IncidentId,
        cursor: Option<&str>,
    ) -> Result<EventPage, AuditError> {
        let mut params: Vec<(&str, String)> = vec![("limit", self.page_size.to_string())];
        if let Some(cursor) = cursor {
            params.push(("cursor", cursor.to_owned()));
        }

        let response = self
            .client
            .get(format!(
                "{}/v1/audit/incident/{}",
                self.base_url, incident_id.0
            ))
            .query(&params)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            // Keep the store's own error text: a 400 from a bad cursor says
            // exactly what is wrong, and swallowing it turns a one-line fix
            // into a debugging session.
            let body = response.text().await.unwrap_or_default();
            return Err(AuditError::Status {
                status: status.as_u16(),
                body,
            });
        }
        Ok(response.json().await?)
    }
}

#[async_trait]
impl AuditSource for HttpAuditSource {
    /// Follow cursors until the stream is exhausted or `max_events` is
    /// reached. No retry here: this call runs inside a leased worker slot, so
    /// a transient fault is re-run by the *queue* — the outer clock — rather
    /// than by a loop that holds the lease while it sleeps.
    async fn audit_stream(
        &self,
        incident_id: IncidentId,
        max_events: usize,
    ) -> Result<AuditStream, AuditError> {
        let max_events = max_events.max(1);
        let mut events: Vec<EventEnvelope> = Vec::new();
        let mut cursor: Option<String> = None;
        let mut pages = 0usize;

        loop {
            let page = self.page(incident_id, cursor.as_deref()).await?;
            pages += 1;
            let was_empty = page.events.is_empty();
            events.extend(page.events);

            if events.len() >= max_events {
                events.truncate(max_events);
                return Ok(AuditStream {
                    incident_id: Some(incident_id),
                    events,
                    truncated: true,
                });
            }

            match page.next_cursor {
                Some(_) if was_empty => return Err(AuditError::PaginationStalled { pages }),
                Some(next) => cursor = Some(next),
                None => {
                    return Ok(AuditStream {
                        incident_id: Some(incident_id),
                        events,
                        truncated: false,
                    })
                }
            }
        }
    }
}

/// In-memory audit source: the events of one or more incidents, keyed by id.
/// Lets the worker and the prompt renderer be exercised with no event-store.
#[derive(Debug, Clone, Default)]
pub struct VecAuditSource {
    streams: std::collections::HashMap<uuid::Uuid, Vec<EventEnvelope>>,
}

impl VecAuditSource {
    pub fn new(incident_id: IncidentId, events: Vec<EventEnvelope>) -> Self {
        let mut streams = std::collections::HashMap::new();
        streams.insert(incident_id.0, events);
        Self { streams }
    }

    pub fn with_stream(mut self, incident_id: IncidentId, events: Vec<EventEnvelope>) -> Self {
        self.streams.insert(incident_id.0, events);
        self
    }
}

#[async_trait]
impl AuditSource for VecAuditSource {
    async fn audit_stream(
        &self,
        incident_id: IncidentId,
        max_events: usize,
    ) -> Result<AuditStream, AuditError> {
        let all = self
            .streams
            .get(&incident_id.0)
            .cloned()
            .unwrap_or_default();
        let truncated = all.len() > max_events;
        Ok(AuditStream {
            incident_id: Some(incident_id),
            events: all.into_iter().take(max_events).collect(),
            truncated,
        })
    }
}

/// One page of historical incidents, for the §20.4 backfill.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IncidentPage {
    /// `(incident, the chain its `IncidentCreated` was stamped with)` — the
    /// chain travels with the incident because a draft row records it and the
    /// platform is multi-chain (§17); defaulting it to the deployment's chain
    /// would mislabel every backfilled L2 incident.
    pub incidents: Vec<(IncidentId, Chain)>,
    pub next_cursor: Option<String>,
}

/// Lists historical incidents over a time window — the backfill's input.
///
/// A seam for the same reason [`AuditSource`] is one: the backfill's whole
/// submit/poll/land lifecycle has to be exercisable without an event store,
/// and "which incidents exist" is the only other thing it reads.
#[async_trait]
pub trait IncidentSource: Send + Sync + std::fmt::Debug {
    /// One page of incidents created in `[from, to)`, oldest first.
    async fn incidents(
        &self,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
        cursor: Option<&str>,
        limit: u64,
    ) -> Result<IncidentPage, AuditError>;
}

#[async_trait]
impl IncidentSource for HttpAuditSource {
    /// `GET /v1/replay?event_type=IncidentCreated` — event-store's existing
    /// deterministic window read (§4/§18).
    ///
    /// Deliberately not a new endpoint: "every incident in a window" is
    /// exactly what replay already answers, and adding a copilot-shaped query
    /// to another service's API would be this crate reaching across the §14
    /// boundary in a politer costume.
    async fn incidents(
        &self,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
        cursor: Option<&str>,
        limit: u64,
    ) -> Result<IncidentPage, AuditError> {
        let mut params: Vec<(&str, String)> = vec![
            ("event_type", "IncidentCreated".to_owned()),
            ("limit", limit.max(1).to_string()),
        ];
        if let Some(from) = from {
            params.push(("from", from.to_rfc3339()));
        }
        if let Some(to) = to {
            params.push(("to", to.to_rfc3339()));
        }
        if let Some(cursor) = cursor {
            params.push(("cursor", cursor.to_owned()));
        }

        let response = self
            .client
            .get(format!("{}/v1/replay", self.base_url))
            .query(&params)
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(AuditError::Status {
                status: status.as_u16(),
                body,
            });
        }
        let page: EventPage = response.json().await?;
        Ok(IncidentPage {
            incidents: page
                .events
                .into_iter()
                .filter_map(|envelope| match envelope.payload {
                    // Read the id off the payload rather than trusting the
                    // filter: a store that ever widens what `event_type`
                    // matches must not silently enqueue drafts for events that
                    // are not incidents.
                    DomainEvent::IncidentCreated(incident) => {
                        Some((incident.incident_id, envelope.chain))
                    }
                    _ => None,
                })
                .collect(),
            next_cursor: page.next_cursor,
        })
    }
}

/// In-memory [`IncidentSource`]: one page of incidents, no event store.
#[derive(Debug, Clone, Default)]
pub struct VecIncidentSource {
    incidents: Vec<(IncidentId, Chain)>,
}

impl VecIncidentSource {
    pub fn new(incidents: Vec<(IncidentId, Chain)>) -> Self {
        Self { incidents }
    }
}

#[async_trait]
impl IncidentSource for VecIncidentSource {
    async fn incidents(
        &self,
        _from: Option<DateTime<Utc>>,
        _to: Option<DateTime<Utc>>,
        cursor: Option<&str>,
        limit: u64,
    ) -> Result<IncidentPage, AuditError> {
        // The cursor is the offset, so a paginating caller is exercised as
        // faithfully as the real store paginates it.
        let offset: usize = cursor.and_then(|c| c.parse().ok()).unwrap_or(0);
        let limit = limit.max(1) as usize;
        let page: Vec<(IncidentId, Chain)> = self
            .incidents
            .iter()
            .skip(offset)
            .take(limit)
            .copied()
            .collect();
        let next = offset + page.len();
        Ok(IncidentPage {
            incidents: page,
            next_cursor: (next < self.incidents.len()).then(|| next.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use event_bus::Transience;

    #[tokio::test]
    async fn the_ceiling_truncates_visibly_rather_than_silently() {
        let incident = IncidentId::new();
        let events = (0..5).map(crate::test_util::envelope).collect();
        let source = VecAuditSource::new(incident, events);

        let stream = source.audit_stream(incident, 3).await.unwrap();
        assert_eq!(stream.len(), 3);
        assert!(
            stream.truncated,
            "a prompt built on a partial stream must be able to say so"
        );
        assert_eq!(stream.event_ids().len(), 3);
    }

    #[tokio::test]
    async fn an_unknown_incident_is_an_empty_stream_not_an_error() {
        let source = VecAuditSource::default();
        let stream = source.audit_stream(IncidentId::new(), 10).await.unwrap();
        assert!(stream.is_empty() && !stream.truncated);
    }

    #[test]
    fn transience_splits_our_bugs_from_their_blips() {
        assert!(AuditError::Status {
            status: 503,
            body: String::new()
        }
        .is_transient());
        assert!(!AuditError::Status {
            status: 400,
            body: String::new()
        }
        .is_transient());
        assert!(!AuditError::PaginationStalled { pages: 3 }.is_transient());
    }
}
