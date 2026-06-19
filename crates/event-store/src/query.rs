//! The read path over the event store (§4 query API, §18 replay source).
//!
//! Three query shapes, all reconstructing the exact [`EventEnvelope`]s that were
//! appended (the `payload` is the source of truth — the denormalized
//! `incident_id`/`addresses` columns only make the lookups fast and are never
//! even selected here):
//!
//!   - [`EventStore::audit_incident`] — every event for one incident (§4 audit
//!     use case, `GET /v1/audit/incident/{id}`).
//!   - [`EventStore::events_by_address`] — every event referencing an address.
//!   - [`EventStore::replay`] — a deterministic stream over a time window,
//!     narrowed to a chain / event type (the §18 replay source, and the §4
//!     by-time-range query).
//!
//! All three return rows in the table's own sort order, `(occurred_at,
//! event_id)`, so a replay is reproducible across runs (§18), and all three
//! paginate by keyset on that same total order — a full page hands back a
//! [`Cursor`] to resume from, so a large window is never silently truncated.
//!
//! Writes still go through [`EventStore::append_batch`]; nothing here mutates.

use chrono::{DateTime, Utc};
use events::primitives::{AccountAddress, IncidentId};
use events::EventEnvelope;
use uuid::Uuid;

use crate::store::{normalized_address, EventStore, StoreError, StoredEvent, STORED_EVENT_COLUMNS};

/// Hard ceiling on a single page — a guard against an unbounded scan turning
/// into an OOM. Callers fetch more by following the [`EventPage::next_cursor`].
pub const MAX_LIMIT: u64 = 10_000;
/// Default page size when a caller doesn't ask for one.
pub const DEFAULT_LIMIT: u64 = 1_000;

/// A failure on the read path.
#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    /// The underlying store/storage failed.
    #[error(transparent)]
    Store(#[from] StoreError),

    /// [`EventStore::replay`] was called with no narrowing at all. Refused rather
    /// than scanning the entire, indefinitely-retained log — replay must name at
    /// least a chain, an event type, or a time bound.
    #[error("replay requires at least one of: chain, event_type, from, to")]
    UnboundedReplay,
}

/// A keyset cursor into the `(occurred_at, event_id)` sort order: the position to
/// resume *after*. Opaque to callers — produced by the store, passed back
/// verbatim — but cheap to encode as a stable token for a URL ([`Cursor::token`]
/// / [`Cursor::parse`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    pub occurred_at: DateTime<Utc>,
    pub event_id: Uuid,
}

impl Cursor {
    /// Encode as `<unix_millis>:<event_id>` — the millisecond resolution matches
    /// the `DateTime64(3)` column, so a round-tripped cursor lands exactly.
    pub fn token(&self) -> String {
        format!("{}:{}", self.occurred_at.timestamp_millis(), self.event_id)
    }

    /// Parse a token from [`Cursor::token`]. Returns `None` on any malformation
    /// (the caller maps that to a 400).
    pub fn parse(token: &str) -> Option<Self> {
        let (millis, event_id) = token.split_once(':')?;
        Some(Self {
            occurred_at: DateTime::<Utc>::from_timestamp_millis(millis.parse().ok()?)?,
            event_id: event_id.parse().ok()?,
        })
    }
}

/// One page of results plus where to resume.
#[derive(Debug)]
pub struct EventPage {
    /// The events, oldest first.
    pub events: Vec<EventEnvelope>,
    /// Set iff this page was full and more rows may follow — pass it back as
    /// [`Filters::cursor`] to fetch the next page. `None` means the stream is
    /// exhausted, so a caller can always tell a complete result from a truncated
    /// one.
    pub next_cursor: Option<Cursor>,
}

/// Optional narrowing shared by all three queries. An unset field is simply not
/// constrained; `cursor`/`limit` drive pagination and never count as narrowing.
#[derive(Debug, Default, Clone)]
pub struct Filters {
    /// Restrict to one chain (the high-order partition key).
    pub chain: Option<u64>,
    /// Restrict to one event type (e.g. `"BlockAssembled"`).
    pub event_type: Option<String>,
    /// Inclusive lower bound on `occurred_at`.
    pub from: Option<DateTime<Utc>>,
    /// Exclusive upper bound on `occurred_at` (half-open `[from, to)` so adjacent
    /// windows tile without overlap).
    pub to: Option<DateTime<Utc>>,
    /// Resume after this point in the sort order (keyset pagination).
    pub cursor: Option<Cursor>,
    /// Max rows for this page; clamped to `[1, MAX_LIMIT]`, defaulting to
    /// [`DEFAULT_LIMIT`].
    pub limit: Option<u64>,
}

impl Filters {
    /// The effective page size: the caller's `limit` clamped to `[1, MAX_LIMIT]`,
    /// or [`DEFAULT_LIMIT`] when unset.
    fn effective_limit(&self) -> u64 {
        self.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
    }

    /// Whether any chain/type/time narrowing is set (pagination doesn't count).
    fn has_narrowing(&self) -> bool {
        self.chain.is_some()
            || self.event_type.is_some()
            || self.from.is_some()
            || self.to.is_some()
    }
}

/// A bound scalar. Keeping the value next to its SQL fragment (in [`Conditions`])
/// is what removes the old "now bind these in the same order" footgun — there is
/// no separate bind step that could drift from the placeholders.
enum Bound {
    U64(u64),
    Str(String),
    Millis(i64),
}

/// Accumulates `WHERE` fragments together with their bind values, so the `?`
/// placeholders and the binds stay in lockstep *by construction* — every
/// [`Conditions::push`] appends a fragment and its binds together, and
/// [`EventStore::run_paged`] replays them in the one shared order.
#[derive(Default)]
struct Conditions {
    fragments: Vec<&'static str>,
    binds: Vec<Bound>,
}

impl Conditions {
    /// Add one condition and the binds its `?`s consume, in left-to-right order.
    fn push(&mut self, fragment: &'static str, binds: impl IntoIterator<Item = Bound>) {
        self.fragments.push(fragment);
        self.binds.extend(binds);
    }

    /// Add whichever of the shared filters / cursor are set. The order is fixed
    /// but irrelevant to correctness now that each fragment carries its own binds.
    fn add_filters(&mut self, filters: &Filters) {
        if let Some(chain) = filters.chain {
            self.push("chain = ?", [Bound::U64(chain)]);
        }
        if let Some(event_type) = &filters.event_type {
            self.push("event_type = ?", [Bound::Str(event_type.clone())]);
        }
        if let Some(from) = filters.from {
            self.push(
                "occurred_at >= fromUnixTimestamp64Milli(?)",
                [Bound::Millis(from.timestamp_millis())],
            );
        }
        if let Some(to) = filters.to {
            self.push(
                "occurred_at < fromUnixTimestamp64Milli(?)",
                [Bound::Millis(to.timestamp_millis())],
            );
        }
        if let Some(cursor) = filters.cursor {
            // Keyset: resume strictly after the previous page's last row.
            self.push(
                "(occurred_at, event_id) > (fromUnixTimestamp64Milli(?), toUUID(?))",
                [
                    Bound::Millis(cursor.occurred_at.timestamp_millis()),
                    Bound::Str(cursor.event_id.to_string()),
                ],
            );
        }
    }

    /// The `WHERE …` clause (with leading space), or empty if unconstrained.
    fn where_clause(&self) -> String {
        if self.fragments.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", self.fragments.join(" AND "))
        }
    }
}

impl EventStore {
    /// The event sequence for one incident, oldest first (§4 audit use case):
    /// every event whose payload directly carries `incident_id` — the simulation
    /// lifecycle and the `AttributionUpdated` overlay — optionally narrowed and
    /// paginated by `filters`.
    pub async fn audit_incident(
        &self,
        incident_id: IncidentId,
        filters: &Filters,
    ) -> Result<EventPage, QueryError> {
        let mut conditions = Conditions::default();
        conditions.push(
            "incident_id = toUUID(?)",
            [Bound::Str(incident_id.0.to_string())],
        );
        conditions.add_filters(filters);
        Ok(self
            .run_paged(conditions, filters.effective_limit())
            .await?)
    }

    /// Every event referencing `address`, oldest first, within `filters`. The
    /// address is matched against the denormalized index after normalizing to
    /// lowercase hex (via the same [`normalized_address`] the write path uses),
    /// so the caller's casing doesn't matter.
    pub async fn events_by_address(
        &self,
        address: AccountAddress,
        filters: &Filters,
    ) -> Result<EventPage, QueryError> {
        let mut conditions = Conditions::default();
        conditions.push(
            "has(addresses, ?)",
            [Bound::Str(normalized_address(&address))],
        );
        conditions.add_filters(filters);
        Ok(self
            .run_paged(conditions, filters.effective_limit())
            .await?)
    }

    /// Replay a deterministic event stream over the window in `filters`, oldest
    /// first (§18). With `event_type` set this is the §4
    /// replay-by-event-type-and-window; without it, the general by-time-range
    /// query. Requires at least one narrowing filter — an all-`None` `filters`
    /// is rejected as [`QueryError::UnboundedReplay`] rather than scanning the
    /// whole log.
    pub async fn replay(&self, filters: &Filters) -> Result<EventPage, QueryError> {
        if !filters.has_narrowing() {
            return Err(QueryError::UnboundedReplay);
        }
        let mut conditions = Conditions::default();
        conditions.add_filters(filters);
        Ok(self
            .run_paged(conditions, filters.effective_limit())
            .await?)
    }

    /// Execute a built query: select the canonical columns, order by the keyset,
    /// and fetch one row past `limit` so we can tell whether another page exists
    /// without a second round-trip.
    async fn run_paged(&self, conditions: Conditions, limit: u64) -> Result<EventPage, StoreError> {
        let sql = format!(
            "SELECT {STORED_EVENT_COLUMNS} FROM events{} ORDER BY occurred_at, event_id LIMIT ?",
            conditions.where_clause()
        );

        let mut query = self.client().query(&sql);
        for bound in conditions.binds {
            query = match bound {
                Bound::U64(v) => query.bind(v),
                Bound::Str(s) => query.bind(s),
                Bound::Millis(m) => query.bind(m),
            };
        }
        // `limit` is already clamped to MAX_LIMIT, so `+ 1` can't overflow.
        let mut rows = query.bind(limit + 1).fetch_all::<StoredEvent>().await?;

        // The probe row beyond `limit` means more pages follow: drop it and hand
        // back a cursor pointing at the last row we actually return.
        let has_more = rows.len() as u64 > limit;
        if has_more {
            rows.truncate(limit as usize);
        }
        let next_cursor = if has_more {
            rows.last().map(|row| Cursor {
                occurred_at: row.occurred_at,
                event_id: row.event_id,
            })
        } else {
            None
        };

        let events = rows
            .into_iter()
            .map(|row| EventEnvelope::try_from(row).map_err(StoreError::from))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(EventPage {
            events,
            next_cursor,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_token_round_trips() {
        let cursor = Cursor {
            occurred_at: DateTime::<Utc>::from_timestamp_millis(1_700_000_000_123).unwrap(),
            event_id: Uuid::from_u128(0xabc),
        };
        assert_eq!(Cursor::parse(&cursor.token()), Some(cursor));
    }

    #[test]
    fn malformed_cursor_tokens_are_rejected() {
        for bad in ["", "nope", "123", "x:y", "123:not-a-uuid", ":"] {
            assert!(Cursor::parse(bad).is_none(), "should reject {bad:?}");
        }
    }

    #[test]
    fn replay_without_narrowing_is_refused_before_touching_storage() {
        let filters = Filters {
            cursor: Some(Cursor {
                occurred_at: Utc::now(),
                event_id: Uuid::nil(),
            }),
            limit: Some(10),
            ..Default::default()
        };
        // Cursor + limit alone are not narrowing.
        assert!(!filters.has_narrowing());
    }
}
