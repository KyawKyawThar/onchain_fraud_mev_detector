//! Shared test doubles for the producer seam, behind the `test-util` feature —
//! the [`EventSink`] counterpart to `detector-api::test_util`'s `MockDetector`.
//!
//! Every producer crate (ingestion, detection, intelligence, simulation, the
//! api-service) used to hand-roll an identical "record every published envelope"
//! sink in its own `#[cfg(test)]` module. That one lives here now, next to the
//! trait it implements, so the double can't drift from the seam and a new
//! producer test reaches for it instead of copying it again.
//!
//! Enable it as a dev-dependency:
//! ```toml
//! [dev-dependencies]
//! event-bus = { workspace = true, features = ["test-util"] }
//! ```
//! Domain-specific assertions (e.g. "give me just the `RiskScoreUpdated`s")
//! stay in each crate's tests as a thin extension over [`RecordingSink::events`]
//! — this module only owns the generic recording behaviour.

use std::sync::Mutex;

use async_trait::async_trait;
use events::{DomainEvent, EventEnvelope};

use crate::{EventSink, PublishError};

/// An [`EventSink`] that records every published envelope for assertions,
/// instead of shipping to a broker. Stores the full [`EventEnvelope`] (the
/// superset) so a test can assert on transport-level fields (`chain`,
/// `topic()`, `event_id`); [`RecordingSink::events`] projects to the payloads
/// for the common "assert on the emitted domain events" case.
///
/// Wrap in an `Arc` to share it between the code under test and the assertions
/// (the `publish` seam takes `&self`).
#[derive(Default)]
pub struct RecordingSink {
    published: Mutex<Vec<EventEnvelope>>,
}

impl RecordingSink {
    /// The payloads published so far, in order — the common assertion target.
    pub fn events(&self) -> Vec<DomainEvent> {
        self.published
            .lock()
            .unwrap()
            .iter()
            .map(|envelope| envelope.payload.clone())
            .collect()
    }

    /// The full envelopes published so far, in order — for the rarer case that a
    /// test needs the transport metadata (`chain`, `topic()`, `event_id`), not
    /// just the payload.
    pub fn envelopes(&self) -> Vec<EventEnvelope> {
        self.published.lock().unwrap().clone()
    }

    /// How many published payloads matched `predicate`.
    pub fn count(&self, predicate: impl Fn(&DomainEvent) -> bool) -> usize {
        self.published
            .lock()
            .unwrap()
            .iter()
            .filter(|envelope| predicate(&envelope.payload))
            .count()
    }

    /// Total number of events published so far.
    pub fn len(&self) -> usize {
        self.published.lock().unwrap().len()
    }

    /// Whether nothing has been published yet.
    pub fn is_empty(&self) -> bool {
        self.published.lock().unwrap().is_empty()
    }

    /// Forget everything recorded so far — lets a test focus its assertions on
    /// the events produced *after* some setup phase.
    pub fn clear(&self) {
        self.published.lock().unwrap().clear();
    }
}

#[async_trait]
impl EventSink for RecordingSink {
    async fn publish(&self, envelope: EventEnvelope) -> Result<(), PublishError> {
        self.published.lock().unwrap().push(envelope);
        Ok(())
    }
}
