//! The seams a rebuildable read model implements.
//!
//! §2 says projections are derived. These traits are that claim written down: a
//! read model is something that can be **re-folded from events into a staging
//! area**, **fingerprinted**, and **promoted atomically**. Anything that cannot
//! do all three is holding state that is not derived — which is the finding a
//! rebuild drill exists to produce.
//!
//! ## Three traits, not one
//!
//! An earlier cut of this crate had a single `ReadModel` trait carrying
//! `wipe`/`apply`/`flush`/`digest`. That conflated two unrelated jobs —
//! *projecting* (folding events and writing them) and *administering storage*
//! (creating, fingerprinting and swapping tables) — and the tell was concrete:
//! a read-only `fingerprint` had to construct a whole Kafka-shaped consumer it
//! never used. Conventions §2's corollary is explicit that a collaborator gets
//! the narrowest trait that does its job, so:
//!
//! * [`Projector`] — folds events and writes them. Held by the replay loop.
//! * [`Snapshotter`] — fingerprints the **live** read model. Held by
//!   `fingerprint`, which needs nothing else.
//! * [`Stageable`] — creates a staging area, hands back the [`Projector`] that
//!   writes into it, fingerprints it, and promotes or discards it.
//!
//! [`ReadModel`] is the blanket supertrait for the one type that owns all
//! three, so a driver can take a single object while each collaborator still
//! sees only what it may do.
//!
//! ## Staging, and why nothing is ever wiped
//!
//! A rebuild never truncates a live table. It builds the new state *beside* the
//! old one and swaps, because the alternative has two failure modes that no
//! amount of runbook prose fixes: a window during which every reader sees an
//! empty model, and a mid-replay fault that leaves production wiped and
//! half-filled. With staging, a failure is a [`Stageable::discard`] and
//! production was never touched — and `verify` becomes **non-destructive**,
//! which is what turns the drill from a scheduled outage into something that
//! can run on a timer.
//!
//! Both stores express a staging area as a *namespace* rather than a schema
//! change, so the production write path needs no modification to target it: a
//! Postgres schema on the `search_path`, a ClickHouse database on the client.
//! The projector that [`Stageable::stage`] returns is the same code writing the
//! same SQL, pointed somewhere else.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use events::EventEnvelope;

use crate::digest::ModelDigest;

/// A failure inside a read model's own storage during a rebuild.
///
/// Deliberately opaque (`anyhow`-shaped): the driver never retries or
/// classifies these. A rebuild is a supervised procedure, so the only correct
/// response to a storage failure is to stop, discard the staging area, and say
/// so — never to skip an event and produce a plausible, wrong projection.
#[derive(Debug, thiserror::Error)]
#[error("{context}")]
pub struct ModelError {
    context: String,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl ModelError {
    pub fn new(context: impl Into<String>) -> Self {
        Self {
            context: context.into(),
            source: None,
        }
    }

    pub fn wrap(
        context: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            context: context.into(),
            source: Some(Box::new(source)),
        }
    }
}

/// The slice of history a rebuild covers.
///
/// A staged rebuild builds a *complete* replacement, so a narrowed scope means
/// promoting a table that is missing everything outside the window. Whether
/// that is even expressible is a property of the read model's storage, which is
/// why it is **declared** ([`Snapshotter::scope_support`]) and enforced once by
/// the driver, rather than re-checked inside every implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// One chain, or every chain.
    pub chain: Option<u64>,
    /// Inclusive lower bound on event time. `UNIX_EPOCH` for a full rebuild.
    pub from: DateTime<Utc>,
    /// Exclusive upper bound on event time, or open-ended.
    pub to: Option<DateTime<Utc>>,
}

impl Scope {
    /// Everything: every chain, all of history — the scope of a real rebuild.
    pub fn everything() -> Self {
        Self {
            chain: None,
            from: DateTime::<Utc>::UNIX_EPOCH,
            to: None,
        }
    }

    /// Whether this scope covers the whole log.
    pub fn is_everything(&self) -> bool {
        self.chain.is_none() && self.from == DateTime::<Utc>::UNIX_EPOCH && self.to.is_none()
    }

    /// Narrow to one chain.
    pub fn for_chain(mut self, chain: u64) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Narrow to a half-open `[from, to)` event-time window.
    pub fn between(mut self, from: DateTime<Utc>, to: Option<DateTime<Utc>>) -> Self {
        self.from = from;
        self.to = to;
        self
    }
}

/// What narrowing a read model's storage can actually honour — a *declared*
/// capability, checked by the driver before anything is created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeSupport {
    /// Only [`Scope::everything`]. The common case, and not a limitation to
    /// route around: a row folded from events that straddle any window cannot
    /// be rebuilt from a slice of that window.
    FullOnly,
    /// Any scope; the storage can express the narrowing on both the staging
    /// build and the fingerprint.
    Narrowable,
}

/// A staging area: somewhere a rebuild writes that is not the live read model.
///
/// The id is the namespace the implementation creates (a Postgres schema, a
/// ClickHouse database). It is deterministic in its prefix and unique in its
/// suffix, so a leftover staging area from a crashed run is recognisable and
/// droppable by an operator, and two concurrent runs cannot collide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Staging {
    id: String,
}

impl Staging {
    /// Mint a new staging id, stamped with the time it was created.
    pub fn new(model: &str) -> Self {
        Self {
            // `-` is not legal unquoted in either store's identifiers; the
            // model name is a Rust `&'static str` from this workspace, never
            // operator input, but normalise anyway so the id is always a safe
            // bare identifier.
            id: format!(
                "rebuild_{}_{}",
                model.replace(['-', '.'], "_"),
                Utc::now().format("%Y%m%d_%H%M%S")
            ),
        }
    }

    /// Reconstruct a handle for an existing staging area (an operator cleaning
    /// up after a crashed run).
    pub fn from_id(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }

    /// The namespace identifier.
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl std::fmt::Display for Staging {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.id)
    }
}

/// Folds events and writes them. The narrow trait the replay loop holds.
///
/// **An implementation must fold through the code the live consumer runs** —
/// not a re-implementation of it. A rebuild that folds through a parallel copy
/// proves that the copy agrees with itself, which is worth nothing. The
/// reference implementation drives the real `ProjectionConsumer::handle` with
/// the broker taken out of the loop.
#[async_trait]
pub trait Projector: Send + Sync {
    /// The event types this projection is derived from, as
    /// [`events::DomainEvent::event_type`] strings. Empty means "the whole
    /// log" — see [`crate::source::MergedReplay`] for the ordering difference.
    ///
    /// Share the live consumer's own constant here. A type that is consumed but
    /// not declared is silently absent from every future rebuild.
    fn event_types(&self) -> Vec<String>;

    /// Fold one event and persist whatever it changed, into the staging area
    /// this projector was created for.
    ///
    /// Taken **by value**: the driver owns each replayed envelope and has no
    /// further use for it, while the live `EventHandler` an implementation
    /// delegates to wants an owned one. Borrowing would buy a clone per event
    /// across a replay that is millions of events long.
    async fn apply(&self, envelope: EventEnvelope) -> Result<(), ModelError>;

    /// Land anything buffered. Called once after the last event, before the
    /// staged fingerprint — so a batching implementation has somewhere to put
    /// its final partial batch.
    async fn flush(&self) -> Result<(), ModelError>;
}

/// Fingerprints the **live** read model. The narrow trait a read-only
/// `fingerprint` holds — it can observe, and can do nothing else.
#[async_trait]
pub trait Snapshotter: Send + Sync {
    /// Stable name, for logs, metrics and staging ids (`"simulation-incidents"`).
    fn name(&self) -> &'static str;

    /// What narrowing this model's storage can honour. Enforced by the driver.
    fn scope_support(&self) -> ScopeSupport;

    /// Fingerprint the live contents within `scope`.
    async fn digest(&self, scope: &Scope) -> Result<ModelDigest, ModelError>;
}

/// Builds a replacement beside the live read model and swaps it in.
///
/// The lifecycle is `stage → (apply…) → digest_staged → promote | discard`.
/// Every method is idempotent-ish in the way that matters operationally:
/// `discard` on an absent staging area succeeds, so cleanup after a crash is
/// safe to repeat.
#[async_trait]
pub trait Stageable: Send + Sync {
    /// Create an empty staging area and return the [`Projector`] that writes
    /// into it.
    ///
    /// The returned projector must write *only* to the staging area. This is
    /// the single most important invariant in the crate: a projector that
    /// leaked a write to the live tables would corrupt production during what
    /// is supposed to be a non-destructive verify.
    async fn stage(&self, staging: &Staging) -> Result<Arc<dyn Projector>, ModelError>;

    /// Fingerprint the staged (not yet live) contents, within `scope`.
    async fn digest_staged(
        &self,
        staging: &Staging,
        scope: &Scope,
    ) -> Result<ModelDigest, ModelError>;

    /// **Atomically** replace the live read model with the staged one, and
    /// return how many rows went live.
    ///
    /// Atomically is not a suggestion: a reader must never observe half the
    /// tables swapped. Postgres DDL is transactional, and ClickHouse has
    /// `EXCHANGE TABLES`; an implementation with neither must say so rather
    /// than approximate it.
    async fn promote(&self, staging: &Staging) -> Result<u64, ModelError>;

    /// Drop the staging area. The live read model is untouched. Succeeds when
    /// the staging area is already gone.
    async fn discard(&self, staging: &Staging) -> Result<(), ModelError>;
}

/// The one type that owns all three roles — what a driver takes.
///
/// A blanket impl, so implementers write the three traits and get this for
/// free (the same shape `copilot::store` uses for its four-way split).
pub trait ReadModel: Snapshotter + Stageable {}

impl<T: Snapshotter + Stageable> ReadModel for T {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_staging_id_is_a_safe_bare_identifier_and_unique_per_run() {
        let staging = Staging::new("simulation-incidents");
        assert!(staging.id().starts_with("rebuild_simulation_incidents_"));
        assert!(
            staging
                .id()
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "must be usable unquoted in both stores: {staging}"
        );
    }

    #[test]
    fn a_staging_handle_round_trips_through_its_id() {
        let staging = Staging::new("x");
        assert_eq!(Staging::from_id(staging.id()), staging);
    }

    #[test]
    fn everything_is_the_only_scope_that_reports_itself_as_full() {
        assert!(Scope::everything().is_everything());
        assert!(!Scope::everything().for_chain(1).is_everything());
        assert!(!Scope::everything()
            .between(Utc::now(), None)
            .is_everything());
    }
}
