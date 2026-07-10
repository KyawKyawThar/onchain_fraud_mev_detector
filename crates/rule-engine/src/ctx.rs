//! The evaluation context (§9) — the *pure* input a compiled matcher sees.
//!
//! The Kafka consumer (t4) builds one [`EventCtx`] per consumed domain event:
//! the event's own facts plus an [`Enrichment`] snapshot it prefetches
//! according to the rule set's [`crate::compile::EnrichmentNeeds`]. Matchers
//! then evaluate over the ctx alone — no I/O, no clock, no globals — which is
//! what makes rule evaluation table-testable and deterministic in replay
//! (§18, the same discipline as the detectors' pure core).
//!
//! Two predicate families share the ctx (documented per
//! [`crate::model::Condition`] arm in the compiler):
//!
//! * **event predicates** (`TransferAmount`, `InteractedWith`, `IncidentKind`)
//!   read [`EventCtx::facts`] — they are about *what just happened*;
//! * **state predicates** (`RiskScore`, `EntityLabel`, `SanctionMatch`,
//!   `HopDistance`, `NewAddress`) read [`EventCtx::enrichment`] — they are
//!   about *what is currently true* of the address. An intelligence-side event
//!   (`RiskScoreUpdated`, `LabelAdded`, `SanctionHit`, `EntityMerged`) is
//!   delivered as [`EventFacts::StateChanged`]: the consumer refreshes the
//!   enrichment and re-evaluates, so there is exactly one source of truth for
//!   state rather than an event-payload copy that can go stale.

use std::collections::{BTreeMap, BTreeSet};

use events::primitives::{AccountAddress, AlertKind, Chain, Confidence, LabelKind};
use rust_decimal::Decimal;

/// One event, as the rule engine evaluates it: which address it is about,
/// where on the chain it happened, what happened, and what intelligence
/// currently says about the address.
#[derive(Debug, Clone)]
pub struct EventCtx {
    /// The subject address rules are evaluated *for* — also the temporal
    /// state-machine partition key (§17: one worker owns an address).
    pub address: AccountAddress,
    /// Block height the event is anchored to (from the event envelope) — the
    /// clock every temporal window and `NewAddress` check measures against.
    pub block: u64,
    pub facts: EventFacts,
    pub enrichment: Enrichment,
}

/// What happened, reduced to the §9 vocabulary the matchers test.
#[derive(Debug, Clone, PartialEq)]
pub enum EventFacts {
    /// A normalized transfer touching the subject address (the §9 "enriched
    /// event stream"). `token` is the contract, `None` = the chain's native
    /// asset; `amount` is in human units, exact-decimal (never f64).
    Transfer {
        chain: Chain,
        token: Option<AccountAddress>,
        amount: Decimal,
        /// The other party — what `InteractedWith` tests, together with
        /// [`Enrichment::counterparty_labels`].
        counterparty: AccountAddress,
    },
    /// A confirmed incident (`IncidentCreated`, §7) involving the address.
    Incident {
        kind: AlertKind,
        confidence: Confidence,
    },
    /// Intelligence state about the address changed (`RiskScoreUpdated`,
    /// `LabelAdded`, `SanctionHit`, `EntityMerged`). Carries no payload on
    /// purpose: the consumer refreshes [`Enrichment`] and re-evaluates, so
    /// state predicates always read the one authoritative snapshot.
    StateChanged,
}

/// What intelligence currently says about the subject address — prefetched
/// per event by the consumer, scoped by the rule set's
/// [`crate::compile::EnrichmentNeeds`] so only fields some enabled rule
/// actually tests are fetched.
///
/// `Default` is the honest empty snapshot: every state predicate evaluates
/// `false` against it (no score, no labels, no sanctions), never panics.
#[derive(Debug, Clone, Default)]
pub struct Enrichment {
    /// Current risk score (0–100, §8.3), if one has been computed.
    pub risk_score: Option<u8>,
    /// Labels on the address's entity, with the read-time confidence (§8.1) —
    /// what `EntityLabel` tests.
    pub entity_labels: Vec<(LabelKind, Confidence)>,
    /// Sanctions lists (`list_name` keys, §8.5) the address appears on.
    pub sanction_lists: BTreeSet<String>,
    /// Labels on *this event's* counterparty (meaningful only for
    /// [`EventFacts::Transfer`]) — what `InteractedWith { label_kind }` tests.
    pub counterparty_labels: BTreeSet<LabelKind>,
    /// Hop distance from each anchor address some rule names in
    /// `HopDistance { from }` (the compiler publishes the anchor set in
    /// [`crate::compile::EnrichmentNeeds::hop_anchors`]); absent = farther
    /// than any rule's bound, or not connected.
    pub hop_distance: BTreeMap<AccountAddress, u8>,
    /// Block of the address's first observed activity — what `NewAddress`
    /// measures against [`EventCtx::block`].
    pub first_active_block: Option<u64>,
}
