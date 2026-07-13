//! The action-delivery seam (§9) — mirrors `event-bus::EventSink`: the
//! evaluation path raises a [`RuleAlert`] and hands each of the rule's
//! [`Action`]s to a [`ActionSink`], never speaking HTTP/SMTP/Slack itself.
//! Production is the webhook adapter ([`crate::webhook::WebhookActionSink`],
//! t5); tests use the recording double in [`crate::test_util`].
//!
//! Keeping delivery behind a seam is what lets t4's consumer be tested
//! end-to-end (event in → alert out) with zero network, and lets the real
//! adapter own its policy (per-target backoff, dedup per incident per
//! subscriber, §12) without the engine knowing.

use async_trait::async_trait;
use events::primitives::{AccountAddress, AlertId, CustomerId, RuleId};

use crate::model::Action;

/// One user-facing alert produced by a matched rule — the payload every
/// [`Action`] delivers, and what `RuleAlertCreated` (§2) is built from.
/// Routing is by `owner`: an alert only ever reaches the customer whose rule
/// fired (the delivery-side half of the §9 isolation contract).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleAlert {
    pub alert_id: AlertId,
    pub rule_id: RuleId,
    pub owner: CustomerId,
    /// The subject address the rule matched for.
    pub address: AccountAddress,
    /// The rule's name, echoed so the customer recognizes which of their
    /// rules fired without a lookup.
    pub rule_name: String,
    /// Human-readable account of what matched (t4 composes it from the
    /// matched conditions / temporal evidence).
    pub explanation: String,
    /// Blocks of the evidence window ([`crate::temporal::Fired`]), empty for
    /// instant rules.
    pub matched_blocks: Vec<u64>,
}

/// Why a delivery attempt failed, carrying the retry/skip decision — the same
/// fault-classification contract as the stores' `StoreError::is_transient`.
#[derive(Debug, thiserror::Error)]
pub enum DeliveryError {
    /// The target refused the alert (a 4xx, a bad channel, a revoked hook).
    /// Permanent: retrying the same payload at the same target fails again;
    /// the shell should surface it (dead-letter / customer notification), not
    /// spin on it.
    #[error("delivery target rejected the alert: {reason}")]
    Rejected { reason: String },
    /// The transport failed (timeout, connection, 5xx). Transient: retry with
    /// backoff per the adapter's policy.
    #[error("delivery transport failed: {reason}")]
    Transport { reason: String },
}

impl DeliveryError {
    pub fn is_transient(&self) -> bool {
        match self {
            DeliveryError::Rejected { .. } => false,
            DeliveryError::Transport { .. } => true,
        }
    }
}

/// Where alerts go. One call per `(alert, action)` pair — a rule with three
/// actions makes three deliveries, each independently retryable.
#[async_trait]
pub trait ActionSink: Send + Sync {
    async fn deliver(&self, alert: &RuleAlert, action: &Action) -> Result<(), DeliveryError>;
}
