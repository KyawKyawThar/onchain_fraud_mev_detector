//! The subscriber-side domain model (§11): who gets notified, on which
//! channels, gated by which filter. See [`crate::notice`] for the other half
//! — what gets sent, derived from the consumed events.

use chrono::{DateTime, Utc};
use events::primitives::{AlertKind, Chain, CustomerId, Severity};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A subscriber's identity. Local to this crate (never on the wire — no
/// `DomainEvent` references it), unlike `events::primitives`' newtypes which
/// exist because they cross service boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SubscriberId(pub Uuid);

impl SubscriberId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for SubscriberId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SubscriberId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// One delivery target. The `channel` column in `notice_deliveries` stores
/// [`ChannelKind`] (this enum's discriminant) — kept separate from `Channel`
/// itself because the dedup ledger keys on *kind*, not on the exact address/
/// URL (a subscriber editing a webhook URL doesn't reset its dedup history).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Channel {
    Webhook { url: String },
    Email { address: String },
    Slack { webhook_url: String },
    PagerDuty { routing_key: String },
}

impl Channel {
    pub fn kind(&self) -> ChannelKind {
        match self {
            Channel::Webhook { .. } => ChannelKind::Webhook,
            Channel::Email { .. } => ChannelKind::Email,
            Channel::Slack { .. } => ChannelKind::Slack,
            Channel::PagerDuty { .. } => ChannelKind::PagerDuty,
        }
    }
}

/// A channel's discriminant, independent of its target — what the dedup
/// ledger keys on (see [`Channel`]'s docs) and what delivery metrics are
/// labeled by.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    strum::IntoStaticStr,
    strum::EnumString,
    strum::EnumIter,
)]
#[strum(serialize_all = "snake_case")]
pub enum ChannelKind {
    Webhook,
    Email,
    Slack,
    PagerDuty,
}

impl ChannelKind {
    pub fn as_wire_str(self) -> &'static str {
        self.into()
    }
}

/// A subscriber's severity-routed delivery filter (§11). Every field is
/// `None`-means-"no gate on this axis" — the exact semantics
/// [`crate::notice::Notice`]'s own `Option` fields need to line up with: a
/// notice that carries no severity/kind of its own (a customer's own
/// `RuleAlertCreated`, a `SanctionHit`'s missing kind) bypasses that axis
/// rather than being rejected by a filter it can never satisfy.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SubscriptionFilter {
    pub min_severity: Option<Severity>,
    pub kinds: Option<Vec<AlertKind>>,
    pub chains: Option<Vec<Chain>>,
}

impl SubscriptionFilter {
    /// Whether `severity` clears this filter's floor. `None` on either side
    /// means "no gate" — a notice with no severity of its own always passes
    /// (see the struct docs), and a subscriber with no floor accepts anything.
    pub fn admits_severity(&self, severity: Option<Severity>) -> bool {
        match (self.min_severity, severity) {
            (Some(min), Some(actual)) => severity_rank(actual) >= severity_rank(min),
            _ => true,
        }
    }

    /// Whether `kind` clears this filter's allowlist. `None` on either side
    /// means "no gate" (see [`Self::admits_severity`]'s doc).
    pub fn admits_kind(&self, kind: Option<AlertKind>) -> bool {
        match (&self.kinds, kind) {
            (Some(allowed), Some(actual)) => allowed.contains(&actual),
            _ => true,
        }
    }

    /// Whether `chain` clears this filter's allowlist. Chain is always
    /// present on a notice (every envelope names one), so only the
    /// subscriber's side can be absent.
    pub fn admits_chain(&self, chain: Chain) -> bool {
        match &self.chains {
            Some(allowed) => allowed.contains(&chain),
            None => true,
        }
    }
}

/// `Severity`'s routing order, low to high. Kept local (not on `Severity`
/// itself — that type lives in the cross-service `events` schema crate and
/// has no reason to know about notification's routing comparison).
fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Low => 0,
        Severity::Medium => 1,
        Severity::High => 2,
        Severity::Critical => 3,
    }
}

/// A customer's alert subscription: a set of channels, gated by a filter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscriber {
    pub id: SubscriberId,
    pub owner: CustomerId,
    pub channels: Vec<Channel>,
    pub filter: SubscriptionFilter,
    pub enabled: bool,
}

impl Subscriber {
    /// Whether `self` should receive a notice with these routing facts — the
    /// severity/kind/chain gate `crate::consumer` applies before fanning out
    /// to (subscriber, channel) delivery attempts. Retraction/finalization
    /// deliberately does **not** call this (see `notice.rs`'s module docs) —
    /// it re-targets prior recipients from the delivery ledger instead.
    pub fn admits(
        &self,
        severity: Option<Severity>,
        kind: Option<AlertKind>,
        chain: Chain,
    ) -> bool {
        self.enabled
            && self.filter.admits_severity(severity)
            && self.filter.admits_kind(kind)
            && self.filter.admits_chain(chain)
    }
}

/// A stage in the §11 lifecycle a notice carries. `Standalone` covers events
/// with no provisional/confirmed/retracted pairing of their own
/// (`RuleAlertCreated`, `SanctionHit`) — see `notice.rs` for the mapping.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    strum::IntoStaticStr,
    strum::EnumString,
    strum::EnumIter,
)]
#[strum(serialize_all = "snake_case")]
pub enum LifecycleStage {
    Provisional,
    Confirmed,
    Retracted,
    Standalone,
}

impl LifecycleStage {
    pub fn as_wire_str(self) -> &'static str {
        self.into()
    }
}

/// A delivery attempt's outcome, stored on `notice_deliveries.status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::IntoStaticStr, strum::EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum DeliveryStatus {
    Pending,
    Delivered,
    Rejected,
    Failed,
}

impl DeliveryStatus {
    pub fn as_wire_str(self) -> &'static str {
        self.into()
    }
}

/// When a subscriber's row was created/updated, threaded through the store
/// so callers stamp a caller-supplied clock rather than the store reading
/// its own — same discipline as `rule_engine::store::RuleStore`.
pub type Timestamp = DateTime<Utc>;

#[cfg(test)]
mod tests {
    use super::*;

    fn subscriber(filter: SubscriptionFilter) -> Subscriber {
        Subscriber {
            id: SubscriberId::new(),
            owner: CustomerId::new(),
            channels: vec![Channel::Webhook {
                url: "https://example.com/hook".into(),
            }],
            filter,
            enabled: true,
        }
    }

    #[test]
    fn no_filter_admits_everything() {
        let s = subscriber(SubscriptionFilter::default());
        assert!(s.admits(
            Some(Severity::Low),
            Some(AlertKind::Sandwich),
            Chain::ETHEREUM
        ));
        assert!(s.admits(None, None, Chain::ETHEREUM));
    }

    #[test]
    fn min_severity_gates_only_when_the_notice_carries_one() {
        let s = subscriber(SubscriptionFilter {
            min_severity: Some(Severity::High),
            ..Default::default()
        });
        assert!(!s.admits(Some(Severity::Low), None, Chain::ETHEREUM));
        assert!(s.admits(Some(Severity::Critical), None, Chain::ETHEREUM));
        // A notice with no severity of its own (e.g. RuleAlertCreated)
        // bypasses the gate rather than being rejected.
        assert!(s.admits(None, None, Chain::ETHEREUM));
    }

    #[test]
    fn kind_allowlist_gates_only_when_the_notice_carries_a_kind() {
        let s = subscriber(SubscriptionFilter {
            kinds: Some(vec![AlertKind::Sandwich]),
            ..Default::default()
        });
        assert!(s.admits(None, Some(AlertKind::Sandwich), Chain::ETHEREUM));
        assert!(!s.admits(None, Some(AlertKind::Arbitrage), Chain::ETHEREUM));
        assert!(
            s.admits(None, None, Chain::ETHEREUM),
            "SanctionHit-style: no kind bypasses"
        );
    }

    #[test]
    fn chain_allowlist_always_gates_since_a_notice_always_names_one() {
        let s = subscriber(SubscriptionFilter {
            chains: Some(vec![Chain(2)]),
            ..Default::default()
        });
        assert!(!s.admits(None, None, Chain::ETHEREUM));
        assert!(s.admits(None, None, Chain(2)));
    }

    #[test]
    fn a_disabled_subscriber_admits_nothing() {
        let mut s = subscriber(SubscriptionFilter::default());
        s.enabled = false;
        assert!(!s.admits(None, None, Chain::ETHEREUM));
    }

    #[test]
    fn channel_kind_wire_strings_are_snake_case() {
        assert_eq!(ChannelKind::PagerDuty.as_wire_str(), "pager_duty");
        assert_eq!(ChannelKind::Webhook.as_wire_str(), "webhook");
    }
}
