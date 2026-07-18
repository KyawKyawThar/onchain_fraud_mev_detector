//! The event side of §11: what gets sent, derived deterministically from one
//! consumed [`events::DomainEvent`] — the pure core `crate::consumer`'s
//! imperative shell builds against (mirrors how `rule_engine::consumer::Fire`
//! is derived from a rule match). See `crate::model` for the subscriber side.

use events::detection::PreliminaryAlertCreated;
use events::intelligence::SanctionHit;
use events::primitives::{
    AccountAddress, AlertId, AlertKind, Chain, Confidence, CustomerId, IncidentId, Severity,
};
use events::rule_engine::RuleAlertCreated;
use events::simulation::IncidentCreated;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::model::LifecycleStage;

/// One notice, ready to route. Every field a subscriber's filter gates on is
/// `Option` — `None` means "this event carries no opinion on this axis",
/// which the routing logic (`SubscriptionFilter::admits_*`, `model.rs`)
/// treats as an automatic pass rather than a rejection. See the module docs
/// on each `from_*` constructor below for why a given event does or doesn't
/// carry a value on a given axis.
#[derive(Debug, Clone, PartialEq)]
pub struct Notice {
    /// The alert/incident lineage key — what `notice_deliveries` dedups and
    /// what a retraction re-targets by.
    pub dedup_key: String,
    pub stage: LifecycleStage,
    pub kind: Option<AlertKind>,
    pub severity: Option<Severity>,
    pub chain: Chain,
    pub addresses: Vec<AccountAddress>,
    /// `Some(_)` restricts fan-out to that customer's own subscribers
    /// (a `RuleAlertCreated`); `None` is a platform-wide fact every matching
    /// subscriber is a candidate for.
    pub owner: Option<CustomerId>,
    pub summary: String,
}

/// Confidence → coarse severity, for events that carry a [`Confidence`] but
/// no native [`Severity`] (only `PreliminaryAlertCreated`, today). A
/// deliberate, documented approximation — not the same measurement as
/// simulation's confirmed [`Severity`], but the closest signal available
/// before confirmation, and the thresholds are conservative (a merely
/// `Medium`-confidence provisional alert still routes as `Low`, so a
/// subscriber gated on severity isn't over-notified pre-confirmation).
pub fn confidence_bucket(confidence: Confidence) -> Severity {
    let value = confidence.get();
    if value >= 0.9 {
        Severity::High
    } else if value >= 0.75 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

impl Notice {
    /// `PreliminaryAlertCreated` (§6, fast path) → the Provisional stage.
    /// Severity is approximated from confidence (see
    /// [`confidence_bucket`]); `dedup_key` is the `alert_id` this incident's
    /// eventual confirm/retract shares (see [`Self::from_incident_created`]).
    pub fn from_preliminary_alert(event: &PreliminaryAlertCreated, chain: Chain) -> Self {
        Self {
            dedup_key: event.alert_id.to_string(),
            stage: LifecycleStage::Provisional,
            kind: Some(event.kind),
            severity: Some(confidence_bucket(event.confidence)),
            chain,
            addresses: event.addresses.clone(),
            owner: None,
            summary: format!(
                "provisional {:?} alert ({:.0}% confidence)",
                event.kind,
                event.confidence.get() * 100.0
            ),
        }
    }

    /// `IncidentCreated` (§7, simulation-confirmed) → the Confirmed stage.
    /// **`dedup_key` is `alert_id`, not `incident_id`** — deliberately the
    /// same key the provisional notice used, so a subscriber's confirmed
    /// delivery reads as an *upgrade* of the provisional one (a distinct
    /// `notice_deliveries` row, same lineage) rather than an unrelated new
    /// item. The `incident_id ↔ alert_id` mapping this implies is recorded
    /// separately by the consumer (`store::NotificationStore::record_incident_alert`)
    /// so a later `IncidentRetracted`/`IncidentFinalized` (keyed only on
    /// `incident_id`) can resolve back to this same `dedup_key`.
    ///
    /// `addresses` is deliberately empty: `IncidentCreated` (§7) carries no
    /// addresses of its own — only `PreliminaryAlertCreated` does — and the
    /// subscriber already received them on the provisional notice. Threading
    /// them through here would mean a second cross-topic correlation buffer
    /// (alert_id → addresses) purely for repeated payload context; not worth
    /// the complexity since addresses play no part in routing.
    pub fn from_incident_created(event: &IncidentCreated, chain: Chain) -> Self {
        Self {
            dedup_key: event.alert_id.to_string(),
            stage: LifecycleStage::Confirmed,
            kind: Some(event.kind),
            severity: Some(event.severity),
            chain,
            addresses: Vec::new(),
            owner: None,
            summary: format!(
                "confirmed {:?} incident: ${:.2} profit, ${:.2} victim loss",
                event.kind, event.profit, event.victim_loss
            ),
        }
    }

    /// `RuleAlertCreated` (§9) → Standalone (no provisional/confirmed pairing
    /// of its own). Both `severity` and `kind` are `None` — a customer's own
    /// rule carries neither on the wire, and it should reach that customer's
    /// subscribers regardless of how they've set those filters (they chose
    /// to author this exact rule; see `model::SubscriptionFilter`'s
    /// Option-bypass docs). `owner` scopes fan-out to that customer alone.
    pub fn from_rule_alert(event: &RuleAlertCreated, chain: Chain) -> Self {
        Self {
            dedup_key: event.alert_id.to_string(),
            stage: LifecycleStage::Standalone,
            kind: None,
            severity: None,
            chain,
            addresses: vec![event.address],
            owner: Some(event.owner),
            summary: event.explanation.clone(),
        }
    }

    /// `SanctionHit` (§8.5) → Standalone. Hardcoded `Severity::Critical` — a
    /// sanctions match is a hard-block-tier fact by design (§8.5's "hard
    /// alert that bypasses the slow path"), not something confidence-scored.
    /// `kind` stays `None`: [`AlertKind`] is a closed MEV-behaviour
    /// vocabulary with no sanctions variant, so the kind gate is bypassed
    /// rather than mis-tagged. `SanctionHit` carries no id of its own, so
    /// `dedup_key` is derived deterministically from its content — the same
    /// SHA-256-preimage recipe `rule_engine::consumer::Fire::alert_id` uses,
    /// so a redelivered event dedups instead of re-notifying.
    pub fn from_sanction_hit(event: &SanctionHit, chain: Chain) -> Self {
        Self {
            dedup_key: sanction_dedup_key(event).to_string(),
            stage: LifecycleStage::Standalone,
            kind: None,
            severity: Some(Severity::Critical),
            chain,
            addresses: vec![event.address],
            owner: None,
            summary: format!("sanctions match: {} ({})", event.list, event.entry),
        }
    }

    /// `IncidentRetracted`/`IncidentFinalized` (§7/§15) carry only
    /// `incident_id` — `crate::consumer` resolves the paired `alert_id`
    /// (durably via `store::NotificationStore::alert_for_incident`, or the
    /// in-memory correlation buffer for one that outran its confirm) before
    /// building this notice, since the dedup lineage is the `alert_id`, not
    /// the `incident_id` (see [`Self::from_incident_created`]'s docs).
    /// Severity/kind/owner are irrelevant here on purpose: a retraction is
    /// **not filtered** — it re-targets exactly who already received the
    /// provisional/confirmed delivery, via
    /// `store::NotificationStore::delivered_targets_for`, not a fresh
    /// subscriber scan (a subscriber's filter may have changed since).
    pub fn retraction(alert_id: AlertId, chain: Chain, reason: &str) -> Self {
        Self {
            dedup_key: alert_id.to_string(),
            stage: LifecycleStage::Retracted,
            kind: None,
            severity: None,
            chain,
            addresses: Vec::new(),
            owner: None,
            summary: format!("retracted: {reason}"),
        }
    }
}

/// The deterministic dedup key for a [`SanctionHit`] (see
/// [`Notice::from_sanction_hit`]'s docs) — SHA-256 over `(address, list,
/// entry)`, stamped as a well-formed UUIDv8 next to the random v4 ids minted
/// elsewhere. The exact preimage is a stability contract (pinned by the
/// golden test below): changing it re-mints every in-flight sanction
/// notice's identity.
fn sanction_dedup_key(event: &SanctionHit) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(b"mevwatch.notification.sanction-hit.v1");
    hasher.update(event.address.as_slice());
    hasher.update(event.list.as_bytes());
    hasher.update([0u8]); // field separator: `list`/`entry` are variable-length strings.
    hasher.update(event.entry.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

/// The incident<->alert correlation: what `IncidentCreated` teaches the
/// consumer about resolving a later `IncidentRetracted`/`IncidentFinalized`
/// back to its `dedup_key`.
pub fn incident_alert_link(event: &IncidentCreated) -> (IncidentId, AlertId) {
    (event.incident_id, event.alert_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use events::primitives::DetectorRef;

    fn addr(byte: u8) -> AccountAddress {
        AccountAddress::repeat_byte(byte)
    }

    #[test]
    fn confidence_buckets_are_conservative() {
        assert_eq!(confidence_bucket(Confidence::new(0.95)), Severity::High);
        assert_eq!(confidence_bucket(Confidence::new(0.9)), Severity::High);
        assert_eq!(confidence_bucket(Confidence::new(0.89)), Severity::Medium);
        assert_eq!(confidence_bucket(Confidence::new(0.75)), Severity::Medium);
        assert_eq!(confidence_bucket(Confidence::new(0.74)), Severity::Low);
        assert_eq!(confidence_bucket(Confidence::new(0.0)), Severity::Low);
    }

    #[test]
    fn preliminary_alert_is_provisional_with_derived_severity() {
        let event = PreliminaryAlertCreated {
            alert_id: AlertId::new(),
            detector: DetectorRef {
                id: "sandwich".into(),
                version: "1.0".into(),
                config_hash: "abc".into(),
            },
            addresses: vec![addr(1)],
            kind: AlertKind::Sandwich,
            confidence: Confidence::new(0.95),
            provisional: true,
        };
        let notice = Notice::from_preliminary_alert(&event, Chain::ETHEREUM);
        assert_eq!(notice.stage, LifecycleStage::Provisional);
        assert_eq!(notice.severity, Some(Severity::High));
        assert_eq!(notice.kind, Some(AlertKind::Sandwich));
        assert_eq!(notice.owner, None, "platform-wide, not customer-scoped");
        assert_eq!(notice.dedup_key, event.alert_id.to_string());
    }

    #[test]
    fn incident_created_shares_the_provisional_alerts_dedup_key() {
        let alert_id = AlertId::new();
        let event = IncidentCreated {
            incident_id: IncidentId::new(),
            alert_id,
            kind: AlertKind::Sandwich,
            txs: vec![],
            profit: 5.0,
            victim_loss: 2.0,
            severity: Severity::Critical,
        };
        let notice = Notice::from_incident_created(&event, Chain::ETHEREUM);
        assert_eq!(notice.stage, LifecycleStage::Confirmed);
        assert_eq!(
            notice.dedup_key,
            alert_id.to_string(),
            "same lineage as the provisional"
        );
        assert_eq!(notice.severity, Some(Severity::Critical));
    }

    #[test]
    fn rule_alert_bypasses_severity_and_kind_but_scopes_to_its_owner() {
        let owner = CustomerId::new();
        let event = RuleAlertCreated {
            alert_id: AlertId::new(),
            rule_id: events::primitives::RuleId::new(),
            owner,
            address: addr(5),
            explanation: "matched".into(),
        };
        let notice = Notice::from_rule_alert(&event, Chain::ETHEREUM);
        assert_eq!(notice.severity, None, "bypasses the severity gate");
        assert_eq!(notice.kind, None, "bypasses the kind gate");
        assert_eq!(notice.owner, Some(owner), "scoped to the rule's owner only");
        assert_eq!(notice.stage, LifecycleStage::Standalone);
    }

    #[test]
    fn sanction_hit_is_hardcoded_critical_with_no_kind() {
        let event = SanctionHit {
            address: addr(9),
            list: "ofac_sdn".into(),
            entry: "SDN-1".into(),
        };
        let notice = Notice::from_sanction_hit(&event, Chain::ETHEREUM);
        assert_eq!(notice.severity, Some(Severity::Critical));
        assert_eq!(notice.kind, None);
        assert_eq!(notice.owner, None, "platform-wide");
    }

    /// The sanction dedup-key preimage is a stability contract — pin it so a
    /// well-meaning refactor can't silently re-mint every in-flight notice's
    /// identity (same style as `rule_engine::consumer`'s `alert_id_preimage_is_pinned`).
    #[test]
    fn sanction_dedup_key_is_deterministic_and_pinned() {
        let event = SanctionHit {
            address: AccountAddress::repeat_byte(0xAB),
            list: "ofac_sdn".into(),
            entry: "SDN-1".into(),
        };
        let key = sanction_dedup_key(&event);
        assert_eq!(key.get_version_num(), 8, "well-formed UUIDv8");
        assert_eq!(
            key,
            sanction_dedup_key(&event),
            "pure: same input, same key"
        );
        assert_eq!(key.to_string(), "87e3e8a7-06c1-8e60-bb9c-31a7246d9d1a");

        let different_entry = SanctionHit {
            entry: "SDN-2".into(),
            ..event
        };
        assert_ne!(
            sanction_dedup_key(&different_entry),
            key,
            "a distinct entry is a distinct dedup key"
        );
    }

    #[test]
    fn retraction_carries_no_filter_axis() {
        let alert_id = AlertId::new();
        let notice = Notice::retraction(alert_id, Chain::ETHEREUM, "block reverted");
        assert_eq!(notice.stage, LifecycleStage::Retracted);
        assert_eq!(notice.severity, None);
        assert_eq!(notice.kind, None);
        assert_eq!(notice.dedup_key, alert_id.to_string());
    }
}
