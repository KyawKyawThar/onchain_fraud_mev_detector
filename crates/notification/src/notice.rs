//! The event side of §11: what gets sent, derived deterministically from one
//! consumed [`events::DomainEvent`] — the pure core `crate::consumer`'s
//! imperative shell builds against (mirrors how `rule_engine::consumer::Fire`
//! is derived from a rule match). See `crate::model` for the subscriber side.

use chrono::{DateTime, Utc};
use events::detection::PreliminaryAlertCreated;
use events::intelligence::SanctionHit;
use events::predictive::{LiquidationCascadeWarned, LiquidationRiskPredicted, PredictedAlert};
use events::primitives::{
    AccountAddress, AlertId, AlertKind, Chain, CustomerId, IncidentId, Severity, SuggestedAction,
};
use events::rule_engine::RuleAlertCreated;
use events::simulation::{IncidentCreated, WalletExposureReportReady};
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
    /// The operator-facing urgency the source scored (§6/§7) — a total function
    /// of `severity`, carried alongside it so a subscriber can route on the
    /// *action* axis directly (e.g. "only page me for `EscalateImmediately`")
    /// without re-deriving it. `None` for an event that carries no scoring of its
    /// own (a `RuleAlertCreated`, a `SanctionHit`, a retraction), which bypasses
    /// the axis exactly like `severity`/`kind` do.
    pub suggested_action: Option<SuggestedAction>,
    pub chain: Chain,
    pub addresses: Vec<AccountAddress>,
    /// `Some(_)` restricts fan-out to that customer's own subscribers
    /// (a `RuleAlertCreated`); `None` is a platform-wide fact every matching
    /// subscriber is a candidate for.
    pub owner: Option<CustomerId>,
    pub summary: String,
    /// When the domain event that produced *this* notice was recorded
    /// (`EventEnvelope::occurred_at`) — the §19 "end-to-end alert latency"
    /// panel is `delivery time - occurred_at`, sampled at each successful
    /// [`crate::delivery::ChannelSink::deliver`]. Per-notice, not
    /// per-lineage: a Confirmed notice's `occurred_at` is `IncidentCreated`'s
    /// own timestamp, not the original provisional alert's — each stage
    /// measures its own event-to-delivery hop.
    pub occurred_at: DateTime<Utc>,
}

impl Notice {
    /// `PreliminaryAlertCreated` (§6, fast path) → the Provisional stage.
    ///
    /// Severity is the band the **detection service already scored** onto the
    /// event (`impact_usd × confidence`, §6) — carried through verbatim, not
    /// re-derived here. That is the whole point of the on-wire `severity`
    /// field: one attribution-blind scoring policy, owned by detection, so
    /// routing can't drift from a second local heuristic. (It supersedes the
    /// old confidence-only `confidence_bucket`, which measured a strictly
    /// weaker signal — confidence alone, blind to blast radius.) It is still a
    /// *provisional* band, distinct from simulation's confirmed [`Severity`]
    /// (§7); `dedup_key` is the `alert_id` this incident's eventual
    /// confirm/retract shares (see [`Self::from_incident_created`]).
    pub fn from_preliminary_alert(
        event: &PreliminaryAlertCreated,
        chain: Chain,
        occurred_at: DateTime<Utc>,
    ) -> Self {
        Self {
            dedup_key: event.alert_id.to_string(),
            stage: LifecycleStage::Provisional,
            kind: Some(event.kind),
            severity: Some(event.severity),
            suggested_action: Some(event.suggested_action),
            chain,
            addresses: event.addresses.clone(),
            owner: None,
            summary: format!(
                "provisional {:?} alert ({:.0}% confidence)",
                event.kind,
                event.confidence.get() * 100.0
            ),
            occurred_at,
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
    pub fn from_incident_created(
        event: &IncidentCreated,
        chain: Chain,
        occurred_at: DateTime<Utc>,
    ) -> Self {
        Self {
            dedup_key: event.alert_id.to_string(),
            stage: LifecycleStage::Confirmed,
            kind: Some(event.kind),
            severity: Some(event.severity),
            suggested_action: Some(event.suggested_action),
            chain,
            addresses: Vec::new(),
            owner: None,
            summary: format!(
                "confirmed {:?} incident: ${:.2} profit, ${:.2} victim loss",
                event.kind, event.profit, event.victim_loss
            ),
            occurred_at,
        }
    }

    /// `RuleAlertCreated` (§9) → Standalone (no provisional/confirmed pairing
    /// of its own). Both `severity` and `kind` are `None` — a customer's own
    /// rule carries neither on the wire, and it should reach that customer's
    /// subscribers regardless of how they've set those filters (they chose
    /// to author this exact rule; see `model::SubscriptionFilter`'s
    /// Option-bypass docs). `owner` scopes fan-out to that customer alone.
    pub fn from_rule_alert(
        event: &RuleAlertCreated,
        chain: Chain,
        occurred_at: DateTime<Utc>,
    ) -> Self {
        Self {
            dedup_key: event.alert_id.to_string(),
            stage: LifecycleStage::Standalone,
            kind: None,
            severity: None,
            suggested_action: None,
            chain,
            addresses: vec![event.address],
            owner: Some(event.owner),
            summary: event.explanation.clone(),
            occurred_at,
        }
    }

    /// `WalletExposureReportReady` (§25, Sprint 15 t5) → Standalone, the same
    /// shape as [`Self::from_rule_alert`]: `severity`/`kind` are `None`
    /// (bypassing both axes — a scheduled digest isn't confidence-scored or
    /// kind-tagged, and should reach the owner regardless of how they've set
    /// those filters), `owner` scopes fan-out to the customer who opted the
    /// wallet in. `summary` is the pre-rendered `headline` simulation built —
    /// this constructor deliberately never inspects `event.summary`'s JSON
    /// shape, keeping this crate decoupled from `simulation::exposure`'s
    /// internal type.
    ///
    /// `dedup_key` is derived deterministically from `(customer_id, address,
    /// period_start)`, the same SHA-256-preimage recipe
    /// [`sanction_dedup_key`] uses — so a redelivered/retried publish of the
    /// same cycle's report dedups instead of double-notifying, without the
    /// scheduler needing to track its own delivery state.
    pub fn from_exposure_report(
        event: &WalletExposureReportReady,
        chain: Chain,
        occurred_at: DateTime<Utc>,
    ) -> Self {
        Self {
            dedup_key: exposure_report_dedup_key(event).to_string(),
            stage: LifecycleStage::Standalone,
            kind: None,
            severity: None,
            suggested_action: None,
            chain,
            addresses: vec![event.address],
            owner: Some(event.customer_id),
            summary: event.headline.clone(),
            occurred_at,
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
    pub fn from_sanction_hit(
        event: &SanctionHit,
        chain: Chain,
        occurred_at: DateTime<Utc>,
    ) -> Self {
        Self {
            dedup_key: sanction_dedup_key(event).to_string(),
            stage: LifecycleStage::Standalone,
            kind: None,
            severity: Some(Severity::Critical),
            // No suggested_action of its own: a sanctions match is a hard-block
            // fact, not confidence-scored, so it bypasses the action axis (like
            // `kind`) rather than being pinned to a band-derived value. The
            // `Critical` severity already routes it to anyone with a severity floor.
            suggested_action: None,
            chain,
            addresses: vec![event.address],
            owner: None,
            summary: format!("sanctions match: {} ({})", event.list, event.entry),
            occurred_at,
        }
    }

    /// `PredictedAlert` (§16, mempool-pending forecast) → Standalone: the
    /// predictive pipeline's forecasts are never sim-confirmed (`events::predictive`'s
    /// module docs), so there is no Provisional/Confirmed pairing to mirror —
    /// same shape as [`Self::from_rule_alert`]/[`Self::from_sanction_hit`].
    /// `owner` stays `None`: a mempool forecast isn't scoped to a customer's
    /// own rule, it's a platform-wide signal every subscriber who opted in is
    /// a candidate for (§16.4, Sprint 16 task 4's opt-in predictive consumer
    /// — see `crate::consumer::predictive_topics`). No `suggested_action` of
    /// its own: the predictive pipeline carries only `confidence`, not a
    /// scored severity band to derive one from (unlike
    /// [`Self::from_liquidation_risk_predicted`], below).
    pub fn from_predicted_alert(
        event: &PredictedAlert,
        chain: Chain,
        occurred_at: DateTime<Utc>,
    ) -> Self {
        Self {
            dedup_key: event.prediction_id.to_string(),
            stage: LifecycleStage::Standalone,
            kind: Some(event.kind),
            severity: None,
            suggested_action: None,
            chain,
            addresses: event.addresses.clone(),
            owner: None,
            summary: format!(
                "predicted {:?} from a pending transaction ({:.0}% confidence)",
                event.kind,
                event.confidence.get() * 100.0
            ),
            occurred_at,
        }
    }

    /// `LiquidationRiskPredicted` (§16.2, cascade engine) → Standalone,
    /// tagged `AlertKind::Liquidation` so a risk-desk subscriber can filter
    /// on that one kind (§16.4, Sprint 16 task 4) without a new routing
    /// axis — `SubscriptionFilter::kinds` already exists for exactly this.
    /// `severity`/`suggested_action` are carried straight off the event's
    /// own measured band via [`events::scoring::suggested_action`], the same
    /// derivation [`Self::from_incident_created`] uses — this is a computed
    /// health-factor crossing, not a heuristic guess, so there is a real
    /// band to route on.
    pub fn from_liquidation_risk_predicted(
        event: &LiquidationRiskPredicted,
        chain: Chain,
        occurred_at: DateTime<Utc>,
    ) -> Self {
        Self {
            dedup_key: event.prediction_id.to_string(),
            stage: LifecycleStage::Standalone,
            kind: Some(AlertKind::Liquidation),
            severity: Some(event.severity),
            suggested_action: Some(events::scoring::suggested_action(event.severity)),
            chain,
            addresses: vec![event.account],
            owner: None,
            summary: format!(
                "{:?} liquidation risk on {:?}: health factor {:.3} ({:.1}% from liquidation)",
                event.severity, event.protocol, event.health_factor, event.distance_pct
            ),
            occurred_at,
        }
    }

    /// `LiquidationCascadeWarned` (§16.3, reflexivity walk) → Standalone,
    /// same `AlertKind::Liquidation` tag as
    /// [`Self::from_liquidation_risk_predicted`] so both liquidation-forecast
    /// events reach the same risk-desk filter. Hardcoded `Severity::Critical`:
    /// unlike a single position's health factor, this event only fires when
    /// the walk found *reflexive* growth beyond the naive at-risk set
    /// (`events::predictive`'s module docs) — by definition never the routine
    /// case, so there is no lower band to compute (mirrors
    /// [`Self::from_sanction_hit`]'s hardcoded-Critical reasoning).
    pub fn from_liquidation_cascade_warned(
        event: &LiquidationCascadeWarned,
        chain: Chain,
        occurred_at: DateTime<Utc>,
    ) -> Self {
        Self {
            dedup_key: event.prediction_id.to_string(),
            stage: LifecycleStage::Standalone,
            kind: Some(AlertKind::Liquidation),
            severity: Some(Severity::Critical),
            suggested_action: Some(events::scoring::suggested_action(Severity::Critical)),
            chain,
            addresses: event.accounts.clone(),
            owner: None,
            summary: format!(
                "liquidation cascade warning: {} account(s), ${:.0} at risk, depth {}{}",
                event.accounts.len(),
                event.aggregate_at_risk_usd.get(),
                event.reflexive_depth,
                if event.hub_capped {
                    " (hub-capped)"
                } else {
                    ""
                }
            ),
            occurred_at,
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
    pub fn retraction(
        alert_id: AlertId,
        chain: Chain,
        reason: &str,
        occurred_at: DateTime<Utc>,
    ) -> Self {
        Self {
            dedup_key: alert_id.to_string(),
            stage: LifecycleStage::Retracted,
            kind: None,
            severity: None,
            suggested_action: None,
            chain,
            addresses: Vec::new(),
            owner: None,
            summary: format!("retracted: {reason}"),
            occurred_at,
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

/// The deterministic dedup key for a [`WalletExposureReportReady`] (see
/// [`Notice::from_exposure_report`]'s docs) — SHA-256 over `(customer_id,
/// address, period_start)`, stamped as a well-formed UUIDv8 next to the
/// random v4 ids minted elsewhere. Pinned by the golden test below: changing
/// this preimage re-mints every in-flight report's delivery identity.
fn exposure_report_dedup_key(event: &WalletExposureReportReady) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(b"mevwatch.notification.wallet-exposure-report.v1");
    hasher.update(event.customer_id.0.as_bytes());
    hasher.update(event.address.as_slice());
    hasher.update(event.period_start.timestamp().to_be_bytes());
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
    use events::primitives::{Confidence, DetectorRef, SuggestedAction};

    fn addr(byte: u8) -> AccountAddress {
        AccountAddress::repeat_byte(byte)
    }

    fn preliminary_alert(confidence: f64, severity: Severity) -> PreliminaryAlertCreated {
        PreliminaryAlertCreated {
            alert_id: AlertId::new(),
            detector: DetectorRef {
                id: "sandwich".into(),
                version: "1.0".into(),
                config_hash: "abc".into(),
            },
            addresses: vec![addr(1)],
            kind: AlertKind::Sandwich,
            confidence: Confidence::new(confidence),
            provisional: true,
            impact_usd: None,
            severity,
            suggested_action: events::scoring::suggested_action(severity),
        }
    }

    #[test]
    fn preliminary_alert_carries_the_events_scored_severity_through() {
        let event = preliminary_alert(0.95, Severity::High);
        let notice = Notice::from_preliminary_alert(&event, Chain::ETHEREUM, Utc::now());
        assert_eq!(notice.stage, LifecycleStage::Provisional);
        assert_eq!(
            notice.severity,
            Some(Severity::High),
            "severity is the band detection scored onto the event, carried through"
        );
        assert_eq!(notice.kind, Some(AlertKind::Sandwich));
        assert_eq!(notice.owner, None, "platform-wide, not customer-scoped");
        assert_eq!(notice.dedup_key, event.alert_id.to_string());
    }

    #[test]
    fn provisional_severity_follows_the_event_not_confidence() {
        // High confidence but a Low scored band (e.g. unpriced impact): routing
        // must honour the event's severity, not re-derive from confidence — the
        // regression the old confidence-only bucket would have made (routing it
        // High) is exactly what consolidating onto `event.severity` prevents.
        let event = preliminary_alert(0.95, Severity::Low);
        let notice = Notice::from_preliminary_alert(&event, Chain::ETHEREUM, Utc::now());
        assert_eq!(notice.severity, Some(Severity::Low));
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
            impact_usd: None,
            severity: Severity::Critical,
            suggested_action: SuggestedAction::EscalateImmediately,
            victim_address: None,
            victim_loss_usd: None,
        };
        let notice = Notice::from_incident_created(&event, Chain::ETHEREUM, Utc::now());
        assert_eq!(notice.stage, LifecycleStage::Confirmed);
        assert_eq!(
            notice.dedup_key,
            alert_id.to_string(),
            "same lineage as the provisional"
        );
        assert_eq!(notice.severity, Some(Severity::Critical));
        assert_eq!(
            notice.suggested_action,
            Some(SuggestedAction::EscalateImmediately),
            "the confirmed action is carried through for routing"
        );
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
        let notice = Notice::from_rule_alert(&event, Chain::ETHEREUM, Utc::now());
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
        let notice = Notice::from_sanction_hit(&event, Chain::ETHEREUM, Utc::now());
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
        let notice = Notice::retraction(alert_id, Chain::ETHEREUM, "block reverted", Utc::now());
        assert_eq!(notice.stage, LifecycleStage::Retracted);
        assert_eq!(notice.severity, None);
        assert_eq!(notice.kind, None);
        assert_eq!(notice.dedup_key, alert_id.to_string());
    }

    fn exposure_report(
        customer_id: CustomerId,
        period_start: DateTime<Utc>,
    ) -> WalletExposureReportReady {
        WalletExposureReportReady {
            customer_id,
            address: addr(7),
            period_start,
            period_end: period_start + chrono::Duration::hours(24),
            headline: "$250.00 lost across 1 incident this period (worst: $250.00)".into(),
            summary: serde_json::json!({ "incident_count": 1 }),
        }
    }

    #[test]
    fn wallet_exposure_report_bypasses_severity_and_kind_but_scopes_to_its_owner() {
        let owner = CustomerId::new();
        let event = exposure_report(owner, Utc::now());
        let notice = Notice::from_exposure_report(&event, Chain::ETHEREUM, Utc::now());
        assert_eq!(notice.severity, None, "bypasses the severity gate");
        assert_eq!(notice.kind, None, "bypasses the kind gate");
        assert_eq!(
            notice.owner,
            Some(owner),
            "scoped to the wallet's owner only"
        );
        assert_eq!(notice.stage, LifecycleStage::Standalone);
        assert_eq!(notice.summary, event.headline);
        assert_eq!(notice.addresses, vec![event.address]);
    }

    /// The exposure-report dedup-key preimage is a stability contract, same
    /// discipline as `sanction_dedup_key_is_deterministic_and_pinned`.
    #[test]
    fn exposure_report_dedup_key_is_deterministic_and_pinned() {
        let owner = CustomerId(uuid::Uuid::from_u128(1));
        let period_start = DateTime::<Utc>::from_timestamp(1_000, 0).unwrap();
        let event = exposure_report(owner, period_start);

        let key = exposure_report_dedup_key(&event);
        assert_eq!(key.get_version_num(), 8, "well-formed UUIDv8");
        assert_eq!(
            key,
            exposure_report_dedup_key(&event),
            "pure: same input, same key"
        );
        assert_eq!(key.to_string(), "06ce5978-0a88-83ab-911f-e65a61c91799");

        // A distinct period is a distinct delivery — a later cycle's report
        // must not collide with (and thus be dedup-suppressed by) an earlier
        // one for the same wallet.
        let later_cycle = exposure_report(owner, period_start + chrono::Duration::hours(24));
        assert_ne!(
            exposure_report_dedup_key(&later_cycle),
            key,
            "a distinct period_start is a distinct dedup key"
        );

        // A different owner monitoring the same address must not collide either.
        let other_owner = exposure_report(CustomerId::new(), period_start);
        assert_ne!(
            exposure_report_dedup_key(&other_owner),
            key,
            "a distinct owner is a distinct dedup key"
        );
    }

    // ── §16.4, Sprint 16 task 4: predictive events ─────────────────────────

    use events::primitives::{LendingProtocol, PredictionId, UsdAmount};

    #[test]
    fn predicted_alert_bypasses_severity_but_carries_its_own_kind() {
        let event = PredictedAlert {
            prediction_id: PredictionId::new(),
            tx_hash: Default::default(),
            addresses: vec![addr(1)],
            kind: AlertKind::Sandwich,
            confidence: Confidence::new(0.9),
            provisional: true,
        };
        let notice = Notice::from_predicted_alert(&event, Chain::ETHEREUM, Utc::now());
        assert_eq!(notice.stage, LifecycleStage::Standalone);
        assert_eq!(notice.kind, Some(AlertKind::Sandwich));
        assert_eq!(notice.severity, None, "no severity of its own to carry");
        assert_eq!(notice.owner, None, "platform-wide, not customer-scoped");
        assert_eq!(notice.dedup_key, event.prediction_id.to_string());
    }

    #[test]
    fn liquidation_risk_predicted_carries_its_measured_severity_tagged_liquidation() {
        let event = LiquidationRiskPredicted {
            prediction_id: PredictionId::new(),
            protocol: LendingProtocol::Aave,
            account: addr(2),
            health_factor: 0.95,
            distance_pct: -5.0,
            severity: Severity::Critical,
            confidence: Confidence::new(1.0),
            provisional: true,
        };
        let notice = Notice::from_liquidation_risk_predicted(&event, Chain::ETHEREUM, Utc::now());
        assert_eq!(notice.stage, LifecycleStage::Standalone);
        assert_eq!(
            notice.kind,
            Some(AlertKind::Liquidation),
            "so a risk-desk subscriber can filter on this one kind"
        );
        assert_eq!(notice.severity, Some(Severity::Critical));
        assert_eq!(
            notice.suggested_action,
            Some(events::scoring::suggested_action(Severity::Critical))
        );
        assert_eq!(notice.addresses, vec![event.account]);
        assert_eq!(notice.owner, None, "platform-wide");
        assert_eq!(notice.dedup_key, event.prediction_id.to_string());
    }

    #[test]
    fn liquidation_cascade_warned_is_hardcoded_critical_tagged_liquidation() {
        let event = LiquidationCascadeWarned {
            prediction_id: PredictionId::new(),
            trigger_asset: Default::default(),
            trigger_price: 1_500.0,
            reflexive_depth: 2,
            accounts: vec![addr(3), addr(4)],
            aggregate_at_risk_usd: UsdAmount::new(40_000_000.0),
            hub_capped: false,
            confidence: Confidence::new(1.0),
            provisional: true,
        };
        let notice = Notice::from_liquidation_cascade_warned(&event, Chain::ETHEREUM, Utc::now());
        assert_eq!(notice.stage, LifecycleStage::Standalone);
        assert_eq!(notice.kind, Some(AlertKind::Liquidation));
        assert_eq!(notice.severity, Some(Severity::Critical));
        assert_eq!(notice.addresses, event.accounts);
        assert_eq!(notice.owner, None, "platform-wide");
        assert_eq!(notice.dedup_key, event.prediction_id.to_string());
    }
}
