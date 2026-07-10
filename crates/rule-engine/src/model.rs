//! The §9 rule model — the document a customer authors and the engine
//! evaluates. Parsed and validated at the boundary ([`Rule::validate`]), so the
//! compiler (t2) and temporal state machines (t3) never re-check shape
//! invariants ("parse, don't validate", same stance as `intelligence::model`).
//!
//! Wire form: the enums are externally tagged with snake_case names, so the
//! stored JSONB reads like §9's YAML examples —
//! `{"transfer_amount": {"chain": 1, "gt": "1000000"}}` — and the JSON a
//! `POST /v1/rules` body carries (t4) is byte-for-byte what the store persists.
//!
//! Two deliberate refinements over §9's sketch:
//!   * `min_confidence` is the schema's [`Confidence`] newtype, not a bare
//!     `f32`; its serde form is transparent (unvalidated), so
//!     [`Rule::validate`] range-checks the threshold — an out-of-range value
//!     never gets past the parse boundary.
//!   * thresholds are [`Decimal`] (string-serde, exact) — money comparisons
//!     never round-trip through f64.

use events::primitives::{
    AccountAddress, AlertKind, Chain, Confidence, CustomerId, LabelKind, RuleId,
};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

/// A customer-defined rule (§9): a set of [`Condition`]s combined by one
/// [`LogicOp`], optionally constrained in time, firing [`Action`]s on match.
///
/// Rules are **owned**: `owner` scopes every store read/write (see
/// [`crate::store::RuleStore`]), so one customer's rules are invisible to — and
/// untouchable by — every other customer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub id: RuleId,
    pub owner: CustomerId,
    pub name: String,
    /// Disabled rules stay stored (and editable) but are never evaluated.
    pub enabled: bool,
    pub conditions: Vec<Condition>,
    pub logic: LogicOp,
    /// `None` = evaluate each event in isolation; `Some` = the t3 windowed
    /// per-`(rule_id, address)` state machine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temporal: Option<TemporalConstraint>,
    pub actions: Vec<Action>,
}

impl Rule {
    /// Check every shape invariant the §9 model implies. Called by the store
    /// before any insert — an invalid rule can never land in Postgres — and by
    /// the `POST /v1/rules` boundary (t4) to reject bad definitions with a
    /// specific reason instead of a 500 later.
    pub fn validate(&self) -> Result<(), InvalidRule> {
        if self.name.trim().is_empty() {
            return Err(InvalidRule::EmptyName);
        }
        if self.conditions.is_empty() {
            return Err(InvalidRule::NoConditions);
        }
        if self.actions.is_empty() {
            return Err(InvalidRule::NoActions);
        }
        for condition in &self.conditions {
            condition.validate()?;
        }
        if let Some(temporal) = &self.temporal {
            temporal.validate()?;
        }
        for action in &self.actions {
            action.validate()?;
        }
        Ok(())
    }

    /// Visit every condition in the rule — top-level *and* inside the temporal
    /// clause — in one place, so consumers that fold over the whole set (the
    /// compiler's [`crate::compile::EnrichmentNeeds`] aggregation, future
    /// linting) don't each re-implement the recursion and miss a spot.
    pub fn for_each_condition<'a>(&'a self, mut f: impl FnMut(&'a Condition)) {
        for condition in &self.conditions {
            f(condition);
        }
        match &self.temporal {
            Some(TemporalConstraint::Sequence { events, .. }) => events.iter().for_each(f),
            Some(TemporalConstraint::Frequency { condition, .. }) => f(condition),
            None => {}
        }
    }
}

/// How a rule's conditions combine (§9).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    strum::IntoStaticStr,
    strum::EnumString,
    strum::EnumIter,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum LogicOp {
    /// Every condition must match.
    All,
    /// At least one condition must match.
    Any,
    /// No condition may match — the rule fires on the *absence* of the
    /// described behaviour.
    Not,
}

/// One testable predicate over the enriched event stream (§9). A closed
/// vocabulary: adding a condition type is a schema change (new matcher in t2,
/// new docs, new API surface), not a config edit.
///
/// Threshold fields come in `gt`/`lt` pairs where §9 defines them; at least one
/// bound must be present ([`Condition::validate`]), and `gt < lt` when both
/// are (a contradiction can never match, so it's rejected as authoring error).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Condition {
    /// A transfer's amount crossed a threshold. `token` is the token contract
    /// (`None` = the chain's native asset); the API layer resolves customer-
    /// friendly symbols ("USDC") to addresses before the rule is stored, so
    /// the stored form is unambiguous. Thresholds are in the token's *human*
    /// units (the enrichment pipeline normalizes decimals), exact-decimal.
    TransferAmount {
        chain: Chain,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<AccountAddress>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gt: Option<Decimal>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lt: Option<Decimal>,
    },
    /// The address interacted with a specific counterparty and/or any
    /// counterparty carrying a label kind. At least one selector is required.
    InteractedWith {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address: Option<AccountAddress>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label_kind: Option<LabelKind>,
    },
    /// A confirmed incident of this kind involves the address (§9's
    /// `IncidentKind` — the schema names the behaviour taxonomy [`AlertKind`]).
    IncidentKind {
        kind: AlertKind,
        min_confidence: Confidence,
    },
    /// The address's entity carries a label of this kind (§8.1 vocabulary).
    EntityLabel {
        kind: LabelKind,
        min_confidence: Confidence,
    },
    /// The address's risk score (0–100, §8.3) crossed a threshold.
    RiskScore {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gt: Option<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lt: Option<u8>,
    },
    /// The address matched a sanctions list (§8.5). `list` is the intelligence
    /// store's `list_name` key (e.g. `"ofac_sdn"`, `"eu_consolidated"` — an
    /// open set, new national lists appear without a schema change); `None`
    /// matches a hit on *any* list.
    SanctionMatch {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        list: Option<String>,
    },
    /// The address is within `max_hops` transfers of `from` on the §8.2
    /// adjacency graph.
    HopDistance { from: AccountAddress, max_hops: u8 },
    /// The address first became active within the last N blocks — fresh
    /// wallets are a fraud signal.
    NewAddress { active_within_blocks: u64 },
}

impl Condition {
    /// Shape invariants for one condition (see [`Rule::validate`]).
    pub fn validate(&self) -> Result<(), InvalidRule> {
        match self {
            Condition::TransferAmount { gt, lt, .. } => {
                validate_range("transfer_amount", gt.as_ref(), lt.as_ref())
            }
            Condition::InteractedWith {
                address: None,
                label_kind: None,
            } => Err(InvalidRule::UnboundedInteraction),
            Condition::InteractedWith { .. } => Ok(()),
            // `Confidence`'s serde form is deliberately transparent (no
            // validation on deserialize — see its docs), so the range check on
            // a customer-supplied threshold happens here, the rule's one parse
            // boundary.
            Condition::IncidentKind { min_confidence, .. }
            | Condition::EntityLabel { min_confidence, .. } => {
                Confidence::try_new(min_confidence.get()).map_err(|err| {
                    InvalidRule::ConfidenceOutOfRange {
                        threshold: err.value,
                    }
                })?;
                Ok(())
            }
            Condition::RiskScore { gt, lt } => {
                for bound in [gt, lt].into_iter().flatten() {
                    if *bound > 100 {
                        return Err(InvalidRule::RiskScoreOutOfRange { bound: *bound });
                    }
                }
                validate_range("risk_score", gt.as_ref(), lt.as_ref())
            }
            Condition::SanctionMatch { list } => {
                if let Some(list) = list {
                    if list.trim().is_empty() {
                        return Err(InvalidRule::EmptyField {
                            what: "sanction_match.list",
                        });
                    }
                }
                Ok(())
            }
            Condition::HopDistance { max_hops, .. } => {
                if *max_hops == 0 {
                    // Zero hops is "is the address itself" — that's an exact
                    // match the customer should express differently, and the
                    // graph walk can't take zero steps.
                    Err(InvalidRule::ZeroBound {
                        what: "hop_distance.max_hops",
                    })
                } else {
                    Ok(())
                }
            }
            Condition::NewAddress {
                active_within_blocks,
            } => {
                if *active_within_blocks == 0 {
                    Err(InvalidRule::ZeroBound {
                        what: "new_address.active_within_blocks",
                    })
                } else {
                    Ok(())
                }
            }
        }
    }
}

/// A `gt`/`lt` threshold pair: at least one bound, and a satisfiable window.
fn validate_range<T: PartialOrd>(
    what: &'static str,
    gt: Option<&T>,
    lt: Option<&T>,
) -> Result<(), InvalidRule> {
    match (gt, lt) {
        (None, None) => Err(InvalidRule::UnboundedRange { what }),
        (Some(gt), Some(lt)) if gt >= lt => Err(InvalidRule::EmptyRange { what }),
        _ => Ok(()),
    }
}

/// The time dimension of a rule (§9): either an ordered sequence of conditions
/// or a repetition count, both bounded by a block window. Evaluated by the t3
/// per-`(rule_id, address)` state machine; a plain (non-temporal) rule is
/// `Rule::temporal == None`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalConstraint {
    /// The conditions must match *in order* within `within_blocks` blocks —
    /// "large transfer, then mixer interaction, within 100 blocks".
    Sequence {
        events: Vec<Condition>,
        within_blocks: u64,
    },
    /// One condition must match at least `count` times within the window.
    Frequency {
        condition: Box<Condition>,
        count: u32,
        within_blocks: u64,
    },
}

impl TemporalConstraint {
    /// Shape invariants for the temporal clause (see [`Rule::validate`]).
    pub fn validate(&self) -> Result<(), InvalidRule> {
        match self {
            TemporalConstraint::Sequence {
                events,
                within_blocks,
            } => {
                if events.len() < 2 {
                    // A one-step "sequence" is just a condition; requiring ≥2
                    // keeps the state machine's semantics meaningful.
                    return Err(InvalidRule::DegenerateSequence {
                        steps: events.len(),
                    });
                }
                if *within_blocks == 0 {
                    return Err(InvalidRule::ZeroBound {
                        what: "sequence.within_blocks",
                    });
                }
                for event in events {
                    event.validate()?;
                }
                Ok(())
            }
            TemporalConstraint::Frequency {
                condition,
                count,
                within_blocks,
            } => {
                if *count < 2 {
                    // Frequency 1 is just the condition itself.
                    return Err(InvalidRule::DegenerateFrequency { count: *count });
                }
                if *within_blocks == 0 {
                    return Err(InvalidRule::ZeroBound {
                        what: "frequency.within_blocks",
                    });
                }
                condition.validate()
            }
        }
    }
}

/// What a matched rule does (§9). Delivery itself (retry, dedup, receipts) is
/// the notification path's job (t5/§12); the model only pins *where* the alert
/// goes, validated well enough that delivery never sees a malformed target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// POST the alert to a customer-controlled endpoint.
    WebhookAlert { url: String },
    /// Email the alert.
    EmailAlert { to: String },
    /// Post the alert to a Slack channel.
    SlackAlert { channel: String },
    /// Feed the match back into intelligence as a customer-scoped tag.
    TagAddress { label: String },
}

impl Action {
    /// Shape invariants for one action (see [`Rule::validate`]).
    pub fn validate(&self) -> Result<(), InvalidRule> {
        match self {
            Action::WebhookAlert { url } => {
                let parsed = url::Url::parse(url).map_err(|source| InvalidRule::BadWebhookUrl {
                    url: url.clone(),
                    reason: source.to_string(),
                })?;
                // http(s) only: the delivery worker speaks HTTP, and accepting
                // arbitrary schemes here would hand it surprises later.
                if !matches!(parsed.scheme(), "http" | "https") {
                    return Err(InvalidRule::BadWebhookUrl {
                        url: url.clone(),
                        reason: format!("unsupported scheme {:?}", parsed.scheme()),
                    });
                }
                Ok(())
            }
            Action::EmailAlert { to } => {
                // Light-touch: a full RFC-5322 validator buys little (delivery
                // bounces are the real test); catch the obvious authoring slip.
                if to.trim().is_empty() || !to.contains('@') {
                    Err(InvalidRule::EmptyField {
                        what: "email_alert.to",
                    })
                } else {
                    Ok(())
                }
            }
            Action::SlackAlert { channel } => {
                if channel.trim().is_empty() {
                    Err(InvalidRule::EmptyField {
                        what: "slack_alert.channel",
                    })
                } else {
                    Ok(())
                }
            }
            Action::TagAddress { label } => {
                if label.trim().is_empty() {
                    Err(InvalidRule::EmptyField {
                        what: "tag_address.label",
                    })
                } else {
                    Ok(())
                }
            }
        }
    }
}

/// Why a rule definition was rejected at the parse boundary. Speaks the
/// customer's language (field names in the wire form) so the `POST /v1/rules`
/// surface (t4) can return it verbatim as a 422 detail.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum InvalidRule {
    #[error("rule name must not be empty")]
    EmptyName,
    #[error("a rule needs at least one condition")]
    NoConditions,
    #[error("a rule needs at least one action")]
    NoActions,
    #[error("{what}: at least one of gt/lt is required")]
    UnboundedRange { what: &'static str },
    #[error("{what}: gt must be strictly below lt — the range can never match")]
    EmptyRange { what: &'static str },
    #[error("risk score bound {bound} is outside 0–100")]
    RiskScoreOutOfRange { bound: u8 },
    #[error("confidence threshold {threshold} is outside [0.0, 1.0]")]
    ConfidenceOutOfRange { threshold: f64 },
    #[error("interacted_with needs an address and/or a label_kind")]
    UnboundedInteraction,
    #[error("{what} must be at least 1")]
    ZeroBound { what: &'static str },
    #[error("a sequence needs at least 2 steps, got {steps}")]
    DegenerateSequence { steps: usize },
    #[error("a frequency needs count of at least 2, got {count}")]
    DegenerateFrequency { count: u32 },
    #[error("webhook url {url:?} is invalid: {reason}")]
    BadWebhookUrl { url: String, reason: String },
    #[error("{what} must not be empty")]
    EmptyField { what: &'static str },
}

#[cfg(test)]
mod tests {
    use super::*;
    use events::primitives::{CustomerId, RuleId};

    fn addr(byte: u8) -> AccountAddress {
        AccountAddress::repeat_byte(byte)
    }

    /// §9's compliance example, as the `POST /v1/rules` JSON the API stores:
    /// "large USDC transfer then mixer interaction within 100 blocks".
    fn compliance_rule() -> Rule {
        Rule {
            id: RuleId::new(),
            owner: CustomerId::new(),
            name: "Large transfer then mixer interaction".into(),
            enabled: true,
            conditions: vec![
                Condition::TransferAmount {
                    chain: Chain::ETHEREUM,
                    token: Some(addr(0xAA)),
                    gt: Some(Decimal::new(1_000_000, 0)),
                    lt: None,
                },
                Condition::InteractedWith {
                    address: None,
                    label_kind: Some(LabelKind::MixerUser),
                },
            ],
            logic: LogicOp::All,
            temporal: Some(TemporalConstraint::Sequence {
                events: vec![
                    Condition::TransferAmount {
                        chain: Chain::ETHEREUM,
                        token: Some(addr(0xAA)),
                        gt: Some(Decimal::new(1_000_000, 0)),
                        lt: None,
                    },
                    Condition::InteractedWith {
                        address: None,
                        label_kind: Some(LabelKind::MixerUser),
                    },
                ],
                within_blocks: 100,
            }),
            actions: vec![Action::WebhookAlert {
                url: "https://compliance.example.com/hook".into(),
            }],
        }
    }

    /// The full model round-trips through its wire/storage JSON exactly —
    /// including the Decimal threshold (string-serde, no f64 on the path).
    #[test]
    fn rule_round_trips_through_json() {
        let rule = compliance_rule();
        let json = serde_json::to_value(&rule).expect("serialize");
        let back: Rule = serde_json::from_value(json).expect("deserialize");
        assert_eq!(rule, back);
    }

    /// The wire form is the §9 shape: externally tagged, snake_case, thresholds
    /// as exact strings.
    #[test]
    fn wire_form_matches_spec_shape() {
        let rule = compliance_rule();
        let json = serde_json::to_value(&rule).expect("serialize");
        assert_eq!(json["logic"], "all");
        let first = &json["conditions"][0]["transfer_amount"];
        assert_eq!(first["gt"], "1000000");
        assert_eq!(first["chain"], 1);
        assert_eq!(
            json["conditions"][1]["interacted_with"]["label_kind"],
            "mixer_user"
        );
        assert!(json["temporal"]["sequence"]["within_blocks"] == 100);
        assert_eq!(
            json["actions"][0]["webhook_alert"]["url"],
            "https://compliance.example.com/hook"
        );
    }

    /// §9's trader-protection example parses from customer-authored JSON.
    #[test]
    fn trader_rule_parses_from_json() {
        let json = serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "owner": uuid::Uuid::new_v4(),
            "name": "Sandwich bot targeting my wallet",
            "enabled": true,
            "conditions": [
                { "incident_kind": { "kind": "sandwich", "min_confidence": 0.8 } },
                { "entity_label": { "kind": "mev_bot", "min_confidence": 0.5 } }
            ],
            "logic": "all",
            "actions": [ { "slack_alert": { "channel": "#trading-alerts" } } ]
        });
        let rule: Rule = serde_json::from_value(json).expect("parse");
        assert!(rule.validate().is_ok());
        assert_eq!(rule.temporal, None);
        assert!(matches!(
            rule.conditions[0],
            Condition::IncidentKind {
                kind: AlertKind::Sandwich,
                ..
            }
        ));
    }

    /// An out-of-range confidence threshold parses (`Confidence`'s serde form
    /// is transparent) but is rejected by validation — it never gets past the
    /// rule's parse boundary into the store.
    #[test]
    fn out_of_range_confidence_rejected_by_validation() {
        let json = serde_json::json!({
            "incident_kind": { "kind": "sandwich", "min_confidence": 1.7 }
        });
        let condition: Condition = serde_json::from_value(json).expect("parses");
        assert_eq!(
            condition.validate(),
            Err(InvalidRule::ConfidenceOutOfRange { threshold: 1.7 })
        );
    }

    #[test]
    fn valid_rule_passes_validation() {
        assert_eq!(compliance_rule().validate(), Ok(()));
    }

    #[test]
    fn validation_rejects_shape_errors() {
        let base = compliance_rule();

        let mut rule = base.clone();
        rule.name = "   ".into();
        assert_eq!(rule.validate(), Err(InvalidRule::EmptyName));

        let mut rule = base.clone();
        rule.conditions.clear();
        assert_eq!(rule.validate(), Err(InvalidRule::NoConditions));

        let mut rule = base.clone();
        rule.actions.clear();
        assert_eq!(rule.validate(), Err(InvalidRule::NoActions));

        // Neither bound on a range condition.
        let mut rule = base.clone();
        rule.conditions[0] = Condition::RiskScore { gt: None, lt: None };
        assert_eq!(
            rule.validate(),
            Err(InvalidRule::UnboundedRange { what: "risk_score" })
        );

        // Contradictory bounds can never match.
        let mut rule = base.clone();
        rule.conditions[0] = Condition::TransferAmount {
            chain: Chain::ETHEREUM,
            token: None,
            gt: Some(Decimal::new(10, 0)),
            lt: Some(Decimal::new(5, 0)),
        };
        assert_eq!(
            rule.validate(),
            Err(InvalidRule::EmptyRange {
                what: "transfer_amount"
            })
        );

        // Score is 0–100.
        let mut rule = base.clone();
        rule.conditions[0] = Condition::RiskScore {
            gt: Some(101),
            lt: None,
        };
        assert_eq!(
            rule.validate(),
            Err(InvalidRule::RiskScoreOutOfRange { bound: 101 })
        );

        // interacted_with with no selector at all.
        let mut rule = base.clone();
        rule.conditions[0] = Condition::InteractedWith {
            address: None,
            label_kind: None,
        };
        assert_eq!(rule.validate(), Err(InvalidRule::UnboundedInteraction));

        // One-step sequence is not a sequence.
        let mut rule = base.clone();
        rule.temporal = Some(TemporalConstraint::Sequence {
            events: vec![Condition::NewAddress {
                active_within_blocks: 10,
            }],
            within_blocks: 100,
        });
        assert_eq!(
            rule.validate(),
            Err(InvalidRule::DegenerateSequence { steps: 1 })
        );

        // Frequency of 1 is just the condition.
        let mut rule = base.clone();
        rule.temporal = Some(TemporalConstraint::Frequency {
            condition: Box::new(Condition::NewAddress {
                active_within_blocks: 10,
            }),
            count: 1,
            within_blocks: 100,
        });
        assert_eq!(
            rule.validate(),
            Err(InvalidRule::DegenerateFrequency { count: 1 })
        );

        // Conditions *inside* a temporal clause are validated too.
        let mut rule = base.clone();
        rule.temporal = Some(TemporalConstraint::Frequency {
            condition: Box::new(Condition::RiskScore { gt: None, lt: None }),
            count: 3,
            within_blocks: 100,
        });
        assert_eq!(
            rule.validate(),
            Err(InvalidRule::UnboundedRange { what: "risk_score" })
        );

        // Webhook target must be a parseable http(s) URL.
        let mut rule = base.clone();
        rule.actions = vec![Action::WebhookAlert {
            url: "ftp://compliance.example.com/hook".into(),
        }];
        assert!(matches!(
            rule.validate(),
            Err(InvalidRule::BadWebhookUrl { .. })
        ));

        let mut rule = base;
        rule.actions = vec![Action::EmailAlert {
            to: "not-an-email".into(),
        }];
        assert_eq!(
            rule.validate(),
            Err(InvalidRule::EmptyField {
                what: "email_alert.to"
            })
        );
    }

    /// `LogicOp`'s storage string and serde form are the same derive-driven
    /// snake_case (the store persists `logic` as TEXT, not JSONB).
    #[test]
    fn logic_op_wire_strings() {
        use strum::IntoEnumIterator;
        for op in LogicOp::iter() {
            let stored: &'static str = op.into();
            let json = serde_json::to_value(op).expect("serialize");
            assert_eq!(json, stored);
            let parsed: LogicOp = stored.parse().expect("parse back");
            assert_eq!(parsed, op);
        }
    }
}
