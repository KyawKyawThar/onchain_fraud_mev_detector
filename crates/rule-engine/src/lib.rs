//! Rule engine service (§9) — customer-defined alerting on top of the
//! intelligence graph; the enterprise pricing tier.
//!
//! The crate is layered so each seam is testable alone and the whole path is
//! testable with zero infrastructure:
//!
//! * [`model`] — the §9 document a customer authors (`Rule`/`Condition`/
//!   [`model::LogicOp`]/`TemporalConstraint`/`Action`), validated at the parse
//!   boundary.
//! * [`store`] — the customer-isolated Postgres rule-definition store behind
//!   [`store::RuleStore`] (t1). Isolation contract (§9: "no cross-customer
//!   data leakage"): every customer-facing operation is keyed by `owner`, so
//!   cross-customer reads/writes are unrepresentable, not merely forbidden.
//! * [`ctx`] + [`compile`] — the rule compiler (t2): definitions compile
//!   *once* per load into pure [`compile::Matcher`] closures over
//!   [`ctx::EventCtx`]; the [`compile::CompiledRuleSet`] is link-or-fail and
//!   also emits the [`compile::EnrichmentNeeds`] prefetch plan; refresh is a
//!   snapshot swap through [`compile::RuleSetHandle`].
//! * [`temporal`] — the pure per-`(rule_id, address)` state machine
//!   (t3's functional core): `step` and the §15 `rewind` are pure transitions;
//!   the Redis persistence/partitioning shell lands in t3.
//! * [`action`] — the delivery seam ([`action::ActionSink`]): evaluation
//!   raises [`action::RuleAlert`]s and hands actions to the sink; the webhook
//!   adapter lands in t5.
//!
//! Evaluation flow (the t4 consumer's loop): consume event → build
//! `EventCtx` (prefetch per `EnrichmentNeeds`) → `set.evaluate(ctx)` for
//! instant rules + `temporal::step` per temporal rule (state from Redis) →
//! for each fire, `RuleAlert` → `ActionSink::deliver` per action.

pub mod action;
pub mod compile;
pub mod ctx;
pub mod model;
pub mod store;
pub mod temporal;

/// Doubles + builders ([`test_util::InMemoryRuleStore`],
/// [`test_util::RecordingActionSink`], [`test_util::RuleBuilder`]) for
/// consumer tests — compiled only with the `test-util` feature (mirrors
/// `intelligence`).
#[cfg(feature = "test-util")]
pub mod test_util;

/// Shared fixtures for this crate's own unit tests (`test_util` is feature-
/// gated and integration-test-facing; these are crate-internal).
#[cfg(test)]
pub(crate) mod test_support {
    use events::primitives::{AccountAddress, Chain, CustomerId, LabelKind, RuleId};
    use rust_decimal::Decimal;

    use crate::model::{Action, Condition, LogicOp, Rule, TemporalConstraint};

    fn addr(byte: u8) -> AccountAddress {
        AccountAddress::repeat_byte(byte)
    }

    /// Step 1 of the §9 compliance example: a large USDC transfer.
    pub(crate) fn large_usdc_transfer() -> Condition {
        Condition::TransferAmount {
            chain: Chain::ETHEREUM,
            token: Some(addr(0xAA)),
            gt: Some(Decimal::new(1_000_000, 0)),
            lt: None,
        }
    }

    /// Step 2: any interaction with a mixer-labeled counterparty.
    pub(crate) fn mixer_interaction() -> Condition {
        Condition::InteractedWith {
            address: None,
            label_kind: Some(LabelKind::MixerUser),
        }
    }

    /// §9's compliance example: large transfer *then* mixer interaction
    /// within 100 blocks.
    pub(crate) fn compliance_rule() -> Rule {
        Rule {
            id: RuleId::new(),
            owner: CustomerId::new(),
            name: "Large transfer then mixer interaction".into(),
            enabled: true,
            conditions: vec![large_usdc_transfer(), mixer_interaction()],
            logic: LogicOp::All,
            temporal: Some(TemporalConstraint::Sequence {
                events: vec![large_usdc_transfer(), mixer_interaction()],
                within_blocks: 100,
            }),
            actions: vec![Action::WebhookAlert {
                url: "https://compliance.example.com/hook".into(),
            }],
        }
    }

    /// An instant rule: risk score above 80.
    pub(crate) fn instant_risk_rule() -> Rule {
        Rule {
            id: RuleId::new(),
            owner: CustomerId::new(),
            name: "High risk score".into(),
            enabled: true,
            conditions: vec![Condition::RiskScore {
                gt: Some(80),
                lt: None,
            }],
            logic: LogicOp::All,
            temporal: None,
            actions: vec![Action::SlackAlert {
                channel: "#alerts".into(),
            }],
        }
    }

    /// A frequency rule: `count` large transfers within `within_blocks`.
    pub(crate) fn frequency_rule(count: u32, within_blocks: u64) -> Rule {
        Rule {
            id: RuleId::new(),
            owner: CustomerId::new(),
            name: "Repeated large transfers".into(),
            enabled: true,
            conditions: vec![large_usdc_transfer()],
            logic: LogicOp::All,
            temporal: Some(TemporalConstraint::Frequency {
                condition: Box::new(large_usdc_transfer()),
                count,
                within_blocks,
            }),
            actions: vec![Action::WebhookAlert {
                url: "https://alerts.example.com/hook".into(),
            }],
        }
    }

    /// The two-rule set the compiler tests exercise: one instant, one
    /// temporal.
    pub(crate) fn rules_for_compile_tests() -> Vec<Rule> {
        vec![instant_risk_rule(), compliance_rule()]
    }
}
