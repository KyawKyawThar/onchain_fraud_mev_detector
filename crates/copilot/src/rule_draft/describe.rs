//! The compiled rule, echoed back in plain language (§20.4 — "the customer
//! reviews the compiled rule before activating it").
//!
//! Rendered from the **compiled definition**, never from anything the model
//! wrote about its own output. That is the difference between an explanation
//! and a claim: a model-written summary of a rule is one more thing that can be
//! wrong, and it would be wrong in exactly the case that matters — where the
//! definition does not say what the customer asked for.
//!
//! Total by construction. Every arm below renders something, including the
//! shapes `Rule::validate` already rejects: a `describe` that panicked would
//! take down a review page over a row that is merely odd.

use rule_engine::model::{Action, Condition, LogicOp, RuleDefinition, TemporalConstraint};

/// One rule, in the customer's language.
pub fn describe(definition: &RuleDefinition) -> String {
    let mut lines = vec![format!(
        "Alert on \"{}\" when {} of the following hold:",
        definition.name,
        match definition.logic {
            LogicOp::All => "all",
            LogicOp::Any => "any",
            LogicOp::Not => "none",
        }
    )];
    for condition in &definition.conditions {
        lines.push(format!("  - {}", describe_condition(condition)));
    }
    match &definition.temporal {
        Some(TemporalConstraint::Sequence {
            events,
            within_blocks,
        }) => {
            lines.push(format!("…in this order, within {within_blocks} blocks:"));
            for (step, condition) in events.iter().enumerate() {
                lines.push(format!("  {}. {}", step + 1, describe_condition(condition)));
            }
        }
        Some(TemporalConstraint::Frequency {
            condition,
            count,
            within_blocks,
        }) => lines.push(format!(
            "…at least {count} times within {within_blocks} blocks: {}",
            describe_condition(condition)
        )),
        None => {}
    }
    for action in &definition.actions {
        lines.push(format!("Then: {}", describe_action(action)));
    }
    if !definition.enabled {
        lines.push("The rule is created disabled and evaluates nothing until enabled.".to_owned());
    }
    lines.join("\n")
}

fn describe_condition(condition: &Condition) -> String {
    match condition {
        Condition::TransferAmount {
            chain,
            token,
            gt,
            lt,
        } => {
            let asset = token
                .as_ref()
                .map(|token| format!("token {token}"))
                .unwrap_or_else(|| "the native asset".to_owned());
            format!(
                "a transfer of {asset} on chain {} {}",
                chain.0,
                describe_range(gt.as_ref(), lt.as_ref())
            )
        }
        Condition::InteractedWith {
            address,
            label_kind,
        } => match (address, label_kind) {
            (Some(address), Some(kind)) => {
                format!("an interaction with {address} (labelled {kind:?})")
            }
            (Some(address), None) => format!("an interaction with {address}"),
            (None, Some(kind)) => format!("an interaction with any address labelled {kind:?}"),
            // Unreachable past `validate`, and stated rather than unwrapped:
            // a describe that panics would take down a review page.
            (None, None) => "an interaction (unbounded)".to_owned(),
        },
        Condition::IncidentKind {
            kind,
            min_confidence,
        } => format!(
            "a confirmed {kind:?} incident at confidence ≥ {:.2}",
            min_confidence.get()
        ),
        Condition::EntityLabel {
            kind,
            min_confidence,
        } => format!(
            "the address's entity is labelled {kind:?} at confidence ≥ {:.2}",
            min_confidence.get()
        ),
        Condition::RiskScore { gt, lt } => {
            format!("a risk score {}", describe_range(gt.as_ref(), lt.as_ref()))
        }
        Condition::SanctionMatch { list } => match list {
            Some(list) => format!("a sanctions hit on list {list:?}"),
            None => "a sanctions hit on any list".to_owned(),
        },
        Condition::HopDistance { from, max_hops } => {
            format!("the address is within {max_hops} transfer hop(s) of {from}")
        }
        Condition::NewAddress {
            active_within_blocks,
        } => format!("the address first became active within {active_within_blocks} blocks"),
    }
}

fn describe_range<T: std::fmt::Display>(gt: Option<&T>, lt: Option<&T>) -> String {
    match (gt, lt) {
        (Some(gt), Some(lt)) => format!("above {gt} and below {lt}"),
        (Some(gt), None) => format!("above {gt}"),
        (None, Some(lt)) => format!("below {lt}"),
        (None, None) => "with no bound".to_owned(),
    }
}

fn describe_action(action: &Action) -> String {
    match action {
        Action::WebhookAlert { url } => format!("POST the alert to {url}"),
        Action::EmailAlert { to } => format!("email the alert to {to}"),
        Action::SlackAlert { channel } => format!("post the alert to Slack {channel}"),
        Action::TagAddress { label } => {
            format!("tag the address {label:?} (records the match, sends nothing)")
        }
    }
}
