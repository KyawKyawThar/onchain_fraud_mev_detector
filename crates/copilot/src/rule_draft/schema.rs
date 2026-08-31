//! The structured-output schema, constrained to §9's wire form.
//!
//! Hand-written and pinned by tests rather than derived, because there is no
//! schema-derivation crate in this workspace and adding one to satisfy a single
//! artifact would be a larger commitment than the tests in
//! [`super::tests`]. What makes that safe is the *direction* of the guarantee:
//! the schema narrows what the model emits, and everything it emits is then
//! parsed by the real [`RuleDefinition`](rule_engine::model::RuleDefinition).
//!
//! A schema that has drifted *narrower* than §9 costs a customer an
//! expressible rule; one that has drifted *wider* costs a blocked draft
//! carrying the compiler's error. Neither can produce a rule that runs — and
//! `the_schema_names_every_condition_the_engine_has` fails the build before
//! either happens.

use std::sync::LazyLock;

use serde_json::{json, Value};

/// The JSON Schema the model's answer must validate against
/// (`output_config.format`).
pub fn wire_schema() -> Value {
    static SCHEMA: LazyLock<Value> = LazyLock::new(build_schema);
    SCHEMA.clone()
}

fn decimal() -> Value {
    json!({ "type": "string", "pattern": r"^-?\d+(\.\d+)?$" })
}

fn address() -> Value {
    json!({ "type": "string", "pattern": "^0x[0-9a-fA-F]{40}$" })
}

/// One externally-tagged variant: `{"transfer_amount": {…}}`.
fn variant(tag: &str, fields: Value, required: Value) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [tag],
        "properties": {
            tag: {
                "type": "object",
                "additionalProperties": false,
                "properties": fields,
                "required": required,
            }
        }
    })
}

fn condition_schema() -> Value {
    json!({
        "description": "One §9 condition. The vocabulary is closed: only these eight.",
        "oneOf": [
            variant("transfer_amount", json!({
                "chain": {"type": "integer", "minimum": 1},
                "token": address(),
                "gt": decimal(),
                "lt": decimal(),
            }), json!(["chain"])),
            variant("interacted_with", json!({
                "address": address(),
                "label_kind": {"type": "string"},
            }), json!([])),
            variant("incident_kind", json!({
                "kind": {"type": "string"},
                "min_confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            }), json!(["kind", "min_confidence"])),
            variant("entity_label", json!({
                "kind": {"type": "string"},
                "min_confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            }), json!(["kind", "min_confidence"])),
            variant("risk_score", json!({
                "gt": {"type": "integer", "minimum": 0, "maximum": 100},
                "lt": {"type": "integer", "minimum": 0, "maximum": 100},
            }), json!([])),
            variant("sanction_match", json!({
                "list": {"type": "string"},
            }), json!([])),
            variant("hop_distance", json!({
                "from": address(),
                "max_hops": {"type": "integer", "minimum": 1, "maximum": 255},
            }), json!(["from", "max_hops"])),
            variant("new_address", json!({
                "active_within_blocks": {"type": "integer", "minimum": 1},
            }), json!(["active_within_blocks"])),
        ]
    })
}

fn action_schema() -> Value {
    json!({
        "description": "Where a match goes. Closed set.",
        "oneOf": [
            variant("webhook_alert", json!({"url": {"type": "string", "format": "uri"}}), json!(["url"])),
            variant("email_alert", json!({"to": {"type": "string"}}), json!(["to"])),
            variant("slack_alert", json!({"channel": {"type": "string"}}), json!(["channel"])),
            variant("tag_address", json!({"label": {"type": "string"}}), json!(["label"])),
        ]
    })
}

fn build_schema() -> Value {
    let condition = condition_schema();
    json!({
        "type": "object",
        "additionalProperties": false,
        // Note what cannot appear: `id` and `owner`. The platform owns both,
        // and a schema that has no slot for them is a stronger guarantee than
        // a handler that strips them.
        "required": ["name", "conditions", "logic", "actions"],
        "properties": {
            "name": {
                "type": "string",
                "minLength": 1,
                "maxLength": 80,
                "description": "What the rule detects, in the customer's terms.",
            },
            "enabled": {"type": "boolean"},
            "conditions": {
                "type": "array",
                "minItems": 1,
                "items": condition.clone(),
            },
            "logic": {"type": "string", "enum": ["all", "any", "not"]},
            "temporal": {
                "description": "Only when the request describes time.",
                "oneOf": [
                    variant("sequence", json!({
                        "events": {"type": "array", "minItems": 2, "items": condition.clone()},
                        "within_blocks": {"type": "integer", "minimum": 1},
                    }), json!(["events", "within_blocks"])),
                    variant("frequency", json!({
                        "condition": condition,
                        "count": {"type": "integer", "minimum": 2},
                        "within_blocks": {"type": "integer", "minimum": 1},
                    }), json!(["condition", "count", "within_blocks"])),
                ]
            },
            "actions": {"type": "array", "minItems": 1, "items": action_schema()},
        }
    })
}
