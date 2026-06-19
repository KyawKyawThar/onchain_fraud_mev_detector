//! Rule engine events (§9). Customers compose conditions over the event stream
//! ("wallet receives >$1M then touches a mixer"); matches raise rule alerts.

use crate::primitives::{AccountAddress, AlertId, CustomerId, RuleId};
use serde::{Deserialize, Serialize};

/// A customer created a rule. `definition` is the rule DSL document (§9).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleCreated {
    pub rule_id: RuleId,
    pub owner: CustomerId,
    pub definition: serde_json::Value,
}

/// A rule's conditions matched for an address (§9).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleTriggered {
    pub rule_id: RuleId,
    pub address: AccountAddress,
    /// The events that satisfied the rule's temporal sequence.
    pub matched_events: Vec<String>,
    pub context: serde_json::Value,
}

/// A user-facing alert produced by a triggered rule (§9).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleAlertCreated {
    pub alert_id: AlertId,
    pub rule_id: RuleId,
    pub address: AccountAddress,
    pub explanation: String,
}
