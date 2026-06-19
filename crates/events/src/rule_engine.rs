//! Rule engine events (§9). Customers compose conditions over the event stream
//! ("wallet receives >$1M then touches a mixer"); matches raise rule alerts.

use crate::primitives::{AccountAddress, AlertId, CustomerId, RuleId};
use serde::{Deserialize, Serialize};

/// A customer created a rule. `definition` is the rule DSL document (§9).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RuleCreated {
    pub rule_id: RuleId,
    pub owner: CustomerId,
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub definition: serde_json::Value,
}

/// A rule's conditions matched for an address (§9).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RuleTriggered {
    pub rule_id: RuleId,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub address: AccountAddress,
    /// The events that satisfied the rule's temporal sequence.
    pub matched_events: Vec<String>,
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub context: serde_json::Value,
}

/// A user-facing alert produced by a triggered rule (§9).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RuleAlertCreated {
    pub alert_id: AlertId,
    pub rule_id: RuleId,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub address: AccountAddress,
    pub explanation: String,
}
