//! System events (§2). Cross-cutting facts not owned by a single domain
//! service — currently just metered usage, which feeds billing (§13).

use crate::primitives::CustomerId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A billable usage event, emitted from the API service (§11, §13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageRecorded {
    pub customer_id: CustomerId,
    pub event_type: String,
    pub quantity: u64,
    pub timestamp: DateTime<Utc>,
}
