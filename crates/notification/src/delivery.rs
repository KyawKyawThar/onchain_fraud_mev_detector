//! The delivery seam (§11) — mirrors `rule_engine::action`: the consumer
//! hands a [`crate::notice::Notice`] and a target [`crate::model::Channel`]
//! to a [`ChannelSink`], never speaking HTTP/SMTP itself. Production is
//! [`crate::sink::MultiChannelSink`] (webhook/Slack/PagerDuty over HTTP,
//! email over SMTP); tests use the recording double in `crate::test_util`.

use std::time::Duration;

use async_trait::async_trait;

use crate::model::Channel;
use crate::notice::Notice;

/// Why a delivery attempt failed, carrying the retry/skip decision — the
/// identical shape to `rule_engine::action::DeliveryError`.
#[derive(Debug, thiserror::Error)]
pub enum DeliveryError {
    /// The target refused the notice (a 4xx, an SSRF-blocked target, a bad
    /// channel). Permanent: retrying the same payload at the same target
    /// fails again.
    #[error("delivery target rejected the notice: {reason}")]
    Rejected { reason: String },
    /// The transport failed (timeout, connection, 5xx, an SMTP 5xx reply).
    /// Transient: retry with backoff per the adapter's policy.
    #[error("delivery transport failed: {reason}")]
    Transport { reason: String },
}

impl event_bus::Transience for DeliveryError {
    fn is_transient(&self) -> bool {
        match self {
            DeliveryError::Rejected { .. } => false,
            DeliveryError::Transport { .. } => true,
        }
    }
}

/// Where notices go. One call per `(notice, channel)` pair — a subscriber
/// with three channels makes three deliveries, each independently
/// retryable and independently claimed/receipted in the store.
#[async_trait]
pub trait ChannelSink: Send + Sync {
    async fn deliver(&self, notice: &Notice, channel: &Channel) -> Result<(), DeliveryError>;
}

/// Tuning shared by every HTTP-based channel (webhook/Slack/PagerDuty) —
/// mirrors `rule_engine::webhook::WebhookConfig` exactly, reused across
/// channels rather than duplicated per channel since the retry policy is the
/// same shape regardless of target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryConfig {
    /// Per-attempt request timeout (connect + response).
    pub timeout: Duration,
    /// Total attempts per delivery (first try included); clamped to ≥ 1.
    pub attempts: u32,
    /// Back-off before the first retry, doubling per further retry.
    pub retry_backoff: Duration,
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            attempts: 3,
            retry_backoff: Duration::from_millis(500),
        }
    }
}

/// Counter (labeled by `channel` and `outcome`: `delivered` | `rejected` |
/// `failed`): delivery receipts — the §19 signal for "notices fire but the
/// subscriber never sees them" (mirrors `rule_engine::webhook::ACTION_DELIVERIES_TOTAL`).
pub const NOTIFICATION_DELIVERIES_TOTAL: &str = "notification_deliveries_total";

pub(crate) fn count_delivery(channel: &'static str, outcome: &'static str) {
    metrics::counter!(
        NOTIFICATION_DELIVERIES_TOTAL,
        "channel" => channel,
        "outcome" => outcome
    )
    .increment(1);
}
