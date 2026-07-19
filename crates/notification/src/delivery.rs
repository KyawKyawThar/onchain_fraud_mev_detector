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

/// Histogram (labeled by `channel`): the §19 "end-to-end alert latency
/// (block → notification)" panel — `now - notice.occurred_at`, sampled only
/// on a successful delivery (a rejected/failed attempt hasn't reached a
/// subscriber yet, so it isn't a latency sample).
pub const ALERT_END_TO_END_SECONDS: &str = "notification_alert_end_to_end_seconds";

/// Record one delivery's outcome, and — only when it succeeded — its
/// end-to-end latency from `notice.occurred_at`. One call site every channel
/// adapter (`email_delivery`, `http_delivery`) shares, so the two metrics
/// can't drift apart.
pub(crate) fn count_delivery(channel: &'static str, notice: &Notice, outcome: &'static str) {
    metrics::counter!(
        NOTIFICATION_DELIVERIES_TOTAL,
        "channel" => channel,
        "outcome" => outcome
    )
    .increment(1);

    if outcome == "delivered" {
        // Clock skew or a stale/future test timestamp could make `occurred_at`
        // land after `now()`; clamp to zero rather than record garbage.
        let elapsed = (chrono::Utc::now() - notice.occurred_at)
            .to_std()
            .unwrap_or_default();
        metrics::histogram!(ALERT_END_TO_END_SECONDS, "channel" => channel)
            .record(elapsed.as_secs_f64());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Utc;
    use events::primitives::{AlertId, Chain};
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::CompositeKey;

    type Series = Vec<(
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    )>;

    fn captured(f: impl FnOnce()) -> Series {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, f);
        snapshotter.snapshot().into_vec()
    }

    fn has_series(series: &Series, name: &str) -> bool {
        series.iter().any(|(ck, ..)| ck.key().name() == name)
    }

    #[test]
    fn a_delivered_outcome_counts_and_samples_end_to_end_latency() {
        let notice = Notice::retraction(AlertId::new(), Chain::ETHEREUM, "x", Utc::now());
        let series = captured(|| count_delivery("webhook", &notice, "delivered"));
        assert!(has_series(&series, NOTIFICATION_DELIVERIES_TOTAL));
        assert!(has_series(&series, ALERT_END_TO_END_SECONDS));
    }

    #[test]
    fn a_rejected_outcome_counts_but_samples_no_latency() {
        let notice = Notice::retraction(AlertId::new(), Chain::ETHEREUM, "x", Utc::now());
        let series = captured(|| count_delivery("webhook", &notice, "rejected"));
        assert!(has_series(&series, NOTIFICATION_DELIVERIES_TOTAL));
        assert!(
            !has_series(&series, ALERT_END_TO_END_SECONDS),
            "a rejected delivery never reached a subscriber, so it isn't a latency sample"
        );
    }

    #[test]
    fn a_future_occurred_at_clamps_latency_to_zero_not_negative() {
        let notice = Notice::retraction(
            AlertId::new(),
            Chain::ETHEREUM,
            "x",
            Utc::now() + chrono::Duration::hours(1),
        );
        let series = captured(|| count_delivery("webhook", &notice, "delivered"));
        match series
            .iter()
            .find(|(ck, ..)| ck.key().name() == ALERT_END_TO_END_SECONDS)
        {
            Some((_, _, _, DebugValue::Histogram(samples))) => {
                assert_eq!(samples.len(), 1);
                assert_eq!(f64::from(samples[0]), 0.0);
            }
            other => panic!("expected a histogram, got {other:?}"),
        }
    }
}
