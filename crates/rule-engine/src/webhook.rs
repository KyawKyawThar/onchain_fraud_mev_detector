//! The production [`ActionSink`] (§9, Sprint 9 t5): deliver
//! [`Action::WebhookAlert`] by POSTing the alert as JSON to the
//! customer-controlled endpoint the rule names — the first customer-visible
//! output of the rule engine that isn't a backbone event.
//!
//! ## Delivery policy (this adapter's half of the [`ActionSink`] contract)
//!
//! * **2xx** — delivered.
//! * **4xx / 3xx** — [`DeliveryError::Rejected`], permanent: the endpoint
//!   understood us and said no (or tried to send us elsewhere — redirects are
//!   never followed: a customer-supplied URL that answers with a redirect is
//!   indistinguishable from a lure toward somewhere the customer doesn't
//!   control). Retrying the same payload cannot change the answer, so it is
//!   attempted once.
//! * **5xx / transport faults** (timeout, refused connection, TLS) —
//!   [`DeliveryError::Transport`], transient: retried here with exponential
//!   backoff up to [`WebhookConfig::attempts`], then surfaced. Bounded on
//!   purpose — the emitter must not block the fire drain indefinitely on one
//!   dead endpoint; §12's notification hardening (durable receipts, per-target
//!   dedup, more channels) owns the long game. The backoff races the shutdown
//!   token (the same shape as the worker's store retries): a stop signal cuts
//!   the wait short and surfaces the last transport error instead of holding
//!   the drain task through a full retry budget.
//!
//! The payload deliberately omits `owner`: routing already isolated the
//! delivery to the rule's owner (§9), and everything else in [`RuleAlert`] is
//! that customer's own data.
//!
//! Non-webhook channels (email / Slack / address tagging) are §12 (Sprint 10):
//! they log the would-be delivery and succeed, exactly what the t4 placeholder
//! sink did for every action.
//!
//! Known gap, documented rather than half-solved: URLs are validated to
//! http(s) at the parse boundary (`Rule::validate`), but nothing here refuses
//! endpoints resolving to private/internal addresses (SSRF). The §12 delivery
//! service is the place for an egress allowlist/proxy; until then the engine
//! should run with egress-restricted networking.

use std::time::Duration;

use async_trait::async_trait;
use events::primitives::{AlertId, RuleId};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::action::{ActionSink, DeliveryError, RuleAlert};
use crate::model::Action;
use event_bus::Transience;

/// Counter (labeled by `channel` and `outcome`: `delivered` | `rejected` |
/// `failed` | `unimplemented`): action-delivery receipts, the §19 signal for
/// "alerts fire but the customer never sees them" (alert on `rejected`/
/// `failed` rates — a revoked or dead endpoint shows up here, not in
/// `rule_fires_total`).
pub const ACTION_DELIVERIES_TOTAL: &str = "rule_action_deliveries_total";

/// Tuning for one [`WebhookActionSink`] (env-resolved in
/// [`crate::config::Config`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebhookConfig {
    /// Per-attempt request timeout (connect + response).
    pub timeout: Duration,
    /// Total attempts per delivery (first try included); clamped to ≥ 1.
    pub attempts: u32,
    /// Back-off before the first retry, doubling per further retry.
    pub retry_backoff: Duration,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            attempts: 3,
            retry_backoff: Duration::from_millis(500),
        }
    }
}

/// What lands on the customer's endpoint — [`RuleAlert`] minus `owner` (see
/// the module docs). The shape is a wire contract with customers, pinned by
/// `payload_shape_is_pinned` below: additions are fine, renames are breakage.
#[derive(Debug, Serialize)]
struct WebhookPayload<'a> {
    alert_id: AlertId,
    rule_id: RuleId,
    rule_name: &'a str,
    /// The subject address, `0x`-hex.
    address: &'a events::primitives::AccountAddress,
    explanation: &'a str,
    /// The temporal evidence window; empty for instant rules.
    matched_blocks: &'a [u64],
}

impl<'a> From<&'a RuleAlert> for WebhookPayload<'a> {
    fn from(alert: &'a RuleAlert) -> Self {
        Self {
            alert_id: alert.alert_id,
            rule_id: alert.rule_id,
            rule_name: &alert.rule_name,
            address: &alert.address,
            explanation: &alert.explanation,
            matched_blocks: &alert.matched_blocks,
        }
    }
}

/// The t5 [`ActionSink`]: HTTP delivery for webhook actions, logging
/// placeholders for the §12 channels. Cheap to share behind an `Arc` — one
/// `reqwest::Client` (its own connection pool) for every delivery.
pub struct WebhookActionSink {
    client: reqwest::Client,
    attempts: u32,
    retry_backoff: Duration,
    shutdown: CancellationToken,
}

impl WebhookActionSink {
    /// Build the sink and its HTTP client; `shutdown` cuts retry backoffs
    /// short (see the module docs). Fails only on a broken TLS/client setup —
    /// a boot-time error, never a per-delivery one.
    pub fn new(config: WebhookConfig, shutdown: CancellationToken) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            // Never follow redirects — see the module docs' policy.
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            client,
            attempts: config.attempts.max(1),
            retry_backoff: config.retry_backoff,
            shutdown,
        })
    }

    /// One POST, classified per the module docs' policy.
    async fn post_once(
        &self,
        url: &str,
        payload: &WebhookPayload<'_>,
    ) -> Result<(), DeliveryError> {
        let response = self
            .client
            .post(url)
            .json(payload)
            .send()
            .await
            .map_err(|err| DeliveryError::Transport {
                reason: err.to_string(),
            })?;
        let status = response.status();
        if status.is_success() {
            Ok(())
        } else if status.is_client_error() || status.is_redirection() {
            Err(DeliveryError::Rejected {
                reason: format!("endpoint answered {status}"),
            })
        } else {
            Err(DeliveryError::Transport {
                reason: format!("endpoint answered {status}"),
            })
        }
    }

    /// POST with bounded retry: transient faults back off and retry up to
    /// `attempts`; a rejection returns immediately; a shutdown mid-backoff
    /// surfaces the last transport error (see the module docs). Every exit is
    /// a `return` the compiler can see — exhaustion is the guard's job, not a
    /// post-loop assertion.
    async fn deliver_webhook(&self, url: &str, alert: &RuleAlert) -> Result<(), DeliveryError> {
        let payload = WebhookPayload::from(alert);
        let mut backoff = self.retry_backoff;
        let mut attempt = 1;
        loop {
            match self.post_once(url, &payload).await {
                Ok(()) => return Ok(()),
                Err(err) if err.is_transient() && attempt < self.attempts => {
                    tracing::warn!(
                        alert_id = %alert.alert_id,
                        attempt,
                        error = %err,
                        "webhook delivery failed transiently; backing off"
                    );
                    tokio::select! {
                        biased;
                        () = self.shutdown.cancelled() => return Err(err),
                        () = tokio::time::sleep(backoff) => {}
                    }
                    backoff = backoff.saturating_mul(2);
                    attempt += 1;
                }
                Err(err) => return Err(err),
            }
        }
    }

    /// The webhook path plus its delivery receipt (§19 counter).
    async fn deliver_webhook_counted(
        &self,
        url: &str,
        alert: &RuleAlert,
    ) -> Result<(), DeliveryError> {
        let outcome = self.deliver_webhook(url, alert).await;
        let label = match &outcome {
            Ok(()) => "delivered",
            Err(DeliveryError::Rejected { .. }) => "rejected",
            Err(DeliveryError::Transport { .. }) => "failed",
        };
        Self::count("webhook", label);
        outcome
    }

    /// §12 channels: log the would-be delivery and succeed (the §2 events
    /// remain the durable output), same stance as the t4 placeholder sink.
    fn log_unimplemented(
        &self,
        channel: &'static str,
        alert: &RuleAlert,
        action: &Action,
    ) -> Result<(), DeliveryError> {
        tracing::info!(
            rule_id = %alert.rule_id,
            owner = %alert.owner,
            address = %alert.address,
            channel,
            ?action,
            "action channel not implemented until §12; logged only: {}",
            alert.explanation
        );
        Self::count(channel, "unimplemented");
        Ok(())
    }

    fn count(channel: &'static str, outcome: &'static str) {
        metrics::counter!(
            ACTION_DELIVERIES_TOTAL,
            "channel" => channel,
            "outcome" => outcome
        )
        .increment(1);
    }
}

#[async_trait]
impl ActionSink for WebhookActionSink {
    async fn deliver(&self, alert: &RuleAlert, action: &Action) -> Result<(), DeliveryError> {
        // One complete statement per arm — a fifth `Action` variant forces a
        // deliberate routing decision here, not a silent fall-through.
        match action {
            Action::WebhookAlert { url } => self.deliver_webhook_counted(url, alert).await,
            Action::EmailAlert { .. } => self.log_unimplemented("email", alert, action),
            Action::SlackAlert { .. } => self.log_unimplemented("slack", alert, action),
            Action::TagAddress { .. } => self.log_unimplemented("tag_address", alert, action),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use events::primitives::{AccountAddress, CustomerId};
    use uuid::Uuid;

    /// The payload is a wire contract with customers — pin the exact JSON so
    /// an accidental rename/retype fails here, not in a customer's parser.
    #[test]
    fn payload_shape_is_pinned() {
        let alert = RuleAlert {
            alert_id: AlertId(Uuid::from_u128(1)),
            rule_id: RuleId(Uuid::from_u128(2)),
            owner: CustomerId(Uuid::from_u128(3)),
            address: AccountAddress::repeat_byte(0xAB),
            rule_name: "Large transfer then mixer".into(),
            explanation: "rule matched".into(),
            matched_blocks: vec![100, 150],
        };
        let json = serde_json::to_value(WebhookPayload::from(&alert)).expect("serialize");
        assert_eq!(
            json,
            serde_json::json!({
                "alert_id": "00000000-0000-0000-0000-000000000001",
                "rule_id": "00000000-0000-0000-0000-000000000002",
                "rule_name": "Large transfer then mixer",
                "address": "0xabababababababababababababababababababab",
                "explanation": "rule matched",
                "matched_blocks": [100, 150],
            })
        );
    }
}
