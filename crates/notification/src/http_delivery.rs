//! The three HTTP-POST channels (§11/§12): webhook, Slack, PagerDuty. All
//! three share one `reqwest::Client`, the same bounded exponential-backoff
//! retry loop (copied from `rule_engine::webhook::WebhookActionSink`'s
//! policy: 2xx delivers, 4xx/redirects reject without retry, 5xx/transport
//! faults retry up to [`DeliveryConfig::attempts`]), and — for the two
//! *customer-supplied* targets (webhook/Slack) — the SSRF guard
//! `rule_engine::webhook`'s module docs named as the gap this service closes:
//! *"the §12 delivery service is the place for an egress allowlist/proxy."*
//!
//! PagerDuty's target is the fixed Events API v2 endpoint, never
//! customer-supplied, so it carries no SSRF surface and skips the guard.

use std::net::IpAddr;

use events::primitives::{AccountAddress, Severity};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::delivery::{count_delivery, DeliveryConfig, DeliveryError};
use crate::model::LifecycleStage;
use crate::notice::Notice;
use event_bus::Transience;

/// PagerDuty Events API v2 — fixed, not customer-configurable.
const PAGERDUTY_ENQUEUE_URL: &str = "https://events.pagerduty.com/v2/enqueue";

/// What lands on a customer's webhook endpoint. A wire contract with
/// customers (mirrors `rule_engine::webhook::WebhookPayload`'s pinned-shape
/// stance) — additions are fine, renames are breakage.
#[derive(Debug, Serialize)]
struct WebhookPayload<'a> {
    dedup_key: &'a str,
    stage: &'static str,
    kind: Option<&'static str>,
    severity: Option<&'static str>,
    chain: u64,
    addresses: &'a [AccountAddress],
    summary: &'a str,
}

impl<'a> From<&'a Notice> for WebhookPayload<'a> {
    fn from(notice: &'a Notice) -> Self {
        Self {
            dedup_key: &notice.dedup_key,
            stage: notice.stage.as_wire_str(),
            kind: notice.kind.map(Into::into),
            severity: notice.severity.map(Into::into),
            chain: notice.chain.id(),
            addresses: &notice.addresses,
            summary: &notice.summary,
        }
    }
}

/// Slack's incoming-webhook shape — a single `text` field is enough for an
/// alert notification (no block-kit formatting, kept simple on purpose).
#[derive(Debug, Serialize)]
struct SlackPayload {
    text: String,
}

impl From<&Notice> for SlackPayload {
    fn from(notice: &Notice) -> Self {
        let stage = notice.stage.as_wire_str();
        let severity = notice
            .severity
            .map(|s| <&str>::from(s).to_owned())
            .unwrap_or_else(|| "n/a".into());
        Self {
            text: format!(
                "[{stage}] severity={severity} chain={} — {}",
                notice.chain.id(),
                notice.summary
            ),
        }
    }
}

/// PagerDuty Events API v2's severity vocabulary. `None` (a notice that
/// carries no severity of its own, e.g. a `RuleAlertCreated`) defaults to
/// `warning` — PagerDuty requires a value on `trigger`, and a mid-range
/// default is the least presumptuous choice for an axis the notice is
/// silent on.
fn pagerduty_severity(severity: Option<Severity>) -> &'static str {
    match severity {
        Some(Severity::Low) => "info",
        Some(Severity::Medium) => "warning",
        Some(Severity::High) => "error",
        Some(Severity::Critical) => "critical",
        None => "warning",
    }
}

/// PagerDuty's `trigger`/`resolve` `event_action` — the natural mapping of
/// our lifecycle onto PagerDuty's own dedup/auto-resolve semantics: a
/// `Retracted` notice resolves the incident PagerDuty opened for the
/// matching `dedup_key`; every other stage (re)triggers it.
fn pagerduty_action(stage: LifecycleStage) -> &'static str {
    match stage {
        LifecycleStage::Retracted => "resolve",
        LifecycleStage::Provisional | LifecycleStage::Confirmed | LifecycleStage::Standalone => {
            "trigger"
        }
    }
}

#[derive(Debug, Serialize)]
struct PagerDutyDetails<'a> {
    summary: &'a str,
    source: &'static str,
    severity: &'static str,
}

#[derive(Debug, Serialize)]
struct PagerDutyEvent<'a> {
    routing_key: &'a str,
    event_action: &'static str,
    dedup_key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<PagerDutyDetails<'a>>,
}

impl<'a> PagerDutyEvent<'a> {
    fn from_notice(notice: &'a Notice, routing_key: &'a str) -> Self {
        let event_action = pagerduty_action(notice.stage);
        let payload = (event_action == "trigger").then(|| PagerDutyDetails {
            summary: &notice.summary,
            source: "mevwatch",
            severity: pagerduty_severity(notice.severity),
        });
        Self {
            routing_key,
            event_action,
            dedup_key: &notice.dedup_key,
            payload,
        }
    }
}

/// Whether `ip` is a non-public target the SSRF guard must refuse (loopback,
/// private/internal ranges, link-local, multicast, unspecified) — see the
/// module docs for the accepted resolve-then-connect TOCTOU limitation.
fn is_non_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                // Unique local addresses (fc00::/7) — IPv6's analogue of RFC 1918.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

/// The webhook/Slack/PagerDuty delivery client. Cheap to share behind an
/// `Arc` — one `reqwest::Client` (its own connection pool) for all three.
pub struct HttpDelivery {
    client: reqwest::Client,
    config: DeliveryConfig,
    shutdown: CancellationToken,
    /// Off in production; a test double sets this so the loopback test
    /// server (a `127.0.0.1` target) isn't refused by the SSRF guard —
    /// mirrors `rule_engine::consumer::FireEmitter::with_publish_backoff`'s
    /// test-only builder shape.
    allow_private_targets: bool,
}

impl HttpDelivery {
    pub fn new(
        config: DeliveryConfig,
        shutdown: CancellationToken,
    ) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            // Never follow redirects — a customer-supplied URL that answers
            // with a redirect is indistinguishable from a lure toward
            // somewhere the customer doesn't control (same policy as
            // rule-engine's webhook adapter).
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            client,
            config,
            shutdown,
            allow_private_targets: false,
        })
    }

    #[cfg(any(test, feature = "test-util"))]
    pub fn allow_private_targets(mut self) -> Self {
        self.allow_private_targets = true;
        self
    }

    /// Resolve `url`'s host and refuse it if any resolved address is
    /// non-public (see [`is_non_public`]). Skipped entirely when
    /// `allow_private_targets` is set (tests only).
    async fn ensure_public_target(&self, url: &str) -> Result<(), DeliveryError> {
        if self.allow_private_targets {
            return Ok(());
        }
        let parsed = url::Url::parse(url).map_err(|err| DeliveryError::Rejected {
            reason: format!("invalid webhook URL: {err}"),
        })?;
        let host = parsed.host_str().ok_or_else(|| DeliveryError::Rejected {
            reason: "webhook URL has no host".into(),
        })?;
        let port = parsed.port_or_known_default().unwrap_or(443);
        let addrs = tokio::net::lookup_host((host, port)).await.map_err(|err| {
            DeliveryError::Transport {
                reason: format!("resolving webhook host: {err}"),
            }
        })?;
        for addr in addrs {
            if is_non_public(addr.ip()) {
                return Err(DeliveryError::Rejected {
                    reason: format!(
                        "webhook target resolves to a non-public address: {}",
                        addr.ip()
                    ),
                });
            }
        }
        Ok(())
    }

    async fn post_once(&self, url: &str, body: &impl Serialize) -> Result<(), DeliveryError> {
        let response = self
            .client
            .post(url)
            .json(body)
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
    /// surfaces the last transport error — identical policy to
    /// `rule_engine::webhook::WebhookActionSink::deliver_webhook`.
    async fn post_with_retry(&self, url: &str, body: &impl Serialize) -> Result<(), DeliveryError> {
        let mut backoff = self.config.retry_backoff;
        let mut attempt = 1;
        loop {
            match self.post_once(url, body).await {
                Ok(()) => return Ok(()),
                Err(err) if err.is_transient() && attempt < self.config.attempts.max(1) => {
                    tracing::warn!(attempt, error = %err, "HTTP delivery failed transiently; backing off");
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

    pub async fn deliver_webhook(&self, notice: &Notice, url: &str) -> Result<(), DeliveryError> {
        // Counted on every path, including an SSRF-guard rejection — a
        // refused target is still a delivery *receipt* (`rejected`), not a
        // silent non-event; a live boot caught this the first time the guard
        // fired and the metric didn't move.
        let outcome = match self.ensure_public_target(url).await {
            Ok(()) => {
                self.post_with_retry(url, &WebhookPayload::from(notice))
                    .await
            }
            Err(err) => Err(err),
        };
        count_delivery("webhook", notice, outcome_label(&outcome));
        outcome
    }

    pub async fn deliver_slack(
        &self,
        notice: &Notice,
        webhook_url: &str,
    ) -> Result<(), DeliveryError> {
        let outcome = match self.ensure_public_target(webhook_url).await {
            Ok(()) => {
                self.post_with_retry(webhook_url, &SlackPayload::from(notice))
                    .await
            }
            Err(err) => Err(err),
        };
        count_delivery("slack", notice, outcome_label(&outcome));
        outcome
    }

    pub async fn deliver_pagerduty(
        &self,
        notice: &Notice,
        routing_key: &str,
    ) -> Result<(), DeliveryError> {
        // No SSRF guard: PAGERDUTY_ENQUEUE_URL is fixed, never customer input.
        let event = PagerDutyEvent::from_notice(notice, routing_key);
        let outcome = self.post_with_retry(PAGERDUTY_ENQUEUE_URL, &event).await;
        count_delivery("pager_duty", notice, outcome_label(&outcome));
        outcome
    }
}

fn outcome_label(outcome: &Result<(), DeliveryError>) -> &'static str {
    match outcome {
        Ok(()) => "delivered",
        Err(DeliveryError::Rejected { .. }) => "rejected",
        Err(DeliveryError::Transport { .. }) => "failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use events::primitives::{AlertId, AlertKind, Chain, CustomerId};

    fn notice() -> Notice {
        Notice {
            dedup_key: AlertId::new().to_string(),
            stage: LifecycleStage::Confirmed,
            kind: Some(AlertKind::Sandwich),
            severity: Some(Severity::Critical),
            chain: Chain::ETHEREUM,
            addresses: vec![AccountAddress::repeat_byte(0xAB)],
            owner: Some(CustomerId::new()),
            summary: "confirmed sandwich".into(),
            occurred_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn webhook_payload_shape_is_pinned() {
        let n = Notice {
            dedup_key: "fixed-key".into(),
            ..notice()
        };
        let json = serde_json::to_value(WebhookPayload::from(&n)).expect("serialize");
        assert_eq!(
            json,
            serde_json::json!({
                "dedup_key": "fixed-key",
                "stage": "confirmed",
                "kind": "sandwich",
                "severity": "critical",
                "chain": 1,
                "addresses": ["0xabababababababababababababababababababab"],
                "summary": "confirmed sandwich",
            })
        );
    }

    #[test]
    fn pagerduty_resolve_omits_the_payload_block() {
        let n = Notice {
            stage: LifecycleStage::Retracted,
            ..notice()
        };
        let event = PagerDutyEvent::from_notice(&n, "rk-1");
        assert_eq!(event.event_action, "resolve");
        assert!(event.payload.is_none(), "resolve carries no detail payload");
    }

    #[test]
    fn pagerduty_trigger_carries_mapped_severity() {
        let n = notice();
        let event = PagerDutyEvent::from_notice(&n, "rk-1");
        assert_eq!(event.event_action, "trigger");
        assert_eq!(event.payload.expect("payload").severity, "critical");
    }

    #[test]
    fn pagerduty_severity_defaults_to_warning_when_the_notice_has_none() {
        assert_eq!(pagerduty_severity(None), "warning");
    }

    #[test]
    fn non_public_addresses_are_rejected() {
        assert!(is_non_public("127.0.0.1".parse().unwrap()));
        assert!(is_non_public("10.0.0.5".parse().unwrap()));
        assert!(is_non_public("192.168.1.1".parse().unwrap()));
        assert!(is_non_public("169.254.1.1".parse().unwrap()));
        assert!(is_non_public("::1".parse().unwrap()));
        assert!(
            !is_non_public("93.184.216.34".parse().unwrap()),
            "a public address is admitted"
        );
    }
}
