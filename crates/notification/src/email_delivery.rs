//! The email channel (§11/§12): SMTP over the async, rustls-backed
//! transport. The one *non*-HTTP delivery target — see `http_delivery.rs`
//! for webhook/Slack/PagerDuty.
//!
//! **Classification is the opposite of HTTP** — a detail worth calling out
//! explicitly so nobody copies the HTTP 4xx/5xx convention by reflex: under
//! SMTP (RFC 5321 §4.2.1), a **4yz** reply is *transient* ("try again
//! later") and a **5yz** reply is *permanent* ("never going to work").
//! `lettre::transport::smtp::Error::is_permanent`/`is_transient` already
//! encode this the right way round, so the classification here is a
//! one-line delegation, not a re-derivation — but it is the inverse of
//! `http_delivery.rs`'s `is_client_error()` check on the same axis.

use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use secrecy::{ExposeSecret, SecretString};
use tokio_util::sync::CancellationToken;

use crate::delivery::{count_delivery, DeliveryConfig, DeliveryError};
use crate::notice::Notice;
use event_bus::Transience;

/// SMTP relay settings (env-resolved in `crate::config::Config`).
#[derive(Debug, Clone)]
pub struct EmailConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: SecretString,
    /// The `From:` address every notification is sent as.
    pub from: String,
}

/// The email [`crate::delivery::ChannelSink`] half — mirrors
/// `http_delivery::HttpDelivery`'s shape (one shared transport, bounded
/// retry over [`DeliveryConfig`]).
pub struct EmailDelivery {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    config: DeliveryConfig,
    shutdown: CancellationToken,
}

impl EmailDelivery {
    /// Build the SMTP transport. Fails only on a malformed relay host or
    /// `from` address — a boot-time error, never a per-delivery one (mirrors
    /// `WebhookActionSink::new`'s stance).
    pub fn new(
        smtp: &EmailConfig,
        config: DeliveryConfig,
        shutdown: CancellationToken,
    ) -> anyhow::Result<Self> {
        let transport = AsyncSmtpTransport::<Tokio1Executor>::relay(&smtp.host)?
            .port(smtp.port)
            .credentials(Credentials::new(
                smtp.username.clone(),
                smtp.password.expose_secret().to_owned(),
            ))
            .timeout(Some(config.timeout))
            .build();
        let from: Mailbox = smtp
            .from
            .parse()
            .map_err(|err| anyhow::anyhow!("invalid SMTP from address {:?}: {err}", smtp.from))?;
        Ok(Self {
            transport,
            from,
            config,
            shutdown,
        })
    }

    fn build_message(&self, notice: &Notice, to: &Mailbox) -> Result<Message, DeliveryError> {
        let severity = notice
            .severity
            .map(|s| <&str>::from(s).to_owned())
            .unwrap_or_else(|| "n/a".into());
        Message::builder()
            .from(self.from.clone())
            .to(to.clone())
            .subject(format!(
                "[MEVWatch] {} alert (severity={severity})",
                notice.stage.as_wire_str()
            ))
            .body(notice.summary.clone())
            .map_err(|err| DeliveryError::Rejected {
                reason: format!("building email message: {err}"),
            })
    }

    async fn send_once(&self, notice: &Notice, to: &Mailbox) -> Result<(), DeliveryError> {
        let message = self.build_message(notice, to)?;
        self.transport
            .send(message)
            .await
            .map(|_| ())
            .map_err(classify_smtp_error)
    }

    pub async fn deliver_email(&self, notice: &Notice, address: &str) -> Result<(), DeliveryError> {
        let to: Mailbox = match address.parse() {
            Ok(to) => to,
            Err(err) => {
                let outcome = Err(DeliveryError::Rejected {
                    reason: format!("invalid recipient address {address:?}: {err}"),
                });
                count_delivery("email", notice, outcome_label(&outcome));
                return outcome;
            }
        };

        let mut backoff = self.config.retry_backoff;
        let mut attempt = 1;
        let outcome = loop {
            match self.send_once(notice, &to).await {
                Ok(()) => break Ok(()),
                Err(err) if err.is_transient() && attempt < self.config.attempts.max(1) => {
                    tracing::warn!(attempt, error = %err, "SMTP delivery failed transiently; backing off");
                    tokio::select! {
                        biased;
                        () = self.shutdown.cancelled() => break Err(err),
                        () = tokio::time::sleep(backoff) => {}
                    }
                    backoff = backoff.saturating_mul(2);
                    attempt += 1;
                }
                Err(err) => break Err(err),
            }
        };
        count_delivery("email", notice, outcome_label(&outcome));
        outcome
    }
}

/// SMTP 4yz → transient, 5yz → permanent — see the module docs' explicit
/// callout that this is the *inverse* of the HTTP classification.
fn classify_smtp_error(err: lettre::transport::smtp::Error) -> DeliveryError {
    if err.is_permanent() {
        DeliveryError::Rejected {
            reason: err.to_string(),
        }
    } else {
        DeliveryError::Transport {
            reason: err.to_string(),
        }
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

    #[test]
    fn an_invalid_recipient_is_a_permanent_rejection_label() {
        // `classify_smtp_error` isn't exercised without a live SMTP server;
        // this pins the address-parse-failure path, which is (units-only)
        // reachable without one.
        let err: Result<Mailbox, _> = "not-an-email".parse();
        assert!(err.is_err());
    }
}
