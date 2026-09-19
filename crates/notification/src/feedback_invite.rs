//! The minting half of the §19 feedback loop (production-readiness Epic E) —
//! the only place in the platform that issues a feedback capability, and the
//! only place that decides which incidents the platform *asks* about.
//!
//! # Why the sender picks the cohort
//!
//! A false-positive rate computed over verdicts people volunteered is a
//! self-selected sample: customers report the alerts that annoyed them and
//! almost nobody clicks "this one was correct". That number is a fine product
//! signal and a poor accuracy claim.
//!
//! A **solicited** verdict comes from an incident chosen by a rule that has
//! never seen the finding — [`Inviter::cohort_for`] hashes the incident id and
//! compares it against a permille threshold. The choice is therefore:
//!
//! * **uniform** over incidents, not over how alarming they looked;
//! * **stateless** — no sampling table, no coordination between replicas, and
//!   two pods delivering the same incident always agree;
//! * **stable** — the same incident is in or out of the sample forever, so a
//!   redelivery cannot move it, and a SHA-256 prefix (not [`std::hash`], whose
//!   output is explicitly not stable across releases) is what makes that true.
//!
//! The cohort is then *signed into the grant*, so the recipient cannot promote
//! their own opinion into the sample that backs a published claim.
//!
//! # Response rate is derived, never stored
//!
//! [`FEEDBACK_SOLICITED_TOTAL`] counts the asking; the API service's
//! `alert_feedback_recorded_total{cohort="solicited"}` counts the answering.
//! The response rate is the ratio of two monotonic counters in PromQL — the
//! same convention detection's hit rate and simulation's confirmation rate
//! follow, and for the same reason: a ratio computed from counters survives
//! restarts and re-aggregates across replicas, where a stored gauge would not.

use chrono::{DateTime, Duration, Utc};
use events::feedback::FeedbackCohort;
use events::primitives::{CustomerId, IncidentId};
use feedback_grant::{Grant, MintingKey};
use secrecy::SecretString;
use sha2::{Digest, Sha256};

/// Counter (labelled by `cohort`): feedback invitations sent. The denominator
/// of the solicited cohort's response rate.
pub const FEEDBACK_SOLICITED_TOTAL: &str = "alert_feedback_solicited_total";
/// Gauge: `1` when this deployment is soliciting feedback at all. An explicit
/// arming state (§15b) — without it, "nobody is answering" and "nobody is
/// being asked" are the same missing series.
pub const FEEDBACK_SOLICITATION_ENABLED: &str = "alert_feedback_solicitation_enabled";
/// Gauge: the sampling rate in permille, so a dashboard can explain a response
/// rate's denominator without reading the deployment's environment.
pub const FEEDBACK_SOLICIT_PERMILLE: &str = "alert_feedback_solicit_permille";

/// One invitation, ready to render into whatever a channel sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedbackInvite {
    /// Where the recipient goes to adjudicate — the base URL with the signed
    /// grant attached.
    pub url: String,
    /// Which sample a verdict through this link will join.
    pub cohort: FeedbackCohort,
}

/// Mints feedback capabilities for delivered incidents.
#[derive(Clone)]
pub struct Inviter {
    key: std::sync::Arc<MintingKey>,
    base_url: String,
    solicit_permille: u32,
    ttl: Duration,
}

impl std::fmt::Debug for Inviter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The key never reaches a log line.
        f.debug_struct("Inviter")
            .field("base_url", &self.base_url)
            .field("solicit_permille", &self.solicit_permille)
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl Inviter {
    /// Build from a deployment's settings.
    ///
    /// `solicit_permille` is clamped to 1000 rather than rejected: an operator
    /// who typed a percentage where permille was wanted has asked for *more*
    /// solicitation than they meant, and the safe reading of "1500" is "all of
    /// them", not a panic in a notification service at 3am.
    pub fn new(
        secret: SecretString,
        base_url: String,
        solicit_permille: u32,
        ttl: Duration,
    ) -> Self {
        let solicit_permille = solicit_permille.min(1_000);
        metrics::gauge!(FEEDBACK_SOLICITATION_ENABLED)
            .set(f64::from(u8::from(solicit_permille > 0)));
        metrics::gauge!(FEEDBACK_SOLICIT_PERMILLE).set(f64::from(solicit_permille));
        Self {
            key: std::sync::Arc::new(MintingKey::from_secret(secret)),
            base_url,
            solicit_permille,
            ttl,
        }
    }

    /// Which cohort this incident belongs to — a pure function of the incident
    /// id and the configured rate, so every replica and every redelivery
    /// agrees without talking to anything.
    ///
    /// SHA-256 over the id's bytes, not a `DefaultHasher`: the standard
    /// library makes no stability promise across releases, and a sampling rule
    /// that silently re-rolls on a Rust upgrade would put the same incident in
    /// both cohorts over its lifetime.
    pub fn cohort_for(&self, incident: IncidentId) -> FeedbackCohort {
        if self.solicit_permille == 0 {
            return FeedbackCohort::Volunteered;
        }
        let digest = Sha256::digest(incident.0.as_bytes());
        let bucket = u64::from_be_bytes(digest[..8].try_into().expect("32-byte digest")) % 1_000;
        if bucket < u64::from(self.solicit_permille) {
            FeedbackCohort::Solicited
        } else {
            FeedbackCohort::Volunteered
        }
    }

    /// Mint the invitation for one delivery. `None` when minting fails, which
    /// is a bug rather than a condition — an alert must still be delivered
    /// without its feedback link.
    pub fn invite(
        &self,
        incident: IncidentId,
        recipient: CustomerId,
        now: DateTime<Utc>,
    ) -> Option<FeedbackInvite> {
        let cohort = self.cohort_for(incident);
        let grant = Grant {
            incident_id: incident.0,
            customer_id: recipient.0,
            cohort: cohort.as_str().to_owned(),
        };
        let token = feedback_grant::mint(&self.key, &grant, (now + self.ttl).timestamp())
            .inspect_err(|err| {
                tracing::warn!(error = %err, "could not mint a feedback grant; delivering without one");
            })
            .ok()?;

        metrics::counter!(FEEDBACK_SOLICITED_TOTAL, "cohort" => cohort.as_str()).increment(1);
        Some(FeedbackInvite {
            url: format!(
                "{}/incidents/{}/feedback?grant={token}",
                self.base_url.trim_end_matches('/'),
                incident.0
            ),
            cohort,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inviter(permille: u32) -> Inviter {
        Inviter::new(
            SecretString::from("test-grant-secret"),
            "https://app.example/".into(),
            permille,
            Duration::days(30),
        )
    }

    #[test]
    fn the_cohort_is_stable_for_an_incident() {
        let inviter = inviter(500);
        let incident = IncidentId::new();
        let first = inviter.cohort_for(incident);
        for _ in 0..10 {
            assert_eq!(
                inviter.cohort_for(incident),
                first,
                "a redelivery must not move an incident between samples"
            );
        }
    }

    #[test]
    fn sampling_is_off_when_the_rate_is_zero_and_total_when_it_is_full() {
        let none = inviter(0);
        let all = inviter(1_000);
        for _ in 0..50 {
            let incident = IncidentId::new();
            assert_eq!(none.cohort_for(incident), FeedbackCohort::Volunteered);
            assert_eq!(all.cohort_for(incident), FeedbackCohort::Solicited);
        }
    }

    #[test]
    fn the_sample_is_roughly_the_configured_rate() {
        // Uniformity is the property that makes a solicited rate defensible:
        // the sample must not correlate with anything about the finding.
        let inviter = inviter(200);
        let solicited = (0..2_000)
            .filter(|_| inviter.cohort_for(IncidentId::new()) == FeedbackCohort::Solicited)
            .count();
        assert!(
            (300..=500).contains(&solicited),
            "expected ~400 of 2000 at 200 permille, got {solicited}"
        );
    }

    #[test]
    fn an_invite_carries_a_grant_the_api_service_can_verify() {
        let inviter = inviter(1_000);
        let incident = IncidentId::new();
        let customer = CustomerId::new();
        let invite = inviter
            .invite(incident, customer, Utc::now())
            .expect("mint");

        assert!(invite.url.starts_with("https://app.example/incidents/"));
        assert_eq!(invite.cohort, FeedbackCohort::Solicited);

        let token = invite
            .url
            .split("grant=")
            .nth(1)
            .expect("a grant in the url");
        let verifying =
            feedback_grant::VerifyingKey::from_secret(SecretString::from("test-grant-secret"));
        let grant = feedback_grant::verify(&verifying, token).expect("verifies");
        assert_eq!(grant.incident_id, incident.0);
        assert_eq!(grant.customer_id, customer.0);
        assert_eq!(grant.cohort, "solicited");
    }

    #[test]
    fn an_expired_invite_no_longer_verifies() {
        // A feedback link in a year-old email is not a standing permission.
        let inviter = Inviter::new(
            SecretString::from("test-grant-secret"),
            "https://app.example".into(),
            1_000,
            Duration::days(30),
        );
        let invite = inviter
            .invite(
                IncidentId::new(),
                CustomerId::new(),
                Utc::now() - Duration::days(60),
            )
            .expect("mint");
        let token = invite.url.split("grant=").nth(1).unwrap();
        let verifying =
            feedback_grant::VerifyingKey::from_secret(SecretString::from("test-grant-secret"));
        assert!(feedback_grant::verify(&verifying, token).is_err());
    }
}
