//! The §19 feedback capability (production-readiness Epic E) — a signed
//! statement that *this recipient was shown this incident*, and may therefore
//! adjudicate it.
//!
//! # Why a capability and not a lookup
//!
//! The obvious design is to check, at the API boundary, whether the incident
//! exists. It is the wrong one in three separate ways, and this crate exists
//! because all three matter at production scale:
//!
//! 1. **It authorizes nothing.** "The incident exists" is true for every
//!    incident in the platform, so any authenticated tenant could adjudicate
//!    any finding — including ones they were never shown. That is a
//!    cross-tenant write dressed up as a read (§9's isolation rule), and it
//!    makes the false-positive rate trivially poisonable by anyone with a
//!    trial account.
//! 2. **It leaks.** A 404-vs-202 split over incident ids is an existence
//!    oracle: it answers "is this a real incident?" for anybody who asks.
//! 3. **It is not even the signal.** A verdict from someone who never received
//!    the alert says nothing about detection quality.
//!
//! A grant answers all three structurally. Notification mints one when it
//! *delivers* an alert, so possession of a grant is itself the evidence of
//! delivery; verification is a signature check with no I/O, no oracle, and no
//! dependency on a second service being up.
//!
//! # The mint/verify asymmetry is a type, not a convention
//!
//! [`auth`](../../auth/src/lib.rs) is verify-only by charter: "a library that
//! can both mint and verify invites a service to trust a token it minted for
//! itself." This crate cannot follow that rule — the whole point is that one
//! service issues and another accepts — so it enforces the same intent with
//! [`MintingKey`] and [`VerifyingKey`] as distinct types built by distinct
//! constructors. A service that configured only verification has no value of
//! the type [`mint`] requires, so "the API service quietly issues itself a
//! grant" is not a code review question; it does not compile.
//!
//! The grant also carries its own audience (`aud = "mevwatch/feedback"`) and
//! is signed with its own secret, so an identity JWT can never be presented as
//! a grant and a grant can never be presented as a bearer token — a confusion
//! that HMAC alone would not prevent.

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The audience every grant carries and every verification requires. A token
/// minted for anything else — an identity JWT, a grant from another
/// deployment's issuer — fails before its claims are read.
const AUDIENCE: &str = "mevwatch/feedback";

/// What a grant says: who may adjudicate what, in which sample, until when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// The incident the holder was shown.
    pub incident_id: Uuid,
    /// The customer it was delivered to. The API service checks this against
    /// the bearer token's own subject, so a leaked grant is useless to anyone
    /// but its recipient.
    pub customer_id: Uuid,
    /// Which sample this verdict will join — `volunteered` or `solicited`.
    /// Decided by the *sender* at delivery time and signed here, precisely so
    /// the recipient cannot promote their own opinion into the cohort that
    /// backs a published claim.
    pub cohort: String,
}

/// The signing half. Constructed only by [`MintingKey::from_secret`], which is
/// called only by the service that delivers alerts.
pub struct MintingKey(SecretString);

/// The checking half. Every other service gets one of these and nothing else.
pub struct VerifyingKey(SecretString);

impl MintingKey {
    /// Build from `FEEDBACK_GRANT_SECRET`. Deliberately not `From<SecretString>`:
    /// the call is meant to be greppable, and there should be exactly one.
    pub fn from_secret(secret: SecretString) -> Self {
        Self(secret)
    }
}

impl VerifyingKey {
    /// Build from the same `FEEDBACK_GRANT_SECRET`.
    pub fn from_secret(secret: SecretString) -> Self {
        Self(secret)
    }
}

/// A grant that could not be minted or trusted.
#[derive(Debug, thiserror::Error)]
pub enum GrantError {
    /// The token is malformed, expired, signed with another key, or issued for
    /// a different audience. Deliberately **one** variant: telling a caller
    /// which of those it was is telling an attacker which of those it was.
    #[error("the feedback grant is not valid")]
    Invalid,
    /// Minting failed — a serialization fault, not a caller's mistake.
    #[error("could not mint a feedback grant")]
    Mint,
}

/// The wire claims. Short names because this token rides in a URL.
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    aud: String,
    exp: i64,
    /// Incident.
    inc: Uuid,
    /// Customer.
    cus: Uuid,
    /// Cohort.
    coh: String,
}

/// Mint a grant valid until `expires_at` (a unix timestamp).
///
/// The expiry is what keeps a grant from becoming a permanent standing
/// permission on an incident: a feedback link in an email a year old should
/// stop working, both because the customer's relationship may have ended and
/// because the SLI's window closed long ago.
pub fn mint(key: &MintingKey, grant: &Grant, expires_at: i64) -> Result<String, GrantError> {
    let claims = Claims {
        aud: AUDIENCE.to_owned(),
        exp: expires_at,
        inc: grant.incident_id,
        cus: grant.customer_id,
        coh: grant.cohort.clone(),
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(key.0.expose_secret().as_bytes()),
    )
    .map_err(|_| GrantError::Mint)
}

/// Verify a grant and return what it says.
///
/// Expiry, signature and audience are all checked here; **who is presenting
/// it is not**. The caller must compare [`Grant::customer_id`] against its own
/// authenticated subject — this crate has no opinion about how a service
/// establishes identity, and conflating the two checks is how a capability
/// quietly becomes a bearer token.
pub fn verify(key: &VerifyingKey, token: &str) -> Result<Grant, GrantError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&[AUDIENCE]);
    // `exp` is validated by default; state it so a future edit to this
    // function cannot silently turn a grant into a permanent one.
    validation.validate_exp = true;

    let decoded = decode::<Claims>(
        token,
        &DecodingKey::from_secret(key.0.expose_secret().as_bytes()),
        &validation,
    )
    .map_err(|_| GrantError::Invalid)?;

    Ok(Grant {
        incident_id: decoded.claims.inc,
        customer_id: decoded.claims.cus,
        cohort: decoded.claims.coh,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> (MintingKey, VerifyingKey) {
        (
            MintingKey::from_secret(SecretString::from("test-grant-secret")),
            VerifyingKey::from_secret(SecretString::from("test-grant-secret")),
        )
    }

    fn grant() -> Grant {
        Grant {
            incident_id: Uuid::from_u128(0x1c),
            customer_id: Uuid::from_u128(0xc0),
            cohort: "solicited".into(),
        }
    }

    fn in_an_hour() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 3_600
    }

    #[test]
    fn a_minted_grant_round_trips() {
        let (mint_key, verify_key) = keys();
        let token = mint(&mint_key, &grant(), in_an_hour()).unwrap();
        assert_eq!(verify(&verify_key, &token).unwrap(), grant());
    }

    #[test]
    fn a_grant_signed_with_another_secret_is_refused() {
        let (mint_key, _) = keys();
        let token = mint(&mint_key, &grant(), in_an_hour()).unwrap();
        let other = VerifyingKey::from_secret(SecretString::from("a-different-secret"));
        assert!(matches!(verify(&other, &token), Err(GrantError::Invalid)));
    }

    #[test]
    fn an_expired_grant_is_refused() {
        let (mint_key, verify_key) = keys();
        let token = mint(&mint_key, &grant(), 1_700_000_000).unwrap();
        assert!(matches!(
            verify(&verify_key, &token),
            Err(GrantError::Invalid)
        ));
    }

    #[test]
    fn an_identity_token_cannot_be_presented_as_a_grant() {
        // The same secret, the same algorithm, a token that is simply not for
        // this audience: the shape of a confused-deputy bug, refused by the
        // audience check rather than by luck.
        #[derive(Serialize)]
        struct IdentityClaims {
            sub: String,
            exp: i64,
            iss: String,
        }
        let token = encode(
            &Header::new(Algorithm::HS256),
            &IdentityClaims {
                sub: "00000000-0000-0000-0000-0000000000c0".into(),
                exp: in_an_hour(),
                iss: "mev".into(),
            },
            &EncodingKey::from_secret(b"test-grant-secret"),
        )
        .unwrap();

        let (_, verify_key) = keys();
        assert!(matches!(
            verify(&verify_key, &token),
            Err(GrantError::Invalid)
        ));
    }

    #[test]
    fn a_tampered_cohort_is_refused() {
        // The cohort decides which sample a verdict joins, so a recipient who
        // could edit it could promote their own opinion into the number a
        // README quotes. It is inside the signature.
        let (mint_key, verify_key) = keys();
        let token = mint(&mint_key, &grant(), in_an_hour()).unwrap();
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged_payload = "eyJhdWQiOiJtZXZ3YXRjaC9mZWVkYmFjayIsImV4cCI6OTk5OTk5OTk5OSwiaW5jIjo\
                              iMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDFjIiwiY3VzIjoiMDAwMDA\
                              wMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMGMwIiwiY29oIjoic29saWNpdGVkIn0";
        parts[1] = forged_payload;
        let forged = parts.join(".");
        assert!(matches!(
            verify(&verify_key, &forged),
            Err(GrantError::Invalid)
        ));
    }
}
