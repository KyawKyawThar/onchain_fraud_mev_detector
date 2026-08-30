//! Shared JWT bearer verification (§11) — the one place a caller's identity is
//! established.
//!
//! Promoted out of the API service when a second surface needed it: the §20.4
//! copilot's review API records **who approved a machine-written SAR
//! narrative**, and "whatever name the caller typed in the request body" is not
//! an audit trail. Two independent verifiers would have been two answers to
//! "who is this", which for a compliance record is one too many.
//!
//! # Verify-only, on purpose
//!
//! Nothing here mints a token. There is no user store in this system yet, so a
//! token is assumed to have been issued elsewhere against the same
//! `JWT_SECRET`/`JWT_ISSUER`; this crate checks the signature (HS256), the
//! expiry and the issuer, and hands back the claims. Adding issuance later is a
//! new crate, not a new function here — a library that can both mint and verify
//! invites a service to trust a token it minted for itself.
//!
//! # What a service does with the claims is the service's business
//!
//! The API service requires `sub` to be a billing customer's UUID, because
//! every call it serves is metered against one (§13). The copilot does not: an
//! incident narrative has no customer, and its reviewer is a person. Both use
//! the *same* verification and then interpret `sub` for themselves, which is
//! why [`verify`] returns [`Claims`] rather than a domain type.

use std::fmt;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// What every service expects in a token.
///
/// `sub` stays a `String`: it is the *subject*, and what a subject means is a
/// per-service question (a customer UUID for the metered API, a reviewer's
/// identity for the copilot). `exp`/`iss` are enforced by [`decode`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iss: String,
}

/// The signing secret and expected issuer.
#[derive(Clone)]
pub struct JwtConfig {
    /// HMAC signing secret. Secret — `Debug` redacts it.
    pub secret: SecretString,
    /// Expected `iss` claim; a token from anywhere else is rejected.
    pub issuer: String,
}

impl fmt::Debug for JwtConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtConfig")
            .field("secret", &"[redacted]")
            .field("issuer", &self.issuer)
            .finish()
    }
}

/// Why a token was refused.
///
/// Deliberately coarse *to the caller* — every variant becomes a bare 401 with
/// no body, because telling an attacker whether a token was missing, expired or
/// signed by the wrong key is a free oracle. The distinction exists for the
/// service's own logs.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("no bearer token presented")]
    Missing,
    #[error("token rejected: {0}")]
    Invalid(String),
}

impl AuthError {
    /// The 401 every failure becomes.
    pub fn into_response(self) -> Response {
        tracing::warn!(error = %self, "bearer token rejected");
        StatusCode::UNAUTHORIZED.into_response()
    }
}

/// Verify a bare token string (no `Bearer ` prefix) and return its claims.
///
/// The whole cryptographic surface of this crate, so it is the whole thing a
/// test needs to exercise.
pub fn verify(token: &str, jwt: &JwtConfig) -> Result<Claims, AuthError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[&jwt.issuer]);
    let key = DecodingKey::from_secret(jwt.secret.expose_secret().as_bytes());
    decode::<Claims>(token, &key, &validation)
        .map(|data| data.claims)
        .map_err(|err| AuthError::Invalid(err.to_string()))
}

/// Pull the bearer token out of an `Authorization` header, if there is one.
pub fn bearer(headers: &header::HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

/// Middleware: require a valid bearer JWT or reject with 401, inserting the
/// verified [`Claims`] as a request extension.
///
/// A service that needs more than "the token is valid" — a customer UUID, a
/// role — reads the extension and applies its own rule, rather than forking
/// this one.
pub async fn require_jwt(State(jwt): State<JwtConfig>, mut req: Request, next: Next) -> Response {
    let Some(token) = bearer(req.headers()) else {
        return AuthError::Missing.into_response();
    };
    match verify(token, &jwt) {
        Ok(claims) => {
            req.extensions_mut().insert(claims);
            next.run(req).await
        }
        Err(err) => err.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    fn config() -> JwtConfig {
        JwtConfig {
            secret: SecretString::from("test-secret"),
            issuer: "mevwatch".to_owned(),
        }
    }

    fn token(sub: &str, issuer: &str, secret: &str, exp: usize) -> String {
        encode(
            &Header::new(Algorithm::HS256),
            &Claims {
                sub: sub.to_owned(),
                exp,
                iss: issuer.to_owned(),
            },
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("sign")
    }

    fn far_future() -> usize {
        // 2286-11-20 — comfortably past any test run, and not a value a clock
        // skew can reach.
        10_000_000_000
    }

    #[test]
    fn a_well_formed_token_verifies_and_carries_its_subject() {
        let claims = verify(
            &token("alice@compliance", "mevwatch", "test-secret", far_future()),
            &config(),
        )
        .expect("valid");
        assert_eq!(claims.sub, "alice@compliance");
    }

    /// The three ways a token is refused. All three are a bare 401 to the
    /// caller; the distinction is for our logs.
    #[test]
    fn a_wrong_signature_issuer_or_expiry_is_refused() {
        for (name, token) in [
            (
                "wrong secret",
                token("alice", "mevwatch", "other-secret", far_future()),
            ),
            (
                "wrong issuer",
                token("alice", "somebody-else", "test-secret", far_future()),
            ),
            ("expired", token("alice", "mevwatch", "test-secret", 1)),
        ] {
            assert!(verify(&token, &config()).is_err(), "{name} must not verify");
        }
    }

    #[test]
    fn the_bearer_prefix_is_required() {
        let mut headers = header::HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Basic abc".parse().unwrap());
        assert!(bearer(&headers).is_none());

        headers.insert(header::AUTHORIZATION, "Bearer abc".parse().unwrap());
        assert_eq!(bearer(&headers), Some("abc"));
    }

    #[test]
    fn debug_redacts_the_secret() {
        let rendered = format!("{:?}", config());
        assert!(!rendered.contains("test-secret"), "{rendered}");
    }
}
