//! The API service's JWT gate (§11) — the shared verifier, plus the one rule
//! that is this service's alone.
//!
//! Signature, expiry and issuer checking live in the workspace's [`auth`]
//! crate, because a second service (the §20.4 copilot's review API) has to
//! answer "who is this" the *same* way. What stays here is the part that is
//! only true of this service: `sub` must be a billing customer's UUID (§13),
//! because every call it serves is metered against one — so a token whose
//! `sub` is not a customer is rejected outright, an unmeterable call on a
//! metered product being an invalid credential rather than a free one.
//!
//! No issuance endpoint: tokens are minted elsewhere against the same
//! `JWT_SECRET`/`JWT_ISSUER`. This module only validates.

use auth::{AuthError, JwtConfig};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use events::primitives::CustomerId;
use uuid::Uuid;

/// Re-exported so existing call sites (and tests) keep naming one type.
pub use auth::Claims;

/// Middleware: require a valid bearer JWT whose `sub` is a customer UUID, or
/// reject with 401. On success, inserts the [`CustomerId`] as a request
/// extension so downstream layers (usage metering, `usage.rs`) know who called
/// without re-parsing the token.
pub async fn require_jwt(State(jwt): State<JwtConfig>, mut req: Request, next: Next) -> Response {
    let Some(token) = auth::bearer(req.headers()) else {
        return AuthError::Missing.into_response();
    };
    let claims = match auth::verify(token, &jwt) {
        Ok(claims) => claims,
        Err(err) => return err.into_response(),
    };

    let Ok(customer) = Uuid::parse_str(&claims.sub) else {
        tracing::warn!(
            sub = %claims.sub,
            "bearer token rejected: sub is not a customer UUID (unmeterable, §13)"
        );
        return StatusCode::UNAUTHORIZED.into_response();
    };
    // The nil UUID is reserved: `crates/usage`'s ClickHouse store uses it as
    // the sentinel for system-wide usage that has no customer at all
    // (`UsageRecorded.customer_id: None`). A real customer minted with this id
    // would be indistinguishable from that system bucket in every usage query,
    // so it is rejected here — the one place every `CustomerId` originates.
    if customer.is_nil() {
        tracing::warn!(
            "bearer token rejected: sub is the nil UUID (reserved for system usage, §13)"
        );
        return StatusCode::UNAUTHORIZED.into_response();
    }
    req.extensions_mut().insert(CustomerId(customer));
    req.extensions_mut().insert(claims);
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::header;
    use axum::http::Request as HttpRequest;
    use axum::middleware;
    use axum::routing::get;
    use axum::Router;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use secrecy::ExposeSecret;
    use secrecy::SecretString;
    use tower::ServiceExt;

    fn jwt_config() -> JwtConfig {
        JwtConfig {
            secret: SecretString::from("test-secret"),
            issuer: "mev".to_owned(),
        }
    }

    fn token(claims: &Claims, secret: &str) -> String {
        encode(
            &Header::new(Algorithm::HS256),
            claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    /// A `sub` the middleware accepts: [`CustomerId`]s are UUIDs (§13).
    const CUSTOMER_SUB: &str = "00000000-0000-0000-0000-0000000000c0";

    fn app(jwt: JwtConfig) -> Router {
        // The handler proves the middleware inserted the CustomerId extension
        // (what usage metering reads) — a missing extension is a 500, not 200.
        Router::new()
            .route(
                "/protected",
                get(|req: HttpRequest<Body>| async move {
                    match req.extensions().get::<CustomerId>() {
                        Some(customer) => {
                            assert_eq!(customer.to_string(), CUSTOMER_SUB);
                            StatusCode::OK
                        }
                        None => StatusCode::INTERNAL_SERVER_ERROR,
                    }
                }),
            )
            .route_layer(middleware::from_fn_with_state(jwt, require_jwt))
    }

    fn future_exp() -> usize {
        (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize
    }

    fn past_exp() -> usize {
        (chrono::Utc::now() - chrono::Duration::hours(1)).timestamp() as usize
    }

    #[tokio::test]
    async fn missing_bearer_is_rejected() {
        let response = app(jwt_config())
            .oneshot(
                HttpRequest::builder()
                    .uri("/protected")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn valid_token_is_accepted() {
        let claims = Claims {
            sub: CUSTOMER_SUB.to_owned(),
            exp: future_exp(),
            iss: "mev".to_owned(),
        };
        let jwt = jwt_config();
        let bearer = token(&claims, jwt.secret.expose_secret());

        let response = app(jwt)
            .oneshot(
                HttpRequest::builder()
                    .uri("/protected")
                    .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn expired_token_is_rejected() {
        let claims = Claims {
            sub: CUSTOMER_SUB.to_owned(),
            exp: past_exp(),
            iss: "mev".to_owned(),
        };
        let jwt = jwt_config();
        let bearer = token(&claims, jwt.secret.expose_secret());

        let response = app(jwt)
            .oneshot(
                HttpRequest::builder()
                    .uri("/protected")
                    .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_issuer_is_rejected() {
        let claims = Claims {
            sub: CUSTOMER_SUB.to_owned(),
            exp: future_exp(),
            iss: "someone-else".to_owned(),
        };
        let jwt = jwt_config();
        let bearer = token(&claims, jwt.secret.expose_secret());

        let response = app(jwt)
            .oneshot(
                HttpRequest::builder()
                    .uri("/protected")
                    .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_secret_is_rejected() {
        let claims = Claims {
            sub: CUSTOMER_SUB.to_owned(),
            exp: future_exp(),
            iss: "mev".to_owned(),
        };
        let bearer = token(&claims, "not-the-real-secret");

        let response = app(jwt_config())
            .oneshot(
                HttpRequest::builder()
                    .uri("/protected")
                    .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn non_uuid_sub_is_rejected() {
        // Correctly signed, unexpired, right issuer — but the sub can't name a
        // CustomerId, so the call would be unmeterable (§13). Rejected.
        let claims = Claims {
            sub: "not-a-customer-uuid".to_owned(),
            exp: future_exp(),
            iss: "mev".to_owned(),
        };
        let jwt = jwt_config();
        let bearer = token(&claims, jwt.secret.expose_secret());

        let response = app(jwt)
            .oneshot(
                HttpRequest::builder()
                    .uri("/protected")
                    .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn nil_uuid_sub_is_rejected() {
        // The nil UUID is reserved as the system-usage sentinel in ClickHouse
        // (§13) — a token naming it as `sub` would be indistinguishable from
        // system-wide usage in every query, so it's rejected like a malformed
        // sub rather than accepted as a "customer."
        let claims = Claims {
            sub: Uuid::nil().to_string(),
            exp: future_exp(),
            iss: "mev".to_owned(),
        };
        let jwt = jwt_config();
        let bearer = token(&claims, jwt.secret.expose_secret());

        let response = app(jwt)
            .oneshot(
                HttpRequest::builder()
                    .uri("/protected")
                    .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
