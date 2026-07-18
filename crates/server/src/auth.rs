//! JWT bearer verification (§11) — the public API service's end-user auth
//! gate. Every `/v1` route requires a valid `Authorization: Bearer <jwt>`;
//! `/healthz` is the only open route (see `http.rs`).
//!
//! No issuance/login endpoint: no user/tenant store exists yet, so a token is
//! assumed to have been minted elsewhere against the same `JWT_SECRET`/
//! `JWT_ISSUER`. This module only validates — signature (HS256), expiry, and
//! issuer.

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use events::primitives::CustomerId;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::JwtConfig;

/// The claims this service expects. `sub` is the billing customer's UUID
/// ([`CustomerId`], §13) — every authenticated call is metered against it
/// (see `usage.rs`), so a token whose `sub` isn't a UUID is rejected outright:
/// an unmeterable call on a metered product is an invalid credential, not a
/// free one. `exp`/`iss` are enforced by [`jsonwebtoken::decode`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iss: String,
}

/// Middleware: require a valid bearer JWT or reject with 401. Mirrors the
/// shape of event-store's `require_write_token`, just JWT instead of a static
/// shared secret. On success, inserts the token's [`CustomerId`] as a request
/// extension so downstream layers (usage metering, `usage.rs`) know who
/// called without re-parsing the token.
pub async fn require_jwt(State(jwt): State<JwtConfig>, mut req: Request, next: Next) -> Response {
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    let Some(token) = presented else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[&jwt.issuer]);

    let key = DecodingKey::from_secret(jwt.secret.expose_secret().as_bytes());
    match decode::<Claims>(token, &key, &validation) {
        Ok(data) => {
            let Ok(customer) = Uuid::parse_str(&data.claims.sub) else {
                tracing::warn!(
                    sub = %data.claims.sub,
                    "bearer token rejected: sub is not a customer UUID (unmeterable, §13)"
                );
                return StatusCode::UNAUTHORIZED.into_response();
            };
            // The nil UUID is reserved: `crates/usage`'s ClickHouse store uses it
            // as the sentinel for system-wide usage that has no customer at all
            // (`UsageRecorded.customer_id: None` — see `events::system::
            // UsageRecorded` and `usage::store::NIL_CUSTOMER`). A real customer
            // minted with this id would be indistinguishable from that system
            // bucket in every usage query, so it's rejected here — the one place
            // every `CustomerId` in the system originates from.
            if customer.is_nil() {
                tracing::warn!(
                    "bearer token rejected: sub is the nil UUID (reserved for system usage, §13)"
                );
                return StatusCode::UNAUTHORIZED.into_response();
            }
            req.extensions_mut().insert(CustomerId(customer));
            next.run(req).await
        }
        Err(err) => {
            tracing::warn!(error = %err, "bearer token rejected");
            StatusCode::UNAUTHORIZED.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use axum::middleware;
    use axum::routing::get;
    use axum::Router;
    use jsonwebtoken::{encode, EncodingKey, Header};
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
