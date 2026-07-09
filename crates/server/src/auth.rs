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
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::config::JwtConfig;

/// The claims this service expects. `sub` is the caller identity (unused
/// beyond being logged/validated as present — there's no user store to look
/// it up against yet); `exp`/`iss` are enforced by [`jsonwebtoken::decode`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iss: String,
}

/// Middleware: require a valid bearer JWT or reject with 401. Mirrors the
/// shape of event-store's `require_write_token`, just JWT instead of a static
/// shared secret.
pub async fn require_jwt(State(jwt): State<JwtConfig>, req: Request, next: Next) -> Response {
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
        Ok(_) => next.run(req).await,
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

    fn app(jwt: JwtConfig) -> Router {
        Router::new()
            .route("/protected", get(|| async { "ok" }))
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
            sub: "caller".to_owned(),
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
            sub: "caller".to_owned(),
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
            sub: "caller".to_owned(),
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
            sub: "caller".to_owned(),
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
}
