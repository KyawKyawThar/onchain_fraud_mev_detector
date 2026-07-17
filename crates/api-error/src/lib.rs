//! The shared HTTP handler-error seam (§11).
//!
//! Every HTTP surface in the workspace — event-store's and simulation-projection's
//! internal read APIs, the public API service's `/v1` routes — converged on the
//! identical shape: a status code + message, 4xx detail returned to the caller
//! (their mistake, the detail helps them fix it), 5xx detail logged but never
//! returned (it can carry storage URLs/SQL/internal error text) and replaced with
//! a generic body. That shape now lives in one place instead of three near-
//! identical copies, so a change to the policy (e.g. adding a structured JSON
//! error envelope later) is a one-crate change.
//!
//! Deliberately does **not** cover authentication failures (401): those are
//! returned as a bare status with no body by the bearer/JWT middleware that
//! guards each service, on purpose — a 401 shouldn't tell a caller *why* it
//! failed (missing vs. expired vs. wrong signature vs. wrong issuer), which is
//! a different policy than the "detail helps a legitimate caller" rule below.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// A handler error carrying the HTTP status to return. Construct via the
/// `ApiError::*` functions below rather than the variants directly, so call
/// sites read as intent ("this is a bad request") rather than status-code
/// trivia.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// 400 — the request itself is malformed (bad query param, invalid cursor,
    /// unsupported schema version, ...). The caller's mistake; the detail is
    /// safe and useful to return.
    #[error("{0}")]
    BadRequest(String),

    /// 404 — the addressed resource doesn't exist (an unknown entity id, ...).
    /// The caller named something real-looking but absent; the detail is safe
    /// and useful to return.
    #[error("{0}")]
    NotFound(String),

    /// 413 — the request body exceeds a service-defined limit.
    #[error("{0}")]
    PayloadTooLarge(String),

    /// 502 — a downstream service (gRPC or HTTP) this handler depends on
    /// failed or was unreachable. Not this service's fault, but not the
    /// caller's either.
    #[error("{0}")]
    BadGateway(String),

    /// 500 — an unexpected failure on this service's own side (storage down,
    /// a serialization bug, ...). The detail is logged, never returned.
    #[error("{0}")]
    Internal(String),
}

impl ApiError {
    /// 400 — a client-supplied request value is invalid. Takes any `Display`
    /// — a literal/formatted message *or* a domain error type directly (e.g.
    /// `.map_err(ApiError::bad_request)` over a `thiserror` validation error)
    /// — so call sites don't need to pre-`.to_string()` it. The rendered text
    /// is returned to the caller verbatim, so it must not leak internals.
    pub fn bad_request(message: impl std::fmt::Display) -> Self {
        Self::BadRequest(message.to_string())
    }

    /// 404 — the addressed resource doesn't exist. `message` names what was
    /// missing; it's returned to the caller verbatim, so it must not leak
    /// internals.
    pub fn not_found(message: impl std::fmt::Display) -> Self {
        Self::NotFound(message.to_string())
    }

    /// 413 — the request exceeds a size/count limit `message` describes.
    pub fn payload_too_large(message: impl std::fmt::Display) -> Self {
        Self::PayloadTooLarge(message.to_string())
    }

    /// 502 — a downstream dependency failed. Takes any `Display` (a
    /// `tonic::Status`, a `reqwest`-backed proxy error, ...) so call sites
    /// don't need their own wrapper per downstream error type.
    pub fn bad_gateway(err: impl std::fmt::Display) -> Self {
        Self::BadGateway(err.to_string())
    }

    /// 500 — this service's own failure. Takes any `Display` for the same
    /// reason as [`Self::bad_gateway`].
    pub fn internal(err: impl std::fmt::Display) -> Self {
        Self::Internal(err.to_string())
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            Self::BadGateway(_) => StatusCode::BAD_GATEWAY,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        if status.is_server_error() {
            // Log the detail, but never return internal error text (which can
            // carry storage URLs / SQL / a downstream's raw error) to the caller.
            tracing::error!(%status, error = %self, "request failed");
            (status, "internal server error").into_response()
        } else {
            // 4xx is the caller's own fault — the detail helps them fix it.
            tracing::warn!(%status, error = %self, "request rejected");
            (status, self.to_string()).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_constructor_maps_to_its_documented_status() {
        assert_eq!(ApiError::bad_request("x").status(), StatusCode::BAD_REQUEST);
        assert_eq!(ApiError::not_found("x").status(), StatusCode::NOT_FOUND);
        assert_eq!(
            ApiError::payload_too_large("x").status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(ApiError::bad_gateway("x").status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            ApiError::internal("x").status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn display_preserves_the_original_message() {
        assert_eq!(ApiError::bad_request("nope").to_string(), "nope");
        assert_eq!(ApiError::internal("boom").to_string(), "boom");
    }
}
