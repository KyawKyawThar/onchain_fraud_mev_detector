//! Thin HTTP proxy clients to event-store's and simulation-projection's
//! existing internal read endpoints (§11): forward the caller's query
//! parameters verbatim and hand back the upstream JSON body as-is, so this
//! crate never has to duplicate `EventPageResponse`/`IncidentPageResponse`'s
//! shape and the two can't drift.

use std::collections::BTreeMap;

use api_error::ApiError;
use reqwest::StatusCode as UpstreamStatus;
use serde_json::Value;

/// A proxied call's outcome: the upstream's status and, on success, the
/// decoded JSON body. Run it through [`Self::client_visible`] before building
/// the caller's response — the raw passthrough is not the caller's contract.
#[derive(Debug)]
pub struct ProxiedResponse {
    pub status: UpstreamStatus,
    pub body: Value,
}

impl ProxiedResponse {
    /// The status-class policy for proxied reads — the HTTP twin of the gRPC
    /// classification in [`crate::intelligence_client::to_api_error`]:
    ///
    /// * **2xx/4xx pass through verbatim.** The upstream's 400 is still the
    ///   caller's bad request (their cursor, their query param) — re-wrapping
    ///   it would hide the detail that helps them fix it.
    /// * **Upstream 5xx becomes *our* 502.** From the caller's seat, a
    ///   dependency of the api-service failed: 502 says "not your request,
    ///   retry-worthy" and keeps the upstream's failure body (already
    ///   sanitized by its own `ApiError`, but not this surface's contract)
    ///   out of the public response. Passing a naked 500 through would
    ///   misreport a backend outage as an api-service bug.
    pub fn client_visible(self, upstream: &str) -> Result<Self, ApiError> {
        if self.status.is_server_error() {
            return Err(ApiError::bad_gateway(format!(
                "{upstream} answered {}: {}",
                self.status, self.body
            )));
        }
        Ok(self)
    }
}

/// A failure reaching the upstream at all (as opposed to the upstream
/// answering with a non-2xx, which [`ProxiedResponse`] carries).
#[derive(Debug, thiserror::Error)]
#[error("upstream request failed")]
pub struct UpstreamError(#[from] pub reqwest::Error);

/// `GET {base_url}{path}`, with `query` appended (percent-encoded by
/// `reqwest`), decoding the body as JSON regardless of status (both
/// event-store's and simulation-projection's error bodies are plain text on
/// failure, so a decode error there is mapped to a JSON string rather than
/// failing the whole proxy).
pub async fn get(
    client: &reqwest::Client,
    base_url: &str,
    path: &str,
    query: &BTreeMap<String, String>,
) -> Result<ProxiedResponse, UpstreamError> {
    let response = client
        .get(format!("{base_url}{path}"))
        .query(query)
        .send()
        .await?;
    let status = response.status();
    let text = response.text().await?;
    let body = serde_json::from_str(&text).unwrap_or(Value::String(text));

    Ok(ProxiedResponse { status, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxied(status: UpstreamStatus, body: &str) -> ProxiedResponse {
        ProxiedResponse {
            status,
            body: Value::String(body.to_owned()),
        }
    }

    #[test]
    fn success_and_caller_fault_pass_through_verbatim() {
        for status in [
            UpstreamStatus::OK,
            UpstreamStatus::BAD_REQUEST,
            UpstreamStatus::NOT_FOUND,
        ] {
            let response = proxied(status, "detail")
                .client_visible("event-store")
                .expect("2xx/4xx must pass through");
            assert_eq!(response.status, status);
            assert_eq!(response.body, Value::String("detail".to_owned()));
        }
    }

    #[test]
    fn upstream_5xx_becomes_our_502_with_the_detail_kept_for_the_log() {
        for status in [
            UpstreamStatus::INTERNAL_SERVER_ERROR,
            UpstreamStatus::SERVICE_UNAVAILABLE,
        ] {
            let err = proxied(status, "storage exploded")
                .client_visible("simulation-projection")
                .expect_err("5xx must not pass through");
            match err {
                ApiError::BadGateway(detail) => {
                    // The detail names the upstream + carries its body — for
                    // the log line; ApiError's 5xx path never returns it.
                    assert!(detail.contains("simulation-projection"), "{detail}");
                    assert!(detail.contains("storage exploded"), "{detail}");
                }
                other => panic!("expected BadGateway, got {other:?}"),
            }
        }
    }
}
