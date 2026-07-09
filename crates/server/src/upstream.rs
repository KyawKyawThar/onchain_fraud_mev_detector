//! Thin HTTP proxy clients to event-store's and simulation-projection's
//! existing internal read endpoints (§11): forward the caller's query
//! parameters verbatim and hand back the upstream JSON body as-is, so this
//! crate never has to duplicate `EventPageResponse`/`IncidentPageResponse`'s
//! shape and the two can't drift.

use std::collections::BTreeMap;

use reqwest::StatusCode as UpstreamStatus;
use serde_json::Value;

/// A proxied call's outcome: the upstream's status (passed straight through —
/// its 400 is still the caller's bad request) and, on success, the decoded
/// JSON body.
pub struct ProxiedResponse {
    pub status: UpstreamStatus,
    pub body: Value,
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
