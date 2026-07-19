//! API request metrics (§19, Sprint 13 t4): the p50/p99 latency + request-rate
//! panel.
//!
//! One middleware ([`record_http_metrics`]), layered alongside the existing
//! `TraceLayer::new_for_http()` in [`crate::http::router`] — every request
//! through the router passes through it, mirroring the single-call-site
//! discipline `detection::metrics` uses. Labeled by route *template* (axum's
//! [`MatchedPath`], e.g. `/v1/address/{addr}/risk`), never the raw path — an
//! address/incident id in the URL would otherwise blow up cardinality, and an
//! unmatched (404-probing) request is folded into one `"unmatched"` label
//! rather than echoing attacker-controlled path segments into a metric label.

use std::time::Instant;

use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;

/// Counter: every request, labeled `method`, `route`, and `status` (the
/// response's status class: `2xx`/`3xx`/`4xx`/`5xx`).
pub const HTTP_REQUESTS_TOTAL: &str = "http_requests_total";
/// Histogram: request wall-clock latency, labeled `method` and `route` (§19 —
/// the API p50/p99 panel, computed with `histogram_quantile` in PromQL).
pub const HTTP_REQUEST_DURATION_SECONDS: &str = "http_request_duration_seconds";

/// Route label for a request that matched no route (404) — a fixed,
/// low-cardinality bucket rather than the raw (attacker-controlled) path.
const UNMATCHED_ROUTE: &str = "unmatched";

pub async fn record_http_metrics(request: Request, next: Next) -> Response {
    let method = request.method().to_string();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| UNMATCHED_ROUTE.to_owned());

    let started = Instant::now();
    let response = next.run(request).await;
    let elapsed = started.elapsed();
    let status = status_class(response.status().as_u16());

    metrics::counter!(
        HTTP_REQUESTS_TOTAL,
        "method" => method.clone(),
        "route" => route.clone(),
        "status" => status,
    )
    .increment(1);
    metrics::histogram!(HTTP_REQUEST_DURATION_SECONDS, "method" => method, "route" => route)
        .record(elapsed.as_secs_f64());

    response
}

/// Collapse a status code to its class (`2xx`..`5xx`) — the dashboard/alert
/// granularity; the exact code stays in the trace/log, not the metric label.
fn status_class(code: u16) -> &'static str {
    match code / 100 {
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_class_buckets_by_hundreds() {
        assert_eq!(status_class(200), "2xx");
        assert_eq!(status_class(201), "2xx");
        assert_eq!(status_class(301), "3xx");
        assert_eq!(status_class(404), "4xx");
        assert_eq!(status_class(500), "5xx");
        assert_eq!(status_class(101), "other");
    }
}
