//! The API dimension: requests per second, measured from the client.
//!
//! Latency is recorded **client-side**, not scraped from the server's own
//! middleware, and that is the whole design of this module. The server's
//! histogram starts when a request reaches a handler — after the accept queue,
//! after connection setup, after whatever the socket backlog did while the
//! service was saturated. Under exactly the load this test exists to apply,
//! those are the terms that grow, and a server-side p99 can stay flat while
//! callers time out. The number a customer experiences is the one measured
//! here.
//!
//! Requests are paced on the same absolute schedule as the block generator, for
//! the same reason (see [`crate::chain`]): a driver that waits for the previous
//! response before issuing the next one offers less load precisely when the
//! system is slow, and reports a latency that never happened.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::profile::{ApiRoute, Method, Profile};
use crate::scrape::{Histogram, OrderedBound};
use crate::source::{self, LoadSource, Offered, Outcomes, Window};

/// The API driver as a [`LoadSource`].
pub struct ApiLoad {
    client: reqwest::Client,
    base_url: String,
    token: Option<String>,
    profile: Profile,
}

impl ApiLoad {
    pub fn new(
        client: reqwest::Client,
        base_url: impl Into<String>,
        token: Option<String>,
        profile: Profile,
    ) -> Self {
        Self {
            client,
            base_url: base_url.into(),
            token,
            profile,
        }
    }
}

#[async_trait]
impl LoadSource for ApiLoad {
    fn name(&self) -> &'static str {
        source::API
    }

    async fn offer(&self, window: Window, shutdown: CancellationToken) -> Result<Offered> {
        drive(
            self.client.clone(),
            &self.base_url,
            self.token.as_deref(),
            &self.profile,
            window,
            shutdown,
        )
        .await
    }
}

/// Shared counters the request tasks fold into. Requests are issued
/// concurrently (a schedule that waits for a response is not a schedule), so the
/// tallies are atomics rather than a returned value per task.
struct Tally {
    responded: AtomicU64,
    succeeded: AtomicU64,
    client_errors: AtomicU64,
    server_errors: AtomicU64,
    failed: AtomicU64,
    /// Every answered request, whatever its status — §19's aggregate API panel.
    all: LadderTally,
    /// Successful responses only, per route template: the population a
    /// per-route budget is judged over. A 429 or a fail-closed 502 answers in
    /// microseconds and is not a decision, so counting it would flatter exactly
    /// the route that is failing.
    routes: BTreeMap<String, LadderTally>,
}

/// One histogram under construction: a counter per bucket of the shared ladder,
/// plus a final overflow slot for samples above the top bound.
struct LadderTally {
    buckets: Vec<AtomicU64>,
    sum_micros: AtomicU64,
}

/// Drive `profile.api_qps` against `base_url` for warmup + duration.
///
/// A profile with `api_qps == 0` returns an *unrun* result (`scheduled == 0`),
/// which is what lets the gates tell "this run does not cover the API" from
/// "the API could not keep up" — two very different things to report.
async fn drive(
    client: reqwest::Client,
    base_url: &str,
    token: Option<&str>,
    profile: &Profile,
    window: Window,
    shutdown: CancellationToken,
) -> Result<Offered> {
    if profile.api_qps <= 0.0 || profile.api_routes.is_empty() {
        return Ok(Offered::none(source::API, "qps", profile.api_qps));
    }

    let ladder = telemetry::metrics::LATENCY_BUCKETS_SECONDS;
    let tally = Arc::new(Tally::new(ladder, &profile.api_routes));

    let mix = RouteMix::new(&profile.api_routes)
        .context("building the request mix from the profile's routes")?
        .with_address_pool(profile.address_pool);
    let total = (window.total().as_secs_f64() * profile.api_qps).round() as u64;
    let interval = Duration::from_secs_f64(1.0 / profile.api_qps);
    let start = Instant::now();

    let mut inflight = tokio::task::JoinSet::new();
    let mut scheduled = 0u64;
    // Measured, not assumed. The driver paces on the same absolute schedule the
    // block generator does, so it falls behind for the same reasons — and a
    // hard-coded zero here would be a fabricated measurement of precisely the
    // quantity this harness is most careful about (see `crate::chain`).
    let mut max_lateness = Duration::ZERO;

    for n in 0..total {
        let due_at = start + interval.mul_f64(n as f64);
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            () = tokio::time::sleep_until(due_at) => {}
        }
        scheduled += 1;
        max_lateness = max_lateness.max(due_at.elapsed());

        let call = mix.call_for(n);
        let url = format!("{}{}", base_url.trim_end_matches('/'), call.path);
        let mut request = match call.method {
            Method::Get => client.get(&url),
            Method::Post => match call.body {
                Some(body) => client.post(&url).json(&body),
                // An explicit empty body: `/screen` treats absent and empty
                // alike (the default policy), and sending no body at all is
                // what a caller with nothing to say actually sends.
                None => client.post(&url).body(""),
            },
        };
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let tally = Arc::clone(&tally);
        let template = call.template;
        inflight.spawn(async move {
            let sent = Instant::now();
            let outcome = request.send().await;
            let elapsed = sent.elapsed();
            match outcome {
                Ok(response) => {
                    tally.observe(&template, response.status().as_u16(), elapsed);
                }
                Err(err) => {
                    tally.failed.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(error = %err, "API request failed");
                }
            }
        });
    }

    // Wait for the tail: a request still in flight when the schedule ends is a
    // *slow* request, which is the one the p99 is about. Dropping the JoinSet
    // here would cancel exactly the samples that decide the verdict.
    while inflight.join_next().await.is_some() {}

    let elapsed = start.elapsed();
    Ok(tally.finish(scheduled, elapsed, max_lateness, ladder, profile.api_qps))
}

impl Tally {
    fn new(ladder: &[f64], routes: &[ApiRoute]) -> Self {
        Self {
            responded: AtomicU64::new(0),
            succeeded: AtomicU64::new(0),
            client_errors: AtomicU64::new(0),
            server_errors: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            all: LadderTally::new(ladder),
            routes: routes
                .iter()
                .map(|route| (route.path.clone(), LadderTally::new(ladder)))
                .collect(),
        }
    }

    /// Fold one answered request in: its status class, the aggregate
    /// histogram, and — on success — its route's own histogram.
    fn observe(&self, template: &str, status: u16, elapsed: Duration) {
        self.responded.fetch_add(1, Ordering::Relaxed);
        match status / 100 {
            2 => &self.succeeded,
            4 => &self.client_errors,
            _ => &self.server_errors,
        }
        .fetch_add(1, Ordering::Relaxed);
        self.all.record(elapsed);
        if status / 100 == 2 {
            if let Some(route) = self.routes.get(template) {
                route.record(elapsed);
            }
        }
    }

    fn finish(
        &self,
        scheduled: u64,
        elapsed: Duration,
        max_lateness: Duration,
        ladder: &[f64],
        target_qps: f64,
    ) -> Offered {
        Offered {
            source: source::API,
            unit: "qps",
            scheduled,
            delivered: self.responded.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            target_rate: target_qps,
            elapsed,
            max_lateness: Some(max_lateness),
            latency: Some(self.all.histogram(ladder)),
            route_latency: self
                .routes
                .iter()
                .map(|(route, tally)| (route.clone(), tally.histogram(ladder)))
                .collect(),
            outcomes: Some(Outcomes {
                succeeded: self.succeeded.load(Ordering::Relaxed),
                client_errors: self.client_errors.load(Ordering::Relaxed),
                server_errors: self.server_errors.load(Ordering::Relaxed),
            }),
        }
    }
}

impl LadderTally {
    fn new(ladder: &[f64]) -> Self {
        Self {
            buckets: (0..=ladder.len()).map(|_| AtomicU64::new(0)).collect(),
            sum_micros: AtomicU64::new(0),
        }
    }

    fn record(&self, elapsed: Duration) {
        let ladder = telemetry::metrics::LATENCY_BUCKETS_SECONDS;
        let seconds = elapsed.as_secs_f64();
        let slot = ladder
            .iter()
            .position(|bound| seconds <= *bound)
            .unwrap_or(ladder.len());
        self.buckets[slot].fetch_add(1, Ordering::Relaxed);
        self.sum_micros
            .fetch_add(elapsed.as_micros() as u64, Ordering::Relaxed);
    }

    /// Fold the per-slot counts into the cumulative form a Prometheus histogram
    /// has, so both sides of this test are read by the same code.
    fn histogram(&self, ladder: &[f64]) -> Histogram {
        let mut buckets = std::collections::BTreeMap::new();
        let mut cumulative = 0u64;
        for (index, bound) in ladder.iter().enumerate() {
            cumulative += self.buckets[index].load(Ordering::Relaxed);
            buckets.insert(OrderedBound(*bound), cumulative);
        }
        // Overflow slot: counted in `count` (as `+Inf` would be) but given no
        // finite bucket, so a quantile above the ladder reports as unbounded
        // rather than silently pinned to the top bound.
        let overflow = self.buckets[ladder.len()].load(Ordering::Relaxed);
        Histogram {
            buckets,
            count: cumulative + overflow,
            sum: self.sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0,
        }
    }
}

/// One resolved request: where to send it, how, and with what.
struct Call {
    path: String,
    /// The profile's path template this call was resolved from — the key its
    /// latency is filed under, since `path` carries a per-request address.
    template: String,
    method: Method,
    body: Option<serde_json::Value>,
}

/// The weighted route mix, flattened into a cycle.
///
/// Deterministic round-robin over the expanded weights rather than a random
/// draw: two runs of a profile must offer the same request sequence, or their
/// p99s are not comparable.
struct RouteMix {
    /// Expanded routes, one entry per unit of weight.
    slots: Vec<ApiRoute>,
    /// Distinct addresses to cycle through, if bounded (see
    /// [`Profile::address_pool`]).
    address_pool: Option<u64>,
}

impl RouteMix {
    fn new(routes: &[ApiRoute]) -> Result<Self> {
        let slots: Vec<ApiRoute> = routes
            .iter()
            .flat_map(|route| std::iter::repeat_n(route.clone(), route.weight as usize))
            .collect();
        anyhow::ensure!(
            !slots.is_empty(),
            "every route has weight 0 — the driver would request nothing"
        );
        Ok(Self {
            slots,
            address_pool: None,
        })
    }

    /// Cycle through `pool` addresses instead of one per request.
    fn with_address_pool(mut self, pool: Option<u64>) -> Self {
        self.address_pool = pool;
        self
    }

    /// The request for ordinal `n`, with `{address}` substituted for a spread
    /// of synthetic addresses.
    ///
    /// The spread matters: a single hot address would be answered from cache
    /// after the first request and measure the cache, not the API. A synthetic
    /// address also cannot collide with real customer data in a staging store.
    fn call_for(&self, n: u64) -> Call {
        let route = &self.slots[(n as usize) % self.slots.len()];
        let path = if route.path.contains("{address}") {
            route.path.replace(
                "{address}",
                &synthetic_address(self.address_pool.map_or(n, |pool| n % pool)),
            )
        } else {
            route.path.clone()
        };
        Call {
            path,
            template: route.path.clone(),
            method: route.method,
            body: route.body.clone(),
        }
    }
}

/// A deterministic, obviously-synthetic address: the request ordinal in the low
/// bytes, zero elsewhere.
fn synthetic_address(n: u64) -> String {
    let mut bytes = [0u8; 20];
    bytes[12..].copy_from_slice(&n.to_be_bytes());
    format!("0x{}", alloy_primitives::hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::SCREEN_ROUTE;

    fn routes() -> Vec<ApiRoute> {
        vec![
            ApiRoute {
                path: "/v1/address/{address}/screen".into(),
                weight: 3,
                method: Method::Post,
                body: None,
            },
            ApiRoute {
                path: "/v1/incidents".into(),
                weight: 1,
                method: Method::Get,
                body: None,
            },
        ]
    }

    #[test]
    fn the_mix_honours_the_weights_over_a_cycle() {
        let mix = RouteMix::new(&routes()).unwrap();
        let screens = (0..40)
            .filter(|n| mix.call_for(*n).path.contains("/screen"))
            .count();
        assert_eq!(screens, 30, "3:1 weighting");
    }

    #[test]
    fn each_request_gets_a_distinct_address_so_the_cache_is_not_the_subject() {
        let mix = RouteMix::new(&routes()).unwrap();
        let a = mix.call_for(0).path;
        let b = mix.call_for(4).path; // same slot in the cycle, different ordinal
        assert!(a.contains("/screen") && b.contains("/screen"));
        assert_ne!(a, b);
    }

    #[test]
    fn a_bounded_address_pool_repeats_counterparties() {
        // The mix cycles 4 slots (3 screen + 1 incidents) and the pool 3
        // addresses, so ordinals 0 and 12 land on the same slot AND the same
        // address; 0 and 4 share a slot but not an address.
        let mix = RouteMix::new(&routes()).unwrap().with_address_pool(Some(3));
        assert_eq!(
            mix.call_for(0).path,
            mix.call_for(12).path,
            "the address wraps"
        );
        assert_ne!(mix.call_for(0).path, mix.call_for(4).path);
    }

    #[test]
    fn a_zero_weight_mix_is_rejected_rather_than_silently_idle() {
        let none = vec![ApiRoute {
            path: "/v1/incidents".into(),
            weight: 0,
            method: Method::Get,
            body: None,
        }];
        assert!(RouteMix::new(&none).is_err());
    }

    /// The failure this guards: `/screen` is a POST (§11), and a GET-only
    /// driver gets a 405 in microseconds — a route that looks blazingly fast
    /// because it was never exercised, which is the worst thing a load test
    /// can report.
    #[test]
    fn the_method_travels_with_the_route() {
        let mix = RouteMix::new(&routes()).unwrap();
        assert_eq!(mix.call_for(0).method, Method::Post, "/screen is a POST");
        assert_eq!(
            mix.call_for(3).method,
            Method::Get,
            "/v1/incidents is a GET"
        );
    }

    /// Per-route latency is judged over successes alone, while the aggregate
    /// still sees every response.
    #[test]
    fn per_route_latency_counts_only_that_routes_successes() {
        let ladder = telemetry::metrics::LATENCY_BUCKETS_SECONDS;
        let tally = Tally::new(ladder, &routes());
        tally.observe(SCREEN_ROUTE, 200, Duration::from_millis(80));
        tally.observe(SCREEN_ROUTE, 429, Duration::from_micros(50));
        tally.observe(SCREEN_ROUTE, 502, Duration::from_micros(50));
        tally.observe("/v1/incidents", 200, Duration::from_millis(2));

        let load = tally.finish(4, Duration::from_secs(1), Duration::ZERO, ladder, 4.0);
        let screen = &load.route_latency[SCREEN_ROUTE];
        assert_eq!(
            screen.count, 1,
            "only the successful screening call is timed"
        );
        assert_eq!(screen.share_at_most(0.1), Some(1.0));
        assert_eq!(load.route_latency["/v1/incidents"].count, 1);
        assert_eq!(
            load.latency.expect("aggregate").count,
            4,
            "the aggregate panel still sees every response"
        );
    }

    #[test]
    fn client_latency_lands_in_the_same_ladder_the_server_uses() {
        let ladder = telemetry::metrics::LATENCY_BUCKETS_SECONDS;
        let tally = Tally::new(ladder, &routes());
        tally.observe(SCREEN_ROUTE, 200, Duration::from_millis(30)); // → the 0.05 bucket
        tally.observe(SCREEN_ROUTE, 200, Duration::from_millis(30));
        tally.observe(SCREEN_ROUTE, 200, Duration::from_secs(30)); // → over the top of the ladder

        let load = tally.finish(3, Duration::from_secs(1), Duration::ZERO, ladder, 3.0);
        let latency = load.latency.expect("the API measures its own latency");
        assert_eq!(latency.count, 3);
        assert_eq!(latency.share_at_most(0.05), Some(2.0 / 3.0));
        assert_eq!(
            latency.quantile_upper_bound(0.99),
            None,
            "a sample above the ladder must not be pinned to the top bound"
        );
    }

    #[test]
    fn a_driver_that_was_configured_away_reports_unrun_not_failed() {
        let unrun = Offered::none(source::API, "qps", 0.0);
        assert!(unrun.never_ran());
        assert_eq!(unrun.success_ratio(), None);
        assert_eq!(
            unrun.max_lateness, None,
            "a driver that never ran has no lateness — not a lateness of zero"
        );
    }

    #[test]
    fn a_synthetic_address_is_well_formed_and_unique_per_request() {
        assert_eq!(synthetic_address(1).len(), 42);
        assert_ne!(synthetic_address(1), synthetic_address(2));
    }
}
