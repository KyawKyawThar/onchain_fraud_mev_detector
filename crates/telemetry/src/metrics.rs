//! Prometheus metrics exporter (§19) — the metrics counterpart to
//! [`crate::init`].
//!
//! A service records measurements through the [`metrics`] facade at the call site
//! (e.g. the detection service's per-detector hit/latency, §19). Those macros are
//! a near-free no-op until *some* process installs a global recorder — that
//! install is this module's one job. [`init`] stands up the
//! [`metrics_exporter_prometheus`] recorder and serves the textual Prometheus
//! exposition over an HTTP listener, so a Prometheus server can scrape
//! `http://<addr>/metrics`.
//!
//! Like [`crate::init`], the service owns config resolution and passes the bind
//! address in explicitly, so this stays a thin, side-effecting wire-up with no
//! reach into ambient process state. Call it once at startup, **inside the Tokio
//! runtime** (the exporter spawns its listener + metric-upkeep tasks onto it).

use std::net::SocketAddr;

use anyhow::Context as _;
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};

/// Histogram buckets (seconds) for every latency metric — anything whose name
/// ends `_seconds` (e.g. detection's `detector_detect_duration_seconds`, §19).
///
/// Without explicit buckets the exporter renders a histogram as a Prometheus
/// *summary* (client-side quantiles), which can't be re-aggregated across
/// instances and isn't queryable with `histogram_quantile`. Declaring buckets
/// makes it a real histogram (`_bucket{le=…}`), so dashboards compute p50/p99 in
/// PromQL and the series sum cleanly across replicas.
///
/// The ladder spans ~10µs (a pure in-process detector on a header-only block) to
/// 10s (a slow detector over a full block), roughly 2–3 buckets per decade — fine
/// resolution where detector latencies actually sit without exploding cardinality.
const LATENCY_BUCKETS_SECONDS: &[f64] = &[
    0.00001, 0.000025, 0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05,
    0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Install the global Prometheus recorder and start the `/metrics` HTTP listener
/// on `addr`. Call once per process, from within the Tokio runtime.
///
/// After this returns, every [`metrics`] macro elsewhere in the process records
/// into the installed recorder, and a scrape of `http://{addr}/metrics` renders
/// the current series in Prometheus text format. `_seconds` metrics are exported
/// as bucketed histograms (see [`LATENCY_BUCKETS_SECONDS`]). Installing a second
/// recorder in the same process fails — there is only one global — so this is a
/// boot-time, fail-fast call, mirroring [`crate::init`].
pub fn init(addr: SocketAddr) -> anyhow::Result<()> {
    init_labeled(addr, &[])
}

/// [`init`] with process-wide labels stamped onto **every** series this
/// process exports — the §19 convention for per-chain service instances
/// (`("chain", chain.metrics_label())` on detection/predictive): one label at
/// the exporter beats threading a chain through every call site, and two
/// chains' instances then aggregate/filter cleanly in PromQL.
pub fn init_labeled(addr: SocketAddr, global_labels: &[(&str, String)]) -> anyhow::Result<()> {
    // Any `_seconds` metric is a latency histogram; bucket it (see above).
    let latency = Matcher::Suffix("_seconds".to_owned());
    let mut builder = PrometheusBuilder::new()
        .with_http_listener(addr)
        .set_buckets_for_metric(latency, LATENCY_BUCKETS_SECONDS)
        .context("configuring latency histogram buckets")?;
    for (key, value) in global_labels {
        builder = builder.add_global_label(*key, value.clone());
    }
    builder
        .install()
        .context("installing the Prometheus metrics exporter")?;
    tracing::info!(%addr, "metrics exporter listening on /metrics");
    Ok(())
}
