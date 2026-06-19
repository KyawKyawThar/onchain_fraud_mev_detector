//! Observability foundation (§19).
//!
//! Two responsibilities, and only these:
//!
//! 1. [`init`] — stand up `tracing` for a service: an `EnvFilter` (via
//!    `RUST_LOG`), a fmt layer (`pretty` or `json`, chosen by `LOG_FORMAT`), and
//!    an OpenTelemetry layer so spans carry real W3C trace ids. It also installs
//!    the global [W3C trace-context] propagator.
//! 2. [`propagation`] — inject the current trace context into outbound message
//!    headers and re-establish it on the consumer side, so a trace started in
//!    one service continues in the next. The carrier is a plain string map,
//!    which the Kafka producer/consumer (Sprint 1) adapts to record headers.
//!
//! [W3C trace-context]: https://www.w3.org/TR/trace-context/

use anyhow::Context as _;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::TracerProvider as SdkTracerProvider;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

pub mod propagation;

/// Held for the lifetime of `main`. On drop it flushes and shuts the tracer
/// provider down, so buffered spans aren't lost on exit. Dropping it early
/// tears tracing down — bind it to a `_guard` that lives as long as the
/// service.
#[must_use = "dropping the guard shuts tracing down; bind it for the lifetime of the service"]
pub struct TelemetryGuard {
    provider: SdkTracerProvider,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        // Best-effort flush; nothing actionable if shutdown fails on exit.
        let _ = self.provider.shutdown();
    }
}

/// How a service wants tracing configured. Passed explicitly to [`init`] so the
/// library never reaches into ambient process state itself — the service owns
/// config resolution and `init` stays pure and testable. Build one from the
/// environment with [`TelemetryConfig::from_env`].
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// Logical service name, attached to every span (e.g. `"ingestion"`).
    pub service_name: &'static str,
    /// Emit structured JSON logs (production) vs. human-readable `pretty` (dev).
    pub json: bool,
    /// `tracing` filter directive, in `RUST_LOG` syntax (e.g. `"info,sqlx=warn"`).
    pub filter: String,
}

impl TelemetryConfig {
    /// Sensible defaults for `service_name`: `pretty` logs at `info`.
    pub fn new(service_name: &'static str) -> Self {
        Self {
            service_name,
            json: false,
            filter: "info".to_owned(),
        }
    }

    /// Resolve config from the environment — the one place env is read.
    /// `LOG_FORMAT=json` selects JSON logs; `RUST_LOG` sets the filter (matching
    /// the `.env` knobs). Builders/tests can construct [`TelemetryConfig`]
    /// directly instead.
    pub fn from_env(service_name: &'static str) -> Self {
        let json = std::env::var("LOG_FORMAT")
            .map(|f| f.eq_ignore_ascii_case("json"))
            .unwrap_or(false);
        let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_owned());
        Self {
            service_name,
            json,
            filter,
        }
    }
}

/// Initialize tracing + W3C propagation for a service. Call once at startup and
/// keep the returned [`TelemetryGuard`] alive for the whole process.
pub fn init(config: TelemetryConfig) -> anyhow::Result<TelemetryGuard> {
    // Cross-service trace stitching: emit/parse the W3C `traceparent` header.
    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());

    // A tracer provider with the default sampler (AlwaysOn) so spans get valid
    // trace ids. No exporter is wired yet — spans stay in-process until an OTLP
    // exporter is added; propagation works regardless.
    let provider = SdkTracerProvider::builder().build();
    let tracer = provider.tracer(config.service_name);
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    let filter = EnvFilter::new(&config.filter);

    let fmt_layer = if config.json {
        tracing_subscriber::fmt::layer().json().boxed()
    } else {
        tracing_subscriber::fmt::layer().boxed()
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(otel_layer)
        .try_init()
        .context("failed to install tracing subscriber")?;

    Ok(TelemetryGuard { provider })
}
