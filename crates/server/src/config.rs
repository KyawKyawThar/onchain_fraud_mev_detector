//! Configuration, resolved once from the environment at startup — the single
//! place this service reads env (mirrors `event-store`/`intelligence`/
//! `simulation`). Everything downstream takes an explicit [`Config`] so the
//! rest of the service stays pure and testable.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{bail, Context, Result};
/// Re-exported: JWT verification is shared (`crates/auth`), so this service
/// configures it but does not define it.
pub use auth::JwtConfig;
use resilience::circuit::BreakerConfig;
use secrecy::SecretString;

/// Broadcast channel capacity for `WS /v1/stream` when `WS_ALERT_CHANNEL_CAPACITY`
/// is unset (§11).
const DEFAULT_ALERT_CHANNEL_CAPACITY: usize = 1024;

/// Usage-metering queue capacity when `USAGE_CHANNEL_CAPACITY` is unset (§13).
const DEFAULT_USAGE_CHANNEL_CAPACITY: usize = 1024;

/// Screening endpoint's dedicated rate-limit ceiling (§19) when
/// `SCREENING_RATE_LIMIT_PER_MINUTE` is unset — a conservative placeholder
/// (no production traffic to calibrate against yet, same posture
/// `deploy/prometheus-rules.yml`'s provisional SLO thresholds document).
const DEFAULT_SCREENING_RATE_LIMIT_PER_MINUTE: u32 = 120;

/// `/screen`'s fresh-answer budget when `SCREENING_FRESH_BUDGET_MS` is unset
/// (§11 graceful degradation, `src/degrade.rs`). Above the p50 < 100ms claim, so
/// a healthy-but-busy read is not flagged stale; and budget plus
/// [`crate::degrade::SNAPSHOT_READ_TIMEOUT`] (175ms) stays under
/// `crates/loadtest/slo.json`'s 250ms `screen_p99_seconds`, so a degraded answer
/// still lands inside the p99 budget.
const DEFAULT_SCREENING_FRESH_BUDGET_MS: u64 = 150;

/// The oldest snapshot allowed to decide a withdrawal when
/// `SCREENING_STALE_MAX_AGE_SECS` is unset. A conservative placeholder: the
/// value is a compliance decision (the window in which a new designation can be
/// missed), so a deployment should set it deliberately — every stale decision
/// discloses its age regardless.
const DEFAULT_SCREENING_STALE_MAX_AGE_SECS: u64 = 900;

/// Snapshot-writer queue capacity when `SCREENING_SNAPSHOT_CHANNEL_CAPACITY` is
/// unset.
const DEFAULT_SCREENING_SNAPSHOT_CHANNEL_CAPACITY: usize = 1024;

/// Floor of the adaptive fresh budget when `SCREENING_FRESH_BUDGET_FLOOR_MS` is
/// unset: below the p50 < 100ms claim with room for one Redis snapshot read, so
/// even a fast intelligence cannot tighten the budget into flagging ordinary
/// jitter as stale.
const DEFAULT_SCREENING_FRESH_BUDGET_FLOOR_MS: u64 = 60;
const DEFAULT_SCREENING_BREAKER_FAILURE_THRESHOLD: u32 = 5;
const DEFAULT_SCREENING_BREAKER_COOLDOWN_SECS: u64 = 10;
/// Per-pod ceiling on in-flight intelligence reads when
/// `SCREENING_MAX_IN_FLIGHT` is unset — far above healthy concurrency (a
/// 100 qps pod at a 20ms read holds ~2), so it only binds when intelligence is
/// already slow.
const DEFAULT_SCREENING_MAX_IN_FLIGHT: usize = 256;
const DEFAULT_SCREENING_HEDGE_RATIO: f64 = 0.05;
const DEFAULT_SCREENING_SNAPSHOT_L1_CAPACITY: usize = 50_000;

/// Sanctions-view refresh interval when `SCREENING_SANCTIONS_REFRESH_SECS` is
/// unset. A designation reaches every pod's view within about this long.
const DEFAULT_SCREENING_SANCTIONS_REFRESH_SECS: u64 = 60;

/// Screening access-audit queue capacity when `AUDIT_CHANNEL_CAPACITY` is
/// unset (§11, Sprint 14 t3).
const DEFAULT_AUDIT_CHANNEL_CAPACITY: usize = 1024;

/// All runtime configuration for the public §11 API service: where to bind,
/// where to reach the three internal services it fronts, and the JWT
/// verification settings that gate every `/v1` route.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address the public HTTP API binds to.
    pub http_addr: SocketAddr,
    /// Base URL of event-store's internal read API (`GET /v1/audit/incident/{id}`).
    pub event_store_url: String,
    /// Base URL of simulation-projection's internal read API (`GET /v1/incidents`).
    pub simulation_url: String,
    /// `http://host:port` of intelligence's `IntelligenceRead` gRPC server.
    pub intelligence_grpc_addr: String,
    /// Postgres — `POST /v1/rules` writes the customer's rule definitions
    /// through the rule-engine crate's `PgRuleStore` (§9/§14).
    pub database_url: SecretString,
    /// Redis, for the screening endpoint's dedicated rate limiter (§19,
    /// `src/rate_limit.rs`) — the same instance `intelligence`'s hot-path
    /// cache uses, a different key prefix (`screen_rl:`).
    pub redis_url: SecretString,
    pub jwt: JwtConfig,
    /// Kafka settings for the `/v1/stream` WebSocket's consumer (§11).
    pub kafka: KafkaConfig,
    /// Capacity of the broadcast channel `WS /v1/stream` fans alerts out
    /// through (§11) — how many alerts a slow client can fall behind by
    /// before it starts missing them (further sends surface as
    /// `RecvError::Lagged`, which `stream::stream_socket` handles by
    /// dropping the backlog, not the connection). Defaults to
    /// [`DEFAULT_ALERT_CHANNEL_CAPACITY`].
    pub alert_channel_capacity: usize,
    /// Capacity of the usage-metering queue between the request path and the
    /// `UsageRecorded` Kafka publisher (§13, see `src/usage.rs`) — how many
    /// events may await publish (e.g. during a broker outage) before further
    /// ones are dropped with a `warn` rather than stalling customer calls.
    /// Defaults to [`DEFAULT_USAGE_CHANNEL_CAPACITY`].
    pub usage_channel_capacity: usize,
    /// Capacity of the screening access-audit queue between the request path
    /// and the `ScreeningDecisionRecorded` Kafka publisher (§11, Sprint 14
    /// t3, see `src/audit.rs`) — the same non-blocking-request-path shape as
    /// `usage_channel_capacity`, for the same p50 < 100ms SLO reason.
    /// Defaults to [`DEFAULT_AUDIT_CHANNEL_CAPACITY`].
    pub audit_channel_capacity: usize,
    /// Client-side deadline on the screening gRPC read (§11), from
    /// `SCREENING_DEADLINE_MS` (default
    /// [`crate::intelligence_client::DEFAULT_SCREENING_DEADLINE`]). `/screen`
    /// carries its own p50 < 100ms SLO (§19), so a stalled intelligence node
    /// must fail fast to the endpoint's 502 rather than queue behind the
    /// router-wide 30s timeout.
    pub screening_deadline: Duration,
    /// The screening endpoint's own rate-limit ceiling (§19,
    /// `src/rate_limit.rs`) — kept separate from any future general `/v1`
    /// limit so this SLO-critical route can never be starved by traffic
    /// elsewhere. From `SCREENING_RATE_LIMIT_PER_MINUTE`, defaulting to
    /// [`DEFAULT_SCREENING_RATE_LIMIT_PER_MINUTE`].
    pub screening_rate_limit_per_minute: u32,
    /// `/screen`'s graceful degradation (§11, readiness Epic D,
    /// `src/degrade.rs`): the fresh-answer budget and the oldest snapshot that
    /// may answer past it. `None` when `SCREENING_STALE_MAX_AGE_SECS=0` disarms
    /// it — fresh or fail closed, as before.
    pub screening_degradation: Option<crate::degrade::Degradation>,
    /// Capacity of the queue between the request path and the snapshot writer
    /// — how many snapshots may await Redis before further ones are dropped
    /// (and counted) rather than slowing a screening call.
    pub screening_snapshot_channel_capacity: usize,
    /// How often the pod-local sanctions view (`src/sanctions_view.rs`) is
    /// refreshed from intelligence, from `SCREENING_SANCTIONS_REFRESH_SECS`.
    pub screening_sanctions_refresh: Duration,
    /// How the screening read reaches intelligence (`src/facts_source.rs`):
    /// breaker, bulkhead, hedging, adaptive budget, and the snapshot memory tier.
    pub screening_resilience: ScreeningResilience,
    /// Address the Prometheus `/metrics` endpoint binds to (§19). Exposes this
    /// service's counters — including `usage_events_recorded_total` /
    /// `usage_events_dropped_total` (§13, `src/usage.rs`) and the request
    /// p50/p99 panel (`src/metrics.rs`), which ops alerts on. Defaults to
    /// `0.0.0.0:9112` — each container sets its own explicitly (§20), but the
    /// default is picked distinct from `DETECTION_METRICS_ADDR`'s `9100` so
    /// both binaries can run on one host in local dev without colliding.
    pub metrics_addr: SocketAddr,
}

/// The screening read path's resilience settings, validated together because
/// they constrain one another (the budget floor sits under the degradation
/// budget; a hedge ratio is a share).
#[derive(Debug, Clone)]
pub struct ScreeningResilience {
    /// Lower bound of the adaptive fresh budget.
    pub fresh_budget_floor: Duration,
    /// Breaker over intelligence reads (slow answers count as failures).
    pub breaker: BreakerConfig,
    /// Most intelligence reads one pod holds open at once.
    pub max_in_flight: usize,
    /// Where hedged reads go; `None` is a second connection to the primary
    /// address.
    pub hedge_addr: Option<String>,
    /// Hedges as a share of requests; `0` disables hedging.
    pub hedge_ratio: f64,
    /// Addresses held in the per-pod snapshot tier; `0` disables it.
    pub snapshot_l1_capacity: usize,
}

/// How to reach Kafka: the `WS /v1/stream` consumer (§11) subscribes to the
/// three lifecycle topics, and the usage publisher (§13, `src/usage.rs`)
/// produces `UsageRecorded`. Both topics are provisioned by event-store's
/// `ensure_topics`, so this service never creates topology.
#[derive(Debug, Clone)]
pub struct KafkaConfig {
    /// Comma-separated bootstrap brokers (`localhost:9092`).
    pub brokers: String,
    /// Consumer-group id — restarts resume from committed offsets. Distinct
    /// from event-store's group so the two consumers advance independently.
    pub group_id: String,
}

impl Config {
    /// Resolve config from the process environment, erroring on anything missing
    /// or malformed (fail fast at boot rather than at first request).
    pub fn from_env() -> Result<Self> {
        let http_addr = format!("{}:{}", env("SERVER_HOST")?, env("SERVER_PORT")?)
            .parse()
            .context("SERVER_HOST:SERVER_PORT is not a valid socket address")?;
        // Read first: the degradation budget is validated against it.
        let screening_deadline = screening_deadline()?;

        Ok(Self {
            http_addr,
            event_store_url: env("EVENT_STORE_URL")?,
            simulation_url: env("SIMULATION_URL")?,
            intelligence_grpc_addr: env("INTELLIGENCE_GRPC_ADDR")?,
            database_url: SecretString::from(env("DATABASE_URL")?),
            redis_url: SecretString::from(env("REDIS_URL")?),
            jwt: JwtConfig {
                secret: SecretString::from(env("JWT_SECRET")?),
                issuer: env("JWT_ISSUER")?,
            },
            kafka: KafkaConfig {
                brokers: env("KAFKA_BROKERS")?,
                group_id: env("SERVER_KAFKA_GROUP")?,
            },
            alert_channel_capacity: channel_capacity(
                "WS_ALERT_CHANNEL_CAPACITY",
                DEFAULT_ALERT_CHANNEL_CAPACITY,
            )?,
            usage_channel_capacity: channel_capacity(
                "USAGE_CHANNEL_CAPACITY",
                DEFAULT_USAGE_CHANNEL_CAPACITY,
            )?,
            audit_channel_capacity: channel_capacity(
                "AUDIT_CHANNEL_CAPACITY",
                DEFAULT_AUDIT_CHANNEL_CAPACITY,
            )?,
            screening_deadline,
            screening_rate_limit_per_minute: screening_rate_limit_per_minute()?,
            screening_degradation: screening_degradation(
                env_parse(
                    "SCREENING_FRESH_BUDGET_MS",
                    DEFAULT_SCREENING_FRESH_BUDGET_MS,
                )?,
                env_parse(
                    "SCREENING_STALE_MAX_AGE_SECS",
                    DEFAULT_SCREENING_STALE_MAX_AGE_SECS,
                )?,
                screening_deadline,
            )?,
            screening_snapshot_channel_capacity: channel_capacity(
                "SCREENING_SNAPSHOT_CHANNEL_CAPACITY",
                DEFAULT_SCREENING_SNAPSHOT_CHANNEL_CAPACITY,
            )?,
            screening_resilience: screening_resilience(
                env_parse(
                    "SCREENING_FRESH_BUDGET_FLOOR_MS",
                    DEFAULT_SCREENING_FRESH_BUDGET_FLOOR_MS,
                )?,
                env_parse(
                    "SCREENING_BREAKER_FAILURE_THRESHOLD",
                    DEFAULT_SCREENING_BREAKER_FAILURE_THRESHOLD,
                )?,
                env_parse(
                    "SCREENING_BREAKER_COOLDOWN_SECS",
                    DEFAULT_SCREENING_BREAKER_COOLDOWN_SECS,
                )?,
                env_parse("SCREENING_MAX_IN_FLIGHT", DEFAULT_SCREENING_MAX_IN_FLIGHT)?,
                std::env::var("INTELLIGENCE_GRPC_HEDGE_ADDR").ok(),
                env_parse("SCREENING_HEDGE_RATIO", DEFAULT_SCREENING_HEDGE_RATIO)?,
                env_parse(
                    "SCREENING_SNAPSHOT_L1_CAPACITY",
                    DEFAULT_SCREENING_SNAPSHOT_L1_CAPACITY,
                )?,
                env_parse(
                    "SCREENING_FRESH_BUDGET_MS",
                    DEFAULT_SCREENING_FRESH_BUDGET_MS,
                )?,
            )?,
            screening_sanctions_refresh: positive_secs(
                "SCREENING_SANCTIONS_REFRESH_SECS",
                DEFAULT_SCREENING_SANCTIONS_REFRESH_SECS,
            )?,
            metrics_addr: env_parse(
                "SERVER_METRICS_ADDR",
                SocketAddr::from(([0, 0, 0, 0], 9112)),
            )?,
        })
    }
}

/// Resolve `SCREENING_DEADLINE_MS`. Zero would time every screening call out
/// before it started — caught here with the same fail-fast-at-boot contract
/// as [`channel_capacity`].
fn screening_deadline() -> Result<Duration> {
    let millis: u64 = env_parse(
        "SCREENING_DEADLINE_MS",
        crate::intelligence_client::DEFAULT_SCREENING_DEADLINE.as_millis() as u64,
    )?;
    if millis == 0 {
        bail!("SCREENING_DEADLINE_MS must be >= 1, got 0");
    }
    Ok(Duration::from_millis(millis))
}

/// Validate `/screen`'s degradation settings (pure, so the rules are tested
/// without touching the process environment).
///
/// A max age of zero disarms degradation — the one explicit off switch. A fresh
/// budget at or past the hard deadline is rejected rather than accepted as
/// inert: the read would always fail before a snapshot could answer a slow one,
/// so the fallback would silently react only to outright faults.
fn screening_degradation(
    fresh_budget_ms: u64,
    stale_max_age_secs: u64,
    deadline: Duration,
) -> Result<Option<crate::degrade::Degradation>> {
    if stale_max_age_secs == 0 {
        return Ok(None);
    }
    let fresh_budget = Duration::from_millis(fresh_budget_ms);
    if fresh_budget.is_zero() {
        bail!("SCREENING_FRESH_BUDGET_MS must be >= 1, got 0 (set SCREENING_STALE_MAX_AGE_SECS=0 to disarm degradation)");
    }
    if fresh_budget >= deadline {
        bail!(
            "SCREENING_FRESH_BUDGET_MS ({fresh_budget_ms}) must be below SCREENING_DEADLINE_MS ({}) — \
             otherwise a slow intelligence read fails before a snapshot can ever answer it",
            deadline.as_millis()
        );
    }
    Ok(Some(crate::degrade::Degradation {
        fresh_budget,
        max_stale_age: Duration::from_secs(stale_max_age_secs),
    }))
}

/// Resolve `SCREENING_RATE_LIMIT_PER_MINUTE`. Zero would reject every
/// screening call unconditionally — caught here with the same
/// fail-fast-at-boot contract as [`screening_deadline`].
fn screening_rate_limit_per_minute() -> Result<u32> {
    let limit: u32 = env_parse(
        "SCREENING_RATE_LIMIT_PER_MINUTE",
        DEFAULT_SCREENING_RATE_LIMIT_PER_MINUTE,
    )?;
    if limit == 0 {
        bail!("SCREENING_RATE_LIMIT_PER_MINUTE must be >= 1, got 0");
    }
    Ok(limit)
}

/// Validate the screening read path's resilience settings (pure; tested
/// without the process environment).
#[allow(clippy::too_many_arguments)]
fn screening_resilience(
    fresh_budget_floor_ms: u64,
    breaker_failure_threshold: u32,
    breaker_cooldown_secs: u64,
    max_in_flight: usize,
    hedge_addr: Option<String>,
    hedge_ratio: f64,
    snapshot_l1_capacity: usize,
    fresh_budget_ceiling_ms: u64,
) -> Result<ScreeningResilience> {
    if fresh_budget_floor_ms == 0 || fresh_budget_floor_ms > fresh_budget_ceiling_ms {
        bail!(
            "SCREENING_FRESH_BUDGET_FLOOR_MS ({fresh_budget_floor_ms}) must be in \
             1..=SCREENING_FRESH_BUDGET_MS ({fresh_budget_ceiling_ms})"
        );
    }
    if breaker_failure_threshold == 0 {
        bail!("SCREENING_BREAKER_FAILURE_THRESHOLD must be >= 1, got 0");
    }
    if breaker_cooldown_secs == 0 {
        bail!("SCREENING_BREAKER_COOLDOWN_SECS must be >= 1, got 0");
    }
    if max_in_flight == 0 {
        bail!(
            "SCREENING_MAX_IN_FLIGHT must be >= 1, got 0 — every screening read would be refused"
        );
    }
    if !(0.0..=1.0).contains(&hedge_ratio) {
        bail!("SCREENING_HEDGE_RATIO is a share of requests in 0..=1, got {hedge_ratio}");
    }
    Ok(ScreeningResilience {
        fresh_budget_floor: Duration::from_millis(fresh_budget_floor_ms),
        breaker: BreakerConfig {
            failure_threshold: breaker_failure_threshold,
            open_cooldown: Duration::from_secs(breaker_cooldown_secs),
            success_threshold: 1,
        },
        max_in_flight,
        hedge_addr: hedge_addr.filter(|addr| !addr.trim().is_empty()),
        hedge_ratio,
        snapshot_l1_capacity,
    })
}

/// Resolve a whole-seconds duration that must be at least one second — zero
/// would be a busy loop or a view that can never be current.
fn positive_secs(key: &str, default: u64) -> Result<Duration> {
    let secs: u64 = env_parse(key, default)?;
    if secs == 0 {
        bail!("{key} must be >= 1, got 0");
    }
    Ok(Duration::from_secs(secs))
}

/// Resolve and validate a channel-capacity env var. A non-positive value
/// would panic inside `tokio::sync::broadcast::channel`/`mpsc::channel`;
/// catching it here keeps the "fail fast with a clear message at boot"
/// contract the rest of this module holds, same as event-store's Kafka
/// topology validation.
fn channel_capacity(key: &str, default: usize) -> Result<usize> {
    let capacity = env_parse(key, default)?;
    if capacity < 1 {
        bail!("{key} must be >= 1, got {capacity}");
    }
    Ok(capacity)
}

/// Read a required env var, with the variable name in the error so a missing
/// value is self-explanatory in the boot log.
fn env(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("missing required env var {key}"))
}

/// Read an *optional* env var parsed into `T`, falling back to `default` when
/// unset. Unlike [`env`], a missing value is fine (these have safe defaults);
/// only a present-but-unparseable value is an error — caught at boot, not at
/// first use.
fn env_parse<T>(key: &str, default: T) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match std::env::var(key) {
        Ok(raw) => raw.parse().map_err(|err| {
            anyhow::anyhow!(
                "env var {key} is not a valid {}: {err}",
                std::any::type_name::<T>()
            )
        }),
        Err(_) => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEADLINE: Duration = Duration::from_millis(500);

    #[test]
    fn the_defaults_arm_degradation_inside_the_deadline() {
        let degradation = screening_degradation(
            DEFAULT_SCREENING_FRESH_BUDGET_MS,
            DEFAULT_SCREENING_STALE_MAX_AGE_SECS,
            crate::intelligence_client::DEFAULT_SCREENING_DEADLINE,
        )
        .unwrap()
        .expect("armed by default");
        assert!(degradation.fresh_budget < crate::intelligence_client::DEFAULT_SCREENING_DEADLINE);
    }

    /// The default budget's documented contract: a degraded answer lands inside
    /// the p99 budget the load test and `ScreeningLatencyP99High` share.
    #[test]
    fn a_degraded_answer_fits_the_screening_p99_budget() {
        let worst_degraded = Duration::from_millis(DEFAULT_SCREENING_FRESH_BUDGET_MS)
            + crate::degrade::SNAPSHOT_READ_TIMEOUT;
        assert!(worst_degraded < Duration::from_millis(250));
    }

    #[test]
    fn a_zero_max_age_is_the_off_switch() {
        assert_eq!(screening_degradation(150, 0, DEADLINE).unwrap(), None);
    }

    #[test]
    fn a_budget_at_or_past_the_deadline_is_rejected_not_inert() {
        assert!(screening_degradation(500, 900, DEADLINE).is_err());
        assert!(screening_degradation(900, 900, DEADLINE).is_err());
        assert!(screening_degradation(499, 900, DEADLINE).unwrap().is_some());
    }

    fn resilience(floor: u64, ratio: f64, in_flight: usize) -> Result<ScreeningResilience> {
        screening_resilience(floor, 5, 10, in_flight, Some(" ".into()), ratio, 1000, 150)
    }

    #[test]
    fn the_resilience_defaults_are_valid() {
        let r = screening_resilience(
            DEFAULT_SCREENING_FRESH_BUDGET_FLOOR_MS,
            DEFAULT_SCREENING_BREAKER_FAILURE_THRESHOLD,
            DEFAULT_SCREENING_BREAKER_COOLDOWN_SECS,
            DEFAULT_SCREENING_MAX_IN_FLIGHT,
            None,
            DEFAULT_SCREENING_HEDGE_RATIO,
            DEFAULT_SCREENING_SNAPSHOT_L1_CAPACITY,
            DEFAULT_SCREENING_FRESH_BUDGET_MS,
        )
        .unwrap();
        assert!(
            r.fresh_budget_floor < Duration::from_millis(100),
            "the floor sits under the p50 claim"
        );
    }

    #[test]
    fn resilience_settings_that_would_disable_the_path_are_rejected() {
        assert!(resilience(0, 0.05, 10).is_err(), "zero floor");
        assert!(
            resilience(151, 0.05, 10).is_err(),
            "floor above the ceiling"
        );
        assert!(resilience(60, 1.5, 10).is_err(), "a ratio is a share");
        assert!(
            resilience(60, 0.05, 0).is_err(),
            "a zero bulkhead refuses everything"
        );
        let ok = resilience(60, 0.0, 10).unwrap();
        assert_eq!(
            ok.hedge_addr, None,
            "a blank hedge address means the primary"
        );
    }

    #[test]
    fn a_zero_budget_is_rejected() {
        assert!(screening_degradation(0, 900, DEADLINE).is_err());
    }
}
