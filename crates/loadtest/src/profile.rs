//! What "target throughput" means, as a value.
//!
//! Nothing in the source doc states a number: it names the three dimensions
//! (chain tps, peak alert volume, API qps) and the budget the fast path must
//! hold across them. So the numbers live here, as committed profiles with their
//! derivation written down, and they are *assumptions of this harness* rather
//! than facts the platform holds elsewhere. A profile that cannot say where its
//! numbers came from cannot be argued with, and an unarguable load target is
//! how a test ends up measuring whatever the machine happened to manage.
//!
//! The readiness exit gate asks for **1.5× projected peak**, so headroom is a
//! multiplier applied at run time rather than a second set of baked-in numbers:
//! the peak and the margin above it are different claims and should not be
//! editable as one.

use std::time::Duration;

use anyhow::{ensure, Context, Result};
use events::primitives::Chain;
use serde::{Deserialize, Serialize};

/// A committed load profile: the offered load, in the terms Epic D names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    /// Human name, echoed into the report so a result is attributable to the
    /// load that produced it.
    pub name: String,
    /// Prose recording where these numbers came from. Serialized, not a comment,
    /// because the report prints it: a p99 is only meaningful next to the load
    /// it was measured under.
    pub rationale: String,
    /// Chain id the synthetic blocks are stamped with. Must match the detection
    /// instance under test — one instance per chain (§20), and blocks for
    /// another chain are commit-only passes that never reach a detector.
    pub chain: u64,
    /// Blocks per second offered. The chain's block rate, not a queue depth.
    pub blocks_per_second: f64,
    /// Transactions declared per block. `BlockAssembled` carries `tx_count`, so
    /// this sets the reported chain tps; it does **not** make the header-only
    /// bundle heavier (see the module docs on `crate::chain`).
    pub txs_per_block: u32,
    /// What share of generated blocks should trigger an alert, driving the
    /// "peak alert volume" dimension. See [`crate::chain`] for how a fraction
    /// becomes a block-number pattern.
    pub alerting_block_fraction: f64,
    /// API requests per second offered across [`Self::api_routes`].
    pub api_qps: f64,
    /// Route templates to drive, with relative weights. Paths may contain
    /// `{address}`, substituted per request so caches and rate limits see the
    /// spread of keys a real workload has.
    pub api_routes: Vec<ApiRoute>,
    /// Load offered before measurement starts. JIT, connection pools, Kafka
    /// partition leaders and page cache all settle here; samples from this
    /// window are excluded by the baseline scrape, not merely ignored.
    #[serde(with = "secs")]
    pub warmup: Duration,
    /// The measurement window.
    #[serde(with = "secs")]
    pub duration: Duration,
    /// How long to wait after the generator stops for the pipeline to catch up
    /// before measuring. See [`crate::run`] — measuring at the instant the load
    /// stops silently discards every block still queued, which under saturation
    /// is exactly the set with the worst latency.
    #[serde(with = "secs")]
    pub drain_timeout: Duration,
}

/// One API route to drive, and how often relative to the others.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiRoute {
    /// Path template, e.g. `/v1/address/{address}/screen`.
    pub path: String,
    /// Relative weight within the request mix.
    pub weight: u32,
    /// HTTP method. Defaults to `GET`, which most read routes are.
    ///
    /// The method is part of the route, not an implementation detail of the
    /// driver: `/v1/address/{address}/screen` is deliberately a **POST**
    /// (§11 — a screening decision is a billable, audited event, not a
    /// cacheable read), and a GET-only driver answers 405 in microseconds.
    /// That is the worst possible failure for a load test — a route that
    /// looks blazingly fast because it was never actually exercised — and it
    /// is only caught by the success-ratio gate, one step removed from the
    /// cause. Naming the method here makes it a property of the committed
    /// profile that a reviewer can check.
    #[serde(default)]
    pub method: Method,
    /// Optional JSON body for a `POST`. Ignored for a `GET`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
}

/// The HTTP methods the driver issues. A closed set, not a free string: a
/// profile naming a method the driver cannot send should fail to parse, not at
/// the first request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Method {
    #[default]
    #[serde(rename = "GET")]
    Get,
    #[serde(rename = "POST")]
    Post,
}

impl Profile {
    /// Read a committed profile.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading the load profile at {}", path.display()))?;
        let profile: Self = serde_json::from_str(&raw)
            .with_context(|| format!("parsing the load profile at {}", path.display()))?;
        profile.validate()?;
        Ok(profile)
    }

    /// Scale the offered load by `headroom` (the exit gate's 1.5×).
    ///
    /// Rates scale; the *shape* of the load — which routes, what fraction
    /// alerts, how many txs a block declares — does not. Scaling those too
    /// would make "1.5× peak" a different workload rather than more of the
    /// same one, and a p99 measured under it would not compare.
    #[must_use]
    pub fn with_headroom(mut self, headroom: f64) -> Self {
        self.blocks_per_second *= headroom;
        self.api_qps *= headroom;
        self
    }

    /// Chain transactions per second — the Epic D dimension, derived rather
    /// than configured so it cannot disagree with the block rate that produces
    /// it.
    pub fn chain_tps(&self) -> f64 {
        self.blocks_per_second * f64::from(self.txs_per_block)
    }

    /// Alerts per second the generated stream should provoke.
    pub fn alerts_per_second(&self) -> f64 {
        self.blocks_per_second * self.alerting_block_fraction
    }

    /// This profile's clock, as the orchestrator will hand it to every source.
    pub fn window(&self) -> crate::source::Window {
        crate::source::Window {
            warmup: self.warmup,
            duration: self.duration,
        }
    }

    /// Blocks the generator will schedule over warmup + measurement.
    pub fn scheduled_blocks(&self) -> u64 {
        ((self.warmup + self.duration).as_secs_f64() * self.blocks_per_second).round() as u64
    }

    /// Alerting fast-path samples this profile can produce **in the measurement
    /// window** — warmup excluded, because those samples are subtracted away by
    /// the baseline scrape.
    ///
    /// The number the SLO's `min_alert_samples` is checked against before a run
    /// is ever started. A profile that cannot reach it is guaranteed to report
    /// inconclusive however healthy the platform is, and would look for all the
    /// world like a flaky test.
    pub fn expected_alerting_samples(&self) -> u64 {
        (self.duration.as_secs_f64() * self.alerts_per_second()).floor() as u64
    }

    pub fn chain(&self) -> Chain {
        Chain(self.chain)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.blocks_per_second > 0.0,
            "blocks_per_second must be positive — a load test that offers no load \
             measures nothing and would pass"
        );
        ensure!(
            (0.0..=1.0).contains(&self.alerting_block_fraction),
            "alerting_block_fraction is a fraction of blocks, not a count"
        );
        ensure!(
            self.api_qps >= 0.0,
            "api_qps must not be negative (0 disables the API driver)"
        );
        ensure!(self.duration > Duration::ZERO, "duration must be positive");
        ensure!(
            self.api_qps == 0.0 || !self.api_routes.is_empty(),
            "api_qps is set but no routes were given — the driver would offer \
             nothing and the API dimension would silently go unmeasured"
        );
        ensure!(
            self.api_routes.iter().any(|r| r.weight > 0) || self.api_routes.is_empty(),
            "every API route has weight 0 — nothing would be requested"
        );
        Ok(())
    }
}

/// Durations are seconds in the committed JSON: a profile is edited by hand and
/// argued about in review, and `"warmup": 30` reads better than a serialized
/// `Duration`'s struct form.
mod secs {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        Ok(Duration::from_secs(u64::deserialize(d)?))
    }
}

/// Measured durations, unlike configured ones, are fractional — a generator's
/// elapsed time and its worst lateness are both sub-second quantities whose
/// whole-second truncation would report `0`.
pub(crate) mod secs_f64 {
    use std::time::Duration;

    use serde::Serializer;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_f64(d.as_secs_f64())
    }
}

/// A measured duration a source may not have. `null`, not `0` — the whole point
/// of the `Option` is that an unmeasured quantity must not render as a measured
/// zero.
pub(crate) mod opt_secs_f64 {
    use std::time::Duration;

    use serde::Serializer;

    pub fn serialize<S: Serializer>(d: &Option<Duration>, s: S) -> Result<S::Ok, S::Error> {
        match d {
            Some(d) => s.serialize_some(&d.as_secs_f64()),
            None => s.serialize_none(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_profile() -> Profile {
        Profile {
            name: "test".into(),
            rationale: "unit test".into(),
            chain: 1,
            blocks_per_second: 2.0,
            txs_per_block: 200,
            alerting_block_fraction: 0.5,
            api_qps: 50.0,
            api_routes: vec![ApiRoute {
                path: "/v1/address/{address}/screen".into(),
                weight: 1,
                method: Method::Post,
                body: None,
            }],
            warmup: Duration::from_secs(10),
            duration: Duration::from_secs(60),
            drain_timeout: Duration::from_secs(30),
        }
    }

    #[test]
    fn chain_tps_is_derived_from_the_block_rate() {
        assert_eq!(a_profile().chain_tps(), 400.0);
    }

    #[test]
    fn headroom_scales_the_rates_and_leaves_the_workload_shape_alone() {
        let scaled = a_profile().with_headroom(1.5);
        assert_eq!(scaled.blocks_per_second, 3.0);
        assert_eq!(scaled.api_qps, 75.0);
        assert_eq!(
            scaled.txs_per_block,
            a_profile().txs_per_block,
            "1.5x peak must be more of the same load, not a different one"
        );
        assert_eq!(scaled.alerting_block_fraction, 0.5);
        // …and the derived tps follows the block rate.
        assert_eq!(scaled.chain_tps(), 600.0);
    }

    #[test]
    fn scheduled_blocks_covers_warmup_and_measurement() {
        assert_eq!(a_profile().scheduled_blocks(), 140);
    }

    #[test]
    fn a_profile_offering_no_blocks_is_rejected() {
        let mut p = a_profile();
        p.blocks_per_second = 0.0;
        let err = p.validate().unwrap_err().to_string();
        assert!(err.contains("measures nothing"), "got: {err}");
    }

    #[test]
    fn api_load_with_no_routes_is_rejected() {
        let mut p = a_profile();
        p.api_routes.clear();
        assert!(p.validate().is_err());
    }

    fn committed_profiles() -> Vec<Profile> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("profiles");
        let mut profiles: Vec<Profile> = std::fs::read_dir(&dir)
            .expect("profiles/ must exist")
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .map(|p| Profile::load(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display())))
            .collect();
        assert!(
            !profiles.is_empty(),
            "no committed profiles in {}",
            dir.display()
        );
        profiles.sort_by(|a, b| a.name.cmp(&b.name));
        profiles
    }

    #[test]
    fn the_committed_profiles_parse_and_validate() {
        assert!(committed_profiles().len() >= 2);
    }

    /// The trap this test exists for: a profile whose rate and duration cannot
    /// produce `min_alert_samples` reports INCONCLUSIVE on a perfectly healthy
    /// platform, forever, and reads as a flaky nightly job rather than as a
    /// mis-specified profile. Caught here, in milliseconds, instead of after a
    /// six-minute run.
    #[test]
    fn every_peak_profile_can_collect_the_samples_its_verdict_requires() {
        let slo = crate::slo::Slo::load(&crate::slo::Slo::committed_path()).unwrap();
        for profile in committed_profiles() {
            if profile.name == "smoke" {
                continue; // pinned below — deliberately cannot conclude
            }
            assert!(
                profile.expected_alerting_samples() >= slo.min_alert_samples,
                "profile `{}` offers {} alerting samples over its {}s window but the \
                 SLO requires {} — it could never return anything but inconclusive",
                profile.name,
                profile.expected_alerting_samples(),
                profile.duration.as_secs(),
                slo.min_alert_samples,
            );
        }
    }

    /// …and the smoke profile's inability to conclude is intentional, so it is
    /// pinned in the other direction. If someone "fixes" it by lengthening the
    /// run, a wiring check has quietly become a load test that people trust.
    #[test]
    fn the_smoke_profile_deliberately_cannot_conclude() {
        let slo = crate::slo::Slo::load(&crate::slo::Slo::committed_path()).unwrap();
        let smoke = committed_profiles()
            .into_iter()
            .find(|p| p.name == "smoke")
            .expect("a smoke profile must exist");
        assert!(
            smoke.expected_alerting_samples() < slo.min_alert_samples,
            "the smoke profile is a wiring check; if it can satisfy the SLO it will be \
             read as a passing load test"
        );
    }
}
