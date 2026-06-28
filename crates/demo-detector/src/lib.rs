//! `demo-v0.1` — a synthetic detector for exercising the pipeline, **not** a real
//! MEV heuristic (§19, dev/test only).
//!
//! The live ingestion source is header-only today: `BlockAssembled` carries no
//! transactions, so the real detectors (`sandwich`, `arb`) correctly find nothing
//! and the per-detector **hit rate / findings** metrics stay at zero. That makes
//! it hard to see those metrics — and the `DetectorTriggered` /
//! `PreliminaryAlertCreated` emit path — actually light up on a dashboard.
//!
//! This detector closes that gap for demos: it ignores transaction content and
//! fires a single synthetic finding on a **deterministic schedule** — every
//! even-numbered block — so over a stream of blocks its hit rate settles around
//! 50% (a flat 100% would look like a stuck metric, and 50% proves the
//! `hits / runs` ratio is real). It is linked only behind the detection crate's
//! `demo` Cargo feature and must never ship in a real build.
//!
//! It is attribution-blind like any detector (it names no actor) and `Scope::Block`
//! (a pure function of the block ref), so it runs on the parallel fan-out with the
//! rest of the roster.

use detector_api::{DetectionCtx, DetectorId, DetectorPlugin, Evidence, ModelKind, Scope, SemVer};
use events::primitives::{AlertKind, Confidence};

/// Confidence stamped on the synthetic finding — a fixed, obviously-test value.
const DEMO_CONFIDENCE: f64 = 0.42;

/// The `demo-v0.1` detector. Stateless; construct with [`plugin`].
#[derive(Debug, Clone, Default)]
pub struct DemoDetector;

impl DemoDetector {
    /// This detector's stable id.
    pub const ID: DetectorId = DetectorId::new("demo");
    /// This build's version: `0.1.0`.
    pub const VERSION: SemVer = SemVer::new(0, 1, 0);
}

/// Construct the detector, ready to register
/// (`b.register_if(flags.is_enabled(DemoDetector::ID), demo_detector::plugin())`).
pub fn plugin() -> DemoDetector {
    DemoDetector
}

impl DetectorPlugin for DemoDetector {
    fn id(&self) -> DetectorId {
        Self::ID
    }

    fn version(&self) -> SemVer {
        Self::VERSION
    }

    fn kind(&self) -> ModelKind {
        ModelKind::Rule
    }

    fn scope(&self) -> Scope {
        Scope::Block
    }

    fn detect(&self, ctx: &DetectionCtx) -> Vec<Evidence> {
        let block = ctx.block();
        // Deterministic synthetic signal: fire on even blocks only, so the
        // hit-rate metric (`hits / runs`) lands near 0.5 over a stream rather than
        // a flat 1.0. Odd blocks are a "run" with no finding (a miss).
        if !block.number.is_multiple_of(2) {
            return Vec::new();
        }

        // Use the block hash as the (synthetic) implicated tx so the evidence is
        // well-formed; there's no enrichment for it, so the alert carries no
        // addresses — fine for a demo.
        let detail = serde_json::json!({
            "synthetic": true,
            "note": "demo detector — not a real finding",
            "block_number": block.number,
        });
        vec![Evidence::new(
            AlertKind::Arbitrage,
            vec![block.hash],
            Confidence::new(DEMO_CONFIDENCE),
        )
        .with_detail(detail)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use detector_api::{BlockBundle, DetectionCtx};
    use events::primitives::{BlockRef, Chain};

    use alloy_primitives::B256;

    fn ctx(number: u64) -> DetectionCtx {
        DetectionCtx::new(BlockBundle::new(
            Chain::ETHEREUM,
            BlockRef::new(number, B256::repeat_byte(number as u8)),
            vec![],
        ))
    }

    #[test]
    fn fires_one_synthetic_finding_on_an_even_block() {
        let found = plugin().detect(&ctx(2));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, AlertKind::Arbitrage);
        assert_eq!(found[0].confidence, Confidence::new(DEMO_CONFIDENCE));
        assert_eq!(found[0].txs, vec![B256::repeat_byte(2)]);
    }

    #[test]
    fn finds_nothing_on_an_odd_block() {
        assert!(plugin().detect(&ctx(3)).is_empty());
    }

    #[test]
    fn fires_regardless_of_transaction_content() {
        // The whole point: header-only block (no txs) still yields a finding.
        let found = plugin().detect(&ctx(100));
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn exposes_its_identity_through_the_plugin_seam() {
        let detector = plugin();
        let plug: &dyn DetectorPlugin = &detector;
        assert_eq!(plug.id(), DemoDetector::ID);
        assert_eq!(plug.version(), DemoDetector::VERSION);
        assert_eq!(plug.scope(), Scope::Block);
    }
}
