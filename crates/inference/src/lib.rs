//! The model-serving seam (§20.2, Sprint 18 t3) — how a trained model reaches
//! the fast path without dragging a runtime into everything that touches it.
//!
//! [`InferenceEngine`] is to model serving what `EventSink` is to publishing:
//! an object-safe trait with one production implementation ([`onnx::OrtEngine`],
//! behind the `onnx` feature) and one in-memory double
//! ([`test_util::StubEngine`]). A detector holds `Arc<dyn InferenceEngine>`,
//! resolved once at boot, and never learns what is behind it — so the logic
//! that *consumes* scores (thresholds, evidence, top contributing features) is
//! unit-testable with no ONNX Runtime, no artifact file, and no native library
//! anywhere near the test binary.
//!
//! ```
//! use inference::{InferenceEngine, Score};
//! use inference::test_util::{block_descriptor, StubEngine};
//! # use detector_api::test_util::CtxBuilder;
//!
//! // What a detector's tests hold in place of a model.
//! let engine = StubEngine::constant(block_descriptor("anomaly-gbdt"), Score::new(0.9)?);
//!
//! let ctx = CtxBuilder::new().build();
//! let score = engine.infer(&ml_features::extract_block(&ctx))?;
//! assert_eq!(score.get(), 0.9);
//! # Ok::<_, Box<dyn std::error::Error>>(())
//! ```
//!
//! # Weights are config (§20.2)
//!
//! A model artifact is hashed at load ([`ArtifactDigest`]) and travels inside a
//! [`ModelDescriptor`] together with the feature contract it was trained
//! against. The descriptor's [`content_hash`](ModelDescriptor::content_hash) is
//! what the composing service folds into the model registry's `config_hash`
//! (`detection::model::ConfigHash::with_model_artifact`), so a retrain — or a
//! feature-schema change — is a new `(id, version, config_hash)` triple, and:
//!
//! - historical evidence stays attributable to the exact weights that produced
//!   it, the same guarantee a threshold change already has;
//! - rollback is the registry's existing `deprecated_at` mechanism, not a
//!   bespoke "which .onnx was live in March?" investigation;
//! - a weight swap cannot ride into production unnoticed — pin
//!   [`OrtConfig::expected_artifact`](onnx::OrtConfig::expected_artifact) and a
//!   changed file is a refused boot.
//!
//! There is deliberately **no hot-swap path** (§20.5): a retrained model is a
//! new registry version that walks the same Shadow → backtest → Live gate as
//! any detector change.
//!
//! # Serving/training skew is checked, not assumed (§20.5)
//!
//! Every `FeatureVector` stamps the `feature_version` it was extracted under,
//! and a model declares the version it was *trained* under. Building a
//! [`ModelDescriptor`] resolves that version through `ml-features`'s registry
//! — a build that can no longer extract it refuses to serve the model at boot
//! (link-or-fail) — and [`ModelDescriptor::accepts`] rejects a mismatched
//! vector at inference. Running a model one feature version behind the current
//! extractor is *not* an error: `ml-features` keeps shipped versions linkable
//! forever precisely so serving doesn't have to move in lockstep with
//! extraction.
//!
//! # Observability is a decorator, not a call-site habit
//!
//! [`ObservedEngine`] wraps *any* engine and records latency, throughput,
//! failures-by-reason and the served score distribution through
//! [`crate::metrics`] — conventions §14's "thin observed outer", expressed as a
//! decorator over the seam so no backend and no call path can ship unmeasured.
//! Wrap once at boot: `Arc::new(ObservedEngine::new(OrtEngine::load(cfg)?))`.
//! The score histogram is also the cheapest §20.5 drift signal available, and
//! t5's per-feature population-stability statistics build on it rather than
//! replacing it.
//!
//! # Explainability lives above the seam, not inside it
//!
//! §20.2 requires an anomaly finding's evidence to carry "the top contributing
//! features". [`Score`] deliberately does not carry them, and no
//! `infer_with_attribution` is planned: contributions are computed *above* the
//! seam from `ml_features::FeatureVector::pairs()` against the same
//! distribution statistics the drift monitor keeps (§20.5). That keeps the
//! seam backend-agnostic — a model format with no attribution output is still
//! explainable — and stops two subsystems from owning overlapping answers to
//! "why did this fire?".
//!
//! # Blindness holds on the serving side too (§6)
//!
//! The seam scores a `FeatureVector`, never a `DetectionCtx`. An engine
//! physically cannot see addresses, hashes, or labels, so the
//! attribution-blindness `ml-features` establishes at extraction cannot be
//! undone here by accident. The arch-conformance rule keeps it structural:
//! this crate takes `ml-features` and nothing else — no service, broker,
//! store, or `intelligence` edge.

mod artifact;
mod descriptor;
mod engine;
mod observe;

/// Serving-side metric names and the single recording function
/// [`ObservedEngine`] drives. Public so a binary's dashboards and alert rules
/// can reference the names instead of re-typing them.
pub mod metrics;

/// The `ort` (ONNX Runtime) backend — the production implementation of the
/// seam. Behind the `onnx` feature so the trait, the digest, the descriptor
/// and the double cost nothing to link without it.
#[cfg(feature = "onnx")]
pub mod onnx;

/// The shared in-memory [`InferenceEngine`] double, behind the `test-util`
/// feature (`inference = { workspace = true, features = ["test-util"] }`).
#[cfg(any(test, feature = "test-util"))]
pub mod test_util;

#[cfg(test)]
mod test_support;

pub use artifact::{ArtifactDigest, ArtifactError, DigestParseError, ModelArtifact};
pub use descriptor::{FeatureSkew, ModelDescriptor, SkewError};
pub use engine::{InferenceEngine, InferenceError, InferenceErrorKind, Score, ScoreOutOfRange};
pub use observe::ObservedEngine;

#[cfg(test)]
mod tests {
    use super::*;
    use detector_api::test_util::CtxBuilder;
    use ml_features::Granularity;
    use test_util::{block_descriptor, StubEngine};

    /// The seam's whole point, as one test: a consumer holds
    /// `Arc<dyn InferenceEngine>` and works identically against either
    /// implementation, so t4's detector can be tested without a runtime.
    #[test]
    fn a_consumer_programs_against_the_trait_object() {
        use std::sync::Arc;

        fn score_block(engine: &Arc<dyn InferenceEngine>, ctx: &detector_api::DetectionCtx) -> f64 {
            engine
                .infer(&ml_features::extract_block(ctx))
                .expect("a block vector from the current version")
                .get()
        }

        let engine: Arc<dyn InferenceEngine> = Arc::new(StubEngine::constant(
            block_descriptor("anomaly-gbdt"),
            Score::new(0.42).unwrap(),
        ));
        assert_eq!(score_block(&engine, &CtxBuilder::new().build()), 0.42);
    }

    /// The end-to-end statement of "weights are config": two deployments that
    /// differ *only* in the artifact file produce different model identities,
    /// which is what makes the folded `config_hash` a real version.
    #[test]
    fn a_retrain_changes_the_identity_the_registry_folds_in() {
        let make = |bytes: &[u8]| {
            ModelDescriptor::new(
                "anomaly-gbdt",
                ArtifactDigest::of(bytes),
                ml_features::FEATURE_VERSION,
                Granularity::Tx,
            )
            .unwrap()
        };
        assert_ne!(
            make(b"weights-march").content_hash(),
            make(b"weights-april").content_hash()
        );
        // ...and the same weights twice are the same identity, so a redeploy
        // that changes nothing does not invent a new registry triple.
        assert_eq!(
            make(b"weights-march").content_hash(),
            make(b"weights-march").content_hash()
        );
    }
}
