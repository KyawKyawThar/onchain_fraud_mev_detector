//! Shared fixtures for this crate's own tests.
//!
//! Deliberately *not* a `test-util` feature: the reusable doubles already
//! exist a layer down (`inference::test_util::StubEngine`,
//! `detector_api::test_util::CtxBuilder`), and these are only the local
//! shorthands that combine them. A downstream crate wiring this detector
//! should build the real thing from a real engine.

use std::sync::Arc;

use inference::test_util::{block_descriptor, tx_descriptor, StubEngine};
use inference::{InferenceEngine, Score};
use ml_features::{FeatureBaseline, FeatureStats, Granularity};

/// A baseline over `granularity`'s current schema with centre `0` and spread
/// `1` for every feature — so an extracted value *is* its deviation and a test
/// can state expected contributions in the units it already has.
pub(crate) fn baseline_for(granularity: Granularity) -> FeatureBaseline {
    let schema = match granularity {
        Granularity::Block => ml_features::block_schema(),
        Granularity::Tx => ml_features::tx_schema(),
    };
    let stats = schema
        .names()
        .map(|name| {
            (
                name.to_owned(),
                FeatureStats {
                    center: 0.0,
                    spread: 1.0,
                },
            )
        })
        .collect();
    FeatureBaseline::new(ml_features::FEATURE_VERSION, granularity, stats)
        .expect("a full set of statistics for the current schema")
}

fn descriptor(model_id: &str, granularity: Granularity) -> inference::ModelDescriptor {
    match granularity {
        Granularity::Block => block_descriptor(model_id),
        Granularity::Tx => tx_descriptor(model_id),
    }
}

/// An engine that always returns `score`.
pub(crate) fn engine(
    model_id: &str,
    granularity: Granularity,
    score: f64,
) -> Arc<dyn InferenceEngine> {
    Arc::new(StubEngine::constant(
        descriptor(model_id, granularity),
        Score::new(score).expect("a test score in [0, 1]"),
    ))
}

/// An engine whose score is derived from the vector — for driving one
/// candidate over the threshold and the rest under it.
pub(crate) fn scoring_engine(
    model_id: &str,
    granularity: Granularity,
    responder: impl Fn(&ml_features::FeatureVector) -> f64 + Send + Sync + 'static,
) -> Arc<dyn InferenceEngine> {
    Arc::new(StubEngine::responding(
        descriptor(model_id, granularity),
        move |v| Ok(Score::new(responder(v)).expect("a test score in [0, 1]")),
    ))
}

/// An engine whose runtime is broken — the case a detector most often forgets
/// to cover.
pub(crate) fn failing_engine(model_id: &str, granularity: Granularity) -> Arc<dyn InferenceEngine> {
    Arc::new(StubEngine::failing(
        descriptor(model_id, granularity),
        "session gone",
    ))
}
