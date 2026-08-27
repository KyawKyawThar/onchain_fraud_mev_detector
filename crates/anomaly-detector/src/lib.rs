//! `anomaly-v1.0` — ML detection on the fast path (§20.2, Sprint 18 t4).
//!
//! The first `ModelKind::Ml` detector, and the payoff of the three seams built
//! before it: it reads the same [`DetectionCtx`] every heuristic detector
//! reads, turns it into the same versioned vectors the training rows were
//! built from (`ml-features`, §20.1), scores them through the same engine
//! seam a `.onnx` artifact is served behind (`inference`, §20.2), and returns
//! ordinary [`Evidence`]. Nothing about it is special-cased downstream: it
//! registers in the same roster, stages through the same rollout policy, and
//! emits the same events as `sandwich-v1.2`.
//!
//! # Two models, two different claims
//!
//! §20.2 asks for two, and the distinction is the whole design:
//!
//! - **Supervised** ([`AnomalyModel::Supervised`]) — gradient-boosted trees
//!   trained on the flywheel labels: `DetectorTriggered` joined to the
//!   `SimulationCompleted` that confirmed or refuted it (§20.1). It scores
//!   *per transaction* and says "this looks like the things that turned out to
//!   be real", sharpening structures the heuristics leave ambiguous.
//! - **Novelty** ([`AnomalyModel::Novelty`]) — an isolation forest over the
//!   same feature vectors, scoring the *block*. It says "this looks like
//!   nothing in the training window": the detector for attacks that have no
//!   signature yet, and therefore the one that must never name a pattern.
//!
//! Both emit [`AlertKind::Anomaly`], the one behaviour kind that claims no
//! known pattern. Reusing `Sandwich` because a model was trained partly on
//! sandwiches would put a specific accusation on the wire that the evidence
//! cannot support; the honest claim is "anomalous, and here is what is
//! unusual about it".
//!
//! Each model produces its own finding. They are not merged when both fire on
//! one block: they are separate claims with separate evidence, and a consumer
//! that sees both learns something a single averaged confidence would have
//! destroyed.
//!
//! # Explainability is the deliverable, not a nicety
//!
//! Every finding carries its [top contributing features](crate::explain) —
//! each named, with the value observed, the training window's centre and
//! spread, and the share of the block's total deviation it accounts for
//! ([`AnomalyDetail`]). §20.2 requires it and §8.3 shapes it: explainable,
//! versioned, and nuanced about what a contribution *is* (a deviation, not a
//! cause — see [`explain`]). An explanation with nothing past the reporting
//! floor comes back empty rather than padded.
//!
//! Contributions are computed **above** the serving seam, from the feature
//! vector against the model's training-window [`FeatureBaseline`] — never from
//! a model-specific attribution output. That keeps the seam backend-agnostic
//! and leaves one subsystem owning "why did this fire?".
//!
//! # Weights are config
//!
//! [`AnomalyDetector::model_digest`] folds the detector's thresholds together
//! with each served model's descriptor (artifact SHA-256 + trained
//! `feature_version` + schema hash) and its baseline hash. The composing
//! service folds *that* into the `config_hash` of the `(id, version,
//! config_hash)` triple stamped on every event, so a retrain, a re-exported
//! baseline, and a lowered threshold are all the same kind of change: a new
//! registry triple, rolled back through `deprecated_at`. There is no hot-swap
//! path (§20.5) — a new model walks Shadow → backtest gate → Live like any
//! detector change.
//!
//! # What this detector deliberately does not do
//!
//! It does not adjust *another* detector's `raw_confidence`. §20.2 describes
//! the supervised model as sharpening ambiguous structures, and the temptation
//! is to have it rewrite the sandwich detector's confidence — but a
//! [`DetectorPlugin`] is a pure function of the context, sees no other
//! detector's findings, and the emit path carries each detector's own
//! facts-only number unadjusted by design (§6). Fusing two detectors' opinions
//! is a composition concern that belongs above the seam, with the ranking to
//! prove it is an improvement; until then this model states its own opinion
//! and lets the evidence stand side by side.
//!
//! # Wiring
//!
//! ```
//! use std::sync::Arc;
//! use anomaly_detector::{AnomalyConfig, AnomalyDetector, ModelSlot};
//! use detector_api::DetectorPlugin;
//! use inference::test_util::{block_descriptor, StubEngine};
//! use inference::Score;
//! use ml_features::{FeatureBaseline, Granularity};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // In production these come from `OrtEngine::load(...)` wrapped once in
//! // `ObservedEngine`, and a baseline snapshot mounted beside the artifact.
//! let engine = Arc::new(StubEngine::constant(
//!     block_descriptor("anomaly-iforest"),
//!     Score::new(0.99)?,
//! ));
//! let ctx = detector_api::test_util::CtxBuilder::new().build();
//! let baseline = FeatureBaseline::from_samples(&[ml_features::extract_block(&ctx)])?;
//!
//! let detector = AnomalyDetector::new(
//!     AnomalyConfig::default(),
//!     vec![ModelSlot::novelty(engine, baseline)?],
//! )?;
//! assert_eq!(detector.id().as_str(), "anomaly");
//! assert!(detector.model_digest().is_some(), "weights are config");
//! # Ok(())
//! # }
//! ```

mod config;
mod detail;
pub mod explain;
mod model;

#[cfg(test)]
mod test_support;

use alloy_primitives::B256;
use sha2::{Digest, Sha256};

use detector_api::{DetectionCtx, DetectorId, DetectorPlugin, Evidence, ModelKind, Scope, SemVer};
use events::primitives::{AlertKind, Confidence};
use inference::Score;
use ml_features::{BlockFeatureView, FeatureVector, Granularity};

pub use config::{
    AnomalyConfig, DEFAULT_MAX_IMPLICATED_TXS, DEFAULT_MIN_DEVIATION, DEFAULT_NOVELTY_MIN_SCORE,
    DEFAULT_SUPERVISED_MIN_SCORE, DEFAULT_TOP_FEATURES,
};
pub use detail::AnomalyDetail;
pub use explain::{top_contributions, FeatureContribution};
pub use model::{AnomalyModel, ModelSlot, WiringError};

/// Domain separation for [`AnomalyDetector::model_digest`]. Frozen: changing
/// it would rotate every deployment's contribution to its `config_hash`, and
/// the digest is an audit identifier, not a cache key.
const DIGEST_DOMAIN: &[u8] = b"anomaly-detector/identity/v1\n";

/// The `anomaly-v1.0` detector: one or both of the §20.2 models, each with the
/// training-window baseline its findings are explained against.
///
/// Unlike the heuristic detectors there is no `plugin()` shorthand — a model
/// and its baseline are deployment artifacts, so the composing service builds
/// the [`ModelSlot`]s and this is constructed from them, link-or-fail.
#[derive(Debug)]
pub struct AnomalyDetector {
    config: AnomalyConfig,
    /// Ordered by role and unique in it, so a block's findings come out in a
    /// deterministic order regardless of how the deployment listed them.
    models: Vec<ModelSlot>,
    digest: [u8; 32],
}

impl AnomalyDetector {
    /// This detector's stable id.
    pub const ID: DetectorId = DetectorId::new("anomaly");
    /// This build's version: `1.0.0`.
    pub const VERSION: SemVer = SemVer::new(1, 0, 0);

    /// Wire the detector from its config and its served models.
    ///
    /// `Err` on an unusable config, no models at all, or two models claiming
    /// one role — all deployment mistakes, surfaced at boot rather than as a
    /// detector that silently scores nothing.
    pub fn new(config: AnomalyConfig, models: Vec<ModelSlot>) -> Result<Self, WiringError> {
        config.validate()?;
        if models.is_empty() {
            return Err(WiringError::NoModels);
        }

        let mut models = models;
        models.sort_by_key(ModelSlot::role);
        if let Some(pair) = models.windows(2).find(|p| p[0].role() == p[1].role()) {
            return Err(WiringError::DuplicateRole {
                role: pair[0].role(),
            });
        }

        let digest = identity_digest(&config, &models);
        Ok(Self {
            config,
            models,
            digest,
        })
    }

    /// The active thresholds — part of what [`model_digest`](Self::model_digest)
    /// covers.
    pub fn config(&self) -> &AnomalyConfig {
        &self.config
    }

    /// The served models, in role order.
    pub fn models(&self) -> &[ModelSlot] {
        &self.models
    }

    /// Score one model over a block and return whatever cleared its threshold.
    ///
    /// A failed inference **skips this model for this block** and emits
    /// nothing. Two deliberate choices there: every `InferenceError` is
    /// permanent for the input that caused it, so retrying is pointless; and
    /// the alternative to skipping is a fabricated score, which is the one
    /// output a detection system must never produce. The failure is not
    /// silent — `inference::ObservedEngine` records it by reason and model,
    /// which is why the composing service is required to wrap the engine once
    /// at boot rather than have every detector hand-roll its own counter.
    fn run(
        &self,
        slot: &ModelSlot,
        ctx: &DetectionCtx,
        view: &BlockFeatureView<'_>,
    ) -> Vec<Evidence> {
        let block_tx_count = ctx.txs().len();
        let (implicated, vectors) = self.candidates(slot, ctx, view);

        // One batched call per model per block: a real backend turns it into a
        // single `[N, features]` runtime invocation instead of one per
        // transaction — the §17 amortisation the whole per-block path is built
        // around.
        let Ok(scores) = slot.engine().infer_batch(&vectors) else {
            return Vec::new();
        };

        let threshold = self.config.min_score(slot.role());
        implicated
            .into_iter()
            .zip(&vectors)
            .zip(scores)
            .filter(|(_, score)| score.get() >= threshold)
            .map(|((txs, features), score)| {
                self.evidence(slot, txs, features, score, block_tx_count)
            })
            .collect()
    }

    /// What this model scores, and which transactions each score implicates.
    ///
    /// Driven by the *model's* declared granularity rather than a compile-time
    /// choice, because the two models legitimately differ and a deployment may
    /// retrain either one at the other granularity.
    fn candidates(
        &self,
        slot: &ModelSlot,
        ctx: &DetectionCtx,
        view: &BlockFeatureView<'_>,
    ) -> (Vec<Vec<B256>>, Vec<FeatureVector>) {
        match slot.granularity() {
            // A block-level model scores the block, so the honest implicated
            // set is the block's transactions — capped, with the true count
            // recorded in the detail so a truncation is visible. The finding's
            // *localisation* is the feature-level explanation, not a claim
            // that a particular transaction did it.
            Granularity::Block => {
                let txs = ctx
                    .txs()
                    .iter()
                    .copied()
                    .take(self.config.max_implicated_txs)
                    .collect();
                (vec![txs], vec![view.block_vector()])
            }
            // A per-transaction model names exactly the transaction it scored.
            Granularity::Tx => view
                .all_tx_vectors()
                .into_iter()
                .map(|(hash, vector)| (vec![hash], vector))
                .unzip(),
        }
    }

    fn evidence(
        &self,
        slot: &ModelSlot,
        txs: Vec<B256>,
        features: &FeatureVector,
        score: Score,
        block_tx_count: usize,
    ) -> Evidence {
        let top_features = top_contributions(
            features,
            slot.baseline(),
            self.config.top_features,
            self.config.min_deviation,
        );
        let descriptor = slot.engine().descriptor();
        let detail = AnomalyDetail {
            model: slot.role(),
            model_id: descriptor.model_id().to_owned(),
            artifact: descriptor.artifact(),
            feature_version: descriptor.feature_version(),
            granularity: descriptor.granularity(),
            schema_hash: descriptor.schema_hash().to_owned(),
            baseline_hash: slot.baseline().content_hash(),
            score: score.get(),
            threshold: self.config.min_score(slot.role()),
            explained_share: top_features.iter().map(|c| c.share).sum(),
            top_features,
            block_tx_count,
            implicated_tx_count: txs.len(),
        };

        // `Score` is already a validated `[0, 1]` confidence, so `new` cannot
        // clamp anything here — the range was parsed at the seam boundary, not
        // patched up at the call site.
        Evidence::from_detail(
            AlertKind::Anomaly,
            txs,
            Confidence::new(score.get()),
            &detail,
        )
        // `impact_usd` is deliberately left unset: this detector has no
        // priced quantity to report — "unusual" is not a dollar figure — so
        // the emit path's transfer-sum fallback supplies the coarse magnitude
        // severity bands on. Inventing a number here would be worse than
        // having none (§6).
    }
}

impl DetectorPlugin for AnomalyDetector {
    fn id(&self) -> DetectorId {
        Self::ID
    }

    fn version(&self) -> SemVer {
        Self::VERSION
    }

    fn kind(&self) -> ModelKind {
        ModelKind::Ml
    }

    fn scope(&self) -> Scope {
        // Both models decide from a single block: the novelty model scores the
        // block vector, the supervised one scores each transaction against its
        // own block. Cross-block position deltas are a later `FEATURE_VERSION`
        // (§20.1), and adopting them would make this `Scope::CrossBlock` and
        // move it onto the serial roster — a deliberate future change, not an
        // accident to leave room for.
        Scope::Block
    }

    fn detect(&self, ctx: &DetectionCtx) -> Vec<Evidence> {
        // An empty block has nothing to implicate and no transaction to score.
        // Returning early also keeps the common header-only case off the
        // feature-extraction path entirely.
        if ctx.txs().is_empty() {
            return Vec::new();
        }

        // One view per block, shared by both models: it computes the
        // block-wide context (gas median, sender census, position index) once
        // instead of per transaction (§17, and the reason `extract_all_txs`
        // is O(n) rather than O(n²)).
        let view = BlockFeatureView::new(ctx);
        self.models
            .iter()
            .flat_map(|slot| self.run(slot, ctx, &view))
            .collect()
    }

    fn model_digest(&self) -> Option<[u8; 32]> {
        Some(self.digest)
    }
}

/// Digest the detector's whole learned configuration: its thresholds, plus
/// every served model's descriptor hash and baseline hash, in role order.
///
/// Length-prefixed field by field so no two distinct deployments can produce
/// the same byte stream by shifting a boundary — the same construction
/// `inference::ModelDescriptor::content_hash` uses, for the same reason.
fn identity_digest(config: &AnomalyConfig, models: &[ModelSlot]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);

    // Through `Value` first so map keys are canonically ordered — the same
    // determinism-by-construction `ConfigHash::of` relies on.
    let canonical =
        serde_json::to_value(config).expect("AnomalyConfig is plain data and always serialises");
    let config_bytes = serde_json::to_vec(&canonical)
        .expect("re-serializing an in-memory serde_json::Value is infallible");
    field(&mut hasher, &config_bytes);

    for slot in models {
        field(&mut hasher, slot.role().as_str().as_bytes());
        field(&mut hasher, &slot.engine().descriptor().content_hash());
        field(&mut hasher, slot.baseline().content_hash().as_bytes());
    }
    hasher.finalize().into()
}

fn field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{baseline_for, engine, failing_engine, scoring_engine};
    use detector_api::test_util::{addr, b256, detail as evidence_detail, transfer, CtxBuilder};
    use ml_features::FeatureBaseline;

    const WETH: u8 = 0xAA;
    const SENDER: u8 = 0x11;
    const OTHER: u8 = 0x22;
    const ETH: u128 = 1_000_000_000_000_000_000;

    /// A three-transaction block with priced transfers, so the extracted
    /// vectors are non-degenerate.
    fn block() -> DetectionCtx {
        let mut builder = CtxBuilder::new().priced_token(addr(WETH), 18, 2000.0);
        for (i, amount) in [(1u8, ETH), (2, 5 * ETH), (3, ETH / 2)] {
            builder = builder.transfer_tx(
                b256(i),
                addr(SENDER),
                vec![transfer(addr(WETH), addr(SENDER), addr(OTHER), amount)],
            );
        }
        builder.build()
    }

    fn detector(models: Vec<ModelSlot>) -> AnomalyDetector {
        AnomalyDetector::new(AnomalyConfig::default(), models).expect("wired")
    }

    fn novelty_slot(score: f64) -> ModelSlot {
        ModelSlot::novelty(
            engine("anomaly-iforest", Granularity::Block, score),
            baseline_for(Granularity::Block),
        )
        .expect("matching schemas")
    }

    fn supervised_slot(score: f64) -> ModelSlot {
        ModelSlot::supervised(
            engine("anomaly-gbdt", Granularity::Tx, score),
            baseline_for(Granularity::Tx),
        )
        .expect("matching schemas")
    }

    fn detail_of(ev: &Evidence) -> AnomalyDetail {
        evidence_detail(ev)
    }

    // ── the seam contract ────────────────────────────────────────────────

    #[test]
    fn declares_itself_as_a_block_scoped_ml_detector() {
        let d = detector(vec![novelty_slot(0.99)]);
        assert_eq!(d.id(), AnomalyDetector::ID);
        assert_eq!(d.version(), AnomalyDetector::VERSION);
        assert_eq!(d.kind(), ModelKind::Ml);
        assert_eq!(d.scope(), Scope::Block);
    }

    #[test]
    fn an_empty_block_is_never_scored() {
        let d = detector(vec![novelty_slot(1.0)]);
        assert!(d.detect(&CtxBuilder::new().build()).is_empty());
    }

    // ── the novelty model ────────────────────────────────────────────────

    #[test]
    fn a_novel_block_is_reported_as_anomalous_not_as_a_named_pattern() {
        let found = detector(vec![novelty_slot(0.99)]).detect(&block());
        assert_eq!(found.len(), 1);
        let ev = &found[0];

        assert_eq!(
            ev.kind,
            AlertKind::Anomaly,
            "a novelty model must not claim a known behaviour"
        );
        assert_eq!(ev.confidence.get(), 0.99, "the model's score, unadjusted");
        assert_eq!(ev.txs.len(), 3, "a block finding implicates its block");
        assert_eq!(
            ev.impact_usd, None,
            "\"unusual\" is not a dollar figure — the emit path estimates instead"
        );

        let detail = detail_of(ev);
        assert_eq!(detail.model, AnomalyModel::Novelty);
        assert_eq!(detail.model_id, "anomaly-iforest");
        assert_eq!(detail.granularity, Granularity::Block);
        assert_eq!(detail.score, 0.99);
        assert_eq!(detail.threshold, DEFAULT_NOVELTY_MIN_SCORE);
        assert_eq!(detail.block_tx_count, 3);
        assert_eq!(detail.implicated_tx_count, 3);
    }

    #[test]
    fn a_block_below_the_novelty_threshold_says_nothing() {
        let found = detector(vec![novelty_slot(DEFAULT_NOVELTY_MIN_SCORE - 0.01)]).detect(&block());
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn the_threshold_is_inclusive_so_a_tuned_bar_means_what_it_says() {
        let found = detector(vec![novelty_slot(DEFAULT_NOVELTY_MIN_SCORE)]).detect(&block());
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn a_large_block_implicates_a_capped_set_and_says_how_many_there_were() {
        let mut builder = CtxBuilder::new();
        for i in 1..=40u8 {
            builder = builder.tx(b256(i), addr(SENDER), vec![]);
        }
        let config = AnomalyConfig {
            max_implicated_txs: 4,
            ..AnomalyConfig::default()
        };
        let d = AnomalyDetector::new(config, vec![novelty_slot(1.0)]).unwrap();

        let found = d.detect(&builder.build());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].txs.len(), 4);
        // The truncation is *visible*, not implied by a short list.
        let detail = detail_of(&found[0]);
        assert_eq!(detail.block_tx_count, 40);
        assert_eq!(detail.implicated_tx_count, 4);
    }

    // ── the supervised model ─────────────────────────────────────────────

    #[test]
    fn the_supervised_model_names_the_transaction_it_scored() {
        // Score the second transaction over the bar and the rest under it.
        let target = b256(2);
        let position = ml_features::tx_schema()
            .names()
            .position(|n| n == "position_in_block")
            .expect("v1 places a tx in its block");
        let slot = ModelSlot::supervised(
            scoring_engine("anomaly-gbdt", Granularity::Tx, move |v| {
                // position_in_block is `index / (tx_count - 1)`, so the middle
                // transaction of three sits at 0.5.
                if (v.values()[position] - 0.5).abs() < 1e-9 {
                    0.95
                } else {
                    0.10
                }
            }),
            baseline_for(Granularity::Tx),
        )
        .unwrap();

        let found = detector(vec![slot]).detect(&block());
        assert_eq!(found.len(), 1, "one transaction cleared the bar");
        assert_eq!(found[0].txs, vec![target]);
        let detail = detail_of(&found[0]);
        assert_eq!(detail.model, AnomalyModel::Supervised);
        assert_eq!(detail.granularity, Granularity::Tx);
        assert_eq!(detail.block_tx_count, 3);
        assert_eq!(detail.implicated_tx_count, 1);
    }

    #[test]
    fn a_per_transaction_model_scores_every_transaction_in_block_order() {
        let found = detector(vec![supervised_slot(1.0)]).detect(&block());
        assert_eq!(found.len(), 3);
        assert_eq!(
            found.iter().map(|e| e.txs[0]).collect::<Vec<_>>(),
            vec![b256(1), b256(2), b256(3)],
            "findings follow bundle order, so replay and the live path agree"
        );
    }

    // ── both models together ─────────────────────────────────────────────

    #[test]
    fn both_models_state_their_own_case_rather_than_being_averaged() {
        let found = detector(vec![novelty_slot(0.99), supervised_slot(0.99)]).detect(&block());
        assert_eq!(found.len(), 4, "1 block finding + 3 transaction findings");

        let roles: Vec<_> = found.iter().map(|e| detail_of(e).model).collect();
        assert_eq!(
            roles,
            vec![
                AnomalyModel::Supervised,
                AnomalyModel::Supervised,
                AnomalyModel::Supervised,
                AnomalyModel::Novelty
            ],
            "role order is deterministic regardless of how the deployment listed them"
        );
    }

    #[test]
    fn the_roster_order_does_not_depend_on_the_deployments_listing_order() {
        let a = detector(vec![novelty_slot(0.99), supervised_slot(0.99)]);
        let b = detector(vec![supervised_slot(0.99), novelty_slot(0.99)]);
        assert_eq!(a.model_digest(), b.model_digest());
        let roles =
            |d: &AnomalyDetector| d.models().iter().map(ModelSlot::role).collect::<Vec<_>>();
        assert_eq!(roles(&a), roles(&b));
    }

    // ── explainability (§20.2, §8.3) ─────────────────────────────────────

    #[test]
    fn evidence_carries_the_features_that_make_the_block_unusual() {
        let found = detector(vec![novelty_slot(0.99)]).detect(&block());
        let detail = detail_of(&found[0]);

        assert!(
            !detail.top_features.is_empty(),
            "a real block deviates from an all-zero baseline"
        );
        assert!(detail.top_features.len() <= DEFAULT_TOP_FEATURES);

        // Ranked by magnitude, and every claim is checkable: the named feature
        // exists in the schema the finding declares, and its reported value is
        // the one that was extracted.
        let schema_names: Vec<&str> = ml_features::block_schema().names().collect();
        let extracted = ml_features::extract_block(&block());
        for pair in detail.top_features.windows(2) {
            assert!(pair[0].deviation.abs() >= pair[1].deviation.abs());
        }
        for contribution in &detail.top_features {
            let index = schema_names
                .iter()
                .position(|n| *n == contribution.feature)
                .expect("a feature of the declared schema");
            assert_eq!(contribution.value, extracted.values()[index]);
            assert!(contribution.deviation.abs() >= DEFAULT_MIN_DEVIATION);
            assert!((0.0..=1.0).contains(&contribution.share));
        }

        assert_eq!(
            detail.schema_hash,
            ml_features::block_schema().content_hash(),
            "an explanation is only interpretable under a stated schema (§8.3)"
        );
        assert_eq!(detail.feature_version, ml_features::FEATURE_VERSION);
        assert!((0.0..=1.0).contains(&detail.explained_share));
    }

    #[test]
    fn a_finding_no_single_feature_explains_says_so_instead_of_padding() {
        // Baseline derived from this very block: nothing deviates at all.
        let ctx = block();
        let baseline = FeatureBaseline::from_samples(&[ml_features::extract_block(&ctx)]).unwrap();
        let slot = ModelSlot::novelty(
            engine("anomaly-iforest", Granularity::Block, 0.99),
            baseline,
        )
        .unwrap();

        let found = detector(vec![slot]).detect(&ctx);
        let detail = detail_of(&found[0]);
        assert!(detail.top_features.is_empty(), "{:?}", detail.top_features);
        assert_eq!(detail.explained_share, 0.0);
        assert_eq!(
            found[0].confidence.get(),
            0.99,
            "a thin explanation does not weaken the model's own claim"
        );
    }

    #[test]
    fn the_same_block_explains_itself_identically_every_time() {
        // Replay and backtest (§18) must reproduce a finding exactly; the
        // ranking's tie-break is what makes that true for equal deviations.
        let d = detector(vec![novelty_slot(0.99), supervised_slot(0.99)]);
        let ctx = block();
        let first: Vec<_> = d.detect(&ctx).iter().map(|e| e.detail.clone()).collect();
        let second: Vec<_> = d.detect(&ctx).iter().map(|e| e.detail.clone()).collect();
        assert_eq!(first, second);
    }

    // ── failure handling ─────────────────────────────────────────────────

    #[test]
    fn a_broken_runtime_skips_that_model_and_never_fabricates_a_score() {
        let slot = ModelSlot::novelty(
            failing_engine("anomaly-iforest", Granularity::Block),
            baseline_for(Granularity::Block),
        )
        .unwrap();
        assert!(detector(vec![slot]).detect(&block()).is_empty());
    }

    #[test]
    fn one_broken_model_does_not_silence_the_other() {
        let broken = ModelSlot::novelty(
            failing_engine("anomaly-iforest", Granularity::Block),
            baseline_for(Granularity::Block),
        )
        .unwrap();
        let found = detector(vec![broken, supervised_slot(0.99)]).detect(&block());
        assert_eq!(found.len(), 3);
        assert!(found
            .iter()
            .all(|e| detail_of(e).model == AnomalyModel::Supervised));
    }

    // ── wiring ───────────────────────────────────────────────────────────

    #[test]
    fn a_detector_with_no_models_is_refused() {
        let err = AnomalyDetector::new(AnomalyConfig::default(), Vec::new()).unwrap_err();
        assert!(matches!(err, WiringError::NoModels), "{err}");
    }

    #[test]
    fn two_models_for_one_role_are_refused() {
        let err = AnomalyDetector::new(
            AnomalyConfig::default(),
            vec![novelty_slot(0.9), novelty_slot(0.8)],
        )
        .unwrap_err();
        assert!(
            matches!(err, WiringError::DuplicateRole { role } if role == AnomalyModel::Novelty),
            "{err}"
        );
    }

    #[test]
    fn an_unusable_config_is_refused_before_any_block_is_scored() {
        let config = AnomalyConfig {
            top_features: 0,
            ..AnomalyConfig::default()
        };
        assert!(matches!(
            AnomalyDetector::new(config, vec![novelty_slot(0.9)]),
            Err(WiringError::InvalidConfig { .. })
        ));
    }

    // ── weights are config (§20.2) ───────────────────────────────────────

    #[test]
    fn a_retrained_model_changes_the_detectors_identity() {
        let march = detector(vec![novelty_slot(0.9)]);
        let april = detector(vec![ModelSlot::novelty(
            engine("anomaly-iforest-v2", Granularity::Block, 0.9),
            baseline_for(Granularity::Block),
        )
        .unwrap()]);
        assert_ne!(march.model_digest(), april.model_digest());
        // …and redeploying the same thing does not invent a new triple.
        assert_eq!(
            march.model_digest(),
            detector(vec![novelty_slot(0.9)]).model_digest()
        );
    }

    #[test]
    fn a_threshold_change_changes_the_identity_too() {
        let base = detector(vec![novelty_slot(0.9)]);
        let tuned = AnomalyDetector::new(
            AnomalyConfig {
                novelty_min_score: 0.5,
                ..AnomalyConfig::default()
            },
            vec![novelty_slot(0.9)],
        )
        .unwrap();
        assert_ne!(base.model_digest(), tuned.model_digest());
    }

    #[test]
    fn a_re_derived_baseline_changes_the_identity() {
        // The explanation is part of what a deployment claims, so swapping the
        // training snapshot is not a cosmetic change.
        let ctx = block();
        let other = ModelSlot::novelty(
            engine("anomaly-iforest", Granularity::Block, 0.9),
            FeatureBaseline::from_samples(&[ml_features::extract_block(&ctx)]).unwrap(),
        )
        .unwrap();
        assert_ne!(
            detector(vec![novelty_slot(0.9)]).model_digest(),
            detector(vec![other]).model_digest()
        );
    }

    #[test]
    fn adding_a_second_model_changes_the_identity() {
        assert_ne!(
            detector(vec![novelty_slot(0.9)]).model_digest(),
            detector(vec![novelty_slot(0.9), supervised_slot(0.9)]).model_digest()
        );
    }
}
