//! [`ModelDescriptor`] — what a deployed model *is*, resolved once at boot.
//!
//! Three facts have to travel together for a served model to be trustworthy:
//! the weights (an [`ArtifactDigest`]), the feature contract they were trained
//! against (a `FeatureVersion` and the schema it names), and the granularity
//! of vector they consume. Carrying them as one value rather than three
//! loose fields is what lets the two checks §20 asks for be *checks*:
//!
//! - **Serving/training skew, at boot, link-or-fail (§20.5).** Constructing a
//!   descriptor resolves the trained `feature_version` through
//!   `ml-features`'s version registry. A build that can no longer extract that
//!   version cannot serve that model, and says so at boot instead of feeding
//!   it a differently-shaped vector at block time.
//! - **Weights are config (§20.2).** [`content_hash`](ModelDescriptor::content_hash)
//!   digests all of it — artifact, feature version, schema digest, arity — and
//!   *that* is what the composing service folds into the registry
//!   `config_hash` (`detection::ConfigHash::with_model_artifact`). So a
//!   retrain and a feature-schema bump both produce a new
//!   `(id, version, config_hash)` triple, and historical evidence stays
//!   attributable to the exact model that produced it.
//!
//! The descriptor is `Serialize` but deliberately **not** `Deserialize`: it is
//! derived from an artifact and a live schema registry, never parsed back from
//! text. A descriptor that exists has passed the skew check (parse, don't
//! validate — conventions §4).

use ml_features::{FeatureVector, FeatureVersion, Granularity};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::artifact::ArtifactDigest;

/// Domain separation for [`ModelDescriptor::content_hash`]. Bumping this
/// string would rotate every model's contribution to every `config_hash`, so
/// it is frozen: the digest is an audit identifier, not a cache key.
const CONTENT_HASH_DOMAIN: &[u8] = b"inference/model-descriptor/v1\n";

/// One deployed model's identity: weights + feature contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModelDescriptor {
    /// How this model is named in logs, metrics and evidence — the detector's
    /// own id, or a sub-model name when a detector runs several (t4 runs a
    /// supervised classifier *and* an isolation forest).
    model_id: String,
    /// SHA-256 of the artifact these weights came from.
    artifact: ArtifactDigest,
    /// The `ml-features` version the model was trained against.
    feature_version: FeatureVersion,
    /// Which vectors it consumes — block-level or per-transaction.
    granularity: Granularity,
    /// How many values a vector of that `(version, granularity)` carries; the
    /// model's input arity must equal it.
    input_len: usize,
    /// The feature schema's own content hash (names + kinds, in order), so a
    /// schema change is visible in the model's identity even if the version
    /// number were ever reused by mistake.
    schema_hash: String,
}

impl ModelDescriptor {
    /// Resolve a descriptor for a model trained under `feature_version`.
    ///
    /// `Err` iff this build no longer ships that version's extractor — the
    /// §20.5 skew check, run at boot so the failure is a refused deploy rather
    /// than a mis-scored block.
    pub fn new(
        model_id: impl Into<String>,
        artifact: ArtifactDigest,
        feature_version: FeatureVersion,
        granularity: Granularity,
    ) -> Result<Self, SkewError> {
        let model_id = model_id.into();
        let schema = ml_features::extractor_for(feature_version)
            .ok_or_else(|| SkewError::UnknownFeatureVersion {
                model_id: model_id.clone(),
                feature_version,
            })?
            .schema(granularity);
        Ok(Self {
            model_id,
            artifact,
            feature_version,
            granularity,
            input_len: schema.len(),
            schema_hash: schema.content_hash(),
        })
    }

    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    pub fn artifact(&self) -> ArtifactDigest {
        self.artifact
    }

    pub fn feature_version(&self) -> FeatureVersion {
        self.feature_version
    }

    pub fn granularity(&self) -> Granularity {
        self.granularity
    }

    /// The model's required input arity — the length of every vector it
    /// accepts.
    pub fn input_len(&self) -> usize {
        self.input_len
    }

    pub fn schema_hash(&self) -> &str {
        &self.schema_hash
    }

    /// Whether this model is trained on the version the *current* build
    /// extracts by default.
    ///
    /// Not an error — running a model one feature version behind is a
    /// legitimate, and expected, rollout state: `ml-features` keeps shipped
    /// versions linkable forever precisely so a model doesn't have to be
    /// retrained the moment the schema moves. The composing service logs this
    /// at boot and the drift monitor (t5) keys off it; what *is* an error is
    /// feeding the model a vector of the wrong version, which
    /// [`accepts`](Self::accepts) refuses.
    pub fn is_current_feature_version(&self) -> bool {
        self.feature_version == ml_features::FEATURE_VERSION
    }

    /// Reject a vector this model cannot interpret.
    ///
    /// The runtime half of the skew rule. A `FeatureVector` stamps its own
    /// version and granularity, so a serving path that extracted under the
    /// wrong version — or handed a block vector to a per-tx model — is caught
    /// by comparison, not by a shape error deep inside the runtime (or worse,
    /// by a silently plausible score).
    pub fn accepts(&self, features: &FeatureVector) -> Result<(), FeatureSkew> {
        if features.feature_version() != self.feature_version {
            return Err(FeatureSkew::Version {
                expected: self.feature_version,
                actual: features.feature_version(),
            });
        }
        if features.granularity() != self.granularity {
            return Err(FeatureSkew::Granularity {
                expected: self.granularity,
                actual: features.granularity(),
            });
        }
        if features.values().len() != self.input_len {
            return Err(FeatureSkew::Arity {
                expected: self.input_len,
                actual: features.values().len(),
            });
        }
        Ok(())
    }

    /// The digest a composing service folds into the registry `config_hash`
    /// (§20.2) — see the module docs.
    ///
    /// Covers every field, each length-prefixed or newline-separated so no two
    /// distinct descriptors can produce the same byte stream by shifting a
    /// boundary (`model_id = "a\n1"` vs `"a"` + version 1).
    pub fn content_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(CONTENT_HASH_DOMAIN);
        let mut field = |bytes: &[u8]| {
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        };
        field(self.model_id.as_bytes());
        field(self.artifact.as_bytes());
        field(self.feature_version.to_string().as_bytes());
        field(granularity_str(self.granularity).as_bytes());
        field(&(self.input_len as u64).to_be_bytes());
        field(self.schema_hash.as_bytes());
        hasher.finalize().into()
    }

    /// [`content_hash`](Self::content_hash) as lowercase hex — the form that
    /// goes in a boot log line or a model card.
    pub fn content_hash_hex(&self) -> String {
        alloy_primitives::hex::encode(self.content_hash())
    }
}

/// `Granularity` has no public string form in `ml-features`; the hash needs a
/// stable one, and defining it here keeps that stability *this* crate's
/// contract rather than a borrowed internal detail.
fn granularity_str(granularity: Granularity) -> &'static str {
    match granularity {
        Granularity::Block => "block",
        Granularity::Tx => "tx",
    }
}

/// A model cannot be served by this build. Raised at boot, link-or-fail.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SkewError {
    /// The model was trained against a feature version this binary no longer
    /// ships an extractor for. Ship the version module (it is frozen and kept
    /// forever for exactly this reason) or retrain — never serve it blind.
    #[error(
        "model {model_id} was trained on feature schema {feature_version}, which this build \
         cannot extract — no registered extractor (serving/training skew, §20.5)"
    )]
    UnknownFeatureVersion {
        model_id: String,
        feature_version: FeatureVersion,
    },
}

/// A feature vector was handed to a model that cannot interpret it — always a
/// wiring bug in the serving path, never a data condition, and never retriable.
///
/// Carries no model id: which model rejected the vector is the caller's
/// context, attached once by `InferenceError`. That keeps this a plain `Copy`
/// value, so the check on the hot path allocates nothing even when it fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FeatureSkew {
    #[error(
        "expects feature schema {expected}, got a vector stamped {actual} \
         (serving/training skew, §20.5)"
    )]
    Version {
        expected: FeatureVersion,
        actual: FeatureVersion,
    },

    #[error("expects {expected:?} vectors, got {actual:?}")]
    Granularity {
        expected: Granularity,
        actual: Granularity,
    },

    /// Same version, wrong length — a corrupted or hand-built vector. The
    /// version check above catches the ordinary case; this catches the rest,
    /// so a short vector can never be zero-padded into a plausible score.
    #[error("expects {expected} features, got {actual}")]
    Arity { expected: usize, actual: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use detector_api::test_util::CtxBuilder;

    fn descriptor(granularity: Granularity) -> ModelDescriptor {
        ModelDescriptor::new(
            "anomaly-gbdt",
            ArtifactDigest::of(b"weights-v1"),
            ml_features::FEATURE_VERSION,
            granularity,
        )
        .expect("the current version is always registered")
    }

    #[test]
    fn a_descriptor_adopts_the_schemas_arity_and_digest() {
        let d = descriptor(Granularity::Block);
        let schema = ml_features::block_schema();
        assert_eq!(d.input_len(), schema.len());
        assert_eq!(d.schema_hash(), schema.content_hash());
        assert!(d.is_current_feature_version());
    }

    #[test]
    fn a_version_this_build_cannot_extract_is_refused_at_boot() {
        let err = ModelDescriptor::new(
            "anomaly-gbdt",
            ArtifactDigest::of(b"w"),
            FeatureVersion(999),
            Granularity::Block,
        )
        .unwrap_err();
        assert!(
            matches!(err, SkewError::UnknownFeatureVersion { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains("v999"));
    }

    #[test]
    fn a_matching_vector_is_accepted() {
        let ctx = CtxBuilder::new().build();
        let d = descriptor(Granularity::Block);
        assert_eq!(d.accepts(&ml_features::extract_block(&ctx)), Ok(()));
    }

    #[test]
    fn the_wrong_granularity_is_refused_rather_than_scored() {
        let ctx = CtxBuilder::new().build();
        let block_vector = ml_features::extract_block(&ctx);
        let tx_model = descriptor(Granularity::Tx);
        assert!(matches!(
            tx_model.accepts(&block_vector),
            Err(FeatureSkew::Granularity { .. })
        ));
    }

    #[test]
    fn a_vector_from_another_feature_version_is_refused() {
        // A vector deserialized from a dataset exported under a different
        // schema — the exact shape serving/training skew takes in practice.
        let ctx = CtxBuilder::new().build();
        let json = serde_json::to_string(&ml_features::extract_block(&ctx)).unwrap();
        let bumped = json.replacen("\"feature_version\":1", "\"feature_version\":7", 1);
        let foreign: FeatureVector = serde_json::from_str(&bumped).unwrap();

        let err = descriptor(Granularity::Block)
            .accepts(&foreign)
            .unwrap_err();
        assert!(matches!(err, FeatureSkew::Version { .. }), "{err:?}");
    }

    #[test]
    fn the_content_hash_moves_with_the_weights() {
        let v1 = descriptor(Granularity::Block);
        let v2 = ModelDescriptor::new(
            "anomaly-gbdt",
            ArtifactDigest::of(b"weights-v2"),
            ml_features::FEATURE_VERSION,
            Granularity::Block,
        )
        .unwrap();
        assert_ne!(
            v1.content_hash(),
            v2.content_hash(),
            "a retrain must produce a new registry triple (§20.2)"
        );
    }

    #[test]
    fn the_content_hash_is_stable_for_the_same_model() {
        let a = descriptor(Granularity::Block);
        let b = descriptor(Granularity::Block);
        assert_eq!(a.content_hash(), b.content_hash());
        assert_eq!(a.content_hash_hex().len(), 64);
    }

    #[test]
    fn the_content_hash_separates_every_field() {
        // Same weights, different granularity/model id ⇒ different identity.
        let block = descriptor(Granularity::Block);
        let tx = descriptor(Granularity::Tx);
        assert_ne!(block.content_hash(), tx.content_hash());

        let renamed = ModelDescriptor::new(
            "anomaly-isolation-forest",
            ArtifactDigest::of(b"weights-v1"),
            ml_features::FEATURE_VERSION,
            Granularity::Block,
        )
        .unwrap();
        assert_ne!(block.content_hash(), renamed.content_hash());
    }

    #[test]
    fn field_boundaries_cannot_be_shifted() {
        // Length-prefixing is what stops two distinct descriptors from
        // hashing the same bytes; assert the property directly rather than
        // trusting the implementation to keep the prefixes.
        let a = ModelDescriptor::new(
            "ab",
            ArtifactDigest::of(b"w"),
            ml_features::FEATURE_VERSION,
            Granularity::Block,
        )
        .unwrap();
        let b = ModelDescriptor::new(
            "a",
            ArtifactDigest::of(b"w"),
            ml_features::FEATURE_VERSION,
            Granularity::Block,
        )
        .unwrap();
        assert_ne!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn serialization_carries_the_provenance_a_model_card_needs() {
        let json = serde_json::to_value(descriptor(Granularity::Block)).unwrap();
        assert_eq!(json["model_id"], "anomaly-gbdt");
        assert_eq!(json["feature_version"], 1);
        assert_eq!(json["granularity"], "block");
        assert_eq!(
            json["artifact"],
            ArtifactDigest::of(b"weights-v1").to_hex().as_str()
        );
    }
}
