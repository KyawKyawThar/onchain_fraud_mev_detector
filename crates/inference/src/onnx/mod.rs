//! The ONNX Runtime backend (§20.2) — the one place a trained model is
//! actually executed.
//!
//! The contract between offline training and Rust serving is "an ONNX artifact
//! plus its `feature_version`" (§20.1), which means everything specific to
//! *how* a model was trained stops here: the rest of the platform sees an
//! [`InferenceEngine`] and a [`Score`].
//!
//! # Loaded once, at boot, link-or-fail
//!
//! [`OrtEngine::load`] is the whole effectful shell. It reads the artifact,
//! digests it, checks it against the pinned digest, resolves the trained
//! feature version through `ml-features`'s registry, builds the sessions, and
//! then validates the *graph itself* against the descriptor — input arity,
//! element type, and that the configured output exists and is a float tensor.
//!
//! Those are all *static* checks, and static checks alone would leave the
//! claim overstated: a graph exported with a dynamic feature dimension
//! (`dims=[None, None]`, which is what a plain `skl2onnx` export produces)
//! declares nothing to check, and neither the configured output `element`
//! index nor the `Squash` range can be verified without a number to read. So
//! `load` finishes by running **one probe inference on a zero vector** and
//! reading a score out of it end to end. Three failures that would otherwise
//! surface at the first block become one refused boot.
//!
//! Every one of those is a deployment fault that no retry fixes. Nothing about
//! a model is discovered at block time.
//!
//! # The runtime is loaded, not linked
//!
//! `ort` is built with `load-dynamic` (see this crate's manifest): the ONNX
//! Runtime shared library is `dlopen`ed at boot from
//! [`OrtConfig::dylib_path`] / `ORT_DYLIB_PATH`. That keeps `cargo build`
//! hermetic — no CDN download in a build script, no C++ toolchain — at the
//! cost of making the runtime's presence a deployment fact. [`ensure_runtime`]
//! turns a missing or too-old library into a typed error, because `ort`'s own
//! lazy path *panics* on it, and a panic inside a rayon worker on the fast
//! path is a much worse way to learn the image is missing a dylib.
//!
//! # Concurrency
//!
//! Inference runs inside the detection scheduler's rayon fan-out (§15), but
//! `ort` requires `&mut Session` — ONNX Runtime's per-session state is not
//! thread-safe, and its own guidance is one session per thread. So the engine
//! holds a pool of independently-locked sessions and hands out whichever is
//! free ([`OrtConfig::sessions`]), rather than funnelling a parallel fan-out
//! through one mutex.

mod config;
mod graph;
mod runtime;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use ml_features::FeatureVector;
use ort::session::Session;

use crate::artifact::{ArtifactError, ModelArtifact};
use crate::descriptor::{ModelDescriptor, SkewError};
use crate::engine::{InferenceEngine, InferenceError, InferenceErrorKind, Score};

use config::RowError;
use graph::{build_sessions, check_input, resolve_output, smoke_inference};

pub use config::{OrtConfig, OutputMapping, OutputRef, Squash};
pub use runtime::ensure_runtime;

/// An `InferenceEngine` backed by ONNX Runtime.
pub struct OrtEngine {
    descriptor: ModelDescriptor,
    /// Independently-locked sessions — see the module docs on concurrency.
    sessions: Vec<Mutex<Session>>,
    /// Round-robin cursor. Only a hint: contention falls back to blocking on
    /// the session it names, so a wrapping `usize` needs no synchronisation
    /// beyond `Relaxed`.
    cursor: AtomicUsize,
    /// The graph output carrying the score, resolved from config to a name at
    /// boot so the hot path never re-resolves it.
    output_name: String,
    output: OutputMapping,
    artifact_path: PathBuf,
}

impl OrtEngine {
    /// Load `config`'s artifact and stand up its sessions. See the module docs
    /// — every failure here is a refused boot.
    pub fn load(config: OrtConfig) -> Result<Self, OrtLoadError> {
        let model_id = config.model_id.clone();
        let fail = |source: OrtLoadKind| OrtLoadError {
            model_id: model_id.clone(),
            source,
        };

        ensure_runtime(config.dylib_path.as_deref()).map_err(&fail)?;

        let artifact = ModelArtifact::load(&config.artifact_path)
            .map_err(|e| fail(OrtLoadKind::Artifact(e)))?;
        if let Some(expected) = &config.expected_artifact {
            artifact
                .verify(expected)
                .map_err(|e| fail(OrtLoadKind::Artifact(e)))?;
        }

        let descriptor = ModelDescriptor::new(
            &config.model_id,
            artifact.digest(),
            config.feature_version,
            config.granularity,
        )
        .map_err(|e| fail(OrtLoadKind::Skew(e)))?;

        let sessions = build_sessions(&artifact, config.sessions, config.intra_threads)
            .map_err(|message| fail(OrtLoadKind::Session { message }))?;
        // Built from a `NonZeroUsize` count, so index 0 exists — the graph
        // checks can borrow it without an emptiness dance.
        let mut probe = sessions[0].lock().expect("freshly built, never locked");
        check_input(probe.inputs(), &descriptor).map_err(&fail)?;
        let output_name = resolve_output(probe.outputs(), &config.output.output).map_err(&fail)?;
        let probe_score = smoke_inference(
            &mut probe,
            descriptor.input_len(),
            &output_name,
            &config.output,
        )
        .map_err(&fail)?;
        drop(probe);

        tracing::info!(
            model_id = %descriptor.model_id(),
            artifact = %descriptor.artifact(),
            artifact_bytes = artifact.len(),
            feature_version = %descriptor.feature_version(),
            current_feature_version = descriptor.is_current_feature_version(),
            input_len = descriptor.input_len(),
            output = %output_name,
            squash = ?config.output.squash,
            sessions = config.sessions.get(),
            model_digest = %descriptor.content_hash_hex(),
            %probe_score,
            "loaded ONNX model"
        );

        Ok(Self {
            descriptor,
            sessions,
            cursor: AtomicUsize::new(0),
            output_name,
            output: config.output,
            artifact_path: config.artifact_path,
        })
    }

    /// Where this engine's artifact was read from — provenance for the health
    /// surface; the digest in [`descriptor`](InferenceEngine::descriptor) is
    /// the identity.
    pub fn artifact_path(&self) -> &Path {
        &self.artifact_path
    }

    /// How many sessions this engine can run concurrently.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// A free session if there is one, else block on the next in rotation.
    fn acquire(&self) -> Result<MutexGuard<'_, Session>, InferenceError> {
        let start = self.cursor.fetch_add(1, Ordering::Relaxed);
        for offset in 0..self.sessions.len() {
            let i = start.wrapping_add(offset) % self.sessions.len();
            match self.sessions[i].try_lock() {
                Ok(guard) => return Ok(guard),
                // Busy: try the next one. Poisoned: skip it for good — a
                // session whose last `Run` panicked has unknown native state,
                // and reusing it is how a crash becomes a corruption.
                Err(_) => continue,
            }
        }
        let i = start % self.sessions.len();
        self.sessions[i].lock().map_err(|_| {
            self.backend_err("every ONNX session is poisoned (a previous inference panicked)")
        })
    }

    /// Attach this engine's model id to an error kind — the identity half of
    /// the `InferenceError` split, in one place.
    fn err(&self, kind: impl Into<InferenceErrorKind>) -> InferenceError {
        InferenceError::new(self.descriptor.model_id(), kind)
    }

    fn backend_err(&self, message: impl Into<String>) -> InferenceError {
        self.err(InferenceErrorKind::Backend(message.into()))
    }

    fn malformed(&self, message: impl Into<String>) -> InferenceError {
        self.err(InferenceErrorKind::MalformedOutput(message.into()))
    }

    /// Attach this model's identity to a row-reading failure — the pure
    /// mapping itself lives in [`OutputMapping::score`].
    fn read_row(&self, row: &[f32]) -> Result<Score, InferenceError> {
        self.output.score(row).map_err(|e| match e {
            RowError::TooShort { width, element } => self.malformed(format!(
                "output {:?} rows have {width} element(s); this deployment reads element {element}",
                self.output_name
            )),
            RowError::NotAConfidence(source) => self.err(source),
        })
    }
}

impl InferenceEngine for OrtEngine {
    fn descriptor(&self) -> &ModelDescriptor {
        &self.descriptor
    }

    fn infer(&self, features: &FeatureVector) -> Result<Score, InferenceError> {
        let mut scores = self.infer_batch(std::slice::from_ref(features))?;
        scores
            .pop()
            .ok_or_else(|| self.malformed("a one-row batch produced no score"))
    }

    /// One `[N, features]` call for the whole block rather than N calls — the
    /// §17 amortisation discipline applied to the runtime boundary (and the
    /// reason `ml-features` hands out `all_tx_vectors`).
    fn infer_batch(&self, features: &[FeatureVector]) -> Result<Vec<Score>, InferenceError> {
        if features.is_empty() {
            return Ok(Vec::new());
        }
        let width = self.descriptor.input_len();
        let mut flat = Vec::with_capacity(features.len() * width);
        for vector in features {
            // Checked per vector, before anything is copied: the skew rule is
            // about *this* vector, and a batch where one row came from the
            // wrong extractor must not be silently scored.
            self.descriptor
                .accepts(vector)
                .map_err(|skew| self.err(skew))?;
            flat.extend(vector.values().iter().map(|&v| v as f32));
        }

        let shape = vec![features.len() as i64, width as i64];
        let input = ort::value::Tensor::from_array((shape, flat))
            .map_err(|e| self.backend_err(format!("building the input tensor: {e}")))?;

        let mut session = self.acquire()?;
        let outputs = session
            .run(ort::inputs![input])
            .map_err(|e| self.backend_err(e.to_string()))?;
        let value = outputs.get(&self.output_name).ok_or_else(|| {
            self.malformed(format!("output {:?} absent from the run", self.output_name))
        })?;
        let (shape, data) = value.try_extract_tensor::<f32>().map_err(|e| {
            self.malformed(format!(
                "output {:?} is not an f32 tensor: {e}",
                self.output_name
            ))
        })?;

        let rows = features.len();
        if data.is_empty() || data.len() % rows != 0 {
            return Err(self.malformed(format!(
                "output {:?} has shape {:?} ({} values) for a batch of {rows} — not a whole \
                 number of non-empty rows",
                self.output_name,
                shape.to_vec(),
                data.len(),
            )));
        }
        // Collected before the guard drops: `data` borrows the session's outputs.
        data.chunks_exact(data.len() / rows)
            .map(|row| self.read_row(row))
            .collect()
    }
}

impl std::fmt::Debug for OrtEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrtEngine")
            .field("descriptor", &self.descriptor)
            .field("sessions", &self.sessions.len())
            .field("output_name", &self.output_name)
            .field("output", &self.output)
            .finish()
    }
}

/// A model could not be brought up. Boot-time only, and always a deployment or
/// artifact fault — the reason `load` is called once at boot and never retried.
#[derive(Debug, thiserror::Error)]
#[error("loading ONNX model {model_id}")]
pub struct OrtLoadError {
    pub model_id: String,
    #[source]
    pub source: OrtLoadKind,
}

/// What went wrong loading a model. Split from [`OrtLoadError`] so the model
/// id is attached once rather than repeated in every variant.
#[derive(Debug, thiserror::Error)]
pub enum OrtLoadKind {
    /// The ONNX Runtime shared library is missing, unreadable, or older than
    /// the version `ort` was built against. An image/deployment problem.
    #[error(
        "ONNX Runtime could not be loaded from {path}: {message} — install libonnxruntime in the \
         image and point ORT_DYLIB_PATH (or the model's `dylib_path`) at it"
    )]
    Runtime { path: PathBuf, message: String },

    #[error(transparent)]
    Artifact(#[from] ArtifactError),

    #[error(transparent)]
    Skew(#[from] SkewError),

    /// ONNX Runtime rejected the artifact (a corrupt or unsupported graph).
    #[error("ONNX Runtime could not create a session: {message}")]
    Session { message: String },

    /// The graph loaded, but doesn't match what this deployment declared.
    #[error("model graph does not match this deployment: {0}")]
    Graph(String),

    /// The boot probe inference failed — see [`smoke_inference`]. Separate
    /// from [`Graph`](Self::Graph) because it is a *runtime* disagreement, not
    /// a declared-shape one, and the operator's next step differs.
    #[error("the model did not survive its boot probe: {message}")]
    Probe { message: String },

    /// A second model asked for a different ONNX Runtime library than the one
    /// already loaded in this process — see [`runtime_decision`].
    #[error(
        "ONNX Runtime is already loaded from {active}, but this model asks for {requested}; one \
         process loads exactly one runtime, so give every model the same dylib_path (or none)"
    )]
    RuntimeConflict { requested: PathBuf, active: PathBuf },
}

#[cfg(test)]
mod tests {
    //! `load`'s own decisions, in order — the runtime guard, the artifact pin,
    //! the skew resolution. The graph checks moved to [`super::graph`] and the
    //! runtime resolution to [`super::runtime`], each next to the code it
    //! covers; neither needs a live ONNX Runtime, and neither does this.

    use super::*;
    use crate::artifact::ArtifactDigest;
    use crate::test_support::TempArtifact;
    use ml_features::{FeatureVersion, Granularity};
    use std::num::NonZeroUsize;

    #[test]
    fn a_missing_runtime_is_a_typed_error_not_a_panic() {
        // The trap this pins: `ort` resolves its dylib lazily and `.expect()`s
        // the result, so without `ensure_runtime` a missing library becomes a
        // panic inside a rayon worker at block time. It is also the *first*
        // thing `load` does, which is what this asserts by reaching it with an
        // artifact that would fail every later check.
        let artifact = TempArtifact::with_bytes("runtime", b"not-really-onnx");
        let err = OrtEngine::load(OrtConfig {
            model_id: "anomaly-gbdt".into(),
            artifact_path: artifact.path().to_path_buf(),
            expected_artifact: None,
            feature_version: ml_features::FEATURE_VERSION,
            granularity: Granularity::Block,
            output: OutputMapping::default(),
            sessions: NonZeroUsize::MIN,
            intra_threads: NonZeroUsize::MIN,
            dylib_path: Some(PathBuf::from("/nonexistent/libonnxruntime.so")),
        })
        .unwrap_err();

        assert_eq!(err.model_id, "anomaly-gbdt");
        assert!(matches!(err.source, OrtLoadKind::Runtime { .. }), "{err:?}");
        assert!(err.source.to_string().contains("ORT_DYLIB_PATH"));
    }

    #[test]
    fn a_swapped_artifact_is_refused() {
        let artifact = TempArtifact::with_bytes("swapped", b"weights-v2");
        let loaded = ModelArtifact::load(artifact.path()).unwrap();
        let err = OrtLoadKind::from(
            loaded
                .verify(&ArtifactDigest::of(b"weights-v1"))
                .unwrap_err(),
        );
        assert!(matches!(err, OrtLoadKind::Artifact(_)), "{err:?}");
    }

    #[test]
    fn a_model_trained_on_an_unshippable_feature_version_cannot_be_described() {
        let err = ModelDescriptor::new(
            "anomaly-gbdt",
            ArtifactDigest::of(b"w"),
            FeatureVersion(404),
            Granularity::Block,
        )
        .unwrap_err();
        // And that it converts into the boot error the loader reports.
        assert!(OrtLoadKind::from(err).to_string().contains("v404"));
    }
}
