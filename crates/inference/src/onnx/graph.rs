//! Checking a loaded graph against the deployment that declares it, and
//! standing up the sessions that will run it.
//!
//! Everything here answers one question — *does this artifact match what this
//! deployment says it is?* — in the two ways it can be answered:
//!
//! - **statically**, from the graph's declared inlets and outlets
//!   ([`check_input`], [`resolve_output`]), which is cheap and precise but
//!   blind to anything the export left dynamic; and
//! - **dynamically**, by running it ([`smoke_inference`]), which is the only
//!   way to catch a dynamic feature dimension, a wrong output element index,
//!   or a `Squash` that doesn't land in `[0, 1]`.
//!
//! Both run at boot, from `OrtEngine::load`, and every failure is a refused
//! boot: these are deployment faults, and no retry fixes one.

use std::num::NonZeroUsize;
use std::sync::Mutex;

use ort::session::Session;
use ort::value::{Outlet, TensorElementType, ValueType};

use crate::artifact::ModelArtifact;
use crate::descriptor::ModelDescriptor;
use crate::engine::Score;

use super::config::{OutputMapping, OutputRef, RowError};
use super::OrtLoadKind;

pub(super) fn build_sessions(
    artifact: &ModelArtifact,
    count: NonZeroUsize,
    intra_threads: NonZeroUsize,
) -> Result<Vec<Mutex<Session>>, String> {
    (0..count.get())
        .map(|_| {
            let session = Session::builder()
                .map_err(|e| e.to_string())?
                .with_intra_threads(intra_threads.get())
                .map_err(|e| e.to_string())?
                // From memory, not from the path: the bytes were already read
                // and digested, and re-reading the file would let the artifact
                // change under the digest that names it.
                .commit_from_memory(artifact.bytes())
                .map_err(|e| e.to_string())?;
            Ok(Mutex::new(session))
        })
        .collect()
}

/// The graph must take exactly one `[batch, input_len]` float tensor.
pub(super) fn check_input(
    inputs: &[Outlet],
    descriptor: &ModelDescriptor,
) -> Result<(), OrtLoadKind> {
    let [input] = inputs else {
        return Err(OrtLoadKind::Graph(format!(
            "expected a single feature-matrix input, the graph declares {}: {:?}",
            inputs.len(),
            inputs.iter().map(Outlet::name).collect::<Vec<_>>()
        )));
    };
    let ValueType::Tensor { ty, shape, .. } = input.dtype() else {
        return Err(OrtLoadKind::Graph(format!(
            "input {:?} is not a tensor",
            input.name()
        )));
    };
    if *ty != TensorElementType::Float32 {
        return Err(OrtLoadKind::Graph(format!(
            "input {:?} is {ty:?}; feature vectors are fed as float32 — re-export the model with \
             a float input",
            input.name()
        )));
    }
    if shape.len() != 2 {
        return Err(OrtLoadKind::Graph(format!(
            "input {:?} has shape {:?}; a [batch, features] matrix is required",
            input.name(),
            shape.to_vec()
        )));
    }
    // -1 is ONNX's dynamic dimension: a model exported with a symbolic feature
    // count can't be checked here, only at the first run. A *fixed* count that
    // disagrees with the schema is the real find — a model trained on a
    // different feature set than the one it is being deployed against.
    let declared = shape[1];
    if declared >= 0 && declared as usize != descriptor.input_len() {
        return Err(OrtLoadKind::Graph(format!(
            "input {:?} takes {declared} features, but feature schema {} produces {} \
             (serving/training skew, §20.5)",
            input.name(),
            descriptor.feature_version(),
            descriptor.input_len()
        )));
    }
    Ok(())
}

/// Resolve the configured output to a name, failing if it isn't there or
/// isn't readable as floats.
pub(super) fn resolve_output(
    outputs: &[Outlet],
    wanted: &OutputRef,
) -> Result<String, OrtLoadKind> {
    let names = || outputs.iter().map(Outlet::name).collect::<Vec<_>>();

    let outlet = match wanted {
        OutputRef::Index(i) => outputs.get(*i).ok_or_else(|| {
            OrtLoadKind::Graph(format!(
                "{wanted} is out of range; the graph has {}: {:?}",
                outputs.len(),
                names()
            ))
        })?,
        OutputRef::Name(name) => outputs.iter().find(|o| o.name() == name).ok_or_else(|| {
            OrtLoadKind::Graph(format!("{wanted} not found; the graph has {:?}", names()))
        })?,
    };

    match outlet.dtype() {
        ValueType::Tensor {
            ty: TensorElementType::Float32,
            ..
        } => Ok(outlet.name().to_owned()),
        // The overwhelmingly common cause: a scikit-learn classifier exported
        // with ZipMap, whose probability output is a sequence of maps rather
        // than a tensor. Say so — the fix is an export flag, not a code change.
        other => Err(OrtLoadKind::Graph(format!(
            "{wanted} has type {other:?}; the score must be read from a float32 tensor. For a \
             scikit-learn classifier, re-export with `zipmap=False` so probabilities come out as \
             a tensor."
        ))),
    }
}

/// Run one inference on an all-zero vector and read a score out of it.
///
/// The dynamic half of link-or-fail. `check_input`/`resolve_output` can only
/// compare declarations; this one call additionally proves that
///
/// - the graph *runs* against a `[1, input_len]` matrix — the only way to
///   catch an arity mismatch on a model exported with a dynamic feature
///   dimension, which is the common `skl2onnx` output;
/// - the configured output really carries that many rows of readable floats;
/// - the configured `element` index exists within a row; and
/// - `Squash` maps this model's output into `[0, 1]` — so a signed margin
///   mistakenly left on `Squash::Unit` is a refused boot, not a range error at
///   the first block.
///
/// A zero vector is safe input for the model families §20.2 serves: a
/// gradient-boosted tree ensemble and an isolation forest are total over every
/// finite input, they just route to some leaf. The probe's *score* is
/// meaningless and is only logged.
pub(super) fn smoke_inference(
    session: &mut Session,
    input_len: usize,
    output_name: &str,
    output: &OutputMapping,
) -> Result<Score, OrtLoadKind> {
    let probe = |message: String| OrtLoadKind::Probe { message };

    let input =
        ort::value::Tensor::from_array((vec![1_i64, input_len as i64], vec![0.0_f32; input_len]))
            .map_err(|e| {
            probe(format!(
                "could not build a [1, {input_len}] probe tensor: {e}"
            ))
        })?;

    let outputs = session.run(ort::inputs![input]).map_err(|e| {
        probe(format!(
            "the graph did not run against a [1, {input_len}] probe vector: {e} — this \
             deployment feeds it that many features; check the model was trained on the same \
             feature schema"
        ))
    })?;

    let value = outputs
        .get(output_name)
        .ok_or_else(|| probe(format!("output {output_name:?} absent from the probe run")))?;
    let (shape, data) = value
        .try_extract_tensor::<f32>()
        .map_err(|e| probe(format!("output {output_name:?} is not an f32 tensor: {e}")))?;

    if data.is_empty() {
        return Err(probe(format!(
            "output {output_name:?} has shape {:?} and carried no values for a one-row probe",
            shape.to_vec()
        )));
    }

    output.score(data).map_err(|e| match e {
        RowError::TooShort { width, element } => probe(format!(
            "output {output_name:?} rows have {width} element(s), but this deployment reads \
             element {element}"
        )),
        RowError::NotAConfidence(source) => probe(format!(
            "{source} under squash {:?} — a signed margin needs `logistic` or \
             `negated_logistic`, not `unit`",
            output.squash
        )),
    })
}

#[cfg(test)]
mod tests {
    //! No test here creates a session: the ONNX Runtime library is a
    //! deployment artifact this repo doesn't vendor, and a test that skipped
    //! itself when the library is absent would report green while checking
    //! nothing (CI runs `#[ignore]`d tests explicitly, so hiding behind
    //! `#[ignore]` wouldn't help either). So the *static* checks are driven
    //! here with hand-built `Outlet`s describing the graphs a real `skl2onnx`
    //! export produces; `smoke_inference` needs a live runtime and is covered
    //! when the first model artifact lands, in t4.

    use super::*;
    use crate::artifact::ArtifactDigest;
    use ml_features::Granularity;
    use ort::value::{Shape, SymbolicDimensions};

    fn descriptor() -> ModelDescriptor {
        ModelDescriptor::new(
            "anomaly-gbdt",
            ArtifactDigest::of(b"weights-v1"),
            ml_features::FEATURE_VERSION,
            Granularity::Block,
        )
        .unwrap()
    }

    /// A `[batch, features]` float32 outlet — what `skl2onnx` emits for a
    /// feature-matrix input (`dims=[None, n]` ⇒ a dynamic leading dimension).
    fn matrix(name: &str, features: i64) -> Outlet {
        tensor(name, TensorElementType::Float32, [-1, features])
    }

    fn tensor(name: &str, ty: TensorElementType, dims: impl IntoIterator<Item = i64>) -> Outlet {
        let shape = Shape::new(dims);
        let symbols = SymbolicDimensions::empty(shape.len());
        Outlet::new(
            name,
            ValueType::Tensor {
                ty,
                shape,
                dimension_symbols: symbols,
            },
        )
    }

    #[test]
    fn a_conforming_graph_passes_both_checks() {
        let d = descriptor();
        let inputs = [matrix("float_input", d.input_len() as i64)];
        assert!(check_input(&inputs, &d).is_ok());

        let outputs = [
            tensor("label", TensorElementType::Int64, [-1]),
            tensor("probabilities", TensorElementType::Float32, [-1, 2]),
        ];
        assert_eq!(
            resolve_output(&outputs, &OutputRef::Name("probabilities".into())).unwrap(),
            "probabilities"
        );
    }

    #[test]
    fn a_dynamic_feature_dimension_is_accepted_here_and_left_to_the_probe() {
        // `dims=[None, None]` — nothing to check statically, and refusing it
        // would reject legitimately-exported models. `smoke_inference` is what
        // catches an actual arity mismatch behind a dynamic dimension.
        let inputs = [matrix("float_input", -1)];
        assert!(check_input(&inputs, &descriptor()).is_ok());
    }

    #[test]
    fn a_graph_trained_on_a_different_feature_count_is_refused_at_boot() {
        // The §20.5 skew check at the graph level: a model whose input arity
        // disagrees with the schema was trained on other features entirely.
        let d = descriptor();
        let inputs = [matrix("float_input", d.input_len() as i64 - 1)];
        let err = check_input(&inputs, &d).unwrap_err();
        assert!(err.to_string().contains("serving/training skew"), "{err}");
    }

    #[test]
    fn a_multi_input_or_non_float_graph_is_refused() {
        let d = descriptor();
        let two = [matrix("a", -1), matrix("b", -1)];
        assert!(check_input(&two, &d)
            .unwrap_err()
            .to_string()
            .contains("single feature-matrix input"));

        let ints = [tensor("float_input", TensorElementType::Int64, [-1, 24])];
        assert!(check_input(&ints, &d)
            .unwrap_err()
            .to_string()
            .contains("float32"));

        let rank_one = [tensor("float_input", TensorElementType::Float32, [24])];
        assert!(check_input(&rank_one, &d)
            .unwrap_err()
            .to_string()
            .contains("[batch, features]"));
    }

    #[test]
    fn a_missing_output_names_what_the_graph_does_have() {
        let outputs = [tensor("scores", TensorElementType::Float32, [-1])];
        let err = resolve_output(&outputs, &OutputRef::Name("probabilities".into())).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("probabilities"), "{message}");
        assert!(message.contains("scores"), "{message}");

        let err = resolve_output(&outputs, &OutputRef::Index(3)).unwrap_err();
        assert!(err.to_string().contains("out of range"), "{err}");
    }

    #[test]
    fn a_zipmap_output_is_refused_with_the_export_flag_that_fixes_it() {
        // The classic scikit-learn export mistake: `probabilities` comes out
        // as a sequence of maps, which is unreadable as a tensor. This is a
        // config/export problem, so the boot error says how to fix it.
        let outputs = [
            tensor("label", TensorElementType::Int64, [-1]),
            Outlet::new(
                "output_probability",
                ValueType::Sequence(Box::new(ValueType::Map {
                    key: TensorElementType::Int64,
                    value: TensorElementType::Float32,
                })),
            ),
        ];
        let err =
            resolve_output(&outputs, &OutputRef::Name("output_probability".into())).unwrap_err();
        assert!(err.to_string().contains("zipmap=False"), "{err}");
    }
}
