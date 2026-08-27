# Training the ML detector's models (§20.1 → §20.2)

This is the Python half of the ONNX boundary. It turns a `dataset export`
Parquet file into a **serving bundle** — artifact, baseline, and the
`anomaly.json` that names them — in exactly the shape
[`deploy/models`](../models/) packages and
[`crates/detection/src/ml.rs`](../../crates/detection/src/ml.rs) loads.

Training happens in a container rather than a virtualenv because a model is an
audit artifact: `DetectorTriggered` events are attributable to an exact model
identity, so the toolchain that produced the model has to be reproducible too.
Every dependency is pinned, and `onnxruntime` is pinned to the *same version
production serves*, which is what lets the script verify its own export.

## The whole loop

```sh
# 0. build the images (once)
just train-build                      # the training image
just k8s-build-images                 # includes the ML-capable detection image

# 1. materialise a labeled window — the flywheel (§20.1).
#    Two exports, because the two models consume different granularities.
cargo run -p dataset -- export --from 2026-07-01T00:00:00Z --to 2026-08-01T00:00:00Z \
    --granularity tx    --parquet out/tx-rows.parquet
cargo run -p dataset -- export --from 2026-07-01T00:00:00Z --to 2026-08-01T00:00:00Z \
    --granularity block --parquet out/block-rows.parquet

# 2. train each role into one bundle directory
just train supervised out/tx-rows.parquet    out/bundle
just train novelty    out/block-rows.parquet out/bundle

# 3. validate against the REAL loader before anything is published
just check-models-image out/bundle

# 4. package and roll out — the tag is the model version
just k8s-build-model-image out/bundle 2026-08-27
```

Step 3 is the gate. It runs the same code path boot takes — artifact digests,
the pinned-digest check, §20.5 feature-version skew, graph conformance, a probe
inference, and the baseline/schema pairing — and prints the `config_hash` the
bundle will stamp onto every event it produces. Record that hash when promoting
a model; it is what ties historical evidence to these exact weights.

## Checking the pipeline without data

```sh
just train-self-test
```

Trains both roles on synthetic rows shaped like a real export and carrying the
real frozen v1 feature names, exports both, and verifies each against the
production ONNX Runtime. It proves *this image* works — that the pins convert,
that the opsets are executable, and that the bundle it writes is well-formed —
without a dataset or a cluster. The bundle it produces is servable, so
`check-models` accepts it: the two commands together are an end-to-end check of
the entire ML path.

## What the script decides, and why

- **Feature order comes from the Parquet file, never from a list in the
  script.** `dataset` writes one column per feature *in schema order*, named as
  the schema names it, so the file is the authority. A matrix assembled in any
  other order yields a model that is wrong in a way nothing downstream can
  detect — the arity still matches, so neither the loader nor the skew check
  would notice.
- **The train/test split is time-ordered, not random.** Several rows commonly
  describe one block or one incident; shuffling puts near-duplicates on both
  sides and reports a precision the model does not have. Cutting on time also
  matches how the model is used: trained on the past, scoring the future.
- **The baseline is computed from the training rows only**, with median and MAD
  (scaled by the same constant as `ml_features::MAD_TO_SIGMA`). Robust
  statistics because on-chain feature columns are heavy-tailed and one $40M
  block would inflate a variance enough to hide every later outlier — the point
  of a baseline is to make outliers visible.
- **Every export is verified by running it** through the pinned ONNX Runtime
  and compared against the fitted estimator; a disagreement past `--tolerance`
  refuses the artifact. Converters have bugs and opsets shift, and a graph that
  loads happily can still compute something else.
- **The output mapping is read off the exported graph, not assumed.** Both
  estimators emit two outputs — a hard `label` (int64) beside the float score —
  and the label sorts first, so a config that defaults to output index 0 picks
  the wrong one.
- **The artifact digest is written into `expected_artifact`.** §20.2 notes a
  first deploy has nothing to pin, but the script that *made* the artifact
  knows its digest, so the bundle ships pinned and a later hand-swap is a
  refused boot.
- **Mixed schemas are refused.** More than one `feature_version`,
  `granularity`, or `schema_hash` in one file is the §20.5 skew this whole
  layer exists to prevent, and it is silent — the matrices are often the same
  width.

## Models

| Role | Estimator | Granularity | Claim |
|---|---|---|---|
| `supervised` | `GradientBoostingClassifier` | tx | "this looks like the things simulation confirmed" |
| `novelty` | `IsolationForest` | block | "this looks like nothing in the training window" |

`GradientBoostingClassifier` rather than the faster `HistGradientBoosting`
variant: skl2onnx converts it cleanly, and correct conversion is worth more
than a faster fit at these dataset sizes. Positives are rare, so the classifier
is fit with balanced sample weights — otherwise it predicts "nothing happened"
for a near-perfect accuracy and a useless recall.

The isolation forest is unsupervised and **must not** see the labels, or it
becomes a worse supervised model. It needs `target_opset={"ai.onnx.ml": 3}`:
skl2onnx targets 4 for this estimator by default, which onnxruntime does not
implement yet, and the failure is at export time rather than at serving.

## Reading the reports

Each run writes `<role>-training-report.json`: the dataset ids, row counts,
feature names in order, artifact digest, seed, and holdout metrics. Attach it
when promoting a model — together with the `config_hash` from `check-models`,
it is the record of what was deployed and how it scored.

Reported precision/recall are measured at `--report-threshold` (default 0.8),
which should match the deployment's `supervised_min_score`, so the numbers
describe what the detector will actually do rather than what argmax would. They
are *not* the rollout gate: promotion off `Shadow` is the backtest harness's
call, measured on the same replay the heuristic detectors are scored on.

## Options worth knowing

```
--role {supervised,novelty}   which model to train
--dataset PATH                the Parquet file from `dataset export --parquet`
--out DIR                     bundle directory (each role fills its own half)
--mount PATH                  where the bundle mounts in the pod (default /models)
--binding a,b                 keep only these trigger→alert bindings
--test-fraction F             newest fraction held out, time-ordered (0.2)
--trees / --max-depth / --learning-rate / --contamination
--report-threshold F          threshold the reported metrics are measured at
--seed N                      training seed, recorded in the report
--tolerance F                 max |exported − fitted| before the artifact is refused
```
