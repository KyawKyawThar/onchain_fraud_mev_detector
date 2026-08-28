# Model bundles for the ML detector (§20.2)

The `anomaly-v1.0` detector serves up to two models, and each needs two files:
an ONNX artifact and the training-window **baseline** its evidence is explained
against. A *bundle* is those files plus the `anomaly.json` that names them.

Bundles are not in this repository — they are build outputs of the offline
training pipeline, they are binary, and they change on a different cadence than
the code. They ship as their own tagged, immutable image
(`Dockerfile` here), which the detection pods pull through an initContainer.

## Layout

Everything lives at `/models` inside the image and at `/models` inside the pod,
so the paths in `anomaly.json` are the same in both places.

```
anomaly.json
gbdt.onnx              # supervised classifier
gbdt-baseline.json     # its training-window feature distribution
iforest.onnx           # isolation-forest novelty model
iforest-baseline.json
```

`anomaly.json` — the whole ML deployment as one document (see
[`crates/detection/src/ml.rs`](../../crates/detection/src/ml.rs)):

```json
{
  "detector": { "novelty_min_score": 0.93 },
  "supervised": {
    "baseline": "/models/gbdt-baseline.json",
    "drift": { "window": 512, "max_age_seconds": 900, "threshold": 3.0 },
    "model": {
      "model_id": "anomaly-gbdt",
      "artifact_path": "/models/gbdt.onnx",
      "expected_artifact": "9f2c…",
      "feature_version": 1,
      "granularity": "tx",
      "sessions": 8,
      "output": { "output": { "name": "probabilities" }, "element": 1, "squash": "unit" }
    }
  },
  "novelty": {
    "baseline": "/models/iforest-baseline.json",
    "model": {
      "model_id": "anomaly-iforest",
      "artifact_path": "/models/iforest.onnx",
      "feature_version": 1,
      "granularity": "block",
      "output": { "output": { "name": "scores" }, "element": 0, "squash": "negated_logistic" }
    }
  }
}
```

Both halves are optional — a deployment may serve only the novelty model — but
naming neither is a refused boot rather than a silently inert detector.

`drift` is optional too, and an omitted section means **monitored with the
shipped defaults**, not off (§20.5). A model's serving-time feature
distribution is compared against the very baseline above, and anything past
`threshold` is logged, counted, and published as a `ModelDriftDetected` event
naming the exact `(id, version, config_hash)` triple that was serving. Turning
it off takes saying so: `"drift": {"disabled": true}`.

The same baseline file does double duty — it is what an anomaly finding's "top
contributing features" are measured against *and* what drift is measured
against — which is why re-deriving one changes the deployment's `config_hash`.

The two window bounds answer different questions and you set both:

| field | default | what it decides |
|---|---|---|
| `window` | 512 vectors | how **good** a reading is — the sample size behind the median and MAD |
| `max_age_seconds` | 900 | how **soon** there is one — a partly-filled window reports anyway once it has at least 32 samples |

The age bound is not a nicety. At one block-level vector per block, 512 vectors
is roughly 100 minutes of Ethereum, so a count-only monitor is blind for the
first hour and a half after every deploy — exactly when new weights are most
likely to be wrong. A model too quiet to reach 32 samples inside `max_age`
keeps accumulating rather than publishing statistics over a handful of points;
that shows up as a flat `model_drift_windows_total`, which
`ModelDriftMonitoringSilent` alerts on.

`threshold` is exported as `model_drift_threshold{model}`, and the alert rules
compare against that gauge rather than a literal — so tuning it here reaches
the alerts without a Prometheus change.

You do not have to write this by hand — [`deploy/training`](../training/)
generates it, reading the values off the artifact it just exported. Three
fields are worth understanding anyway, because getting them wrong is quiet:

- **`output.output.name`** picks which graph output carries the score. Both
  estimators emit *two*: a hard `label` (int64) alongside the float score, and
  the label sorts first. Defaulting to index 0 therefore picks the wrong one —
  the Rust loader refuses it, correctly, but only at boot. Name it:
  `probabilities` for the classifier, `scores` for the isolation forest.
- **`squash`** declares how the raw number becomes a confidence. `unit` for a
  classifier already emitting probabilities; `negated_logistic` for an
  isolation forest, whose `decision_function` is *negative* for outliers.
  Guessing wrong is not a crash — it is a score that is out of range half the
  time and plausible the other half — so it is stated per deployment and
  exercised by a probe inference at boot.
- **`element`** picks the column within one output row: `1` for a binary
  classifier's positive class, `0` for a single-column score.

`expected_artifact` pins the artifact's SHA-256; the training script sets it
from the file it wrote, so a bundle ships pinned and a later hand-swap is a
refused boot rather than a silent change in behaviour.

## Producing a bundle

Use the training image — see [deploy/training/README.md](../training/README.md).
It reads a `dataset export` Parquet file, trains the model, derives the
baseline from the same rows, verifies the export against the ONNX Runtime
version production ships, and writes everything here in the layout above.

The contract between training and serving is *only* the ONNX file plus its
`feature_version` — so any stack that emits ONNX works. Two things it must get
right if you replace the script:

- **Feature order is schema order.** `dataset` writes one column per feature in
  schema order; a matrix assembled in any other order produces a model that is
  wrong in a way nothing downstream can detect (the arity still matches).
- **The baseline comes from the rows the model trained on**, with median/MAD
  statistics matching `ml_features::MAD_TO_SIGMA`. Deriving it from a different
  window is not an error anything can catch — it just makes every explanation
  subtly wrong.

## Building and validating

```sh
# 1. Build the bundle image. The build fails if anomaly.json references a file
#    the bundle doesn't contain.
docker build -f deploy/models/Dockerfile --build-arg BUNDLE=. \
  -t ghcr.io/<org>/<repo>/detection-models:2026-08-27 ./path/to/bundle

# 2. Validate it against the real loader *before* it reaches a cluster: this is
#    the same code path boot takes — digests, pinned-digest check, feature-
#    version skew, graph conformance, the probe inference, and the
#    baseline/schema pairing.
docker run --rm \
  -v ./path/to/bundle:/models:ro \
  ghcr.io/<org>/<repo>/detection:latest check-models /models/anomaly.json
```

`check-models` prints each model's identity and the `config_hash` the bundle
will stamp onto every `DetectorTriggered`. Record that hash when promoting a
model — it is what ties historical evidence to these exact weights — and copy
each printed artifact digest into `expected_artifact` to pin the bundle.

## Rolling it out

Enabling ML detection in a cluster is a config change, not an image rebuild:
the detection image always links the detector and carries the ONNX Runtime, and
the detector stays inert until `DETECTION_ANOMALY_CONFIG` names a bundle. Turn
it on with the kustomize component:

```sh
# deploy/k8s/overlays/<env>/kustomization.yaml
components:
  - ../../components/anomaly-detection
```

and set the bundle image there. The detector is staged `Shadow` in
[`main.rs`](../../crates/detection/src/main.rs), so it runs and is scored but
raises no customer-facing alert until the backtest gate promotes it.
