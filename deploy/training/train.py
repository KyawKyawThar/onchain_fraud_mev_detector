#!/usr/bin/env python3
"""Train one of the §20.2 models from a `dataset export` Parquet file and emit
a serving bundle: an ONNX artifact, its training-window baseline, and the
`anomaly.json` that names them.

Run it twice — once per role — into the same output directory:

    train.py --role supervised --dataset tx-rows.parquet   --out bundle/
    train.py --role novelty    --dataset block-rows.parquet --out bundle/

Each run fills in its own half of `anomaly.json` and leaves the other half
alone, so the two compose into one bundle.

Five things here are decisions rather than defaults, and each is commented
where it happens:

1. The feature order comes from the Parquet file, never from a list in this
   script. `dataset` writes one column per feature *in schema order*, named as
   the schema names it, so the file is the authority and this script cannot
   drift from it.
2. The train/test split is **time-ordered**, not random. Rows from one block —
   or one incident — would otherwise land on both sides and report a precision
   the model does not have.
3. The baseline is computed from the **training rows only**, and with robust
   statistics (median / MAD), because it is what serving-side explanations are
   measured against.
4. Every export is **verified by running it** through the same ONNX Runtime
   version production ships, and compared against the fitted estimator.
5. The output mapping in `anomaly.json` is read off the exported graph, not
   assumed. Both estimators emit two outputs; picking the wrong one is a boot
   failure at best and a plausible-but-wrong score at worst.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import sys
import tempfile
from pathlib import Path

import numpy as np
import onnx
import onnxruntime as ort
import pyarrow.parquet as pq
from skl2onnx import to_onnx
from skl2onnx.common.data_types import FloatTensorType
from sklearn.ensemble import GradientBoostingClassifier, IsolationForest
from sklearn.metrics import average_precision_score, precision_recall_fscore_support, roc_auc_score

# The provenance columns `dataset`'s Parquet sink writes before the feature
# columns (crates/dataset/src/sink/parquet.rs, PROVENANCE_COLUMNS). Everything
# in the file that is *not* one of these is a feature, in file order. Kept as a
# set rather than a count so adding a provenance column upstream surfaces as a
# feature-count mismatch here (and, failing that, as an arity error at boot)
# rather than silently shifting the matrix.
PROVENANCE_COLUMNS = {
    "dataset_id", "trigger_event_id", "chain", "block_number", "block_hash",
    "occurred_at", "detector_id", "detector_version", "detector_config_hash",
    "tx_hash", "alert_id", "binding", "fidelity", "feature_version",
    "granularity", "schema_hash", "label", "outcome", "raw_confidence",
    "profit", "victim_loss",
}

# Scale factor turning a MAD into a sigma-equivalent for normal data
# (1 / Phi^-1(0.75)). Must match ml_features::MAD_TO_SIGMA exactly, or every
# served deviation is off by a constant factor.
MAD_TO_SIGMA = 1.482602218505602

ROLE_GRANULARITY = {"supervised": "tx", "novelty": "block"}

# The frozen `ml-features` v1 schemas, used **only** by `self-test` so the
# bundle it produces is one the serving side actually accepts — which turns
# `train self-test` + `detection check-models` into a real end-to-end gate for
# the whole pipeline, with no dataset and no cluster.
#
# Hardcoding these is safe precisely because a shipped feature version is
# frozen forever: a changed name is a new version module, never an edit (see
# crates/ml-features/src/v1/mod.rs). Real training never reads this — it takes
# the names and their order from the Parquet file, which is the authority.
V1_BLOCK_FEATURES = [
    "tx_count_log", "enriched_tx_fraction", "contract_creation_fraction",
    "distinct_sender_fraction", "top_sender_tx_share", "repeat_sender_tx_fraction",
    "gas_known_fraction", "gas_price_gwei_log_mean", "gas_price_gwei_log_std",
    "head_gas_premium", "gas_used_log_mean", "swap_count_log", "transfer_count_log",
    "swap_usd_volume_log", "priced_swap_fraction", "transfer_usd_volume_log",
    "priced_transfer_fraction", "max_transfer_usd_log", "flow_concentration",
    "distinct_pool_count_log", "swaps_per_pool", "top_pool_swap_share",
    "pool_round_trip_fraction", "max_pool_impact_log",
]
V1_TX_FEATURES = [
    "position_in_block", "is_enriched", "is_contract_creation", "swap_count_log",
    "transfer_count_log", "sender_block_tx_share", "gas_known", "gas_price_gwei_log",
    "gas_price_vs_block_median", "gas_used_log", "swap_in_usd_log",
    "priced_swap_fraction", "transfer_usd_log", "max_transfer_usd_log",
    "distinct_pool_count_log", "distinct_token_count_log", "swap_chain_overlap",
    "self_pool_round_trip", "max_pool_impact_log",
]


class TrainingError(Exception):
    """A refusal. Every one of these is a bad input or an unusable dataset —
    never a transient condition, so the caller's only response is to fix it."""


# ──────────────────────────────────────────────────────────────────────
# Loading
# ──────────────────────────────────────────────────────────────────────

@dataclasses.dataclass(frozen=True)
class Dataset:
    """A loaded export: the feature matrix plus the provenance every artifact
    derived from it has to carry."""

    features: np.ndarray          # float32 [n_rows, n_features], schema order
    labels: np.ndarray | None     # int [n_rows] — None when unlabeled
    feature_names: list[str]
    feature_version: int
    granularity: str
    schema_hash: str
    dataset_ids: list[str]
    n_rows: int


def load_dataset(path: Path, keep_bindings: set[str] | None) -> Dataset:
    table = pq.read_table(path)
    if table.num_rows == 0:
        raise TrainingError(f"{path} has no rows")

    names = table.schema.names
    feature_names = [n for n in names if n not in PROVENANCE_COLUMNS]
    if not feature_names:
        raise TrainingError(
            f"{path} has no feature columns — is this a `dataset export` Parquet file?"
        )

    # One dataset, one schema. Mixing feature versions or granularities in a
    # single training run is exactly the serving/training skew §20.5 exists to
    # prevent, and it is silent: the matrices are the same width often enough
    # to train "successfully".
    def one(column: str) -> object:
        values = set(table.column(column).to_pylist())
        if len(values) != 1:
            raise TrainingError(
                f"{path} mixes {len(values)} distinct {column} values ({sorted(values)[:4]}…) — "
                f"train one schema at a time (§20.5)"
            )
        return values.pop()

    feature_version = int(one("feature_version"))
    granularity = str(one("granularity"))
    schema_hash = str(one("schema_hash"))

    keep = np.ones(table.num_rows, dtype=bool)
    if keep_bindings is not None:
        binding = np.array(table.column("binding").to_pylist())
        keep &= np.isin(binding, list(keep_bindings))
        if not keep.any():
            raise TrainingError(
                f"no rows left after --binding {sorted(keep_bindings)} — "
                f"the file holds {sorted(set(binding))}"
            )

    # Rows come out of `dataset` in replay order, which is time order; sort
    # anyway so the split below cannot depend on that staying true.
    occurred_at = np.array(table.column("occurred_at").to_pylist())
    order = np.argsort(occurred_at[keep], kind="stable")

    columns = [np.asarray(table.column(n).to_numpy(zero_copy_only=False), dtype=np.float64)
               for n in feature_names]
    matrix = np.column_stack(columns)[keep][order]

    # `ml-features` guarantees every value is finite — the extractors guard
    # every division and log, and `FeatureVector` sanitizes on construction. A
    # violation here means a corrupted file, not a modelling decision to make.
    if not np.isfinite(matrix).all():
        bad = np.array(feature_names)[~np.isfinite(matrix).all(axis=0)]
        raise TrainingError(f"{path} carries non-finite values in {list(bad)} — corrupt export")

    labels = np.asarray(table.column("label").to_numpy(zero_copy_only=False), dtype=int)[keep][order]

    return Dataset(
        features=matrix.astype(np.float32),
        labels=labels,
        feature_names=feature_names,
        feature_version=feature_version,
        granularity=granularity,
        schema_hash=schema_hash,
        dataset_ids=sorted(set(table.column("dataset_id").to_pylist())),
        n_rows=int(keep.sum()),
    )


def time_ordered_split(data: Dataset, test_fraction: float) -> tuple[slice, slice]:
    """Oldest rows train, newest rows test.

    A random split leaks: several rows commonly describe one block or one
    incident, so shuffling puts near-duplicates on both sides and inflates
    every metric. Cutting on time also matches how the model will actually be
    used — trained on the past, scoring the future.
    """
    if not 0.0 < test_fraction < 1.0:
        raise TrainingError("--test-fraction must be strictly between 0 and 1")
    cut = int(round(data.n_rows * (1.0 - test_fraction)))
    if cut < 1 or cut >= data.n_rows:
        raise TrainingError(
            f"{data.n_rows} rows cannot be split at {test_fraction:g} — need more data"
        )
    return slice(0, cut), slice(cut, data.n_rows)


# ──────────────────────────────────────────────────────────────────────
# Baseline
# ──────────────────────────────────────────────────────────────────────

def build_baseline(data: Dataset, rows: slice) -> dict:
    """The `ml_features::BaselineSnapshot` for the rows the model trained on.

    Median and MAD rather than mean and standard deviation: on-chain feature
    columns are heavy-tailed, and one $40M block inflates a variance enough to
    hide every subsequent outlier behind it. The whole point of the baseline is
    to make outliers visible.

    A column that never varied gets `spread: 0.0`, which is honest — the
    serving side floors it and clamps the resulting deviation rather than
    dividing by zero.
    """
    block = data.features[rows].astype(np.float64)
    center = np.median(block, axis=0)
    mad = np.median(np.abs(block - center), axis=0)
    spread = mad * MAD_TO_SIGMA
    return {
        "feature_version": data.feature_version,
        "granularity": data.granularity,
        "features": {
            name: {"center": float(c), "spread": float(s)}
            for name, c, s in zip(data.feature_names, center, spread)
        },
    }


# ──────────────────────────────────────────────────────────────────────
# Export + verification
# ──────────────────────────────────────────────────────────────────────

def graph_outputs(model: onnx.ModelProto) -> dict[str, int]:
    """Output name → ONNX element type, for picking the right one by evidence."""
    return {o.name: o.type.tensor_type.elem_type for o in model.graph.output}


FLOAT32 = 1


def pick_float_output(model: onnx.ModelProto, preferred: str) -> str:
    """Name the float32 output the deployment should read.

    Both estimators emit *two* outputs — a hard `label` alongside the score —
    and the label is an int64 tensor. Defaulting to output index 0 would pick
    it, which the Rust loader refuses (correctly, and only at boot). Choosing
    by name and checking the dtype here means the mapping in `anomaly.json` is
    derived from the artifact rather than assumed about it.
    """
    outputs = graph_outputs(model)
    if outputs.get(preferred) == FLOAT32:
        return preferred
    floats = [n for n, t in outputs.items() if t == FLOAT32]
    if len(floats) == 1:
        return floats[0]
    raise TrainingError(
        f"cannot tell which output carries the score: {outputs} "
        f"(expected a float32 output named {preferred!r})"
    )


def verify_export(model: onnx.ModelProto, sample: np.ndarray, expected: np.ndarray,
                  output_name: str, element: int, tolerance: float) -> float:
    """Run the exported graph through the *production* ONNX Runtime version and
    compare it against the estimator it came from.

    This is the check that makes "the artifact is the model" a fact instead of
    a hope: converters have bugs, opsets shift, and a graph that loads happily
    can still compute something else. Cheap, and it runs on every export.
    """
    session = ort.InferenceSession(model.SerializeToString(),
                                   providers=["CPUExecutionProvider"])
    (input_name,) = [i.name for i in session.get_inputs()]
    outputs = session.run(None, {input_name: sample})
    served = np.asarray(dict(zip([o.name for o in session.get_outputs()], outputs))[output_name])
    served = served.reshape(served.shape[0], -1)[:, element]

    drift = float(np.max(np.abs(served.astype(np.float64) - expected.astype(np.float64))))
    if drift > tolerance:
        raise TrainingError(
            f"the exported graph disagrees with the fitted model by {drift:.3g} "
            f"(tolerance {tolerance:g}) — do not ship this artifact"
        )
    return drift


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ──────────────────────────────────────────────────────────────────────
# The two roles
# ──────────────────────────────────────────────────────────────────────

def train_supervised(data: Dataset, args) -> tuple[onnx.ModelProto, dict, dict]:
    """Gradient-boosted trees on the flywheel labels (§20.1) — the incidents
    simulation confirmed or refuted.

    `GradientBoostingClassifier` rather than the faster `HistGradientBoosting`
    variant: skl2onnx converts it cleanly and the datasets here are small
    enough that training time is not the constraint. Correct conversion is
    worth more than a faster fit.
    """
    train, test = time_ordered_split(data, args.test_fraction)
    y_train, y_test = data.labels[train], data.labels[test]

    classes = set(np.unique(data.labels).tolist())
    if classes != {0, 1}:
        raise TrainingError(
            f"the supervised model needs both classes; this dataset has {sorted(classes)}. "
            f"Widen the replay window — confirmed incidents are the positives (§20.1)."
        )
    if len(set(np.unique(y_train).tolist())) < 2:
        raise TrainingError(
            "the training split has only one class after the time-ordered cut — "
            "widen the window or lower --test-fraction"
        )

    # Positives are rare by nature. Balanced sample weights keep the model from
    # trivially predicting "nothing happened" for a near-perfect accuracy and a
    # useless recall.
    positives = int((y_train == 1).sum())
    weights = np.where(y_train == 1, len(y_train) / (2 * positives),
                       len(y_train) / (2 * (len(y_train) - positives)))

    model = GradientBoostingClassifier(
        n_estimators=args.trees, max_depth=args.max_depth,
        learning_rate=args.learning_rate, random_state=args.seed,
    ).fit(data.features[train], y_train, sample_weight=weights)

    onx = to_onnx(model, initial_types=[("features", FloatTensorType([None, len(data.feature_names)]))],
                  options={id(model): {"zipmap": False}})
    output = pick_float_output(onx, "probabilities")

    sample = data.features[test][: args.verify_rows]
    drift = verify_export(onx, sample, model.predict_proba(sample)[:, 1], output, 1, args.tolerance)

    # Holdout metrics at the *default serving threshold*, so the numbers mean
    # what the deployed detector will do rather than what argmax would.
    scores = model.predict_proba(data.features[test])[:, 1]
    predicted = (scores >= args.report_threshold).astype(int)
    precision, recall, _, _ = precision_recall_fscore_support(
        y_test, predicted, average="binary", zero_division=0)
    metrics = {
        "rows_train": int(train.stop - train.start),
        "rows_test": int(test.stop - test.start),
        "positive_rate_train": float((y_train == 1).mean()),
        "positive_rate_test": float((y_test == 1).mean()),
        "threshold": args.report_threshold,
        "precision": float(precision),
        "recall": float(recall),
        "roc_auc": float(roc_auc_score(y_test, scores)) if len(set(y_test.tolist())) > 1 else None,
        "average_precision": float(average_precision_score(y_test, scores))
        if len(set(y_test.tolist())) > 1 else None,
        "export_max_abs_drift": drift,
    }
    mapping = {"output": {"name": output}, "element": 1, "squash": "unit"}
    return onx, mapping, metrics


def train_novelty(data: Dataset, args) -> tuple[onnx.ModelProto, dict, dict]:
    """Isolation forest over the same vectors — "nothing like the training
    window", the detector for attacks with no signature yet.

    Unsupervised, so it fits the training split as-is: the labels are not used
    and must not be, or it becomes a worse supervised model. Its
    `decision_function` is *negative* for outliers, which is why the serving
    mapping is `negated_logistic` rather than `unit`.
    """
    train, test = time_ordered_split(data, args.test_fraction)

    model = IsolationForest(
        n_estimators=args.trees, contamination=args.contamination,
        random_state=args.seed, n_jobs=-1,
    ).fit(data.features[train])

    # `ai.onnx.ml` opset 3: skl2onnx targets 4 by default for this estimator,
    # which onnxruntime does not implement yet. Stating the opset is what makes
    # the export land on a graph the pinned runtime can execute.
    onx = to_onnx(model, initial_types=[("features", FloatTensorType([None, len(data.feature_names)]))],
                  target_opset={"": args.opset, "ai.onnx.ml": 3})
    output = pick_float_output(onx, "scores")

    sample = data.features[test][: args.verify_rows]
    drift = verify_export(onx, sample, model.decision_function(sample), output, 0, args.tolerance)

    margins = model.decision_function(data.features[test])
    served = 1.0 / (1.0 + np.exp(margins))  # the negated_logistic the detector applies
    metrics = {
        "rows_train": int(train.stop - train.start),
        "rows_test": int(test.stop - test.start),
        "contamination": args.contamination,
        "holdout_outlier_rate": float((margins < 0).mean()),
        "served_score_p50": float(np.percentile(served, 50)),
        "served_score_p99": float(np.percentile(served, 99)),
        "served_score_max": float(served.max()),
        "export_max_abs_drift": drift,
    }
    mapping = {"output": {"name": output}, "element": 0, "squash": "negated_logistic"}
    return onx, mapping, metrics


# ──────────────────────────────────────────────────────────────────────
# Bundle assembly
# ──────────────────────────────────────────────────────────────────────

def write_bundle(args, data: Dataset, onx: onnx.ModelProto, mapping: dict,
                 metrics: dict, baseline: dict) -> dict:
    """Write this role's half of the bundle, preserving the other half.

    Paths inside `anomaly.json` are the paths *inside the pod* (`/models/...`),
    not wherever this ran — the bundle image mounts at the same place it was
    built at, which is what lets one document describe both.
    """
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    artifact = out / f"{args.role}.onnx"
    artifact.write_bytes(onx.SerializeToString())
    baseline_path = out / f"{args.role}-baseline.json"
    baseline_path.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n")

    digest = sha256(artifact)
    config_path = out / "anomaly.json"
    config = json.loads(config_path.read_text()) if config_path.exists() else {}
    config.setdefault("detector", {})
    config[args.role] = {
        "baseline": f"{args.mount}/{baseline_path.name}",
        "model": {
            "model_id": args.model_id or f"anomaly-{args.role}",
            "artifact_path": f"{args.mount}/{artifact.name}",
            # Pinned by construction. §20.2 notes a first deploy has nothing to
            # pin, but the script that *made* the artifact knows its digest —
            # so the bundle ships pinned and a later hand-swap is a refused
            # boot rather than a silent change of behaviour.
            "expected_artifact": digest,
            "feature_version": data.feature_version,
            "granularity": data.granularity,
            # One session per rayon worker for a per-transaction model; a
            # block-level model is called once per block and needs one.
            "sessions": 8 if data.granularity == "tx" else 1,
            "output": mapping,
        },
    }
    config_path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n")

    # The record you attach when promoting a model: what it was trained on,
    # how it scored, and the identity it will serve under.
    report_path = out / f"{args.role}-training-report.json"
    report = {
        "role": args.role,
        "model_id": config[args.role]["model"]["model_id"],
        "artifact_sha256": digest,
        "feature_version": data.feature_version,
        "granularity": data.granularity,
        "schema_hash": data.schema_hash,
        "feature_names": data.feature_names,
        "dataset_ids": data.dataset_ids,
        "rows": data.n_rows,
        "seed": args.seed,
        "metrics": metrics,
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


# ──────────────────────────────────────────────────────────────────────
# Self-test
# ──────────────────────────────────────────────────────────────────────

def self_test(args) -> int:
    """Run the whole pipeline on synthetic rows shaped like a real export.

    Not a substitute for training on real data — it is the check that *this
    image* works: that the pins convert, that the exports verify against the
    production runtime, and that the bundle it writes is well-formed. Worth
    running in CI whenever the image changes, because every failure it catches
    is one that would otherwise appear the first time someone had a dataset in
    front of them.
    """
    import pyarrow as pa

    with tempfile.TemporaryDirectory() as tmp:
        failures = []
        # One fixture per role at its natural granularity — 19 features for a
        # per-transaction schema, 24 for a block one, matching v1 — so the
        # check exercises the pairing a real deployment uses.
        for role, granularity, names in (("supervised", "tx", V1_TX_FEATURES),
                                         ("novelty", "block", V1_BLOCK_FEATURES)):
            path = _write_fixture(Path(tmp) / f"{role}.parquet", granularity, names, args.seed)
            args.role, args.dataset = role, path
            try:
                run_one(args)
            except TrainingError as err:
                failures.append(f"{role}: {err}")
        if failures:
            for failure in failures:
                print(f"self-test FAILED — {failure}", file=sys.stderr)
            return 1
    print("\nself-test passed: both roles trained, exported, and verified "
          "against the production ONNX Runtime.")
    return 0


def _write_fixture(path: Path, granularity: str, names: list[str], seed: int) -> Path:
    """Synthetic rows in exactly the shape `dataset export --parquet` writes,
    carrying the real v1 feature names so the resulting bundle is servable."""
    import pyarrow as pa

    rng = np.random.default_rng(seed)
    n_rows, n_features = 600, len(names)
    features = rng.normal(size=(n_rows, n_features))
    # A learnable signal, so the supervised half exercises a real fit.
    labels = ((features[:, 0] + rng.normal(scale=0.4, size=n_rows)) > 1.0).astype(int)

    columns = {
        "dataset_id": pa.array(["self-test"] * n_rows),
        "trigger_event_id": pa.array([f"{i:032x}" for i in range(n_rows)]),
        "chain": pa.array([1] * n_rows, pa.int64()),
        "block_number": pa.array(list(range(n_rows)), pa.int64()),
        "block_hash": pa.array(["0x00"] * n_rows),
        "occurred_at": pa.array(list(range(n_rows)), pa.int64()),
        "detector_id": pa.array(["sandwich"] * n_rows),
        "detector_version": pa.array(["1.2.0"] * n_rows),
        "detector_config_hash": pa.array(["deadbeef"] * n_rows),
        "tx_hash": pa.array(["0x01"] * n_rows),
        "alert_id": pa.array([None] * n_rows, pa.string()),
        "binding": pa.array(["exact"] * n_rows),
        "fidelity": pa.array(["full"] * n_rows),
        "feature_version": pa.array([1] * n_rows, pa.int32()),
        "granularity": pa.array([granularity] * n_rows),
        "schema_hash": pa.array(["self-test-schema"] * n_rows),
        "label": pa.array(labels.tolist(), pa.int32()),
        "outcome": pa.array(["confirmed"] * n_rows),
        "raw_confidence": pa.array([0.8] * n_rows, pa.float64()),
        "profit": pa.array([0.0] * n_rows, pa.float64()),
        "victim_loss": pa.array([0.0] * n_rows, pa.float64()),
    }
    for i, name in enumerate(names):
        columns[name] = pa.array(features[:, i].tolist(), pa.float64())

    pq.write_table(pa.table(columns), path)
    return path


# ──────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────

def run_one(args) -> dict:
    data = load_dataset(Path(args.dataset), args.binding)

    expected = ROLE_GRANULARITY[args.role]
    if data.granularity != expected and not args.allow_granularity_mismatch:
        raise TrainingError(
            f"--role {args.role} normally trains on {expected}-granularity rows but "
            f"{args.dataset} holds {data.granularity} rows. The detector reads granularity "
            f"from the model descriptor, so this is legal — pass "
            f"--allow-granularity-mismatch if you mean it."
        )

    trainer = train_supervised if args.role == "supervised" else train_novelty
    onx, mapping, metrics = trainer(data, args)
    train, _ = time_ordered_split(data, args.test_fraction)
    report = write_bundle(args, data, onx, mapping, metrics, build_baseline(data, train))

    print(f"\n── {args.role} ────────────────────────────────────────")
    print(f"   rows           {data.n_rows} ({data.granularity}, feature schema v{data.feature_version})")
    print(f"   features       {len(data.feature_names)} in schema order")
    print(f"   artifact       {args.role}.onnx  sha256={report['artifact_sha256']}")
    print(f"   output mapping {json.dumps(mapping)}")
    for key, value in metrics.items():
        print(f"   {key:<22} {value}")
    return report


def parse_args(argv: list[str]):
    parser = argparse.ArgumentParser(
        description="Train a §20.2 model from a `dataset export` Parquet file into a serving bundle.")
    parser.add_argument("mode", nargs="?", default="train", choices=["train", "self-test"],
                        help="`train` (default) or `self-test` — synthetic end-to-end check of this image")
    parser.add_argument("--role", choices=sorted(ROLE_GRANULARITY),
                        help="which model to train")
    parser.add_argument("--dataset", help="Parquet file written by `dataset export --parquet`")
    parser.add_argument("--out", default="bundle", help="bundle directory to write (default: bundle)")
    parser.add_argument("--mount", default="/models",
                        help="where the bundle is mounted in the pod; the paths written into "
                             "anomaly.json (default: /models)")
    parser.add_argument("--model-id", help="deployment name (default: anomaly-<role>)")
    parser.add_argument("--binding", type=lambda s: set(s.split(",")),
                        help="comma-separated trigger→alert bindings to keep (default: whatever the "
                             "export already gated to)")
    parser.add_argument("--test-fraction", type=float, default=0.2,
                        help="newest fraction of rows held out, time-ordered (default: 0.2)")
    parser.add_argument("--trees", type=int, default=200)
    parser.add_argument("--max-depth", type=int, default=3)
    parser.add_argument("--learning-rate", type=float, default=0.1)
    parser.add_argument("--contamination", default="auto",
                        help="isolation-forest contamination: 'auto' or a float (default: auto)")
    parser.add_argument("--report-threshold", type=float, default=0.8,
                        help="threshold the reported precision/recall are measured at; match the "
                             "deployment's supervised_min_score (default: 0.8)")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--opset", type=int, default=18)
    parser.add_argument("--verify-rows", type=int, default=256)
    parser.add_argument("--tolerance", type=float, default=1e-5,
                        help="max allowed |exported - fitted| before the artifact is refused")
    parser.add_argument("--allow-granularity-mismatch", action="store_true")
    args = parser.parse_args(argv)

    if args.contamination != "auto":
        args.contamination = float(args.contamination)
    if args.mode == "train":
        missing = [f"--{n}" for n in ("role", "dataset") if getattr(args, n) is None]
        if missing:
            parser.error(f"train needs {' and '.join(missing)}")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        if args.mode == "self-test":
            return self_test(args)
        run_one(args)
        print(f"\nbundle written to {args.out}. Validate it before deploying:")
        print(f"  docker run --rm -v \"$(realpath {args.out})\":/models:ro \\")
        print(f"    ghcr.io/<org>/<repo>/detection:latest check-models /models/anomaly.json")
        return 0
    except TrainingError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
