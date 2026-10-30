#!/usr/bin/env python3
"""Independently validate the invocation-boundary attack evidence bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MODES = tuple("ABCDEFG")
CONTROL_MODES = ("A", "B")
BATCHED_MODES = frozenset({"E", "G"})
EXPECTED_CONFIG = {
    "version": 1,
    "seed": 20261031,
    "trials": 30,
    "sessions": 8,
    "operations": 8,
    "epoch_ms": 100,
}
EXPECTED_CONFIG_SHA256 = "7f4434f7302c2f5b36f4b2417c4ef610c363d657bf629da09a3c2ba8ef1a1064"
EXPECTED_FEATURES = [
    "request_bytes",
    "response_bytes",
    "response_latency_ns",
    "interarrival_ns",
]
EXPECTED_ATTACK = {
    "classifier": "RandomForestClassifier",
    "n_estimators": 200,
    "max_depth": 4,
    "min_samples_leaf": 2,
    "class_weight": "balanced",
    "n_jobs": 1,
    "model_seed": 20261210,
    "positive_class": 0,
    "classification_threshold": 0.5,
    "bootstrap_resamples": 5000,
    "bootstrap_seed": 20261211,
    "bootstrap_unit": "test trial",
    "training_sessions": "0..3",
    "testing_sessions": "4..7",
}
SOURCE_FILES = (
    "Cargo.lock",
    "crates/oblivion-batcher/src/lib.rs",
    "crates/oblivion-exec/src/lib.rs",
    "crates/oblivion-harness/src/main.rs",
    "crates/oblivion-harness/src/system.rs",
    "crates/oblivion-pir/src/lib.rs",
    "crates/oblivion-store/src/lib.rs",
)


class VerificationError(ValueError):
    """An evidence input or derived result does not match the frozen study."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json(path: Path) -> dict:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot read JSON {path}") from error
    if not isinstance(value, dict):
        raise VerificationError(f"expected JSON object in {path}")
    return value


def _jsonl(path: Path) -> list[dict]:
    rows = []
    try:
        with Path(path).open("r", encoding="utf-8") as source:
            for line_number, line in enumerate(source, 1):
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise VerificationError(f"non-object JSON at {path}:{line_number}")
                rows.append(value)
    except (OSError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot read JSONL {path}") from error
    return rows


def _close(actual: object, expected: float, field: str) -> None:
    if (
        isinstance(actual, bool)
        or not isinstance(actual, (int, float))
        or not math.isfinite(float(actual))
        or not math.isclose(float(actual), expected, rel_tol=1e-12, abs_tol=1e-12)
    ):
        raise VerificationError(f"reported {field} differs from independent recomputation")


def auc(labels: list[int], scores: list[float]) -> float:
    """Compute binary ROC AUC by average ranks, including tied scores."""
    positives = sum(labels)
    negatives = len(labels) - positives
    if (
        not labels
        or positives == 0
        or negatives == 0
        or len(labels) != len(scores)
        or any(label not in (0, 1) for label in labels)
        or any(not math.isfinite(score) or not 0 <= score <= 1 for score in scores)
    ):
        raise VerificationError("AUC requires aligned binary labels and finite probability scores")
    ordered = sorted(zip(scores, labels, strict=True))
    positive_rank_sum = 0.0
    index = 0
    while index < len(ordered):
        end = index + 1
        while end < len(ordered) and ordered[end][0] == ordered[index][0]:
            end += 1
        average_rank = ((index + 1) + end) / 2
        positive_rank_sum += average_rank * sum(label for _, label in ordered[index:end])
        index = end
    return (positive_rank_sum - positives * (positives + 1) / 2) / (positives * negatives)


def _binary_metrics(labels: list[int], predictions: list[int]) -> tuple[float, float, float]:
    positives = sum(label == 0 for label in labels)
    negatives = len(labels) - positives
    if (
        not labels
        or positives == 0
        or negatives == 0
        or len(labels) != len(predictions)
        or any(prediction not in (0, 4) for prediction in predictions)
    ):
        raise VerificationError("binary metrics require aligned two-class labels and predictions")
    truth = [1 if value == 0 else 0 for value in labels]
    predicted = [1 if value == 0 else 0 for value in predictions]
    true_positive = sum(actual == 1 and guess == 1 for actual, guess in zip(truth, predicted, strict=True))
    true_negative = sum(actual == 0 and guess == 0 for actual, guess in zip(truth, predicted, strict=True))
    accuracy = sum(actual == guess for actual, guess in zip(truth, predicted, strict=True)) / len(truth)
    balanced = (true_positive / positives + true_negative / negatives) / 2
    majority = max(positives, negatives) / len(truth)
    return accuracy, balanced, majority


def _bootstrap_interval(values: list[float], seed: int, replicates: int = 5000) -> list[float]:
    data = np.asarray(values, dtype=np.float64)
    if data.size < 2:
        raise VerificationError("trial bootstrap requires at least two trial units")
    rng = np.random.default_rng(seed)
    means = rng.choice(data, size=(replicates, len(data)), replace=True).mean(axis=1)
    return [float(np.quantile(means, 0.025)), float(np.quantile(means, 0.975))]


def validate_control_scope(report: dict) -> None:
    metrics = report.get("metrics_by_mode")
    if not isinstance(metrics, dict) or not set(CONTROL_MODES) <= set(metrics):
        raise VerificationError("both positive controls must have metrics")
    passed = report.get("positive_controls_passed")
    expected_modes = set(MODES) if passed is True else set(CONTROL_MODES)
    if set(metrics) != expected_modes:
        raise VerificationError("mode scores violate the positive-control stop rule")
    expected_scope = "performed" if passed is True else "omitted_control_failure"
    if report.get("protected_scoring") != expected_scope:
        raise VerificationError("protected scoring status disagrees with control gate")
    gates = report.get("positive_control_gates")
    if not isinstance(gates, dict) or set(gates) != set(CONTROL_MODES):
        raise VerificationError("positive-control gate metadata is incomplete")
    derived = all(
        metrics[mode].get("mean_roc_auc", -1) >= 0.70
        and metrics[mode].get("roc_auc_ci95", [0])[0] > 0.50
        for mode in CONTROL_MODES
    )
    for mode in CONTROL_MODES:
        gate = gates[mode]
        if (
            gate.get("minimum_mean_auc") != 0.70
            or gate.get("minimum_lower_auc_ci95") != 0.50
            or gate.get("passed")
            != (
                metrics[mode].get("mean_roc_auc", -1) >= 0.70
                and metrics[mode].get("roc_auc_ci95", [0])[0] > 0.50
            )
        ):
            raise VerificationError("positive-control gate does not follow the frozen rule")
    if derived != passed:
        raise VerificationError("overall positive-control result does not follow the frozen rule")


def join_predictions(predictions: list[dict], private_labels: list[dict]) -> list[dict]:
    """Join evaluation truth only after accepting attacker-only predictions."""
    prediction_fields = {
        "mode",
        "trial",
        "session",
        "step",
        "score_function_0",
        "predicted_function",
    }
    truth_fields = {"mode", "trial", "session", "step", "true_function"}
    key_fields = ("mode", "trial", "session", "step")
    predicted_by_key = {}
    for row in predictions:
        if set(row) != prediction_fields:
            raise VerificationError("attacker prediction file contains truth or unknown fields")
        if (
            row["mode"] not in MODES
            or any(type(row[field]) is not int for field in ("trial", "session", "step"))
        ):
            raise VerificationError("malformed attacker prediction key")
        key = tuple(row[field] for field in key_fields)
        if key in predicted_by_key:
            raise VerificationError("duplicate attacker prediction key")
        score = row["score_function_0"]
        guess = row["predicted_function"]
        if (
            not isinstance(score, (int, float))
            or isinstance(score, bool)
            or not math.isfinite(float(score))
            or not 0 <= score <= 1
            or type(guess) is not int
            or guess not in (0, 4)
        ):
            raise VerificationError("malformed attacker prediction")
        if guess != (0 if score >= 0.5 else 4):
            raise VerificationError("prediction does not use the frozen 0.5 threshold")
        predicted_by_key[key] = row

    truth_by_key = {}
    for row in private_labels:
        if set(row) != truth_fields:
            raise VerificationError("private truth file has an invalid schema")
        if (
            row["mode"] not in MODES
            or any(type(row[field]) is not int for field in ("trial", "session", "step"))
            or type(row["true_function"]) is not int
        ):
            raise VerificationError("malformed private evaluation key")
        key = tuple(row[field] for field in key_fields)
        if key in truth_by_key or row["true_function"] not in (0, 4):
            raise VerificationError("duplicate or invalid private evaluation label")
        truth_by_key[key] = row["true_function"]
    if not predicted_by_key or predicted_by_key.keys() != truth_by_key.keys():
        raise VerificationError("predictions and private truth do not align exactly")
    joined = []
    for key in sorted(predicted_by_key):
        row = dict(predicted_by_key[key])
        row["true_function"] = truth_by_key[key]
        joined.append(row)
    return joined


def _compare_mode_metrics(mode: str, rows: list[dict], reported: dict) -> dict:
    by_trial: dict[int, list[dict]] = defaultdict(list)
    for row in rows:
        if row["mode"] != mode:
            raise VerificationError("joined prediction has an unexpected mode")
        by_trial[row["trial"]].append(row)
    reported_trials = reported.get("per_trial")
    if not isinstance(reported_trials, list) or {row.get("trial") for row in reported_trials} != set(by_trial):
        raise VerificationError("reported per-trial metrics do not cover scored trials")
    if reported.get("bootstrap_resamples") != 5000:
        raise VerificationError("reported bootstrap resample count differs from preregistration")
    trial_report = {row["trial"]: row for row in reported_trials}
    recomputed = []
    for trial in sorted(by_trial):
        trial_rows = by_trial[trial]
        labels = [int(row["true_function"] == 0) for row in trial_rows]
        scores = [float(row["score_function_0"]) for row in trial_rows]
        guesses = [int(row["predicted_function"]) for row in trial_rows]
        counts = Counter(row["true_function"] for row in trial_rows)
        accuracy, balanced, majority = _binary_metrics(
            [row["true_function"] for row in trial_rows], guesses
        )
        metrics = {
            "trial": trial,
            "test_observations": len(trial_rows),
            "class_counts": {"0": counts[0], "4": counts[4]},
            "roc_auc": auc(labels, scores),
            "balanced_accuracy": balanced,
            "raw_accuracy": accuracy,
            "majority_accuracy": majority,
        }
        for name, value in metrics.items():
            if name in ("trial", "test_observations", "class_counts"):
                if trial_report[trial].get(name) != value:
                    raise VerificationError(f"reported {name} differs in mode {mode}, trial {trial}")
            else:
                _close(trial_report[trial].get(name), value, f"{mode}.{trial}.{name}")
        recomputed.append(metrics)

    if reported.get("test_observations") != len(rows):
        raise VerificationError(f"test observation count differs in mode {mode}")
    actual_counts = Counter(row["true_function"] for row in rows)
    if reported.get("test_class_counts") != {"0": actual_counts[0], "4": actual_counts[4]}:
        raise VerificationError(f"test class counts differ in mode {mode}")

    for metric_name in (
        "roc_auc",
        "balanced_accuracy",
        "raw_accuracy",
        "majority_accuracy",
    ):
        values = [row[metric_name] for row in recomputed]
        _close(
            reported.get(f"mean_{metric_name}"),
            float(np.mean(values)),
            f"{mode}.mean_{metric_name}",
        )
        expected_ci = _bootstrap_interval(
            values,
            seed=20261211,
            replicates=5000,
        )
        actual_ci = reported.get(f"{metric_name}_ci95")
        if not isinstance(actual_ci, list) or len(actual_ci) != 2:
            raise VerificationError(f"missing confidence interval for {mode}.{metric_name}")
        for index, endpoint in enumerate(expected_ci):
            _close(actual_ci[index], endpoint, f"{mode}.{metric_name}.ci95[{index}]")
    return {"mode": mode, "trials_verified": len(recomputed), "observations_verified": len(rows)}


def _verify_raw_collection(collection: Path, config: dict) -> dict:
    counts = {}
    expected_events_per_session = {}
    total_truth_rows = 0
    for mode in MODES:
        observations = 0
        invocation_events = 0
        for trial in range(config["trials"]):
            for session in range(config["sessions"]):
                directory = collection / mode / f"{trial}-{session}"
                truth_rows = _jsonl(directory / "ground-truth.jsonl")
                if len(truth_rows) != config["operations"]:
                    raise VerificationError(f"wrong truth row count in {directory}")
                labels = [row.get("label") for row in truth_rows]
                if any(
                    type(row.get("label")) is not int or row["label"] not in (0, 1, 2)
                    or type(row.get("step")) is not int
                    for row in truth_rows
                ):
                    raise VerificationError(f"invalid truth-label type in {directory}")
                if labels.count(0) != 4 or labels.count(1) != 2 or labels.count(2) != 2:
                    raise VerificationError(f"wrong class balance in {directory}")
                if (
                    any(type(row.get("step")) is not int for row in truth_rows)
                    or [row.get("step") for row in truth_rows]
                    != list(range(config["operations"]))
                ):
                    raise VerificationError(f"truth steps are incomplete in {directory}")
                truth = {row["step"]: row["label"] for row in truth_rows}
                event_map: dict[int, dict[str, dict]] = defaultdict(dict)
                for event in _jsonl(directory / "network-observer.jsonl"):
                    if event.get("observer") != "invocation":
                        continue
                    step = event.get("step")
                    direction = event.get("direction")
                    frame = event.get("frame")
                    if (
                        type(step) is not int
                        or step not in truth
                        or direction not in ("request", "response")
                        or direction in event_map[step]
                        or not isinstance(frame, list)
                        or any(type(byte) is not int or not 0 <= byte <= 255 for byte in frame)
                        or type(event.get("bytes")) is not int
                        or event["bytes"] != len(frame)
                        or type(event.get("elapsed_ns")) is not int
                        or event["elapsed_ns"] < 0
                    ):
                        raise VerificationError(f"malformed invocation frame in {directory}")
                    event_map[step][direction] = event
                    invocation_events += 1
                for step, label in truth.items():
                    pair = event_map.get(step, {})
                    should_send = mode in BATCHED_MODES or label != 0
                    if should_send:
                        if set(pair) != {"request", "response"}:
                            raise VerificationError(f"missing invocation pair in {directory}, step {step}")
                        observations += 1
                    elif pair:
                        raise VerificationError(f"unbatched dummy emitted traffic in {directory}, step {step}")
                total_truth_rows += len(truth_rows)
        expected = config["trials"] * config["sessions"] * (
            config["operations"] if mode in BATCHED_MODES else config["operations"] // 2
        )
        if observations != expected or invocation_events != expected * 2:
            raise VerificationError(f"invocation message totals differ in mode {mode}")
        counts[mode] = observations
        expected_events_per_session[mode] = invocation_events

    return {
        "session_directories_verified": len(MODES) * config["trials"] * config["sessions"],
        "ground_truth_rows_verified": total_truth_rows,
        "invocation_observations_by_mode": counts,
        "invocation_events_by_mode": expected_events_per_session,
    }


def _verify_hashes(collection: Path, analysis: Path, metadata: dict, config_path: Path) -> dict:
    expected_raw = metadata.get("collection_input_sha256")
    actual_paths = sorted(path for path in collection.rglob("*") if path.is_file())
    actual_raw = {
        path.relative_to(collection).as_posix(): sha256(path) for path in actual_paths
    }
    if not isinstance(expected_raw, dict) or actual_raw != expected_raw:
        raise VerificationError("raw collection hash manifest mismatch")
    if sha256(config_path) != EXPECTED_CONFIG_SHA256 or metadata.get("study_config_sha256") != EXPECTED_CONFIG_SHA256:
        raise VerificationError("frozen study config hash mismatch")
    outputs = sorted(
        path for path in analysis.iterdir() if path.is_file() and path.name != "output-manifest.json"
    )
    expected_outputs = {path.name: sha256(path) for path in outputs}
    if _json(analysis / "output-manifest.json") != expected_outputs:
        raise VerificationError("analysis output hash manifest mismatch")

    source = metadata.get("source_and_binary", {})
    actual_source = {
        relative: sha256(REPOSITORY_ROOT / relative) for relative in SOURCE_FILES
    }
    if source.get("source_sha256") != actual_source:
        raise VerificationError("harness source hashes differ from analysis metadata")
    binary = REPOSITORY_ROOT / "target/release/oblivion-harness"
    analysis_script = REPOSITORY_ROOT / "research/analysis/invocation_boundary_attack.py"
    if (
        source.get("harness_binary_sha256") != sha256(binary)
        or source.get("analysis_script_sha256") != sha256(analysis_script)
    ):
        raise VerificationError("harness binary or analysis source hash mismatch")
    collection_meta = _json(collection / "collection-metadata.json")
    if (
        collection_meta.get("harness_binary_sha256") != source.get("harness_binary_sha256")
        or collection_meta.get("source_sha256") != actual_source
        or collection_meta.get("config_sha256") != EXPECTED_CONFIG_SHA256
        or collection_meta.get("collector_exit_code") != 0
        or collection_meta.get("git_commit") != source.get("git_commit")
    ):
        raise VerificationError("collection environment receipt disagrees with analysis metadata")
    return {
        "raw_files_hashed": len(actual_raw),
        "analysis_outputs_hashed": len(expected_outputs),
        "source_files_verified": len(actual_source),
        "harness_binary_verified": True,
        "config_verified": True,
    }


def verify_bundle(config_path: Path, collection: Path, analysis: Path) -> dict:
    """Recompute raw event shapes, control gate, predictions, and statistics."""
    try:
        config = _json(config_path)
        captured_config = _json(collection / "config.json")
        metrics = _json(analysis / "metrics.json")
        metadata = _json(analysis / "analysis-metadata.json")
        predictions = _jsonl(analysis / "attacker-predictions.jsonl")
        private_labels = _jsonl(analysis / "private-evaluation-labels.jsonl")
    except VerificationError:
        raise
    if config != EXPECTED_CONFIG or captured_config != EXPECTED_CONFIG:
        raise VerificationError("collection or analysis config differs from frozen config")
    if metadata.get("study_config") != EXPECTED_CONFIG:
        raise VerificationError("analysis metadata does not record the frozen config")
    if metrics.get("feature_names") != EXPECTED_FEATURES or metrics.get("attack") != EXPECTED_ATTACK:
        raise VerificationError("reported feature or attack protocol differs from preregistration")

    raw_summary = _verify_raw_collection(collection, config)
    hash_summary = _verify_hashes(collection, analysis, metadata, config_path)
    validate_control_scope(metrics)
    joined = join_predictions(predictions, private_labels)
    mode_summaries = []
    for row in joined:
        if (
            row["trial"] not in range(config["trials"])
            or row["session"] not in range(config["sessions"] // 2, config["sessions"])
        ):
            raise VerificationError("analysis prediction is outside held-out sessions")
    for mode in metrics["metrics_by_mode"]:
        mode_rows = [row for row in joined if row["mode"] == mode]
        mode_summaries.append(
            _compare_mode_metrics(mode, mode_rows, metrics["metrics_by_mode"][mode])
        )
    if {row["mode"] for row in joined} != set(metrics["metrics_by_mode"]):
        raise VerificationError("prediction modes and scored modes differ")

    return {
        "format_version": 1,
        "verified_utc": datetime.now(timezone.utc).isoformat(),
        "study": "invocation-boundary-function-identity",
        "verifier_sha256": sha256(Path(__file__).resolve()),
        "positive_controls_passed": metrics["positive_controls_passed"],
        "protected_scoring": metrics["protected_scoring"],
        "control_auc": {
            mode: metrics["metrics_by_mode"][mode]["mean_roc_auc"]
            for mode in CONTROL_MODES
        },
        "control_gate_verified": True,
        "mode_metrics_recomputed": mode_summaries,
        "raw_collection": raw_summary,
        "integrity": hash_summary,
        "limitations": [
            "The data are a local in-process component-boundary simulation, not packet capture or remote network timing.",
            "The positive-control gate failed; no C–G attack scores are present or accepted.",
            "The result does not establish cryptographic indistinguishability or security.",
        ] if not metrics["positive_controls_passed"] else [
            "The data are a local in-process component-boundary simulation, not packet capture or remote network timing.",
            "Near-chance attack performance is not proof of cryptographic security.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("collection", type=Path)
    parser.add_argument("analysis", type=Path)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    receipt_path = args.receipt or args.analysis.parent / "independent-verification.json"
    if receipt_path.exists():
        parser.error(f"refusing to overwrite verification receipt: {receipt_path}")
    try:
        receipt = verify_bundle(args.config, args.collection, args.analysis)
        receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    except (VerificationError, OSError) as error:
        parser.error(str(error))
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
