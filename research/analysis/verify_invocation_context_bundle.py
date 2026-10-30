#!/usr/bin/env python3
"""Independently reconstruct and verify a session-normalized timing study."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MODES = tuple("ABCDEFG")
CONTROL_MODES = ("A", "B")
BATCHED_MODES = frozenset({"E", "G"})
TRAIN_SESSIONS = frozenset({0, 1})
TEST_SESSIONS = frozenset({2, 3})
FROZEN_CONFIG = {
    "version": 1,
    "seed": 20261032,
    "trials": 30,
    "sessions": 4,
    "operations": 16,
    "epoch_ms": 100,
}
FROZEN_CONFIG_SHA256 = "9953dcb3b903b2b076d3c16f8e41bd5a498c3c9968dbe7b64c434d64199fc120"
FEATURE_NAMES = [
    "request_bytes",
    "response_bytes",
    "log1p_response_latency_ns",
    "mad_scaled_response_latency",
    "log1p_interarrival_ns",
    "latency_midrank_fraction",
]
ATTACK_CONFIG = {
    "classifier": "RandomForestClassifier",
    "n_estimators": 500,
    "max_depth": 6,
    "min_samples_leaf": 2,
    "class_weight": "balanced",
    "n_jobs": 1,
    "model_seed": 20261220,
    "positive_class": 0,
    "classification_threshold": 0.5,
    "bootstrap_resamples": 5000,
    "bootstrap_seed": 20261221,
    "bootstrap_unit": "test trial",
    "training_sessions": "0..1",
    "testing_sessions": "2..3",
}
SOURCE_FILES = (
    "Cargo.lock",
    "crates/oblivion-batcher/src/lib.rs",
    "crates/oblivion-exec/src/lib.rs",
    "crates/oblivion-harness/src/main.rs",
    "crates/oblivion-harness/src/system.rs",
    "crates/oblivion-pir/src/lib.rs",
    "crates/oblivion-store/src/lib.rs",
    "research/analysis/invocation_boundary_attack.py",
    "research/analysis/invocation_context_attack.py",
)
COLLECTION_FILES = {
    "config.json",
    "collection-metadata.json",
    "collector-run.log",
    "metrics.jsonl",
}
PREDICTION_FIELDS = {
    "mode",
    "trial",
    "session",
    "step",
    "score_function_0",
    "predicted_function",
}
LABEL_FIELDS = {"mode", "trial", "session", "step", "true_function"}


class VerificationError(ValueError):
    """An evidence input or derived result differs from the frozen study."""


@dataclass(frozen=True)
class Sample:
    mode: str
    trial: int
    session: int
    step: int
    label: int
    features: tuple[float, float, float, float, float, float]

    @property
    def key(self) -> tuple[str, int, int, int]:
        return self.mode, self.trial, self.session, self.step


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
        raise VerificationError(f"cannot read JSON object: {path}") from error
    if not isinstance(value, dict):
        raise VerificationError(f"expected JSON object: {path}")
    return value


def _jsonl(path: Path) -> list[dict]:
    if not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
        raise VerificationError(f"missing or oversized JSONL file: {path}")
    rows = []
    try:
        with path.open("r", encoding="utf-8") as source:
            for line_number, line in enumerate(source, 1):
                if len(line) > 1024 * 1024:
                    raise VerificationError(f"oversized JSONL row: {path}:{line_number}")
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise VerificationError(f"non-object JSONL row: {path}:{line_number}")
                rows.append(row)
    except (OSError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot read JSONL file: {path}") from error
    return rows


def _strict_int(value: object, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise VerificationError(f"invalid {field}")
    return value


def _close(actual: object, expected: float, field: str) -> None:
    if (
        isinstance(actual, bool)
        or not isinstance(actual, (int, float))
        or not math.isfinite(float(actual))
        or not math.isclose(float(actual), expected, rel_tol=1e-12, abs_tol=1e-12)
    ):
        raise VerificationError(f"reported {field} differs from independent recomputation")


def extract_session(directory: Path, mode: str, trial: int, session: int) -> list[Sample]:
    """Rebuild public numeric features directly from raw frames and timestamps."""
    if mode not in MODES:
        raise VerificationError(f"unknown mode {mode}")
    truth_rows = _jsonl(directory / "ground-truth.jsonl")
    if len(truth_rows) != FROZEN_CONFIG["operations"]:
        raise VerificationError(f"wrong ground-truth row count: {directory}")
    truth: dict[int, int] = {}
    for row in truth_rows:
        step = _strict_int(row.get("step"), "truth step")
        label = _strict_int(row.get("label"), "truth label")
        if step in truth or step >= FROZEN_CONFIG["operations"] or label not in (0, 1, 2):
            raise VerificationError(f"duplicate or invalid truth row: {directory}")
        truth[step] = label
    if set(truth) != set(range(FROZEN_CONFIG["operations"])):
        raise VerificationError(f"truth steps are not contiguous: {directory}")
    labels = list(truth.values())
    if (labels.count(0), labels.count(1), labels.count(2)) != (8, 4, 4):
        raise VerificationError(f"unexpected session workload balance: {directory}")

    events: dict[int, dict[str, tuple[int, int]]] = defaultdict(dict)
    for event in _jsonl(directory / "network-observer.jsonl"):
        if event.get("observer") != "invocation":
            continue
        step = _strict_int(event.get("step"), "invocation event step")
        direction = event.get("direction")
        frame = event.get("frame")
        byte_count = _strict_int(event.get("bytes"), "frame size", minimum=1)
        timestamp = _strict_int(event.get("elapsed_ns"), "observer timestamp")
        if (
            step not in truth
            or direction not in ("request", "response")
            or direction in events[step]
            or not isinstance(frame, list)
            or any(type(byte) is not int or not 0 <= byte <= 255 for byte in frame)
            or byte_count != len(frame)
        ):
            raise VerificationError(f"malformed invocation frame: {directory}")
        events[step][direction] = (byte_count, timestamp)

    unnormalized = []
    previous_request_ns: int | None = None
    for step in range(FROZEN_CONFIG["operations"]):
        label = truth[step]
        pair = events.get(step, {})
        should_emit = mode in BATCHED_MODES or label != 0
        if not should_emit:
            if pair:
                raise VerificationError(f"unbatched dummy emitted invocation traffic: {directory}:{step}")
            continue
        if set(pair) != {"request", "response"}:
            raise VerificationError(f"invocation request/response pair missing: {directory}:{step}")
        request_bytes, request_ns = pair["request"]
        response_bytes, response_ns = pair["response"]
        if response_ns < request_ns:
            raise VerificationError(f"response timestamp precedes request: {directory}:{step}")
        interarrival = (
            request_ns
            if previous_request_ns is None
            else request_ns - previous_request_ns
        )
        if interarrival < 0:
            raise VerificationError(f"request timestamps are not monotonic: {directory}:{step}")
        previous_request_ns = request_ns
        latency = response_ns - request_ns
        function_id = 0 if label == 1 else 4
        unnormalized.append((step, function_id, request_bytes, response_bytes, latency, interarrival))
    if len(events) != len(unnormalized):
        raise VerificationError(f"unexpected invocation event key in {directory}")
    if len(unnormalized) != (16 if mode in BATCHED_MODES else 8):
        raise VerificationError(f"unexpected invocation count in {directory}")

    latencies = np.asarray([row[4] for row in unnormalized], dtype=np.float64)
    median = float(np.median(latencies))
    mad = float(np.median(np.abs(latencies - median)))
    scale = max(1.0, 1.4826 * mad)
    order = sorted(range(len(latencies)), key=lambda index: (latencies[index], index))
    rank_fraction = [0.0] * len(order)
    cursor = 0
    while cursor < len(order):
        end = cursor + 1
        value = latencies[order[cursor]]
        while end < len(order) and latencies[order[end]] == value:
            end += 1
        average_rank = ((cursor + 1) + end) / 2
        fraction = average_rank / len(order)
        for ordered_index in range(cursor, end):
            rank_fraction[order[ordered_index]] = fraction
        cursor = end

    result = []
    for index, (step, label, request_bytes, response_bytes, latency, interarrival) in enumerate(unnormalized):
        features = (
            float(request_bytes),
            float(response_bytes),
            float(np.log1p(latency)),
            float((latency - median) / scale),
            float(np.log1p(interarrival)),
            rank_fraction[index],
        )
        if any(not math.isfinite(value) for value in features):
            raise VerificationError(f"non-finite public feature: {directory}:{step}")
        result.append(Sample(mode, trial, session, step, label, features))
    return result


def validate_control_scope(metrics: dict) -> None:
    """Reapply the frozen positive-control stop rule to reported scope."""
    scored = metrics.get("metrics_by_mode")
    if not isinstance(scored, dict) or not set(CONTROL_MODES) <= set(scored):
        raise VerificationError("both positive controls must be scored")
    passed = metrics.get("positive_controls_passed")
    expected_modes = set(MODES) if passed is True else set(CONTROL_MODES)
    if set(scored) != expected_modes:
        raise VerificationError("reported modes violate the positive-control stop rule")
    expected_scope = "performed" if passed is True else "omitted_control_failure"
    if metrics.get("protected_scoring") != expected_scope:
        raise VerificationError("protected-scoring scope disagrees with control gate")
    gates = metrics.get("positive_control_gates")
    if not isinstance(gates, dict) or set(gates) != set(CONTROL_MODES):
        raise VerificationError("positive-control gate metadata is incomplete")
    derived = True
    for mode in CONTROL_MODES:
        row = scored[mode]
        auc_ci = row.get("roc_auc_ci95")
        if (
            not isinstance(auc_ci, list)
            or len(auc_ci) != 2
            or isinstance(row.get("mean_roc_auc"), bool)
            or not isinstance(row.get("mean_roc_auc"), (int, float))
            or not math.isfinite(float(row["mean_roc_auc"]))
            or any(
                isinstance(bound, bool)
                or not isinstance(bound, (int, float))
                or not math.isfinite(float(bound))
                for bound in auc_ci
            )
        ):
            raise VerificationError(f"invalid control metrics in mode {mode}")
        gate_passed = row["mean_roc_auc"] >= 0.70 and auc_ci[0] > 0.50
        gate = gates[mode]
        if (
            gate.get("minimum_mean_auc") != 0.70
            or gate.get("minimum_lower_auc_ci95") != 0.50
            or gate.get("passed") is not gate_passed
        ):
            raise VerificationError(f"control gate changed or is inconsistent in mode {mode}")
        derived = derived and gate_passed
    if passed is not derived:
        raise VerificationError("overall positive-control status is inconsistent")


def _auc(labels: list[int], scores: list[float]) -> float:
    positives = sum(labels)
    negatives = len(labels) - positives
    if not labels or positives == 0 or negatives == 0 or len(labels) != len(scores):
        raise VerificationError("AUC requires aligned observations from both classes")
    ordered = sorted(zip(scores, labels, strict=True))
    positive_rank_sum = 0.0
    cursor = 0
    while cursor < len(ordered):
        end = cursor + 1
        while end < len(ordered) and ordered[end][0] == ordered[cursor][0]:
            end += 1
        average_rank = ((cursor + 1) + end) / 2
        positive_rank_sum += average_rank * sum(label for _, label in ordered[cursor:end])
        cursor = end
    return (positive_rank_sum - positives * (positives + 1) / 2) / (positives * negatives)


def _binary_metrics(labels: list[int], predictions: list[int]) -> tuple[float, float, float]:
    positive_count = sum(label == 0 for label in labels)
    negative_count = len(labels) - positive_count
    if not labels or positive_count == 0 or negative_count == 0 or len(labels) != len(predictions):
        raise VerificationError("classification metrics require aligned observations from both classes")
    tp = sum(actual == 0 and guess == 0 for actual, guess in zip(labels, predictions, strict=True))
    tn = sum(actual == 4 and guess == 4 for actual, guess in zip(labels, predictions, strict=True))
    accuracy = sum(actual == guess for actual, guess in zip(labels, predictions, strict=True)) / len(labels)
    balanced = (tp / positive_count + tn / negative_count) / 2
    majority = max(positive_count, negative_count) / len(labels)
    return accuracy, balanced, majority


def _bootstrap_ci(values: list[float]) -> list[float]:
    if len(values) < 2:
        raise VerificationError("trial-level bootstrap requires multiple trial units")
    rng = np.random.default_rng(ATTACK_CONFIG["bootstrap_seed"])
    draws = rng.choice(
        np.asarray(values, dtype=np.float64),
        (ATTACK_CONFIG["bootstrap_resamples"], len(values)),
        replace=True,
    )
    means = draws.mean(axis=1)
    return [float(np.quantile(means, 0.025)), float(np.quantile(means, 0.975))]


def _hashes(root: Path) -> dict[str, str]:
    paths = list(root.rglob("*"))
    files = sorted(path for path in paths if path.is_file())
    if any(path.is_symlink() for path in paths):
        raise VerificationError(f"symlink is not accepted in evidence tree: {root}")
    return {path.relative_to(root).as_posix(): sha256(path) for path in files}


def _verify_integrity(config_path: Path, collection: Path, analysis: Path, metadata: dict) -> dict:
    if sha256(config_path) != FROZEN_CONFIG_SHA256:
        raise VerificationError("frozen configuration hash differs from preregistration")
    if metadata.get("study_config_sha256") != FROZEN_CONFIG_SHA256:
        raise VerificationError("analysis metadata records a different configuration hash")
    raw_hashes = _hashes(collection)
    if metadata.get("collection_input_sha256") != raw_hashes:
        raise VerificationError("raw collection content does not match analysis input hashes")
    output_files = {
        path.name: sha256(path)
        for path in sorted(analysis.iterdir())
        if path.is_file() and path.name != "output-manifest.json"
    }
    if _json(analysis / "output-manifest.json") != output_files:
        raise VerificationError("analysis outputs do not match their immutable manifest")
    if set(output_files) != {
        "analysis-metadata.json",
        "attacker-predictions.jsonl",
        "metrics.json",
        "private-evaluation-labels.jsonl",
    }:
        raise VerificationError("analysis directory contains an unexpected file set")

    source = metadata.get("source_and_binary")
    if not isinstance(source, dict):
        raise VerificationError("analysis source/binary provenance is absent")
    expected_source_hashes = {
        relative: sha256(REPOSITORY_ROOT / relative) for relative in SOURCE_FILES
    }
    if source.get("source_sha256") != expected_source_hashes:
        raise VerificationError("current evaluator/harness sources differ from collection receipt")
    binary_path = REPOSITORY_ROOT / "target/release/oblivion-harness"
    if source.get("harness_binary_sha256") != sha256(binary_path):
        raise VerificationError("harness release binary hash differs from analysis metadata")
    if source.get("analysis_script_sha256") != expected_source_hashes[
        "research/analysis/invocation_context_attack.py"
    ]:
        raise VerificationError("analysis source hash differs from source manifest")

    collection_meta = _json(collection / "collection-metadata.json")
    if (
        collection_meta.get("source_sha256") != expected_source_hashes
        or collection_meta.get("harness_binary_sha256") != source.get("harness_binary_sha256")
        or collection_meta.get("config_sha256") != FROZEN_CONFIG_SHA256
        or collection_meta.get("collector_exit_code") != 0
        or collection_meta.get("git_commit") != source.get("git_commit")
        or collection_meta.get("collector_log_sha256") != sha256(collection / "collector-run.log")
    ):
        raise VerificationError("collection environment receipt is inconsistent")
    if not {
        "cpu_model",
        "kernel",
        "logical_cpu_count",
        "platform",
        "load_average_start",
        "load_average_end",
        "ended_utc",
    } <= set(collection_meta):
        raise VerificationError("collection host metadata is incomplete")
    analysis_environment = metadata.get("analysis_environment", {})
    if (
        analysis_environment.get("numpy") != np.__version__
        or analysis_environment.get("scikit_learn") != sklearn.__version__
        or analysis_environment.get("platform") != platform.platform()
    ):
        raise VerificationError("analysis environment does not match the verifier environment")
    return {
        "raw_files_hashed": len(raw_hashes),
        "analysis_outputs_hashed": len(output_files),
        "source_files_verified": len(expected_source_hashes),
        "release_binary_verified": True,
        "configuration_verified": True,
        "analysis_environment_verified": True,
    }


def _verify_raw_collection(collection: Path) -> tuple[dict[str, list[Sample]], dict]:
    if _json(collection / "config.json") != FROZEN_CONFIG:
        raise VerificationError("captured collection configuration differs from preregistration")
    samples_by_mode = {mode: [] for mode in MODES}
    observations_by_mode = Counter()
    total_truth = 0
    session_count = 0
    expected_sessions = {
        f"{trial}-{session}"
        for trial in range(FROZEN_CONFIG["trials"])
        for session in range(FROZEN_CONFIG["sessions"])
    }
    for mode in MODES:
        mode_root = collection / mode
        if not mode_root.is_dir() or {path.name for path in mode_root.iterdir()} != expected_sessions:
            raise VerificationError(f"collection session set is incomplete in mode {mode}")
        for trial in range(FROZEN_CONFIG["trials"]):
            for session in range(FROZEN_CONFIG["sessions"]):
                directory = mode_root / f"{trial}-{session}"
                rows = extract_session(directory, mode, trial, session)
                samples_by_mode[mode].extend(rows)
                observations_by_mode[mode] += len(rows)
                total_truth += FROZEN_CONFIG["operations"]
                session_count += 1
    expected = {
        mode: FROZEN_CONFIG["trials"]
        * FROZEN_CONFIG["sessions"]
        * (16 if mode in BATCHED_MODES else 8)
        for mode in MODES
    }
    if dict(observations_by_mode) != expected:
        raise VerificationError("reconstructed per-mode observation totals are incorrect")
    allowed_files = set(COLLECTION_FILES)
    for mode in MODES:
        allowed_files.add(mode)
    actual_top = {path.name for path in collection.iterdir()}
    if actual_top != allowed_files:
        raise VerificationError("collection has missing or unexpected top-level entries")
    return samples_by_mode, {
        "session_directories_reconstructed": session_count,
        "ground_truth_rows_checked": total_truth,
        "public_observations_reconstructed_by_mode": dict(observations_by_mode),
    }


def _keyed_rows(rows: list[dict], expected_fields: set[str], name: str) -> dict:
    by_key = {}
    for row in rows:
        if set(row) != expected_fields:
            raise VerificationError(f"{name} contains truth or unexpected fields")
        if (
            row.get("mode") not in MODES
            or type(row.get("trial")) is not int
            or type(row.get("session")) is not int
            or type(row.get("step")) is not int
        ):
            raise VerificationError(f"{name} contains a malformed observation key")
        key = (row["mode"], row["trial"], row["session"], row["step"])
        if key in by_key:
            raise VerificationError(f"{name} contains duplicate observation keys")
        if name == "private labels" and (
            type(row.get("true_function")) is not int
            or row["true_function"] not in (0, 4)
        ):
            raise VerificationError("private evaluation label is malformed")
        by_key[key] = row
    return by_key


def _verify_model_and_metrics(samples_by_mode: dict[str, list[Sample]], metrics: dict,
                              predictions: list[dict], private_labels: list[dict]) -> dict:
    validate_control_scope(metrics)
    if metrics.get("feature_names") != FEATURE_NAMES or metrics.get("attack") != ATTACK_CONFIG:
        raise VerificationError("reported attack definition differs from preregistration")
    scored_modes = set(metrics["metrics_by_mode"])
    prediction_map = _keyed_rows(predictions, PREDICTION_FIELDS, "attacker predictions")
    label_map = _keyed_rows(private_labels, LABEL_FIELDS, "private labels")
    if prediction_map.keys() != label_map.keys():
        raise VerificationError("prediction and private-label keys are not aligned")
    sample_by_key = {
        sample.key: sample
        for mode in MODES
        for sample in samples_by_mode[mode]
    }
    expected_keys = {
        sample.key
        for sample in sample_by_key.values()
        if sample.mode in scored_modes and sample.session in TEST_SESSIONS
    }
    if prediction_map.keys() != expected_keys:
        raise VerificationError("scored observations are not exactly the held-out trace rows")
    for key, sample in sample_by_key.items():
        if key in label_map and label_map[key].get("true_function") != sample.label:
            raise VerificationError("private held-out labels differ from raw workload labels")
    if set(row["mode"] for row in prediction_map.values()) != scored_modes:
        raise VerificationError("prediction modes differ from metric modes")

    verified_modes = []
    for mode in MODES:
        if mode not in scored_modes:
            continue
        rows = samples_by_mode[mode]
        train = [row for row in rows if row.session in TRAIN_SESSIONS]
        test = [row for row in rows if row.session in TEST_SESSIONS]
        if not train or not test:
            raise VerificationError(f"empty training or testing partition in mode {mode}")
        train_x = np.asarray([row.features for row in train], dtype=np.float64)
        train_y = np.asarray([row.label for row in train], dtype=np.int64)
        test_x = np.asarray([row.features for row in test], dtype=np.float64)
        model = RandomForestClassifier(
            n_estimators=500,
            max_depth=6,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=20261220,
            n_jobs=1,
        )
        model.fit(train_x, train_y)
        zero_column = int(np.flatnonzero(model.classes_ == 0)[0])
        scores = model.predict_proba(test_x)[:, zero_column]
        guesses = np.where(scores >= 0.5, 0, 4)
        predictions_by_key = prediction_map
        per_trial_rows: dict[int, list[tuple[Sample, float, int]]] = defaultdict(list)
        for row, score, guess in zip(test, scores, guesses, strict=True):
            record = predictions_by_key[row.key]
            _close(record.get("score_function_0"), float(score), f"{mode}.{row.key}.score")
            if type(record.get("predicted_function")) is not int or record["predicted_function"] != int(guess):
                raise VerificationError(f"predicted class differs from independent model in {row.key}")
            if record["predicted_function"] != (0 if record["score_function_0"] >= 0.5 else 4):
                raise VerificationError(f"class prediction violates frozen threshold in {row.key}")
            per_trial_rows[row.trial].append((row, float(score), int(guess)))

        report = metrics["metrics_by_mode"][mode]
        if report.get("train_observations") != len(train) or report.get("test_observations") != len(test):
            raise VerificationError(f"reported train/test sizes are wrong in mode {mode}")
        train_counts = Counter(row.label for row in train)
        test_counts = Counter(row.label for row in test)
        if report.get("train_class_counts") != {"0": train_counts[0], "4": train_counts[4]}:
            raise VerificationError(f"reported training class balance is wrong in mode {mode}")
        if report.get("test_class_counts") != {"0": test_counts[0], "4": test_counts[4]}:
            raise VerificationError(f"reported test class balance is wrong in mode {mode}")
        if report.get("bootstrap_resamples") != 5000:
            raise VerificationError("reported bootstrap count differs from preregistration")
        trials_reported = report.get("per_trial")
        if not isinstance(trials_reported, list):
            raise VerificationError(f"per-trial metric data missing in mode {mode}")
        trial_map = {row.get("trial"): row for row in trials_reported}
        if len(trial_map) != FROZEN_CONFIG["trials"] or set(trial_map) != set(per_trial_rows):
            raise VerificationError(f"per-trial metrics do not cover all trials in mode {mode}")

        recomputed = []
        for trial in sorted(per_trial_rows):
            trial_rows = per_trial_rows[trial]
            labels = [row.label for row, _, _ in trial_rows]
            binary = [int(label == 0) for label in labels]
            trial_scores = [score for _, score, _ in trial_rows]
            guesses_for_trial = [guess for _, _, guess in trial_rows]
            counts = Counter(labels)
            accuracy, balanced, majority = _binary_metrics(labels, guesses_for_trial)
            derived = {
                "trial": trial,
                "test_observations": len(trial_rows),
                "class_counts": {"0": counts[0], "4": counts[4]},
                "roc_auc": _auc(binary, trial_scores),
                "balanced_accuracy": balanced,
                "raw_accuracy": accuracy,
                "majority_accuracy": majority,
            }
            given = trial_map[trial]
            for field, value in derived.items():
                if field in ("trial", "test_observations", "class_counts"):
                    if given.get(field) != value:
                        raise VerificationError(f"reported {mode}.{trial}.{field} is incorrect")
                else:
                    _close(given.get(field), value, f"{mode}.{trial}.{field}")
            recomputed.append(derived)

        for metric_name in ("roc_auc", "balanced_accuracy", "raw_accuracy", "majority_accuracy"):
            values = [row[metric_name] for row in recomputed]
            _close(report.get(f"mean_{metric_name}"), float(np.mean(values)), f"{mode}.mean_{metric_name}")
            interval = report.get(f"{metric_name}_ci95")
            expected_interval = _bootstrap_ci(values)
            if not isinstance(interval, list) or len(interval) != 2:
                raise VerificationError(f"confidence interval missing for {mode}.{metric_name}")
            for index, bound in enumerate(expected_interval):
                _close(interval[index], bound, f"{mode}.{metric_name}_ci95[{index}]")
        verified_modes.append({"mode": mode, "trials_recomputed": len(recomputed), "heldout_predictions_replayed": len(test)})
    return {
        "mode_metrics_and_predictions_recomputed": verified_modes,
        "attacker_prediction_rows": len(predictions),
        "private_label_rows": len(private_labels),
    }


def verify_bundle(config_path: Path, collection: Path, analysis: Path) -> dict:
    """Rebuild trace features, replay the frozen model, and verify outputs."""
    config = _json(config_path)
    if config != FROZEN_CONFIG:
        raise VerificationError("config differs from the frozen study")
    metadata = _json(analysis / "analysis-metadata.json")
    if metadata.get("study_config") != FROZEN_CONFIG:
        raise VerificationError("analysis metadata does not record the frozen config")
    metrics = _json(analysis / "metrics.json")
    predictions = _jsonl(analysis / "attacker-predictions.jsonl")
    private_labels = _jsonl(analysis / "private-evaluation-labels.jsonl")

    samples_by_mode, raw_summary = _verify_raw_collection(collection)
    integrity = _verify_integrity(config_path, collection, analysis, metadata)
    model_summary = _verify_model_and_metrics(samples_by_mode, metrics, predictions, private_labels)
    controls = metrics["metrics_by_mode"]
    failed = not metrics["positive_controls_passed"]
    return {
        "format_version": 1,
        "verified_utc": datetime.now(timezone.utc).isoformat(),
        "study": "session-normalized-invocation-context-function-identity",
        "verifier_sha256": sha256(Path(__file__).resolve()),
        "positive_controls_passed": metrics["positive_controls_passed"],
        "protected_scoring": metrics["protected_scoring"],
        "control_auc": {mode: controls[mode]["mean_roc_auc"] for mode in CONTROL_MODES},
        "control_auc_ci95": {mode: controls[mode]["roc_auc_ci95"] for mode in CONTROL_MODES},
        "control_gate_verified": True,
        **raw_summary,
        **model_summary,
        "integrity": integrity,
        "limitations": [
            "The traces come from a local in-process component-boundary simulation, not remote packet capture or internet-path timing.",
            "The encrypt-only control missed the preregistered mean AUC threshold; protected modes were not scored.",
            "This experiment does not establish cryptographic indistinguishability or security.",
            "The verifier replays the declared scikit-learn classifier and independently rebuilds its public feature matrix from raw observer frames.",
        ] if failed else [
            "The traces come from a local in-process component-boundary simulation, not remote packet capture or internet-path timing.",
            "Near-chance attack performance is not proof of cryptographic security.",
            "The verifier replays the declared scikit-learn classifier and independently rebuilds its public feature matrix from raw observer frames.",
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
        receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (VerificationError, OSError) as error:
        parser.error(str(error))
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
