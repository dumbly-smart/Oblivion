#!/usr/bin/env python3
"""Evaluate a preregistered frame-size and response-timing attack."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping, Sequence

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import balanced_accuracy_score, roc_auc_score


MODES = tuple("ABCDEFG")
BATCHED_MODES = frozenset({"E", "G"})
FEATURE_NAMES = (
    "request_bytes",
    "response_bytes",
    "response_latency_ns",
    "interarrival_ns",
)
FROZEN_CONFIG = {
    "version": 1,
    "seed": 20261031,
    "trials": 30,
    "sessions": 8,
    "operations": 8,
    "epoch_ms": 100,
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


class StudyError(ValueError):
    """Malformed or inconsistent study input."""


@dataclass(frozen=True)
class Observation:
    trial: int
    session: int
    step: int
    label: int
    features: tuple[int, int, int, int]


def _read_jsonl(path: Path) -> list[dict]:
    if not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
        raise StudyError(f"missing or oversized trace file: {path}")
    rows = []
    with path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if len(line) > 1024 * 1024:
                raise StudyError(f"oversized JSONL row in {path}:{line_number}")
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                raise StudyError(f"invalid JSON in {path}:{line_number}") from error
            if not isinstance(row, dict):
                raise StudyError(f"non-object JSONL row in {path}:{line_number}")
            rows.append(row)
    return rows


def _integer(value: object, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise StudyError(f"invalid {field}")
    return value


def extract_session(
    directory: Path, mode: str, trial: int, session: int
) -> list[Observation]:
    """Pair invocation frames privately, then emit only size/timing features."""
    if mode not in MODES:
        raise StudyError(f"unknown mode: {mode}")
    truth_rows = _read_jsonl(directory / "ground-truth.jsonl")
    truth: dict[int, int] = {}
    for row in truth_rows:
        step = _integer(row.get("step"), "truth step")
        label = _integer(row.get("label"), "truth label")
        if label not in (0, 1, 2) or step in truth:
            raise StudyError("invalid or duplicate ground-truth row")
        truth[step] = label
    if not truth:
        raise StudyError("empty ground-truth schedule")
    if sorted(truth) != list(range(len(truth))):
        raise StudyError("ground-truth steps must be contiguous from zero")

    events: dict[int, dict[str, tuple[int, int]]] = defaultdict(dict)
    for row in _read_jsonl(directory / "network-observer.jsonl"):
        if row.get("observer") != "invocation":
            continue
        direction = row.get("direction")
        if direction not in ("request", "response"):
            raise StudyError("invalid invocation event direction")
        step = _integer(row.get("step"), "event step")
        if step not in truth or direction in events[step]:
            raise StudyError("invocation event has an unknown step or duplicate direction")
        byte_count = _integer(row.get("bytes"), "frame length", minimum=1)
        elapsed = _integer(row.get("elapsed_ns"), "event timestamp")
        frame = row.get("frame")
        if (
            not isinstance(frame, list)
            or any(isinstance(byte, bool) or not isinstance(byte, int) or not 0 <= byte <= 255 for byte in frame)
            or len(frame) != byte_count
        ):
            raise StudyError("invocation frame length does not match its recorded bytes")
        events[step][direction] = (byte_count, elapsed)

    observations = []
    previous_request_ns: int | None = None
    for step in sorted(truth):
        label = truth[step]
        pair = events.get(step, {})
        if not pair:
            if label == 0 and mode not in BATCHED_MODES:
                continue
            raise StudyError("expected invocation request/response is missing")
        if set(pair) != {"request", "response"}:
            raise StudyError("invocation request/response pair is incomplete")
        if label == 0 and mode not in BATCHED_MODES:
            raise StudyError("unbatched dummy unexpectedly emitted an invocation")

        request_bytes, request_ns = pair["request"]
        response_bytes, response_ns = pair["response"]
        if response_ns < request_ns:
            raise StudyError("response timestamp precedes request timestamp")
        interarrival_ns = (
            request_ns
            if previous_request_ns is None
            else request_ns - previous_request_ns
        )
        if interarrival_ns < 0:
            raise StudyError("invocation request timestamps are not monotonic")
        previous_request_ns = request_ns

        # The harness maps echo to ID 0 and both stateful calls and batched
        # cover calls to the stateful module ID 4.
        function_id = 0 if label == 1 else 4
        features = (
            request_bytes,
            response_bytes,
            response_ns - request_ns,
            interarrival_ns,
        )
        observations.append(
            Observation(trial, session, step, function_id, features)
        )
    return observations


def feature_matrix(observations: Sequence[Observation]) -> np.ndarray:
    """Project observations to public numeric features without truth fields."""
    if not observations:
        raise StudyError("no invocation observations")
    matrix = np.asarray([row.features for row in observations], dtype=np.float64)
    if matrix.ndim != 2 or matrix.shape[1] != len(FEATURE_NAMES):
        raise StudyError("unexpected attacker feature shape")
    return matrix


def training_data(
    observations: Sequence[Observation],
) -> tuple[np.ndarray, np.ndarray]:
    """Return feature matrix and labels separately; only X is model input."""
    matrix = feature_matrix(observations)
    labels = np.asarray([row.label for row in observations], dtype=np.int64)
    if set(np.unique(labels)) != {0, 4}:
        raise StudyError("both function classes are required")
    return matrix, labels


def split_sessions(
    observations: Sequence[Observation], sessions: int
) -> tuple[list[Observation], list[Observation]]:
    """Hold out whole, independently seeded sessions within every trial."""
    if sessions < 2 or sessions % 2:
        raise StudyError("session count must be even and at least two")
    midpoint = sessions // 2
    train = [row for row in observations if row.session < midpoint]
    test = [row for row in observations if row.session >= midpoint]
    train_groups = {(row.trial, row.session) for row in train}
    test_groups = {(row.trial, row.session) for row in test}
    if not train or not test or train_groups & test_groups:
        raise StudyError("invalid whole-session split")
    if any(row.session >= sessions for row in observations):
        raise StudyError("observation session exceeds configured count")
    return train, test


def _bootstrap_interval(
    values: Sequence[float], resamples: int, seed: int
) -> list[float]:
    if not values or resamples < 1:
        raise StudyError("bootstrap requires observations and resamples")
    rng = np.random.default_rng(seed)
    samples = rng.choice(np.asarray(values, dtype=np.float64), (resamples, len(values)), replace=True)
    means = samples.mean(axis=1)
    return [float(value) for value in np.quantile(means, [0.025, 0.975])]


def _evaluate_mode(
    mode: str,
    observations: Sequence[Observation],
    sessions: int,
    bootstrap_resamples: int,
    bootstrap_seed: int,
    model_seed: int,
) -> tuple[dict, list[dict], list[dict]]:
    train, test = split_sessions(observations, sessions)
    train_x, train_y = training_data(train)
    test_x = feature_matrix(test)
    if set(np.unique(train_y)) != {0, 4}:
        raise StudyError(f"mode {mode} training data is missing a class")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=4,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=model_seed,
        n_jobs=1,
    )
    model.fit(train_x, train_y)
    zero_column = int(np.flatnonzero(model.classes_ == 0)[0])
    score_zero = model.predict_proba(test_x)[:, zero_column]
    predicted = np.where(score_zero >= 0.5, 0, 4)

    trial_indexes: dict[int, list[int]] = defaultdict(list)
    for index, row in enumerate(test):
        trial_indexes[row.trial].append(index)
    per_trial = []
    for trial in sorted(trial_indexes):
        indexes = trial_indexes[trial]
        truth = np.asarray([test[index].label for index in indexes], dtype=np.int64)
        if set(np.unique(truth)) != {0, 4}:
            raise StudyError(f"mode {mode} test trial {trial} is missing a class")
        scores = score_zero[indexes]
        predictions = predicted[indexes]
        counts = Counter(int(value) for value in truth)
        per_trial.append(
            {
                "trial": trial,
                "test_observations": len(indexes),
                "class_counts": {"0": counts[0], "4": counts[4]},
                "roc_auc": float(roc_auc_score(truth == 0, scores)),
                "balanced_accuracy": float(
                    balanced_accuracy_score(truth, predictions)
                ),
                "raw_accuracy": float(np.mean(truth == predictions)),
                "majority_accuracy": float(max(counts.values()) / len(truth)),
            }
        )

    metric_names = (
        "roc_auc",
        "balanced_accuracy",
        "raw_accuracy",
        "majority_accuracy",
    )
    metrics = {
        "mode": mode,
        "train_observations": len(train),
        "test_observations": len(test),
        "train_class_counts": {
            "0": int(np.sum(train_y == 0)),
            "4": int(np.sum(train_y == 4)),
        },
        "test_class_counts": {
            "0": int(sum(row.label == 0 for row in test)),
            "4": int(sum(row.label == 4 for row in test)),
        },
        "bootstrap_resamples": bootstrap_resamples,
        "per_trial": per_trial,
    }
    for metric_name in metric_names:
        values = [row[metric_name] for row in per_trial]
        metrics[f"mean_{metric_name}"] = float(np.mean(values))
        metrics[f"{metric_name}_ci95"] = _bootstrap_interval(
            values, bootstrap_resamples, bootstrap_seed
        )

    predictions = [
        {
            "mode": mode,
            "trial": row.trial,
            "session": row.session,
            "step": row.step,
            "score_function_0": float(score),
            "predicted_function": int(prediction),
        }
        for row, score, prediction in zip(test, score_zero, predicted, strict=True)
    ]
    private_labels = [
        {
            "mode": mode,
            "trial": row.trial,
            "session": row.session,
            "step": row.step,
            "true_function": row.label,
        }
        for row in test
    ]
    return metrics, predictions, private_labels


def evaluate_modes(
    rows_by_mode: Mapping[str, Sequence[Observation]],
    sessions: int,
    bootstrap_resamples: int = 5000,
    bootstrap_seed: int = 20261211,
    model_seed: int = 20261210,
) -> tuple[dict, list[dict], list[dict]]:
    """Evaluate controls first and suppress protected scores if either fails."""
    if set(rows_by_mode) != set(MODES):
        raise StudyError("all seven A–G modes are required")
    metrics_by_mode = {}
    predictions = []
    private_labels = []
    for mode in ("A", "B"):
        metrics, mode_predictions, mode_labels = _evaluate_mode(
            mode,
            rows_by_mode[mode],
            sessions,
            bootstrap_resamples,
            bootstrap_seed,
            model_seed,
        )
        metrics_by_mode[mode] = metrics
        predictions.extend(mode_predictions)
        private_labels.extend(mode_labels)

    control_gates = {
        mode: {
            "passed": metrics_by_mode[mode]["mean_roc_auc"] >= 0.70
            and metrics_by_mode[mode]["roc_auc_ci95"][0] > 0.50,
            "minimum_mean_auc": 0.70,
            "minimum_lower_auc_ci95": 0.50,
        }
        for mode in ("A", "B")
    }
    passed = all(gate["passed"] for gate in control_gates.values())
    if passed:
        for mode in "CDEFG":
            metrics, mode_predictions, mode_labels = _evaluate_mode(
                mode,
                rows_by_mode[mode],
                sessions,
                bootstrap_resamples,
                bootstrap_seed,
                model_seed,
            )
            metrics_by_mode[mode] = metrics
            predictions.extend(mode_predictions)
            private_labels.extend(mode_labels)

    return (
        {
            "positive_controls_passed": passed,
            "positive_control_gates": control_gates,
            "protected_scoring": "performed" if passed else "omitted_control_failure",
            "metrics_by_mode": metrics_by_mode,
            "feature_names": list(FEATURE_NAMES),
            "attack": {
                "classifier": "RandomForestClassifier",
                "n_estimators": 200,
                "max_depth": 4,
                "min_samples_leaf": 2,
                "class_weight": "balanced",
                "n_jobs": 1,
                "model_seed": model_seed,
                "positive_class": 0,
                "classification_threshold": 0.5,
                "bootstrap_resamples": bootstrap_resamples,
                "bootstrap_seed": bootstrap_seed,
                "bootstrap_unit": "test trial",
                "training_sessions": f"0..{sessions // 2 - 1}",
                "testing_sessions": f"{sessions // 2}..{sessions - 1}",
            },
        },
        predictions,
        private_labels,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_jsonl(path: Path, rows: Iterable[dict]) -> None:
    with path.open("w", encoding="utf-8") as destination:
        for row in rows:
            destination.write(json.dumps(row, sort_keys=True) + "\n")


def _load_config(path: Path, raw_root: Path) -> dict:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
        collected = json.loads((raw_root / "config.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise StudyError("cannot read preregistered or collected configuration") from error
    if config != FROZEN_CONFIG or collected != FROZEN_CONFIG:
        raise StudyError("configuration differs from the frozen preregistration")
    return config


def _load_all(raw_root: Path, config: dict) -> dict[str, list[Observation]]:
    rows_by_mode = {mode: [] for mode in MODES}
    for trial in range(config["trials"]):
        for session in range(config["sessions"]):
            for mode in MODES:
                directory = raw_root / mode / f"{trial}-{session}"
                rows_by_mode[mode].extend(
                    extract_session(directory, mode, trial, session)
                )
    return rows_by_mode


def _collection_manifest(raw_root: Path) -> dict:
    paths = sorted(path for path in raw_root.rglob("*") if path.is_file())
    return {
        path.relative_to(raw_root).as_posix(): _sha256(path) for path in paths
    }


def _source_metadata(repo_root: Path) -> dict:
    sources = {
        relative: _sha256(repo_root / relative)
        for relative in SOURCE_FILES
        if (repo_root / relative).is_file()
    }
    binary = repo_root / "target/release/oblivion-harness"
    if not binary.is_file():
        raise StudyError("release oblivion-harness binary is missing")
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return {
        "git_commit": commit,
        "source_sha256": sources,
        "harness_binary_sha256": _sha256(binary),
        "analysis_script_sha256": _sha256(Path(__file__).resolve()),
    }


def analyze(config_path: Path, raw_root: Path, output: Path) -> dict:
    """Run the frozen analysis and write immutable, split-boundary outputs."""
    if output.exists():
        raise StudyError(f"analysis output already exists: {output}")
    config = _load_config(config_path, raw_root)
    rows_by_mode = _load_all(raw_root, config)
    report, predictions, private_labels = evaluate_modes(
        rows_by_mode,
        sessions=config["sessions"],
    )
    repo_root = Path(__file__).resolve().parents[2]
    manifest = _collection_manifest(raw_root)
    metadata = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "study_config": config,
        "study_config_sha256": _sha256(config_path),
        "collection_input_sha256": manifest,
        "source_and_binary": _source_metadata(repo_root),
        "analysis_environment": {
            "python": sys.version,
            "numpy": np.__version__,
            "scikit_learn": __import__("sklearn").__version__,
            "platform": platform.platform(),
            "processor": platform.processor(),
            "logical_cpu_count": os.cpu_count(),
            "load_average_at_analysis": os.getloadavg() if hasattr(os, "getloadavg") else None,
        },
        "collection_metadata_present": (raw_root / "collection-metadata.json").is_file(),
        "gate_failure_outputs_only_controls": not report["positive_controls_passed"],
    }
    output.mkdir(parents=True, exist_ok=False)
    (output / "metrics.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _write_jsonl(output / "attacker-predictions.jsonl", predictions)
    _write_jsonl(output / "private-evaluation-labels.jsonl", private_labels)
    (output / "analysis-metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    output_hashes = {
        path.name: _sha256(path)
        for path in sorted(output.iterdir())
        if path.is_file()
    }
    (output / "output-manifest.json").write_text(
        json.dumps(output_hashes, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("collection", type=Path)
    parser.add_argument("new_analysis_directory", type=Path)
    args = parser.parse_args()
    try:
        report = analyze(args.config, args.collection, args.new_analysis_directory)
    except (StudyError, OSError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    print(
        "Invocation boundary attack:",
        "controls passed" if report["positive_controls_passed"] else "control gate failed",
        "->",
        args.new_analysis_directory,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
