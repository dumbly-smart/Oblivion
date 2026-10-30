#!/usr/bin/env python3
"""Evaluate a preregistered session-normalized timing classifier."""

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

from research.analysis.invocation_boundary_attack import (
    BATCHED_MODES,
    MODES,
    Observation,
    StudyError,
    extract_session,
    split_sessions,
)


FEATURE_NAMES = (
    "request_bytes",
    "response_bytes",
    "log1p_response_latency_ns",
    "mad_scaled_response_latency",
    "log1p_interarrival_ns",
    "latency_midrank_fraction",
)
FROZEN_CONFIG = {
    "version": 1,
    "seed": 20261032,
    "trials": 30,
    "sessions": 4,
    "operations": 16,
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
    "research/analysis/invocation_boundary_attack.py",
)


@dataclass(frozen=True)
class ContextObservation:
    trial: int
    session: int
    step: int
    label: int
    features: tuple[float, float, float, float, float, float]


def add_context_features(
    observations: Sequence[Observation],
) -> list[ContextObservation]:
    """Normalize timings within one unlabeled session and add tie-aware ranks."""
    if not observations:
        raise StudyError("cannot normalize an empty invocation session")
    groups = {(row.trial, row.session) for row in observations}
    if len(groups) != 1 or len({row.step for row in observations}) != len(observations):
        raise StudyError("normalization requires one session with unique steps")
    latencies = np.asarray([row.features[2] for row in observations], dtype=np.float64)
    interarrivals = [row.features[3] for row in observations]
    if not np.all(np.isfinite(latencies)) or np.any(latencies < 0):
        raise StudyError("invalid response latency for session normalization")
    if any(value < 0 for value in interarrivals):
        raise StudyError("invalid request interarrival")

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

    output = []
    for index, row in enumerate(observations):
        request_bytes, response_bytes, latency, interarrival = row.features
        features = (
            float(request_bytes),
            float(response_bytes),
            float(np.log1p(latency)),
            float((latency - median) / scale),
            float(np.log1p(interarrival)),
            rank_fraction[index],
        )
        output.append(
            ContextObservation(
                row.trial,
                row.session,
                row.step,
                row.label,
                features,
            )
        )
    return output


def feature_matrix(observations: Sequence[ContextObservation]) -> np.ndarray:
    if not observations:
        raise StudyError("no invocation observations")
    matrix = np.asarray([row.features for row in observations], dtype=np.float64)
    if matrix.ndim != 2 or matrix.shape[1] != len(FEATURE_NAMES):
        raise StudyError("unexpected context attack feature shape")
    return matrix


def training_data(
    observations: Sequence[ContextObservation],
) -> tuple[np.ndarray, np.ndarray]:
    matrix = feature_matrix(observations)
    labels = np.asarray([row.label for row in observations], dtype=np.int64)
    if set(np.unique(labels)) != {0, 4}:
        raise StudyError("both function classes are required")
    return matrix, labels


def _bootstrap_interval(values: Sequence[float], resamples: int, seed: int) -> list[float]:
    if not values or resamples < 1:
        raise StudyError("bootstrap requires observations and resamples")
    rng = np.random.default_rng(seed)
    samples = rng.choice(
        np.asarray(values, dtype=np.float64),
        (resamples, len(values)),
        replace=True,
    )
    means = samples.mean(axis=1)
    return [float(value) for value in np.quantile(means, [0.025, 0.975])]


def _evaluate_mode(
    mode: str,
    observations: Sequence[ContextObservation],
    sessions: int,
    bootstrap_resamples: int,
    bootstrap_seed: int,
    model_seed: int,
) -> tuple[dict, list[dict], list[dict]]:
    train, test = split_sessions(observations, sessions)
    train_x, train_y = training_data(train)
    test_x = feature_matrix(test)
    model = RandomForestClassifier(
        n_estimators=500,
        max_depth=6,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=model_seed,
        n_jobs=1,
    )
    model.fit(train_x, train_y)
    zero_column = int(np.flatnonzero(model.classes_ == 0)[0])
    scores = model.predict_proba(test_x)[:, zero_column]
    predictions = np.where(scores >= 0.5, 0, 4)

    indexes_by_trial: dict[int, list[int]] = defaultdict(list)
    for index, row in enumerate(test):
        indexes_by_trial[row.trial].append(index)
    per_trial = []
    for trial in sorted(indexes_by_trial):
        indexes = indexes_by_trial[trial]
        truth = np.asarray([test[index].label for index in indexes], dtype=np.int64)
        if set(np.unique(truth)) != {0, 4}:
            raise StudyError(f"mode {mode}, trial {trial} is missing a test class")
        trial_scores = scores[indexes]
        trial_predictions = predictions[indexes]
        counts = Counter(int(value) for value in truth)
        per_trial.append(
            {
                "trial": trial,
                "test_observations": len(indexes),
                "class_counts": {"0": counts[0], "4": counts[4]},
                "roc_auc": float(roc_auc_score(truth == 0, trial_scores)),
                "balanced_accuracy": float(
                    balanced_accuracy_score(truth, trial_predictions)
                ),
                "raw_accuracy": float(np.mean(truth == trial_predictions)),
                "majority_accuracy": float(max(counts.values()) / len(truth)),
            }
        )

    report = {
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
    for name in (
        "roc_auc",
        "balanced_accuracy",
        "raw_accuracy",
        "majority_accuracy",
    ):
        values = [row[name] for row in per_trial]
        report[f"mean_{name}"] = float(np.mean(values))
        report[f"{name}_ci95"] = _bootstrap_interval(
            values, bootstrap_resamples, bootstrap_seed
        )

    attacker_predictions = [
        {
            "mode": mode,
            "trial": row.trial,
            "session": row.session,
            "step": row.step,
            "score_function_0": float(score),
            "predicted_function": int(prediction),
        }
        for row, score, prediction in zip(test, scores, predictions, strict=True)
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
    return report, attacker_predictions, private_labels


def evaluate_modes(
    rows_by_mode: Mapping[str, Sequence[ContextObservation]],
    sessions: int,
    bootstrap_resamples: int = 5000,
    bootstrap_seed: int = 20261221,
    model_seed: int = 20261220,
) -> tuple[dict, list[dict], list[dict]]:
    if set(rows_by_mode) != set(MODES):
        raise StudyError("all seven A–G modes are required")
    metrics = {}
    predictions = []
    private_labels = []
    for mode in ("A", "B"):
        mode_metrics, mode_predictions, mode_labels = _evaluate_mode(
            mode,
            rows_by_mode[mode],
            sessions,
            bootstrap_resamples,
            bootstrap_seed,
            model_seed,
        )
        metrics[mode] = mode_metrics
        predictions.extend(mode_predictions)
        private_labels.extend(mode_labels)
    gates = {
        mode: {
            "minimum_mean_auc": 0.70,
            "minimum_lower_auc_ci95": 0.50,
            "passed": metrics[mode]["mean_roc_auc"] >= 0.70
            and metrics[mode]["roc_auc_ci95"][0] > 0.50,
        }
        for mode in ("A", "B")
    }
    passed = all(gate["passed"] for gate in gates.values())
    if passed:
        for mode in "CDEFG":
            mode_metrics, mode_predictions, mode_labels = _evaluate_mode(
                mode,
                rows_by_mode[mode],
                sessions,
                bootstrap_resamples,
                bootstrap_seed,
                model_seed,
            )
            metrics[mode] = mode_metrics
            predictions.extend(mode_predictions)
            private_labels.extend(mode_labels)
    return (
        {
            "positive_controls_passed": passed,
            "positive_control_gates": gates,
            "protected_scoring": "performed" if passed else "omitted_control_failure",
            "metrics_by_mode": metrics,
            "feature_names": list(FEATURE_NAMES),
            "attack": {
                "classifier": "RandomForestClassifier",
                "n_estimators": 500,
                "max_depth": 6,
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
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_jsonl(path: Path, rows: Iterable[dict]) -> None:
    with path.open("w", encoding="utf-8") as destination:
        for row in rows:
            destination.write(json.dumps(row, sort_keys=True) + "\n")


def _load_config(config_path: Path, collection: Path) -> dict:
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        collected = json.loads((collection / "config.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise StudyError("cannot read frozen or collected configuration") from error
    if config != FROZEN_CONFIG or collected != FROZEN_CONFIG:
        raise StudyError("configuration differs from preregistered session-normalized study")
    return config


def _load_all(collection: Path, config: dict) -> dict[str, list[ContextObservation]]:
    rows_by_mode = {mode: [] for mode in MODES}
    for trial in range(config["trials"]):
        for session in range(config["sessions"]):
            for mode in MODES:
                directory = collection / mode / f"{trial}-{session}"
                raw_rows = extract_session(directory, mode, trial, session)
                rows_by_mode[mode].extend(add_context_features(raw_rows))
    return rows_by_mode


def _hash_collection(collection: Path) -> dict:
    paths = sorted(path for path in collection.rglob("*") if path.is_file())
    return {path.relative_to(collection).as_posix(): _sha256(path) for path in paths}


def _source_metadata(root: Path) -> dict:
    files = (*SOURCE_FILES, "research/analysis/invocation_context_attack.py")
    source_hashes = {name: _sha256(root / name) for name in files}
    binary = root / "target/release/oblivion-harness"
    if not binary.is_file():
        raise StudyError("release oblivion-harness binary is missing")
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()
    return {
        "git_commit": commit,
        "source_sha256": source_hashes,
        "harness_binary_sha256": _sha256(binary),
        "analysis_script_sha256": source_hashes["research/analysis/invocation_context_attack.py"],
    }


def analyze(config_path: Path, collection: Path, output: Path) -> dict:
    if output.exists():
        raise StudyError(f"analysis output already exists: {output}")
    config = _load_config(config_path, collection)
    rows_by_mode = _load_all(collection, config)
    report, predictions, private_labels = evaluate_modes(
        rows_by_mode,
        sessions=config["sessions"],
    )
    root = Path(__file__).resolve().parents[2]
    metadata = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "study_config": config,
        "study_config_sha256": _sha256(config_path),
        "collection_input_sha256": _hash_collection(collection),
        "source_and_binary": _source_metadata(root),
        "analysis_environment": {
            "python": sys.version,
            "numpy": np.__version__,
            "scikit_learn": __import__("sklearn").__version__,
            "platform": platform.platform(),
            "processor": platform.processor(),
            "logical_cpu_count": os.cpu_count(),
            "load_average_at_analysis": os.getloadavg() if hasattr(os, "getloadavg") else None,
        },
        "collection_metadata_present": (collection / "collection-metadata.json").is_file(),
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
    hashes = {
        path.name: _sha256(path)
        for path in sorted(output.iterdir())
        if path.is_file()
    }
    (output / "output-manifest.json").write_text(
        json.dumps(hashes, indent=2, sort_keys=True) + "\n", encoding="utf-8"
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
        "Session-normalized invocation attack:",
        "controls passed" if report["positive_controls_passed"] else "control gate failed",
        "->",
        args.new_analysis_directory,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
