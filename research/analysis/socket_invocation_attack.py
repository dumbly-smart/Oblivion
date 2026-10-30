#!/usr/bin/env python3
"""Strictly extract the preregistered attacker view from TCP session traces."""

from __future__ import annotations

import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Mapping

from research.analysis.invocation_boundary_attack import (
    BATCHED_MODES,
    MODES,
    Observation,
    StudyError,
    _integer,
    _read_jsonl,
)
from research.analysis import invocation_context_attack as context_attack


FROZEN_CONFIG = {
    "version": 1,
    "seed": 20261033,
    "trials": 30,
    "sessions": 4,
    "operations": 16,
    "epoch_ms": 100,
}

SOCKET_EVENT_FIELDS = {
    "version",
    "observer",
    "direction",
    "sequence",
    "bytes",
    "elapsed_ns",
    "frame",
}
TRUTH_FIELDS = {"step", "label"}

# These are the loopback application-frame sizes: the Rust payload/envelope
# bodies plus the four-byte big-endian length prefix. Keep this bound tied to
# the frozen protocol and fail closed if those sizes change.
PAYLOAD_FRAME_BYTES = 192 + 4
ENVELOPE_FRAME_BYTES = 192 + 20 + 16 + 4
PLAINTEXT_ECHO_RESPONSE_BYTES = 65 + 4
PLAINTEXT_STATE_RESPONSE_BYTES = 5 + 4
SCHEDULE_COUNTS = {0: 8, 1: 4, 2: 4}


def _read_trace(path: Path) -> list[dict]:
    try:
        return _read_jsonl(path)
    except (OSError, UnicodeError) as error:
        raise StudyError(f"cannot read socket study trace: {path}") from error


def _validate_coordinates(mode: str, trial: int, session: int) -> None:
    if mode not in MODES:
        raise StudyError(f"unknown mode: {mode}")
    if isinstance(trial, bool) or not isinstance(trial, int) or not 0 <= trial < FROZEN_CONFIG["trials"]:
        raise StudyError("invalid trial coordinate")
    if (
        isinstance(session, bool)
        or not isinstance(session, int)
        or not 0 <= session < FROZEN_CONFIG["sessions"]
    ):
        raise StudyError("invalid session coordinate")


def _read_private_schedule(directory: Path) -> list[int]:
    rows = _read_trace(directory / "ground-truth.jsonl")
    labels: dict[int, int] = {}
    for row in rows:
        if set(row) != TRUTH_FIELDS:
            raise StudyError("ground-truth row has an unexpected shape")
        step = _integer(row.get("step"), "truth step")
        label = _integer(row.get("label"), "truth label")
        if label not in SCHEDULE_COUNTS or step in labels:
            raise StudyError("invalid or duplicate ground-truth row")
        labels[step] = label

    expected_steps = FROZEN_CONFIG["operations"]
    if sorted(labels) != list(range(expected_steps)):
        raise StudyError("ground-truth schedule must cover every frozen operation")
    counts = {label: list(labels.values()).count(label) for label in SCHEDULE_COUNTS}
    if counts != SCHEDULE_COUNTS:
        raise StudyError("ground-truth schedule has inconsistent class counts")
    return [labels[step] for step in range(expected_steps)]


def _read_socket_events(directory: Path) -> list[dict]:
    rows = _read_trace(directory / "socket-observer.jsonl")
    if not rows:
        raise StudyError("empty socket invocation trace")

    previous_timestamp = -1
    seen: dict[int, set[str]] = defaultdict(set)
    for row in rows:
        if set(row) != SOCKET_EVENT_FIELDS:
            raise StudyError("socket event has an unexpected shape")
        if _integer(row.get("version"), "socket event version", minimum=1) != 1:
            raise StudyError("unsupported socket event version")
        if row.get("observer") != "invocation":
            raise StudyError("unexpected observer in socket invocation trace")
        direction = row.get("direction")
        if direction not in ("request", "response"):
            raise StudyError("invalid socket event direction")

        sequence = _integer(row.get("sequence"), "socket sequence")
        if direction in seen[sequence]:
            raise StudyError("duplicate socket event direction")
        seen[sequence].add(direction)

        byte_count = _integer(row.get("bytes"), "framed byte count", minimum=1)
        elapsed_ns = _integer(row.get("elapsed_ns"), "socket timestamp")
        if elapsed_ns < previous_timestamp:
            raise StudyError("socket event timestamps are not monotonic")
        previous_timestamp = elapsed_ns

        frame = row.get("frame")
        if (
            not isinstance(frame, list)
            or any(
                isinstance(byte, bool)
                or not isinstance(byte, int)
                or not 0 <= byte <= 255
                for byte in frame
            )
            or len(frame) + 4 != byte_count
        ):
            raise StudyError("socket frame does not match its prefix-inclusive size")
    return rows


def extract_socket_session(
    directory: Path, mode: str, trial: int, session: int
) -> list[Observation]:
    """Join one private schedule to its public socket events.

    Only prefix-inclusive request/response sizes and worker-local timestamps
    are returned as model features. Raw frame contents are validated for
    integrity and then discarded. ``step`` and ``label`` remain evaluator-side
    metadata on ``Observation``; ``feature_matrix`` consumes only ``features``.
    """
    _validate_coordinates(mode, trial, session)
    labels = _read_private_schedule(directory)
    rows = _read_socket_events(directory)

    expected_steps = [
        step
        for step, label in enumerate(labels)
        if mode in BATCHED_MODES or label != 0
    ]
    expected_events = 2 * len(expected_steps)
    if len(rows) != expected_events:
        raise StudyError("socket event count does not match the visible schedule")

    grouped: dict[int, dict[str, dict]] = defaultdict(dict)
    expected_order = []
    for sequence in range(len(expected_steps)):
        expected_order.extend(((sequence, "request"), (sequence, "response")))
    actual_order = []
    for row in rows:
        sequence = _integer(row.get("sequence"), "socket sequence")
        direction = row["direction"]
        actual_order.append((sequence, direction))
        if sequence >= len(expected_steps):
            raise StudyError("socket event sequence exceeds the private schedule")
        grouped[sequence][direction] = row
    if actual_order != expected_order:
        raise StudyError("socket events are not complete ordered request/response pairs")

    observations = []
    previous_request_ns: int | None = None
    encrypted = mode != "A"
    expected_request_bytes = (
        ENVELOPE_FRAME_BYTES if encrypted else PAYLOAD_FRAME_BYTES
    )
    for sequence, step in enumerate(expected_steps):
        label = labels[step]
        pair = grouped[sequence]
        request = pair["request"]
        response = pair["response"]
        request_bytes = _integer(request["bytes"], "request frame size", minimum=1)
        response_bytes = _integer(response["bytes"], "response frame size", minimum=1)
        if request_bytes != expected_request_bytes:
            raise StudyError("request frame size does not match the selected mode")

        if encrypted:
            expected_response_bytes = ENVELOPE_FRAME_BYTES
        elif label == 1:
            expected_response_bytes = PLAINTEXT_ECHO_RESPONSE_BYTES
        else:
            expected_response_bytes = PLAINTEXT_STATE_RESPONSE_BYTES
        if response_bytes != expected_response_bytes:
            raise StudyError("response frame size does not match the selected mode")

        request_ns = _integer(request["elapsed_ns"], "request timestamp")
        response_ns = _integer(response["elapsed_ns"], "response timestamp")
        if response_ns < request_ns:
            raise StudyError("response timestamp precedes its request")
        interarrival_ns = (
            request_ns
            if previous_request_ns is None
            else request_ns - previous_request_ns
        )
        if interarrival_ns < 0:
            raise StudyError("request timestamps are not monotonic")
        previous_request_ns = request_ns

        function_id = 0 if label == 1 else 4
        observations.append(
            Observation(
                trial,
                session,
                step,
                function_id,
                (
                    request_bytes,
                    response_bytes,
                    response_ns - request_ns,
                    interarrival_ns,
                ),
            )
        )

    if {row.label for row in observations} != {0, 4}:
        raise StudyError("socket session must contain both visible function classes")
    return observations


def _read_json_artifact(path: Path) -> dict:
    try:
        if not path.is_file() or path.stat().st_size > 1024 * 1024:
            raise StudyError(f"missing or oversized study artifact: {path}")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise StudyError(f"invalid study artifact: {path}") from error
    if not isinstance(value, dict):
        raise StudyError(f"study artifact must be an object: {path}")
    return value


def _validate_frozen_config(config: Mapping[str, object]) -> None:
    if not isinstance(config, Mapping) or set(config) != set(FROZEN_CONFIG):
        raise StudyError("socket attack config does not match the frozen schema")
    for key, expected in FROZEN_CONFIG.items():
        value = config[key]
        if type(value) is not type(expected) or value != expected:
            raise StudyError("socket attack config differs from the preregistration")


def _positive_control_gates(metrics_by_mode: Mapping[str, dict]) -> dict[str, dict]:
    if set(metrics_by_mode) != {"A", "B"}:
        raise StudyError("positive-control gate requires exactly modes A and B")
    gates = {}
    for mode in ("A", "B"):
        metrics = metrics_by_mode[mode]
        try:
            mean_auc = metrics["mean_roc_auc"]
            interval = metrics["roc_auc_ci95"]
        except (KeyError, TypeError) as error:
            raise StudyError(f"mode {mode} is missing its frozen AUC metrics") from error
        if (
            isinstance(mean_auc, bool)
            or not isinstance(mean_auc, (float, int))
            or not math.isfinite(mean_auc)
            or not 0.0 <= mean_auc <= 1.0
            or not isinstance(interval, list)
            or len(interval) != 2
            or any(
                isinstance(value, bool)
                or not isinstance(value, (float, int))
                or not math.isfinite(value)
                or not 0.0 <= value <= 1.0
                for value in interval
            )
            or interval[0] > interval[1]
        ):
            raise StudyError(f"mode {mode} has invalid AUC gate metrics")
        gates[mode] = {
            "mean_roc_auc": float(mean_auc),
            "lower_roc_auc_ci95": float(interval[0]),
            "minimum_mean_roc_auc": 0.70,
            "minimum_lower_roc_auc_ci95_exclusive": 0.50,
            "passed": mean_auc >= 0.70 and interval[0] > 0.50,
        }
    return gates


def _write_json(path: Path, value: dict) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as destination:
        for row in rows:
            destination.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")


def analyze_controls(
    config: Mapping[str, object],
    control_collection: Path,
    new_analysis_directory: Path,
) -> dict:
    """Score only plaintext/encrypt-only controls and apply the frozen gate."""
    analysis_directory = Path(new_analysis_directory)
    collection = Path(control_collection)
    if analysis_directory.exists():
        raise StudyError("analysis output directory already exists")
    _validate_frozen_config(config)
    if not collection.is_dir():
        raise StudyError("control collection directory is missing")
    collected_config = _read_json_artifact(collection / "config.json")
    _validate_frozen_config(collected_config)
    selection = _read_json_artifact(collection / "mode-selection.json")
    if (
        set(selection) != {"version", "modes"}
        or type(selection["version"]) is not int
        or selection["version"] != 1
        or selection["modes"] != ["A", "B"]
    ):
        raise StudyError("control collection must contain exactly modes A and B")
    if any((collection / mode).exists() for mode in "CDEFG"):
        raise StudyError("control collection unexpectedly contains protected modes")

    expected_sessions = {
        f"{trial}-{session}"
        for trial in range(FROZEN_CONFIG["trials"])
        for session in range(FROZEN_CONFIG["sessions"])
    }
    rows_by_mode = {mode: [] for mode in ("A", "B")}
    for mode in ("A", "B"):
        mode_directory = collection / mode
        if not mode_directory.is_dir():
            raise StudyError(f"control collection is missing mode {mode}")
        if {path.name for path in mode_directory.iterdir()} != expected_sessions:
            raise StudyError(f"control mode {mode} has missing or extra sessions")
        for trial in range(FROZEN_CONFIG["trials"]):
            for session in range(FROZEN_CONFIG["sessions"]):
                directory = collection / mode / f"{trial}-{session}"
                base = extract_socket_session(directory, mode, trial, session)
                if len(base) != 8:
                    raise StudyError("control session has an unexpected visible sample count")
                rows_by_mode[mode].extend(context_attack.add_context_features(base))

    metrics_by_mode = {}
    predictions = []
    private_labels = []
    for mode in ("A", "B"):
        metrics, mode_predictions, mode_labels = context_attack._evaluate_mode(
            mode,
            rows_by_mode[mode],
            FROZEN_CONFIG["sessions"],
            bootstrap_resamples=5000,
            bootstrap_seed=20261221,
            model_seed=20261220,
        )
        metrics_by_mode[mode] = metrics
        predictions.extend(mode_predictions)
        private_labels.extend(mode_labels)

    gates = _positive_control_gates(metrics_by_mode)
    passed = all(gate["passed"] for gate in gates.values())
    report = {
        "version": 1,
        "phase": "positive_controls",
        "config": dict(FROZEN_CONFIG),
        "mode_selection": ["A", "B"],
        "feature_names": list(context_attack.FEATURE_NAMES),
        "positive_controls_passed": passed,
        "positive_control_gates": gates,
        "protected_scoring": (
            "not_in_control_phase" if passed else "omitted_control_failure"
        ),
        "metrics_by_mode": metrics_by_mode,
        "attack": {
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
            "bootstrap_unit": "trial",
            "training_sessions": "0..1",
            "testing_sessions": "2..3",
        },
    }

    analysis_directory.mkdir(parents=True, exist_ok=False)
    _write_json(analysis_directory / "report.json", report)
    _write_jsonl(analysis_directory / "predictions.jsonl", predictions)
    _write_jsonl(analysis_directory / "private-labels.jsonl", private_labels)
    return report
