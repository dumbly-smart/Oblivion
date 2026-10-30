#!/usr/bin/env python3
"""Strictly extract the preregistered attacker view from TCP session traces."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from research.analysis.invocation_boundary_attack import (
    BATCHED_MODES,
    MODES,
    Observation,
    StudyError,
    _integer,
    _read_jsonl,
)


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
