import json
import tempfile
import unittest
from pathlib import Path

import numpy as np

from research.analysis import invocation_context_attack as context_attack
from research.analysis import socket_invocation_attack as attack
from research.analysis.invocation_boundary_attack import StudyError


PAYLOAD_BYTES = 192
ENVELOPE_BYTES = 228
LABELS = [0, 1, 0, 2] * 4


def write_session(directory, mode, labels=None, request_base_ns=1_000, frame_fill=0):
    labels = list(LABELS if labels is None else labels)
    truth = [{"step": step, "label": label} for step, label in enumerate(labels)]
    active_steps = [
        step for step, label in enumerate(labels) if mode in ("E", "G") or label != 0
    ]
    events = []
    for sequence, step in enumerate(active_steps):
        label = labels[step]
        encrypted = mode != "A"
        request_body_bytes = ENVELOPE_BYTES if encrypted else PAYLOAD_BYTES
        response_body_bytes = (
            ENVELOPE_BYTES if encrypted else (65 if label == 1 else 5)
        )
        request_ns = request_base_ns + sequence * 100
        response_ns = request_ns + 10 + sequence
        for direction, byte_count, elapsed_ns, marker in (
            ("request", request_body_bytes, request_ns, frame_fill + sequence),
            ("response", response_body_bytes, response_ns, frame_fill + 128 + sequence),
        ):
            events.append(
                {
                    "version": 1,
                    "observer": "invocation",
                    "direction": direction,
                    "sequence": sequence,
                    "bytes": byte_count + 4,
                    "elapsed_ns": elapsed_ns,
                    "frame": [marker % 256] * byte_count,
                }
            )
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "ground-truth.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in truth), encoding="utf-8"
    )
    (directory / "socket-observer.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in events), encoding="utf-8"
    )
    return truth, events


class SocketInvocationAttackExtractionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_unbatched_modes_omit_dummy_opportunities_and_use_wire_sizes(self):
        for mode in "ABCDF":
            with self.subTest(mode=mode):
                directory = self.root / mode
                _, events = write_session(directory, mode)

                observations = attack.extract_socket_session(directory, mode, 3, 2)

                visible_steps = [
                    step for step, label in enumerate(LABELS) if label != 0
                ]
                self.assertEqual([row.step for row in observations], visible_steps)
                self.assertEqual([row.label for row in observations].count(0), 4)
                self.assertEqual([row.label for row in observations].count(4), 4)
                self.assertEqual(len(events), len(observations) * 2)
                for row, request, response in zip(
                    observations, events[::2], events[1::2], strict=True
                ):
                    self.assertEqual(row.trial, 3)
                    self.assertEqual(row.session, 2)
                    self.assertEqual(row.features[0], request["bytes"])
                    self.assertEqual(row.features[1], response["bytes"])
                    if mode == "A":
                        self.assertEqual(row.features[0], PAYLOAD_BYTES + 4)
                        expected_response = 65 + 4 if LABELS[row.step] == 1 else 5 + 4
                        self.assertEqual(row.features[1], expected_response)
                    else:
                        self.assertEqual(row.features[:2], (ENVELOPE_BYTES + 4,) * 2)

    def test_batched_modes_include_dummy_cover_as_function_four(self):
        for mode in "EG":
            with self.subTest(mode=mode):
                directory = self.root / mode
                write_session(directory, mode)

                observations = attack.extract_socket_session(directory, mode, 0, 0)

                self.assertEqual(len(observations), 16)
                self.assertEqual([row.step for row in observations], list(range(16)))
                self.assertEqual([row.label for row in observations].count(0), 4)
                self.assertEqual([row.label for row in observations].count(4), 12)
                self.assertTrue(
                    all(row.features[:2] == (ENVELOPE_BYTES + 4,) * 2 for row in observations)
                )

    def test_timing_join_and_context_features_use_only_public_frame_sizes_and_times(self):
        directory = self.root / "A"
        write_session(directory, "A", request_base_ns=5_000, frame_fill=11)

        observations = attack.extract_socket_session(directory, "A", 1, 0)
        context = context_attack.add_context_features(observations)
        matrix, labels = context_attack.training_data(context)

        first_visible_step = next(step for step, label in enumerate(LABELS) if label != 0)
        self.assertEqual(observations[0].step, first_visible_step)
        self.assertEqual(observations[0].features[2], 10)
        self.assertEqual(observations[0].features[3], 5_000)
        self.assertEqual(observations[1].features[3], 100)
        self.assertEqual(len(context[0].features), 6)
        self.assertEqual(matrix.shape, (8, 6))
        self.assertEqual(labels.shape, (8,))
        self.assertAlmostEqual(context[0].features[2], np.log1p(10))
        self.assertAlmostEqual(context[0].features[4], np.log1p(5_000))

        other_directory = self.root / "A-other-body"
        write_session(other_directory, "A", request_base_ns=5_000, frame_fill=73)
        other = attack.extract_socket_session(other_directory, "A", 1, 0)
        self.assertEqual(
            [row.features for row in observations], [row.features for row in other]
        )
        self.assertNotEqual(
            events_from(directory), events_from(other_directory)
        )

    def test_duplicate_unknown_and_incomplete_sequence_events_are_rejected(self):
        cases = ("duplicate", "unknown", "missing_response")
        for case in cases:
            with self.subTest(case=case):
                directory = self.root / case
                _, events = write_session(directory, "A")
                if case == "duplicate":
                    events[-1]["sequence"] = events[-3]["sequence"]
                elif case == "unknown":
                    events[-1]["sequence"] = 99
                else:
                    events.pop()
                write_jsonl(directory / "socket-observer.jsonl", events)

                with self.assertRaises(StudyError):
                    attack.extract_socket_session(directory, "A", 0, 0)

    def test_malformed_sizes_timestamps_and_private_schedule_are_rejected(self):
        for case in (
            "frame_length",
            "mode_length",
            "timestamp",
            "schedule",
            "missing_truth_step",
        ):
            with self.subTest(case=case):
                directory = self.root / case
                truth, events = write_session(directory, "A")
                if case == "frame_length":
                    events[0]["frame"].pop()
                elif case == "mode_length":
                    events[0]["frame"].pop()
                    events[0]["bytes"] -= 1
                elif case == "timestamp":
                    events[2]["elapsed_ns"] = events[1]["elapsed_ns"] - 1
                elif case == "schedule":
                    truth[0]["label"] = 1
                    write_jsonl(directory / "ground-truth.jsonl", truth)
                else:
                    truth.pop()
                    write_jsonl(directory / "ground-truth.jsonl", truth)
                write_jsonl(directory / "socket-observer.jsonl", events)

                with self.assertRaises(StudyError):
                    attack.extract_socket_session(directory, "A", 0, 0)

    def test_invalid_mode_and_malformed_jsonl_are_rejected(self):
        directory = self.root / "A"
        write_session(directory, "A")
        with self.assertRaises(StudyError):
            attack.extract_socket_session(directory, "Z", 0, 0)

        (directory / "socket-observer.jsonl").write_text("{bad json}\n", encoding="utf-8")
        with self.assertRaises(StudyError):
            attack.extract_socket_session(directory, "A", 0, 0)


def events_from(directory):
    return [
        json.loads(line)
        for line in (directory / "socket-observer.jsonl").read_text(encoding="utf-8").splitlines()
    ]


def write_jsonl(path, rows):
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
