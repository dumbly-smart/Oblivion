import json
import random
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


def write_session(
    directory,
    mode,
    labels=None,
    request_base_ns=1_000,
    frame_fill=0,
    timing_signal="sequence",
):
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
        if timing_signal == "class":
            request_spacing_ns = 1_000
            latency_ns = 10 if label == 1 else 500
        elif timing_signal == "constant":
            request_spacing_ns = 100
            latency_ns = 50
        else:
            request_spacing_ns = 100
            latency_ns = 10 + sequence
        request_ns = request_base_ns + sequence * request_spacing_ns
        response_ns = request_ns + latency_ns
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


class SocketInvocationControlAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def control_collection(self, name, encrypted_timing_signal):
        collection = self.root / name
        collection.mkdir()
        (collection / "config.json").write_text(
            json.dumps(attack.FROZEN_CONFIG), encoding="utf-8"
        )
        (collection / "mode-selection.json").write_text(
            json.dumps({"version": 1, "modes": ["A", "B"]}), encoding="utf-8"
        )
        for mode in "AB":
            for trial in range(attack.FROZEN_CONFIG["trials"]):
                for session in range(attack.FROZEN_CONFIG["sessions"]):
                    labels = list(LABELS)
                    random.Random(trial * 4 + session).shuffle(labels)
                    write_session(
                        collection / mode / f"{trial}-{session}",
                        mode,
                        labels=labels,
                        timing_signal=(
                            encrypted_timing_signal if mode == "B" else "sequence"
                        ),
                    )
        return collection

    def test_control_analysis_passes_when_both_positive_controls_are_learnable(self):
        collection = self.control_collection("pass-controls", "class")
        analysis = self.root / "pass-analysis"

        report = attack.analyze_controls(attack.FROZEN_CONFIG, collection, analysis)

        self.assertTrue(report["positive_controls_passed"])
        self.assertEqual(set(report["metrics_by_mode"]), {"A", "B"})
        self.assertEqual(set(report["positive_control_gates"]), {"A", "B"})
        self.assertTrue(all(gate["passed"] for gate in report["positive_control_gates"].values()))
        self.assertEqual(report["attack"]["positive_class"], 0)
        self.assertEqual(report["attack"]["classification_threshold"], 0.5)
        self.assertEqual(report["attack"]["bootstrap_resamples"], 5000)
        self.assertEqual(report["attack"]["bootstrap_seed"], 20261221)
        for mode in "AB":
            metric = report["metrics_by_mode"][mode]
            self.assertEqual(len(metric["per_trial"]), 30)
            self.assertEqual(metric["test_observations"], 30 * 2 * 8)
            self.assertEqual(metric["test_class_counts"], {"0": 240, "4": 240})
        predictions = [
            json.loads(line)
            for line in (analysis / "predictions.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        private_labels = [
            json.loads(line)
            for line in (analysis / "private-labels.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual({row["mode"] for row in predictions}, {"A", "B"})
        self.assertTrue(all("true_function" not in row for row in predictions))
        self.assertTrue(all("true_function" in row for row in private_labels))
        self.assertEqual(report["protected_scoring"], "not_in_control_phase")

    def test_failed_encrypt_only_control_produces_no_protected_scores_or_predictions(self):
        collection = self.control_collection("failed-controls", "constant")
        analysis = self.root / "failed-analysis"

        report = attack.analyze_controls(attack.FROZEN_CONFIG, collection, analysis)

        self.assertFalse(report["positive_controls_passed"])
        self.assertTrue(report["positive_control_gates"]["A"]["passed"])
        self.assertFalse(report["positive_control_gates"]["B"]["passed"])
        self.assertEqual(set(report["metrics_by_mode"]), {"A", "B"})
        self.assertEqual(report["protected_scoring"], "omitted_control_failure")
        predictions = [
            json.loads(line)
            for line in (analysis / "predictions.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual({row["mode"] for row in predictions}, {"A", "B"})
        self.assertFalse(any(mode in report["metrics_by_mode"] for mode in "CDEFG"))

    def test_each_positive_control_must_meet_both_frozen_auc_conditions(self):
        passing = {
            "A": {"mean_roc_auc": 0.70, "roc_auc_ci95": [0.51, 0.80]},
            "B": {"mean_roc_auc": 0.75, "roc_auc_ci95": [0.52, 0.88]},
        }
        self.assertTrue(all(gate["passed"] for gate in attack._positive_control_gates(passing).values()))

        failures = (
            {
                **passing,
                "A": {"mean_roc_auc": 0.699, "roc_auc_ci95": [0.60, 0.80]},
            },
            {
                **passing,
                "A": {"mean_roc_auc": 0.70, "roc_auc_ci95": [0.50, 0.80]},
            },
            {
                **passing,
                "B": {"mean_roc_auc": 0.69, "roc_auc_ci95": [0.60, 0.80]},
            },
            {
                **passing,
                "B": {"mean_roc_auc": 0.75, "roc_auc_ci95": [0.49, 0.80]},
            },
        )
        for metrics in failures:
            with self.subTest(metrics=metrics):
                self.assertFalse(
                    all(gate["passed"] for gate in attack._positive_control_gates(metrics).values())
                )

    def test_session_split_is_disjoint_and_bootstrap_is_seed_reproducible(self):
        observations = [
            context_attack.ContextObservation(
                trial=trial,
                session=session,
                step=step,
                label=step % 2 * 4,
                features=(1, 2, 3, 4, 5, 6),
            )
            for trial in range(2)
            for session in range(4)
            for step in range(2)
        ]

        train, test = context_attack.split_sessions(observations, sessions=4)

        train_groups = {(row.trial, row.session) for row in train}
        test_groups = {(row.trial, row.session) for row in test}
        self.assertTrue(train_groups.isdisjoint(test_groups))
        self.assertEqual({session for _, session in train_groups}, {0, 1})
        self.assertEqual({session for _, session in test_groups}, {2, 3})
        values = [0.4, 0.6, 0.8, 1.0]
        self.assertEqual(
            context_attack._bootstrap_interval(values, 5000, 20261221),
            context_attack._bootstrap_interval(values, 5000, 20261221),
        )

    def test_control_analysis_requires_frozen_config_and_fresh_analysis_directory(self):
        existing_analysis = self.root / "existing-analysis"
        existing_analysis.mkdir()
        with self.assertRaises(StudyError):
            attack.analyze_controls(attack.FROZEN_CONFIG, self.root / "unused", existing_analysis)

        changed_config = dict(attack.FROZEN_CONFIG, trials=29)
        with self.assertRaises(StudyError):
            attack.analyze_controls(changed_config, self.root / "unused", self.root / "new-analysis")

    def test_control_artifacts_reject_boolean_versions(self):
        collection = self.root / "typed-controls"
        collection.mkdir()
        invalid_config = dict(attack.FROZEN_CONFIG, version=True)
        (collection / "config.json").write_text(
            json.dumps(invalid_config), encoding="utf-8"
        )
        (collection / "mode-selection.json").write_text(
            json.dumps({"version": 1, "modes": ["A", "B"]}), encoding="utf-8"
        )
        with self.assertRaises(StudyError):
            attack.analyze_controls(
                attack.FROZEN_CONFIG, collection, self.root / "typed-analysis"
            )

        (collection / "config.json").write_text(
            json.dumps(attack.FROZEN_CONFIG), encoding="utf-8"
        )
        (collection / "mode-selection.json").write_text(
            json.dumps({"version": True, "modes": ["A", "B"]}), encoding="utf-8"
        )
        with self.assertRaises(StudyError):
            attack.analyze_controls(
                attack.FROZEN_CONFIG, collection, self.root / "typed-analysis-2"
            )

    def test_control_collection_rejects_protected_or_incomplete_mode_directories(self):
        for case in ("protected", "incomplete"):
            with self.subTest(case=case):
                collection = self.root / case
                collection.mkdir()
                (collection / "config.json").write_text(
                    json.dumps(attack.FROZEN_CONFIG), encoding="utf-8"
                )
                (collection / "mode-selection.json").write_text(
                    json.dumps({"version": 1, "modes": ["A", "B"]}),
                    encoding="utf-8",
                )
                if case == "protected":
                    (collection / "C").mkdir()
                else:
                    (collection / "A").mkdir()
                    (collection / "B").mkdir()

                with self.assertRaises(StudyError):
                    attack.analyze_controls(
                        attack.FROZEN_CONFIG,
                        collection,
                        self.root / f"{case}-analysis",
                    )

def events_from(directory):
    return [
        json.loads(line)
        for line in (directory / "socket-observer.jsonl").read_text(encoding="utf-8").splitlines()
    ]


def write_jsonl(path, rows):
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
