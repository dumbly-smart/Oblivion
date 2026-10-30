import json
import tempfile
import unittest
from pathlib import Path

from research.analysis import invocation_boundary_attack as attack


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))


def event(step, direction, elapsed_ns, frame):
    return {
        "version": 1,
        "step": step,
        "observer": "invocation",
        "direction": direction,
        "bytes": len(frame),
        "elapsed_ns": elapsed_ns,
        "frame": frame,
    }


def session_rows(path, labels, mode="B"):
    write_jsonl(
        path / "ground-truth.jsonl",
        [{"step": step, "label": label} for step, label in labels.items()],
    )
    events = []
    for step, label in labels.items():
        if label == 0 and mode not in {"E", "G"}:
            continue
        request = [step + 1] * 12
        response = [step + 2] * (15 if label == 1 else 8)
        request_at = 100 + step * 100
        events.append(event(step, "request", request_at, request))
        events.append(event(step, "response", request_at + 10 + step, response))
    write_jsonl(path / "network-observer.jsonl", events)


class InvocationBoundaryAttackTests(unittest.TestCase):
    def test_features_use_only_lengths_and_timing_and_unbatched_cover_is_absent(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            session_rows(path, {0: 0, 1: 1, 2: 2}, mode="B")

            observations = attack.extract_session(path, "B", trial=3, session=5)
            matrix, labels = attack.training_data(observations)

            self.assertEqual(labels.tolist(), [0, 4])
            self.assertEqual(matrix.shape, (2, 4))
            self.assertEqual(matrix[0].tolist(), [12, 15, 11, 200])
            self.assertEqual(matrix[1].tolist(), [12, 8, 12, 100])
            self.assertEqual(
                attack.FEATURE_NAMES,
                ("request_bytes", "response_bytes", "response_latency_ns", "interarrival_ns"),
            )

    def test_batched_cover_is_labeled_as_the_stateful_module_executed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            session_rows(path, {0: 0, 1: 1, 2: 2}, mode="G")

            observations = attack.extract_session(path, "G", trial=0, session=0)

            self.assertEqual([row.label for row in observations], [4, 0, 4])

    def test_train_and_test_sets_are_disjoint_by_whole_session(self):
        rows = [
            attack.Observation(trial=trial, session=session, step=step, label=step % 2, features=(1, 2, 3, 4))
            for trial in range(3)
            for session in range(8)
            for step in range(2)
        ]

        train, test = attack.split_sessions(rows, sessions=8)

        train_groups = {(row.trial, row.session) for row in train}
        test_groups = {(row.trial, row.session) for row in test}
        self.assertFalse(train_groups & test_groups)
        self.assertTrue(all(session < 4 for _, session in train_groups))
        self.assertTrue(all(session >= 4 for _, session in test_groups))

    def test_failed_positive_control_gate_omits_protected_mode_scores(self):
        rows_by_mode = {}
        for mode in "ABCDEFG":
            rows = []
            for trial in range(5):
                for session in range(4):
                    for step, label in enumerate((0, 4, 0, 4)):
                        signal = label if mode == "C" else 1
                        rows.append(
                            attack.Observation(
                                trial=trial,
                                session=session,
                                step=step,
                                label=label,
                                features=(signal, signal, signal, signal),
                            )
                        )
            rows_by_mode[mode] = rows

        report, _, _ = attack.evaluate_modes(
            rows_by_mode,
            sessions=4,
            bootstrap_resamples=50,
            bootstrap_seed=7,
            model_seed=11,
        )

        self.assertFalse(report["positive_controls_passed"])
        self.assertEqual(set(report["metrics_by_mode"]), {"A", "B"})
        self.assertEqual(report["protected_scoring"], "omitted_control_failure")

    def test_passing_controls_score_all_modes_and_keep_truth_separate(self):
        rows_by_mode = {}
        for mode in "ABCDEFG":
            rows = []
            for trial in range(5):
                for session in range(4):
                    for step, label in enumerate((0, 4, 0, 4)):
                        signal = label + 1
                        rows.append(
                            attack.Observation(
                                trial=trial,
                                session=session,
                                step=step,
                                label=label,
                                features=(signal, signal, signal, signal),
                            )
                        )
            rows_by_mode[mode] = rows

        report, predictions, private_labels = attack.evaluate_modes(
            rows_by_mode,
            sessions=4,
            bootstrap_resamples=50,
            bootstrap_seed=7,
            model_seed=11,
        )

        self.assertTrue(report["positive_controls_passed"])
        self.assertEqual(set(report["metrics_by_mode"]), set("ABCDEFG"))
        self.assertTrue(predictions)
        self.assertTrue(private_labels)
        self.assertTrue(all("true_function" not in row for row in predictions))
        self.assertTrue(all("true_function" in row for row in private_labels))


if __name__ == "__main__":
    unittest.main()
