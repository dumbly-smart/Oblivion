import json
import math
import tempfile
import unittest
from pathlib import Path

from research.analysis import verify_invocation_context_bundle as verifier


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows))


def _session_fixture(root: Path, mode: str = "A") -> Path:
    directory = root / mode / "0-0"
    labels = [0] * 8 + [1] * 4 + [2] * 4
    _write_jsonl(
        directory / "ground-truth.jsonl",
        [{"step": step, "label": label} for step, label in enumerate(labels)],
    )
    events = []
    real_steps = range(8, 16) if mode not in verifier.BATCHED_MODES else range(16)
    latencies = [10, 10, 30, 40, 50, 60, 70, 80]
    for ordinal, step in enumerate(real_steps):
        request_ns = 1_000 + ordinal * 100
        response_ns = request_ns + latencies[ordinal % len(latencies)]
        for direction, timestamp, frame in (
            ("request", request_ns, [1, 2, 3]),
            ("response", response_ns, [4, 5, 6, 7]),
        ):
            events.append(
                {
                    "observer": "invocation",
                    "step": step,
                    "direction": direction,
                    "frame": frame,
                    "bytes": len(frame),
                    "elapsed_ns": timestamp,
                }
            )
    _write_jsonl(directory / "network-observer.jsonl", events)
    return directory


class InvocationContextBundleVerifierTests(unittest.TestCase):
    def test_reconstructs_session_normalized_features_from_observer_frames(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = _session_fixture(Path(temporary))

            rows = verifier.extract_session(directory, "A", 0, 0)

        self.assertEqual(len(rows), 8)
        self.assertEqual([row.label for row in rows], [0] * 4 + [4] * 4)
        self.assertEqual(rows[0].features[:2], (3.0, 4.0))
        self.assertAlmostEqual(rows[0].features[2], math.log1p(10))
        self.assertAlmostEqual(rows[0].features[3], (10 - 45) / (1.4826 * 20))
        self.assertAlmostEqual(rows[0].features[4], math.log1p(1000))
        self.assertEqual(rows[0].features[5], rows[1].features[5])

    def test_rejects_incomplete_or_extra_invocation_pairs(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = _session_fixture(Path(temporary))
            path = directory / "network-observer.jsonl"
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            rows.pop()
            _write_jsonl(path, rows)

            with self.assertRaises(verifier.VerificationError):
                verifier.extract_session(directory, "A", 0, 0)

    def test_control_gate_rejects_protected_scores_after_failure(self):
        metrics = {
            "positive_controls_passed": False,
            "protected_scoring": "omitted_control_failure",
            "metrics_by_mode": {
                "A": {"mean_roc_auc": 1.0, "roc_auc_ci95": [1.0, 1.0]},
                "B": {
                    "mean_roc_auc": 0.69,
                    "roc_auc_ci95": [0.60, 0.75],
                },
                "C": {"mean_roc_auc": 0.99, "roc_auc_ci95": [0.98, 1.0]},
            },
            "positive_control_gates": {
                "A": {
                    "minimum_mean_auc": 0.70,
                    "minimum_lower_auc_ci95": 0.50,
                    "passed": True,
                },
                "B": {
                    "minimum_mean_auc": 0.70,
                    "minimum_lower_auc_ci95": 0.50,
                    "passed": False,
                },
            },
        }

        with self.assertRaises(verifier.VerificationError):
            verifier.validate_control_scope(metrics)

    def test_failed_gate_accepts_only_a_and_b_metrics(self):
        metrics = {
            "positive_controls_passed": False,
            "protected_scoring": "omitted_control_failure",
            "metrics_by_mode": {
                "A": {"mean_roc_auc": 1.0, "roc_auc_ci95": [1.0, 1.0]},
                "B": {
                    "mean_roc_auc": 0.6989583333333333,
                    "roc_auc_ci95": [0.6682291666666667, 0.7317708333333334],
                },
            },
            "positive_control_gates": {
                "A": {
                    "minimum_mean_auc": 0.70,
                    "minimum_lower_auc_ci95": 0.50,
                    "passed": True,
                },
                "B": {
                    "minimum_mean_auc": 0.70,
                    "minimum_lower_auc_ci95": 0.50,
                    "passed": False,
                },
            },
        }

        verifier.validate_control_scope(metrics)

    def test_reported_metric_cannot_use_a_weaker_mean_auc_gate(self):
        metrics = {
            "positive_controls_passed": True,
            "protected_scoring": "performed",
            "metrics_by_mode": {
                mode: {"mean_roc_auc": 0.71, "roc_auc_ci95": [0.51, 0.8]}
                for mode in "ABCDEFG"
            },
            "positive_control_gates": {
                mode: {
                    "minimum_mean_auc": 0.69,
                    "minimum_lower_auc_ci95": 0.50,
                    "passed": True,
                }
                for mode in "AB"
            },
        }

        with self.assertRaises(verifier.VerificationError):
            verifier.validate_control_scope(metrics)


if __name__ == "__main__":
    unittest.main()
