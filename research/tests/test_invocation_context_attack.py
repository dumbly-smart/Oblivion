import math
import unittest

import numpy as np

from research.analysis import invocation_context_attack as attack


class InvocationContextAttackTests(unittest.TestCase):
    def test_session_normalization_and_tie_ranks_follow_frozen_transform(self):
        observations = [
            attack.ContextObservation(
                trial=0,
                session=0,
                step=step,
                label=label,
                features=(100, 100, latency, interarrival),
            )
            for step, (label, latency, interarrival) in enumerate(
                ((0, 10, 100), (4, 20, 200), (0, 20, 300), (4, 40, 400))
            )
        ]

        transformed = attack.add_context_features(observations)

        self.assertEqual(attack.FEATURE_NAMES, (
            "request_bytes",
            "response_bytes",
            "log1p_response_latency_ns",
            "mad_scaled_response_latency",
            "log1p_interarrival_ns",
            "latency_midrank_fraction",
        ))
        self.assertAlmostEqual(transformed[0].features[3], -10 / 7.413)
        self.assertAlmostEqual(transformed[1].features[3], 0.0)
        self.assertAlmostEqual(transformed[3].features[3], 20 / 7.413)
        self.assertEqual([row.features[5] for row in transformed], [0.25, 0.625, 0.625, 1.0])
        self.assertAlmostEqual(transformed[0].features[2], math.log1p(10))
        self.assertAlmostEqual(transformed[0].features[4], math.log1p(100))

    def test_zero_mad_uses_unit_scale_and_model_input_has_no_truth(self):
        observations = [
            attack.ContextObservation(0, 0, step, step % 2 * 4, (1, 2, 5, 10))
            for step in range(4)
        ]

        transformed = attack.add_context_features(observations)
        matrix, labels = attack.training_data(transformed)

        self.assertTrue(np.all(matrix[:, 3] == 0))
        self.assertEqual(labels.tolist(), [0, 4, 0, 4])
        self.assertEqual(matrix.shape, (4, 6))

    def test_normalization_rejects_multiple_sessions(self):
        observations = [
            attack.ContextObservation(0, session, step, step % 2 * 4, (1, 2, 5, 10))
            for session in range(2)
            for step in range(2)
        ]

        with self.assertRaises(attack.StudyError):
            attack.add_context_features(observations)

    def test_failed_encrypt_only_gate_omits_protected_modes(self):
        rows_by_mode = {}
        for mode in "ABCDEFG":
            rows = []
            for trial in range(5):
                for session in range(4):
                    for step, label in enumerate((0, 4, 0, 4)):
                        signal = label if mode == "C" else 1
                        rows.append(
                            attack.ContextObservation(
                                trial, session, step, label,
                                (signal, signal, signal, signal, signal, signal),
                            )
                        )
            rows_by_mode[mode] = rows

        report, _, _ = attack.evaluate_modes(
            rows_by_mode,
            sessions=4,
            bootstrap_resamples=50,
            bootstrap_seed=21,
            model_seed=20,
        )

        self.assertFalse(report["positive_controls_passed"])
        self.assertEqual(set(report["metrics_by_mode"]), {"A", "B"})
        self.assertEqual(report["protected_scoring"], "omitted_control_failure")

    def test_successful_control_gate_keeps_predictions_and_truth_separate(self):
        rows_by_mode = {}
        for mode in "ABCDEFG":
            rows = []
            for trial in range(5):
                for session in range(4):
                    for step, label in enumerate((0, 4, 0, 4)):
                        signal = label + 1
                        rows.append(
                            attack.ContextObservation(
                                trial, session, step, label,
                                (signal, signal, signal, signal, signal, signal),
                            )
                        )
            rows_by_mode[mode] = rows

        report, predictions, private_labels = attack.evaluate_modes(
            rows_by_mode,
            sessions=4,
            bootstrap_resamples=50,
            bootstrap_seed=21,
            model_seed=20,
        )

        self.assertTrue(report["positive_controls_passed"])
        self.assertEqual(set(report["metrics_by_mode"]), set("ABCDEFG"))
        self.assertTrue(predictions)
        self.assertTrue(private_labels)
        self.assertTrue(all("true_function" not in row for row in predictions))
        self.assertTrue(all("true_function" in row for row in private_labels))


if __name__ == "__main__":
    unittest.main()
