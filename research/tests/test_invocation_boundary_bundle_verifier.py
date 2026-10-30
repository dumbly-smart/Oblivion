import unittest

from research.analysis import verify_invocation_boundary_bundle as verifier


class InvocationBoundaryBundleVerifierTests(unittest.TestCase):
    def test_auc_recomputes_average_ranks_for_tied_scores(self):
        self.assertAlmostEqual(
            verifier.auc([1, 0, 1, 0], [0.9, 0.5, 0.5, 0.1]),
            0.875,
        )

    def test_control_failure_rejects_any_protected_mode_score(self):
        report = {
            "positive_controls_passed": False,
            "protected_scoring": "omitted_control_failure",
            "metrics_by_mode": {mode: {} for mode in "ABC"},
        }

        with self.assertRaises(verifier.VerificationError):
            verifier.validate_control_scope(report)

    def test_control_gate_cannot_change_preregistered_auc_threshold(self):
        report = {
            "positive_controls_passed": False,
            "protected_scoring": "omitted_control_failure",
            "metrics_by_mode": {
                mode: {"mean_roc_auc": 0.60, "roc_auc_ci95": [0.55, 0.65]}
                for mode in ("A", "B")
            },
            "positive_control_gates": {
                mode: {
                    "passed": False,
                    "minimum_mean_auc": 0.60,
                    "minimum_lower_auc_ci95": 0.50,
                }
                for mode in ("A", "B")
            },
        }

        with self.assertRaises(verifier.VerificationError):
            verifier.validate_control_scope(report)

    def test_private_labels_join_only_after_attacker_predictions_exist(self):
        predictions = [
            {
                "mode": "A",
                "trial": 0,
                "session": 4,
                "step": 0,
                "score_function_0": 0.8,
                "predicted_function": 0,
            }
        ]
        private_labels = [
            {"mode": "A", "trial": 0, "session": 4, "step": 0, "true_function": 0}
        ]

        joined = verifier.join_predictions(predictions, private_labels)

        self.assertEqual(joined[0]["true_function"], 0)
        self.assertNotIn("true_function", predictions[0])
        self.assertEqual(joined[0]["score_function_0"], 0.8)

    def test_truth_column_inside_attacker_predictions_is_rejected(self):
        predictions = [
            {
                "mode": "A",
                "trial": 0,
                "session": 4,
                "step": 0,
                "score_function_0": 0.8,
                "predicted_function": 0,
                "true_function": 0,
            }
        ]
        private_labels = [
            {"mode": "A", "trial": 0, "session": 4, "step": 0, "true_function": 0}
        ]

        with self.assertRaises(verifier.VerificationError):
            verifier.join_predictions(predictions, private_labels)


if __name__ == "__main__":
    unittest.main()
