"""Preregistered condition-order and paired-effect checks."""
import unittest

from research.analysis.oram_affinity_crossover import (
    counterbalanced_condition_orders,
    paired_auc_summary,
)


class AffinityCrossoverTests(unittest.TestCase):
    def test_condition_order_is_balanced_and_reproducible(self):
        orders = counterbalanced_condition_orders(30, seed=984)
        self.assertEqual(orders.count(("pinned", "unpinned")), 15)
        self.assertEqual(orders.count(("unpinned", "pinned")), 15)
        self.assertEqual(orders, counterbalanced_condition_orders(30, seed=984))
        self.assertNotEqual(orders, counterbalanced_condition_orders(30, seed=985))

    def test_paired_auc_effect_uses_per_trial_differences(self):
        result = paired_auc_summary([0.6, 0.4, 0.8], [0.5, 0.3, 0.7], seed=7)
        self.assertAlmostEqual(result["pinned_minus_unpinned_mean"], 0.1)
        self.assertEqual(result["trials"], 3)
        self.assertAlmostEqual(result["ci95_paired_difference"][0], 0.1)
        self.assertAlmostEqual(result["ci95_paired_difference"][1], 0.1)

    def test_paired_auc_rejects_mismatched_or_nonfinite_trials(self):
        with self.assertRaises(ValueError):
            paired_auc_summary([0.6], [], seed=1)
        with self.assertRaises(ValueError):
            paired_auc_summary([float("nan")], [0.5], seed=1)


if __name__ == "__main__":
    unittest.main()
