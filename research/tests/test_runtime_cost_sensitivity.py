"""Unit tests for normalized full-path CPU cost accounting."""
import unittest

from research.analysis.runtime_cost_sensitivity import (
    cpu_cost_usd_per_1000_successes,
    summarize_profile,
)


class RuntimeCostSensitivityTests(unittest.TestCase):
    def test_profile_uses_ratio_of_totals_and_trial_bootstrap(self):
        rows = [
            {"cpu_seconds_observed": 1.0, "offered": 12, "admitted": 10, "dropped": 2,
             "slo_failure_fraction": 0.2, "sampled_rss_mib": 24.0,
             "private_status_counts": {"Success": 10}},
            {"cpu_seconds_observed": 3.0, "offered": 22, "admitted": 20, "dropped": 2,
             "slo_failure_fraction": 0.1, "sampled_rss_mib": 28.0,
             "private_status_counts": {"Success": 20}},
        ]
        result = summarize_profile(rows, resamples=200, seed=7)
        self.assertEqual(result["successes"], 30)
        self.assertEqual(result["offers"], 34)
        self.assertAlmostEqual(result["cpu_seconds_per_1000_successes"], 4000 / 30)
        self.assertAlmostEqual(result["cpu_seconds_per_1000_offers"], 4000 / 34)
        self.assertEqual(result["cpu_seconds_per_1000_successes_ci95"],
                         summarize_profile(rows, resamples=200, seed=7)["cpu_seconds_per_1000_successes_ci95"])

    def test_explicit_rate_is_applied_as_vcpu_hour_conversion(self):
        self.assertAlmostEqual(cpu_cost_usd_per_1000_successes(3600, 1.0), 1.0)
        self.assertAlmostEqual(cpu_cost_usd_per_1000_successes(1800, 0.2), 0.1)

    def test_zero_success_and_invalid_price_are_rejected_or_undefined(self):
        rows = [{"cpu_seconds_observed": 1.0, "offered": 2, "admitted": 0, "dropped": 2,
                 "slo_failure_fraction": 1.0, "sampled_rss_mib": 20.0,
                 "private_status_counts": {}}]
        result = summarize_profile(rows, resamples=200, seed=3)
        self.assertIsNone(result["cpu_seconds_per_1000_successes"])
        with self.assertRaises(ValueError):
            cpu_cost_usd_per_1000_successes(10, -1)
        with self.assertRaises(ValueError):
            cpu_cost_usd_per_1000_successes(10, float("nan"))
        with self.assertRaises(ValueError):
            cpu_cost_usd_per_1000_successes(10, True)


if __name__ == "__main__":
    unittest.main()
