import unittest
from unittest.mock import patch

from research.attacks.scaler_interval import count_intervals, interval_features
from research.simulation.scaler import (
    Config, Request, bounded_arrival_counts, dp_laplace_parameters, simulate,
)


def observer(instances, scale_up, scale_down=None):
    scale_down = scale_down or [0 for _ in instances]
    return [
        {"epoch": epoch, "instances": [count], "scale_up": [up],
         "scale_down": [down], "cold_starts": [up]}
        for epoch, (count, up, down) in enumerate(zip(instances, scale_up, scale_down))
    ]


class ScalerIntervalTests(unittest.TestCase):
    def test_bounds_include_arrivals_across_up_and_censored_no_up_transitions(self):
        cfg = Config(duration=4, epoch=1, functions=1, service=1,
                     utilization=1, initial=0, maximum=100, alpha=1)
        trace = observer([10, 10, 15, 15], [10, 0, 5, 0])

        intervals = count_intervals(trace, cfg, policy="dp_laplace", noise_cap=2)

        self.assertEqual(intervals, [[(7, 12)], [(0, 12)], [(12, 17)], [(0, 17)]])
        features = interval_features(trace, cfg, policy="dp_laplace", noise_cap=2)
        self.assertEqual(features.shape, (4, 3))
        self.assertTrue((features[:, 0] <= features[:, 1]).all())

    def test_capacity_saturation_does_not_create_a_false_arrival_upper_bound(self):
        cfg = Config(duration=1, epoch=1, functions=1, service=1,
                     utilization=1, initial=0, maximum=2, alpha=1)
        trace = observer([2], [2])

        intervals = count_intervals(trace, cfg, policy="dp_laplace", noise_cap=2)

        self.assertEqual(intervals[0][0][0], 0)
        self.assertEqual(intervals[0][0][1], 1_000_000)

    def test_intervals_cover_actual_counts_for_a_simulated_csprng_transcript(self):
        cfg = Config(duration=4, epoch=1, functions=1, service=1,
                     utilization=1, initial=0, maximum=100, alpha=0.35,
                     dp_epsilon=2, dp_delta=1e-3)
        counts = [10, 0, 15, 0]
        requests = [Request(epoch + 0.01 + index / 1000, 0)
                    for epoch, count in enumerate(counts) for index in range(count)]
        with patch('research.simulation.scaler.secrets.randbits', return_value=0):
            transcript = simulate(cfg, requests, 'dp_laplace', 91,
                                  dp_noise_source='os_csprng')['observer']

        intervals = count_intervals(
            transcript, cfg, 'dp_laplace',
            noise_cap=dp_laplace_parameters(cfg)['geometric_cap'],
        )
        actual = bounded_arrival_counts(requests, cfg)
        for epoch, row in enumerate(intervals):
            for pool, (lower, upper) in enumerate(row):
                self.assertLessEqual(lower, int(actual[epoch, pool]))
                self.assertGreaterEqual(upper, int(actual[epoch, pool]))

    def test_input_requires_fixed_horizon_and_public_policy_name(self):
        cfg = Config(duration=2, epoch=1, functions=1)
        with self.assertRaises(ValueError):
            count_intervals(observer([1], [1]), cfg, "dp_laplace", 2)
        with self.assertRaises(ValueError):
            count_intervals(observer([1, 1], [1, 0]), cfg, "unknown", 2)


if __name__ == "__main__":
    unittest.main()
