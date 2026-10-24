import itertools
import math
import unittest
from fractions import Fraction

from research.attacks.scaler_likelihood import (
    CappedNoiseLikelihoodAttack,
    capped_noise_pmf,
    dp_transcript_log_likelihood,
)
from research.simulation.scaler import Config


class CappedNoisePmfTests(unittest.TestCase):
    def test_matches_exhaustive_pair_enumeration(self):
        numerator, denominator, cap = 2, 5, 3
        q = Fraction(numerator, denominator)
        geometric = [q ** n * (1 - q) for n in range(cap)] + [q ** cap]
        expected = {}
        for left, right in itertools.product(range(cap + 1), repeat=2):
            expected[left - right] = (expected.get(left - right, Fraction(0))
                                      + geometric[left] * geometric[right])

        self.assertEqual(capped_noise_pmf(cap, numerator, denominator), expected)

    def test_is_normalized_and_symmetric(self):
        pmf = capped_noise_pmf(4, 7, 16)

        self.assertEqual(sum(pmf.values()), Fraction(1))
        for value, probability in pmf.items():
            self.assertEqual(pmf[-value], probability)

    def test_zero_cap_is_point_mass(self):
        self.assertEqual(capped_noise_pmf(0, 1, 2), {0: Fraction(1)})

    def test_rejects_invalid_parameters(self):
        for args in [(-1, 1, 2), (1, 0, 2), (1, 2, 2), (1, 1, 1)]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                capped_noise_pmf(*args)

    def test_visible_count_likelihood_separates_profiled_hot_classes(self):
        profile = [
            {"session_id": "p0", "labels": [{"hot": 0}],
             "arrival_counts": [[0, 4], [0, 4]]},
            {"session_id": "p1", "labels": [{"hot": 0}],
             "arrival_counts": [[0, 4], [0, 4]]},
            {"session_id": "p2", "labels": [{"hot": 1}],
             "arrival_counts": [[4, 0], [4, 0]]},
            {"session_id": "p3", "labels": [{"hot": 1}],
             "arrival_counts": [[4, 0], [4, 0]]},
        ]
        attack = CappedNoiseLikelihoodAttack("hot").fit(profile)

        scores = attack.score_visible_counts([[0, 4], [0, 4]], "target-0")

        self.assertGreater(scores[0], scores[1])

    def test_likelihood_attack_rejects_profile_session_as_target(self):
        profile = [
            {"session_id": "p0", "labels": [{"intensity": 0}],
             "arrival_counts": [[1]]},
            {"session_id": "p1", "labels": [{"intensity": 1}],
             "arrival_counts": [[4]]},
        ]
        attack = CappedNoiseLikelihoodAttack("intensity").fit(profile)

        with self.assertRaisesRegex(ValueError, "disjoint"):
            attack.score_visible_counts([[1]], "p0")

    def test_profile_labels_reject_boolean_values(self):
        profile = [
            {"session_id": "p0",
             "labels": [{"intensity": 1}, {"intensity": True}],
             "arrival_counts": [[1], [2]]},
            {"session_id": "p1",
             "labels": [{"intensity": 0}, {"intensity": 0}],
             "arrival_counts": [[1], [2]]},
        ]

        with self.assertRaisesRegex(ValueError, "stable binary"):
            CappedNoiseLikelihoodAttack("intensity").fit(profile)

    def test_dp_particle_likelihood_matches_single_epoch_poisson_mass(self):
        cfg = Config(duration=1, epoch=1, service=1, utilization=1, alpha=1,
                     initial=1, maximum=4, functions=1)
        rows = [{"epoch": 0, "instances": [2], "scale_up": [1],
                 "scale_down": [0], "cold_starts": [1]}]

        result = dp_transcript_log_likelihood(
            rows, [[1.0]], cfg, capped_noise_pmf(0, 1, 2),
            particles=100_000, seed=1701,
        )

        self.assertAlmostEqual(math.exp(result), math.exp(-1) / 2, delta=0.005)

    def test_dp_likelihood_treats_scale_down_as_impossible(self):
        cfg = Config(duration=1, epoch=1, service=1, utilization=1, alpha=1,
                     initial=1, maximum=4, functions=1)
        rows = [{"epoch": 0, "instances": [0], "scale_up": [0],
                 "scale_down": [0], "cold_starts": [0]}]

        result = dp_transcript_log_likelihood(
            rows, [[1.0]], cfg, capped_noise_pmf(0, 1, 2),
            particles=1000, seed=1701,
        )

        self.assertEqual(result, -math.inf)


if __name__ == "__main__":
    unittest.main()
