import itertools
import unittest
from fractions import Fraction

from research.attacks.scaler_likelihood import capped_noise_pmf


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


if __name__ == "__main__":
    unittest.main()
