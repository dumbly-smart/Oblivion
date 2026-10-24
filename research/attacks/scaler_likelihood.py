"""Exact finite noise probabilities for autoscaler likelihood attacks."""

from fractions import Fraction


def capped_noise_pmf(cap, numerator, denominator):
    """Return the exact PMF of the difference of two capped geometrics.

    Each geometric stream counts successes with probability ``numerator /
    denominator`` and stops at ``cap``. The cap is part of the sampled law:
    the probability of the cap includes the entire tail, matching
    ``discrete_laplace_from_bits``. Results are exact :class:`Fraction`
    values keyed by noise in ``[-cap, cap]``.
    """
    if (type(cap) is not int or cap < 0
            or type(numerator) is not int or type(denominator) is not int
            or denominator <= 0 or not 0 < numerator < denominator):
        raise ValueError("invalid capped geometric parameters")

    q = Fraction(numerator, denominator)
    stop = 1 - q
    ratio = 1 - q * q

    def positive_probability(delta):
        # For b < cap-delta, both geometric draws are uncapped. The last
        # feasible b puts the first draw at the cap and absorbs its tail.
        count = cap - delta
        interior = (stop * stop * q ** delta
                    * (1 - q ** (2 * count)) / ratio)
        boundary = stop * q ** (2 * cap - delta)
        return interior + boundary

    zero = (stop * stop * (1 - q ** (2 * cap)) / ratio
            + q ** (2 * cap))
    result = {0: zero}
    for delta in range(1, cap + 1):
        probability = positive_probability(delta)
        result[delta] = probability
        result[-delta] = probability
    return result
