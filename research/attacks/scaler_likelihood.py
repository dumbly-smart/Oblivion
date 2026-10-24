"""Known-policy likelihood attacks for autoscaler observer traces."""

from fractions import Fraction
import math

import numpy as np


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


def _count_matrix(counts, shape=None):
    if not isinstance(counts, list) or not counts:
        raise ValueError("arrival counts must be a non-empty matrix")
    width = len(counts[0]) if isinstance(counts[0], list) else 0
    if width < 1 or any(not isinstance(row, list) or len(row) != width
                         for row in counts):
        raise ValueError("arrival counts must be a rectangular matrix")
    if shape is not None and (len(counts), width) != shape:
        raise ValueError("arrival count shape mismatch")
    if any(type(value) is not int or value < 0
           for row in counts for value in row):
        raise ValueError("arrival counts must be nonnegative integers")
    return np.asarray(counts, dtype=np.int64)


class CappedNoiseLikelihoodAttack:
    """Fit class-conditional Poisson rates on complete labeled profile sessions.

    Target sessions are scored either from visible per-pool arrival counts or
    from the DP autoscaler's instance-count transcript. The latter uses a
    bootstrap particle filter over hidden arrivals and the exact finite capped
    noise law. It is an empirical model-based attack, not a security proof.
    """

    def __init__(self, task):
        if task not in ("intensity", "hot"):
            raise ValueError("task must be intensity or hot")
        self.task = task

    def fit(self, profile_sessions):
        if not isinstance(profile_sessions, list) or not profile_sessions:
            raise ValueError("labeled profile sessions are required")
        session_ids = set()
        grouped = {}
        expected_shape = None
        for session in profile_sessions:
            if (not isinstance(session, dict)
                    or set(session) != {"session_id", "labels", "arrival_counts"}
                    or not isinstance(session["session_id"], str)
                    or not session["session_id"]
                    or session["session_id"] in session_ids
                    or not isinstance(session["labels"], list)
                    or not session["labels"]):
                raise ValueError("invalid profile session")
            session_ids.add(session["session_id"])
            labels = session["labels"]
            value = labels[0].get(self.task) if isinstance(labels[0], dict) else None
            if (type(value) is not int or value not in (0, 1)
                    or any(not isinstance(label, dict)
                           or label.get(self.task) != value for label in labels)):
                raise ValueError("profile task labels must be stable binary values")
            counts = _count_matrix(session["arrival_counts"])
            shape = counts.shape
            if expected_shape is not None and shape != expected_shape:
                raise ValueError("profile sessions have inconsistent horizons")
            expected_shape = shape
            grouped.setdefault(value, []).append(counts)
        if set(grouped) != {0, 1}:
            raise ValueError("both task classes must occur in profile sessions")

        self.rates = {}
        for value, sessions in grouped.items():
            totals = np.sum(sessions, axis=0, dtype=np.int64)
            # Gamma(shape=0.5, rate=0.5) smoothing avoids zero-probability
            # classes when a low-rate profile happens to contain no arrivals.
            self.rates[value] = (totals + 0.5) / (len(sessions) + 0.5)
        self.profile_sessions = session_ids
        self.shape = expected_shape
        return self

    def _check_target(self, session_id):
        if not hasattr(self, "rates"):
            raise ValueError("fit must run before target scoring")
        if not isinstance(session_id, str) or not session_id:
            raise ValueError("target session identifier is required")
        if session_id in self.profile_sessions:
            raise ValueError("profile and target sessions must be disjoint")

    def score_visible_counts(self, counts, target_session_id):
        """Return class log-likelihoods for the plaintext count control."""
        self._check_target(target_session_id)
        matrix = _count_matrix(counts, self.shape)
        scores = {}
        for value, rates in self.rates.items():
            scores[value] = float(np.sum(
                matrix * np.log(rates) - rates
                - np.vectorize(math.lgamma)(matrix + 1)
            ))
        return scores

    def score_dp_observer(self, rows, target_session_id, cfg, noise_pmf,
                          particles, seed):
        """Score a target using only public DP autoscaler observer rows."""
        self._check_target(target_session_id)
        if self.shape[1] != cfg.functions:
            raise ValueError("profile function count disagrees with target config")
        return {value: dp_transcript_log_likelihood(
            rows, rates.tolist(), cfg, noise_pmf, particles=particles,
            seed=seed + value,
        ) for value, rates in self.rates.items()}


def dp_transcript_log_likelihood(rows, rates, cfg, noise_pmf, particles, seed):
    """Estimate observer log-likelihood with a bootstrap particle filter.

    The modeled transcript is the per-epoch public instance count. DP scaling
    has no downscale or queue-dependent target, so each pool's hidden state is
    its EWMA signal and previous instance count. The returned Monte Carlo
    likelihood is approximate; a zero-particle event is represented by
    ``-inf`` rather than hidden by smoothing.
    """
    cfg.validate()
    horizon = math.ceil(cfg.duration / cfg.epoch)
    if (not isinstance(rows, list) or len(rows) != horizon
            or not isinstance(rates, list) or len(rates) != horizon
            or any(not isinstance(row, list) or len(row) != cfg.functions
                   for row in rates)
            or any(type(value) not in (int, float) or not math.isfinite(value)
                   or value <= 0 for row in rates for value in row)
            or type(particles) is not int or not 100 <= particles <= 1_000_000
            or type(seed) is not int or seed < 0):
        raise ValueError("invalid DP likelihood inputs")
    noise_values = sorted(noise_pmf)
    probabilities = np.asarray([float(noise_pmf[value]) for value in noise_values],
                                dtype=float)
    if (not noise_values or any(type(value) is not int for value in noise_values)
            or not np.all(np.isfinite(probabilities)) or np.any(probabilities < 0)
            or not math.isclose(float(np.sum(probabilities)), 1.0, abs_tol=1e-12)):
        raise ValueError("invalid finite noise PMF")
    from research.simulation.scaler import features

    for epoch, row in enumerate(rows):
        features(row)
        if type(row.get("epoch")) is not int or row["epoch"] != epoch:
            raise ValueError("DP observer epochs must be complete and ordered")
        if any(row["scale_down"]) or any(row["instances"][pool] < cfg.initial
                                          for pool in range(cfg.functions)):
            return -math.inf
    rng = np.random.default_rng(seed)
    factor = cfg.service / (cfg.epoch * cfg.utilization)
    total_log_likelihood = 0.0
    for pool in range(cfg.functions):
        signal = np.zeros(particles, dtype=float)
        previous_instances = cfg.initial
        for epoch, row in enumerate(rows):
            arrivals = rng.poisson(rates[epoch][pool], size=particles)
            noise = rng.choice(noise_values, size=particles, p=probabilities)
            noisy_count = np.maximum(0, arrivals + noise)
            signal = cfg.alpha * noisy_count + (1 - cfg.alpha) * signal
            targets = np.ceil(signal * factor).astype(np.int64)
            targets = np.clip(targets, 0, cfg.maximum)
            targets = np.maximum(targets, previous_instances)
            observed = row["instances"][pool]
            if (row["scale_up"][pool] != max(0, observed - previous_instances)
                    or row["cold_starts"][pool] != row["scale_up"][pool]):
                return -math.inf
            matching = np.flatnonzero(targets == observed)
            if len(matching) == 0:
                return -math.inf
            total_log_likelihood += math.log(len(matching) / particles)
            if len(matching) != particles:
                selected = rng.choice(matching, size=particles, replace=True)
                signal = signal[selected]
            previous_instances = observed
    return total_log_likelihood
