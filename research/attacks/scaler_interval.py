"""Conservative policy-aware arrival intervals from public scaler counts."""

import math

import numpy as np

from research.simulation.scaler import Config, features


MAX_REQUESTS = 1_000_000


def count_intervals(rows, cfg, policy, noise_cap):
    """Bound included arrivals using only public counts and known policy bounds.

    For ``dp_laplace``, the hidden geometric-difference draw is only known to
    lie in ``[-noise_cap, noise_cap]``. For ``naive``, the draw is exactly zero
    and the public signal is the per-epoch arrival count. Capacity saturation
    and scale-down transitions are treated as censored rather than guessed.
    """
    cfg.validate()
    horizon = math.ceil(cfg.duration / cfg.epoch)
    if not isinstance(rows, list) or len(rows) != horizon:
        raise ValueError("observer must contain the complete fixed horizon")
    if policy not in ("naive", "dp_laplace"):
        raise ValueError("interval inversion supports naive and dp_laplace policies")
    if type(noise_cap) is not int or noise_cap < 0:
        raise ValueError("noise cap must be a nonnegative integer")
    if policy == "naive" and noise_cap != 0:
        raise ValueError("naive policy has no discrete-noise cap")

    factor = cfg.service / (cfg.epoch * cfg.utilization)
    alpha = cfg.alpha if policy == "dp_laplace" else 1.0
    noise_limit = noise_cap if policy == "dp_laplace" else 0
    max_signal = MAX_REQUESTS + noise_limit
    previous_instances = [cfg.initial] * cfg.functions
    previous_signal = [(0.0, 0.0) for _ in range(cfg.functions)]
    result = []

    for epoch, row in enumerate(rows):
        features(row)
        if type(row.get("epoch")) is not int or row["epoch"] != epoch:
            raise ValueError("observer epochs must be contiguous and ordered")
        intervals = []
        next_signal = []
        for pool in range(cfg.functions):
            before = previous_instances[pool]
            after = row["instances"][pool]
            if policy == "dp_laplace" and after - before != row["scale_up"][pool]:
                raise ValueError("DP observer counts must match no-retirement scale-up events")

            if row["scale_down"][pool] or after < before:
                signal_low, signal_high = 0.0, float(max_signal)
            elif after == cfg.maximum and before == cfg.maximum:
                # At the public capacity limit, additional scale demand is hidden.
                signal_low, signal_high = 0.0, float(max_signal)
            elif after == before:
                signal_low, signal_high = 0.0, before / factor
            elif after > before:
                signal_low = max(0.0, (after - 1) / factor)
                signal_high = (after / factor if after < cfg.maximum
                               else float(max_signal))
            else:
                signal_low, signal_high = 0.0, float(max_signal)

            if policy == "dp_laplace":
                old_low, old_high = previous_signal[pool]
                noisy_low = max(0.0, (signal_low - (1 - alpha) * old_high) / alpha)
                noisy_high = max(0.0, (signal_high - (1 - alpha) * old_low) / alpha)
            else:
                noisy_low, noisy_high = signal_low, signal_high

            # Closed intervals deliberately include integer threshold ties.
            lower = max(0, math.ceil(noisy_low - noise_limit - 1e-9))
            upper = min(MAX_REQUESTS,
                        math.floor(noisy_high + noise_limit + 1e-9))
            if lower > upper:
                raise ValueError("public transitions imply an empty arrival interval")
            intervals.append((lower, upper))
            next_signal.append((signal_low, signal_high))

        result.append(intervals)
        previous_instances = row["instances"]
        previous_signal = next_signal
    return result


def interval_features(rows, cfg, policy, noise_cap):
    """Return per-epoch lower, upper and width features for each pool."""
    intervals = count_intervals(rows, cfg, policy, noise_cap)
    values = np.asarray([
        [coordinate for lower, upper in epoch
         for coordinate in (lower, upper, upper - lower)]
        for epoch in intervals
    ], dtype=float)
    return values
