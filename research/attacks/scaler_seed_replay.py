"""Recover an autoscaler's noisy signal when its deterministic seed is public."""
import numpy as np

from research.simulation.scaler import Config, features, dp_laplace_scale, session_features


def public_policy_seed(experiment_seed, trial, session, workload_index):
    """Replay run.py's public seed derivation for one session's DP policy."""
    seed = np.random.SeedSequence(
        [experiment_seed, trial, session, workload_index]
    ).generate_state(1)[0]
    return int(seed) + 991


def recover_noisy_signal(rows, cfg, policy_seed):
    """Estimate per-pool EWMA arrivals by inverting public scale-up counts.

    The estimate uses only the public observer rows, public controller
    parameters, and the deterministic noise seed. Capacity quantization and
    maximum-capacity clipping make the inverse censored, so this returns
    interval midpoints/lower bounds rather than exact arrivals.
    """
    cfg.validate()
    horizon = int(np.ceil(cfg.duration / cfg.epoch))
    if not isinstance(rows, list) or len(rows) != horizon:
        raise ValueError('observer must contain the complete fixed horizon')
    if type(policy_seed) is not int or policy_seed < 0:
        raise ValueError('policy seed must be a nonnegative integer')
    if not (0 < cfg.service / (cfg.epoch * cfg.utilization)):
        raise ValueError('invalid capacity conversion')

    factor = cfg.service / (cfg.epoch * cfg.utilization)
    noise_scale = dp_laplace_scale(cfg)
    rng = np.random.default_rng(policy_seed)
    previous = np.full(cfg.functions, cfg.initial, dtype=int)
    recovered = np.zeros((horizon, cfg.functions), dtype=float)

    for epoch, row in enumerate(rows):
        features(row)  # Enforce the public observer schema.
        if type(row['epoch']) is not int or row['epoch'] != epoch:
            raise ValueError('observer epochs must be contiguous and ordered')
        for field in ('instances', 'scale_up', 'scale_down', 'cold_starts'):
            values = row[field]
            if (not isinstance(values, list) or len(values) != cfg.functions
                    or any(type(value) is not int or value < 0 for value in values)):
                raise ValueError('observer pool counts must be nonnegative integers')
        if any(row['scale_down']) or any(current < before for current, before in
                                         zip(row['instances'], previous.tolist())):
            raise ValueError('seed replay requires the no-retirement DP policy')
        if any(current - before != added for current, before, added in
               zip(row['instances'], previous.tolist(), row['scale_up'])):
            raise ValueError('public instance deltas disagree with scale-up events')

        for pool in range(cfg.functions):
            noise = float(rng.laplace(0.0, noise_scale))
            before = int(previous[pool])
            after = row['instances'][pool]
            if after > before:
                if after < cfg.maximum:
                    low_signal = max(0.0, (after - 1) / factor - noise)
                    high_signal = max(0.0, after / factor - noise)
                    recovered[epoch, pool] = (low_signal + high_signal) / 2
                else:
                    # The capacity cap exposes only the lower threshold.
                    recovered[epoch, pool] = max(
                        0.0, (after - 1) / factor - noise)
            else:
                # No new worker means the target did not exceed current count.
                upper_signal = max(0.0, before / factor - noise)
                recovered[epoch, pool] = upper_signal / 2
        previous = np.asarray(row['instances'], dtype=int)
    return recovered


def seed_replay_features(rows, cfg, policy_seed):
    """Combine public counts with the signal estimate from replayed noise."""
    current = recover_noisy_signal(rows, cfg, policy_seed)
    previous = np.vstack([np.zeros_like(current[:1]), current[:-1]])
    cumulative = np.cumsum(current, axis=0) / np.arange(1, len(current) + 1)[:, None]
    return np.hstack([session_features(rows), current, previous, cumulative])
