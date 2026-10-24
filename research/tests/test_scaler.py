"""Queue mechanics and inference boundaries for the autoscaler experiment."""
import tempfile
import unittest
from pathlib import Path
from research.simulation.scaler import (Config, Request, simulate, workload, load_imported,
    features, trial_interval, dp_laplace_parameters, discrete_laplace_from_bits,
    bounded_arrival_counts)


class ScalerTests(unittest.TestCase):
    def test_config_rejects_boolean_numeric_parameters(self):
        for field in ('duration', 'dp_epsilon', 'dp_delta'):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, 'finite numeric parameters'):
                    Config(**{field: True}).validate()

    def test_bounded_discrete_laplace_parameters_certify_composed_delta(self):
        cfg = Config(duration=5.5, epoch=1, dp_epsilon=2.0, dp_delta=1e-6)
        cfg.validate()
        parameters = dp_laplace_parameters(cfg)
        self.assertEqual(parameters['releases'], 6)
        self.assertLessEqual(parameters['epsilon_effective_per_release'],
                             parameters['epsilon_per_release'])
        self.assertLessEqual(parameters['composed_delta_bound'], cfg.dp_delta)
        self.assertGreater(parameters['geometric_cap'], 0)

    def test_exact_capped_noise_hockey_stick_is_below_declared_delta(self):
        from fractions import Fraction

        cases = (
            Config(duration=1, epoch=1, functions=1,
                   dp_epsilon=2.0, dp_delta=1e-3),
            Config(duration=2, epoch=1, functions=1,
                   dp_epsilon=2.0, dp_delta=1e-6),
            Config(duration=3, epoch=1, functions=1,
                   dp_epsilon=0.5, dp_delta=1e-4),
        )
        for cfg in cases:
            with self.subTest(epsilon=cfg.dp_epsilon, delta=cfg.dp_delta):
                cfg.validate()
                parameters = dp_laplace_parameters(cfg)
                q = Fraction(parameters['geometric_numerator'],
                             parameters['geometric_denominator'])
                cap = parameters['geometric_cap']
                geometric = [(1 - q) * q ** count for count in range(cap)]
                geometric.append(q ** cap)
                noise = {}
                for left, p_left in enumerate(geometric):
                    for right, p_right in enumerate(geometric):
                        value = left - right
                        noise[value] = noise.get(value, Fraction(0)) + p_left * p_right

                self.assertEqual(sum(noise.values()), Fraction(1))
                # e^epsilon_effective is exactly 1/q for the one-count add/remove pair.
                multiplier = 1 / q
                forward = sum(
                    max(noise.get(output, Fraction(0))
                        - multiplier * noise.get(output - 1, Fraction(0)), Fraction(0))
                    for output in range(-cap, cap + 2)
                )
                reverse = sum(
                    max(noise.get(output - 1, Fraction(0))
                        - multiplier * noise.get(output, Fraction(0)), Fraction(0))
                    for output in range(-cap, cap + 2)
                )
                self.assertLessEqual(
                    float(max(forward, reverse)), parameters['per_release_delta_bound']
                )

    def test_exact_bounded_user_two_pool_hockey_stick_is_below_declared_delta(self):
        from fractions import Fraction
        from itertools import product

        cases = (
            Config(duration=1, epoch=1, functions=2, dp_epsilon=2.0,
                   dp_delta=1e-3, dp_user_contribution_cap=2),
            Config(duration=1, epoch=1, functions=3, dp_epsilon=1.5,
                   dp_delta=1e-2, dp_user_contribution_cap=2),
            Config(duration=1, epoch=1, functions=2, dp_epsilon=3.0,
                   dp_delta=1e-2, dp_user_contribution_cap=3),
        )
        for cfg in cases:
            with self.subTest(functions=cfg.functions,
                              user_cap=cfg.dp_user_contribution_cap):
                cfg.validate()
                parameters = dp_laplace_parameters(cfg)
                q = Fraction(parameters['geometric_numerator'],
                             parameters['geometric_denominator'])
                cap = parameters['geometric_cap']
                geometric = [(1 - q) * q ** count for count in range(cap)]
                geometric.append(q ** cap)
                one_pool = {}
                for left, p_left in enumerate(geometric):
                    for right, p_right in enumerate(geometric):
                        value = left - right
                        one_pool[value] = (one_pool.get(value, Fraction(0))
                                           + p_left * p_right)

                contribution_cap = cfg.dp_user_contribution_cap
                multiplier = 1 / q ** contribution_cap
                shifts = (shift for shift in product(
                    range(contribution_cap + 1), repeat=cfg.functions)
                    if 0 < sum(shift) <= contribution_cap)
                outputs = range(-cap, cap + contribution_cap + 1)
                for shift in shifts:
                    forward = Fraction(0)
                    reverse = Fraction(0)
                    for output in product(outputs, repeat=cfg.functions):
                        p = Fraction(1)
                        q_neighbor = Fraction(1)
                        for value, displacement in zip(output, shift):
                            p *= one_pool.get(value, Fraction(0))
                            q_neighbor *= one_pool.get(
                                value - displacement, Fraction(0))
                        forward += max(p - multiplier * q_neighbor, Fraction(0))
                        reverse += max(q_neighbor - multiplier * p, Fraction(0))
                    self.assertLessEqual(
                        float(max(forward, reverse)),
                        parameters['per_release_delta_bound'],
                        msg=f'bounded-user shift {shift}',
                    )

    def test_user_level_cap_limits_whole_horizon_count_sensitivity(self):
        cfg = Config(duration=4, epoch=1, functions=1,
                     dp_user_contribution_cap=3)
        both = sorted([Request(.1, 0, 'a'), Request(.2, 0, 'a'),
                Request(1.1, 0, 'a'), Request(2.1, 0, 'a'),
                Request(2.2, 0, 'a'), Request(2.3, 0, 'a'),
                Request(.3, 0, 'b'), Request(.4, 0, 'b'),
                Request(3.1, 0, 'b')], key=lambda request: request.time)
        a = bounded_arrival_counts(both, cfg)
        without_a = bounded_arrival_counts(
            [request for request in both if request.user_id != 'a'], cfg)
        self.assertEqual(a[:, 0].tolist(), [4, 1, 0, 1])
        self.assertEqual(sum(abs(int(left - right))
                             for left, right in zip(a.flat, without_a.flat)), 3)
        self.assertEqual(dp_laplace_parameters(cfg)['l1_sensitivity_bound'], 3)

    def test_user_level_mode_requires_stable_user_identity(self):
        cfg = Config(duration=2, epoch=1, dp_user_contribution_cap=2)
        with self.assertRaises(ValueError):
            simulate(cfg, [Request(.1, 0)], 'dp_laplace', 4)

    def test_user_level_runner_emits_and_rebuilds_declared_adjacency(self):
        import json
        from research.simulation.run import run
        from scripts.regenerate_scaler import regenerate
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / 'config.json'
            config.write_text(json.dumps(dict(version=1, seed=18, trials=2,
                sessions=8, workloads=['uniform'], policies=['naive', 'dp_laplace'],
                simulation=dict(duration=4, dp_epsilon=2,
                                dp_user_contribution_cap=2))))
            output = root / 'run'
            report = run(config, output)
            claim = report['privacy_claims']['dp_laplace']
            self.assertEqual(claim['privacy_unit'], 'bounded_user')
            self.assertEqual(claim['per_user_request_cap'], 2)
            self.assertLessEqual(claim['effective_per_release_epsilon'],
                                 claim['per_release_epsilon'])
            self.assertLessEqual(claim['delta'], claim['configured_delta'])
            rebuilt = regenerate(output, root / 'rebuilt')
            self.assertEqual(rebuilt['privacy_claims']['dp_laplace'], claim)

    def test_user_level_import_requires_user_id_column(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'users.csv'
            path.write_text('time,function\n0.1,0\n')
            with self.assertRaises(ValueError):
                load_imported(path, Config(dp_user_contribution_cap=2))
            path.write_text('time,function,user_id\n0.1,0,account-a\n')
            self.assertEqual(load_imported(path, Config(dp_user_contribution_cap=2)),
                             [Request(.1, 0, 'account-a')])

    def test_user_level_synthetic_workload_assigns_reproducible_identities(self):
        cfg = Config(duration=8, dp_user_contribution_cap=2)
        left = workload(cfg, 'uniform', 101)[0]
        right = workload(cfg, 'uniform', 101)[0]
        self.assertEqual(left, right)
        self.assertTrue(left)
        self.assertTrue(all(request.user_id for request in left))

    def test_bounded_discrete_laplace_sampler_has_fixed_entropy_shape(self):
        parameters = dp_laplace_parameters(Config(duration=2, epoch=1))
        bits = parameters['geometric_cap'] * parameters['coin_bits']
        all_successes = discrete_laplace_from_bits(parameters, lambda requested: (1 << requested) - 1)
        all_failures = discrete_laplace_from_bits(parameters, lambda requested: 0)
        self.assertEqual(all_successes, 0)
        self.assertEqual(all_failures, 0)
        calls = []
        discrete_laplace_from_bits(parameters, lambda requested: calls.append(requested) or 0)
        self.assertEqual(calls, [2 * bits])

    def test_bounded_discrete_laplace_sampler_rejects_malformed_entropy(self):
        parameters = dp_laplace_parameters(Config(duration=2, epoch=1))
        bits = 2 * parameters['geometric_cap'] * parameters['coin_bits']
        for draw in (lambda requested: -1, lambda requested: 1 << requested,
                     lambda requested: 1.5):
            with self.subTest(draw=draw):
                with self.assertRaises(ValueError):
                    discrete_laplace_from_bits(parameters, draw)

    def test_difference_of_geometric_sampler_matches_reference_marginals(self):
        import random
        parameters = dict(coin_bits=64, geometric_cap=20,
                         geometric_numerator=1 << 63,
                         geometric_denominator=1 << 64)
        rng = random.Random(4481)
        values = [discrete_laplace_from_bits(parameters, rng.getrandbits)
                  for _ in range(12000)]
        self.assertLess(abs(sum(values) / len(values)), 0.08)
        self.assertAlmostEqual(values.count(0) / len(values), 1 / 3, delta=0.025)

    def test_simulator_rejects_unknown_dp_noise_source(self):
        with self.assertRaises(ValueError):
            simulate(Config(duration=2), [], 'dp_laplace', 5,
                     dp_noise_source='public_seed')

    def test_csprng_mode_draws_fresh_noise_at_each_pool_tick(self):
        from unittest.mock import patch
        cfg = Config(duration=2, epoch=1, functions=1, dp_epsilon=1)
        with patch('research.simulation.scaler.secrets.randbits', return_value=0) as entropy:
            result = simulate(cfg, [], 'dp_laplace', 5, dp_noise_source='os_csprng')
        self.assertEqual(entropy.call_count, 2)
        self.assertEqual([row['epoch'] for row in result['observer']], [0, 1])

    def test_fifo_service_and_cold_start_latency(self):
        cfg = Config(duration=4, epoch=1, service=0.5, cold_start=1, initial=0, maximum=1, functions=1)
        result = simulate(cfg, [Request(0, 0), Request(.1, 0)], 'naive', 3)
        self.assertEqual([r['finished'] for r in result['requests']], [2.5, 3.0])
        self.assertAlmostEqual(result['metrics']['instance_seconds'], 2)
        self.assertEqual(result['metrics']['completed'], 2)

    def test_fixed_schedule_is_independent_of_demand(self):
        cfg = Config(duration=5, initial=1, functions=2)
        a = simulate(cfg, [], 'fixed', 4)
        b = simulate(cfg, [Request(0, 0), Request(.1, 1)], 'fixed', 4)
        self.assertEqual(a['observer'], b['observer'])

    def test_queue_limit_drops_and_accounts_all_requests(self):
        cfg = Config(duration=2, epoch=1, initial=0, maximum=1, functions=1, queue_limit=1)
        result = simulate(cfg, [Request(0, 0)] * 4, 'fixed', 0)
        m = result['metrics']
        self.assertEqual(m['arrivals'], m['completed'] + m['dropped'] + m['unfinished'])
        self.assertEqual(m['dropped'], 3)

    def test_synthetic_workload_seed_and_profile_support(self):
        cfg = Config(duration=12)
        for kind in ['uniform', 'zipf', 'diurnal', 'burst']:
            a, labels = workload(cfg, kind, 17, intensity=1, hot=1)
            self.assertEqual((a, labels), workload(cfg, kind, 17, intensity=1, hot=1))
            self.assertTrue(all(0 <= r.function < cfg.functions for r in a))
            self.assertEqual(len(labels), 12)

    def test_import_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'trace.csv'
            p.write_text('time,function\n0.2,0\n0.1,0\n')
            with self.assertRaises(ValueError):
                load_imported(p, Config())

    def test_features_reject_private_labels(self):
        with self.assertRaises(ValueError):
            features({'epoch': 0, 'instances': [1], 'scale_up': [0], 'scale_down': [0], 'cold_starts': [0], 'load': 3})

    def test_profiler_uses_only_observable_vectors(self):
        import numpy as np
        from research.simulation.scaler import ProfileAttack
        x = np.array([[0., 1.], [0., 1.], [4., 8.], [4., 8.]])
        y = np.array([0, 0, 1, 1])
        self.assertEqual(ProfileAttack().fit(x, y).predict(x).tolist(), y.tolist())

    def test_busy_retirement_does_not_cancel_service(self):
        cfg = Config(duration=5, epoch=1, service=2, initial=1, functions=1)
        result = simulate(cfg, [Request(0, 0)], 'naive', 5)
        self.assertEqual(result['requests'][0]['finished'], 2)
        self.assertEqual(result['metrics']['unfinished'], 0)

    def test_all_policies_obey_capacity_and_conserve_work(self):
        from research.simulation.scaler import POLICIES
        cfg = Config(duration=6, maximum=2)
        requests, _ = workload(cfg, 'burst', 6, intensity=1)
        for policy in POLICIES:
            r = simulate(cfg, requests, policy, 9)
            self.assertTrue(all(0 <= n <= 2 for row in r['observer'] for n in row['instances']))
            m = r['metrics']
            self.assertEqual(m['arrivals'], m['completed'] + m['dropped'] + m['unfinished'])

    def test_dp_laplace_noise_uses_fixed_horizon_basic_composition(self):
        cfg = Config(duration=5.5, epoch=1, dp_epsilon=2.0)
        cfg.validate()
        parameters = dp_laplace_parameters(cfg)
        self.assertEqual(parameters['releases'], 6)
        self.assertAlmostEqual(parameters['epsilon_per_release'], 1 / 3)
        self.assertAlmostEqual(1 / parameters['epsilon_effective_per_release'], 3.0,
                               places=12)
        with self.assertRaises(ValueError):
            Config(dp_epsilon=0).validate()
        with self.assertRaises(ValueError):
            Config(dp_delta=0).validate()

    def test_dp_policy_never_retires_busy_workers_based_on_queue_state(self):
        from research.simulation.scaler import simulate
        cfg = Config(duration=8, epoch=1, service=.4, cold_start=.2,
                     initial=1, maximum=4, functions=2, dp_epsilon=.5)
        requests = [Request(i * .05, i % 2) for i in range(80)]
        result = simulate(cfg, requests, 'dp_laplace', 41)
        self.assertTrue(all(row['scale_down'] == [0, 0] for row in result['observer']))
        instance_counts = [row['instances'] for row in result['observer']]
        self.assertTrue(all(
            all(previous <= current for previous, current in zip(left, right))
            for left, right in zip(instance_counts, instance_counts[1:])
        ))

    def test_dp_policy_excludes_true_queue_from_scaling_observer(self):
        cfg = Config(duration=3, epoch=1, service=.5, cold_start=0,
                     initial=1, maximum=4, functions=1, utilization=.5,
                     alpha=1, dp_epsilon=1e9)
        early = [Request(.1, 0), Request(.2, 0)]
        late = [Request(.9, 0), Request(.95, 0)]
        dp_early = simulate(cfg, early, 'dp_laplace', 9)
        dp_late = simulate(cfg, late, 'dp_laplace', 9)
        self.assertEqual(dp_early['observer'], dp_late['observer'])
        ewma_early = simulate(cfg, early, 'ewma', 9)
        ewma_late = simulate(cfg, late, 'ewma', 9)
        self.assertNotEqual(ewma_early['observer'], ewma_late['observer'])

    def test_invalid_time_and_fractional_pool_parameters_rejected(self):
        for cfg in [Config(epoch=0), Config(functions=1.5), Config(service=-1), Config(maximum=0, initial=1)]:
            with self.assertRaises(ValueError):
                simulate(cfg, [], 'fixed', 1)

    def test_valid_import_preserves_arrival_times(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'trace.csv'
            p.write_text('time,function\n0.1,0\n0.2,1\n')
            self.assertEqual(load_imported(p, Config()), [Request(.1, 0), Request(.2, 1)])

    def test_end_to_end_runner_keeps_observer_separate(self):
        import gzip
        import json
        from research.simulation.run import run
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'config.json'
            config.write_text(json.dumps(dict(version=1, seed=71, trials=2, sessions=8,
                workloads=['uniform'], simulation=dict(duration=4))))
            output = Path(directory) / 'result'
            report = run(config, output)
            self.assertEqual(len(report['summary']), 5)
            self.assertTrue(all(s['independent_trials'] == 2 for s in report['summary']))
            with gzip.open(output / 'observer.jsonl.gz', 'rt') as source:
                for line in source:
                    for row in json.loads(line)['rows']:
                        features(row)
            self.assertTrue((output / 'pareto-intensity.png').exists())

    def test_runner_records_scoped_dp_claim_for_selected_policy(self):
        import json
        from research.simulation.run import run
        from scripts.regenerate_scaler import regenerate
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'config.json'
            base = dict(version=1, seed=72, trials=2, sessions=8,
                workloads=['uniform'], simulation=dict(duration=4, dp_epsilon=2))
            config.write_text(json.dumps(dict(**base, policies=['naive', 'dp_laplace'])))
            output = Path(directory) / 'result'
            report = run(config, output)
            self.assertEqual({row['policy'] for row in report['summary']}, {'naive', 'dp_laplace'})
            claim = report['privacy_claims']['dp_laplace']
            self.assertEqual(claim['epsilon'], 2)
            self.assertLessEqual(claim['delta'], claim['configured_delta'])
            self.assertEqual(claim['release_count'], 4)
            self.assertIn('one added or removed Request record', claim['adjacency'])
            self.assertIn('conditional (epsilon, delta) guarantee', claim['mechanism_design_claim'])
            self.assertEqual(claim['artifact_guarantee'], 'none: deterministic noise is derived from the public experiment seed')
            self.assertIn('public experiment seed', claim['randomness'])
            rebuilt_path = Path(directory) / 'rebuilt'
            rebuilt = regenerate(output, rebuilt_path)
            self.assertEqual({row['policy'] for row in rebuilt['summary']}, {'naive', 'dp_laplace'})
            self.assertEqual(rebuilt['privacy_claims']['dp_laplace'], claim)
            self.assertTrue((rebuilt_path / 'artifact-sha256.json').exists())
            manifest = json.loads((output / 'artifact-sha256.json').read_text())
            self.assertEqual(set(manifest), {'config.json', 'observer.jsonl.gz', 'private.jsonl.gz',
                'report.json', 'workloads-private.jsonl.gz', 'pareto-intensity.png'})

            default_config = Path(directory) / 'default.json'
            default_config.write_text(json.dumps(base))
            default_output = Path(directory) / 'default-run'
            run(default_config, default_output)
            default_rebuilt = regenerate(default_output, Path(directory) / 'default-rebuilt')
            self.assertEqual({row['policy'] for row in default_rebuilt['summary']},
                {'naive', 'ewma', 'quantized', 'fixed', 'noisy'})
            repeated_output = Path(directory) / 'default-repeat'
            run(default_config, repeated_output)
            for name in ['observer.jsonl.gz', 'private.jsonl.gz', 'workloads-private.jsonl.gz']:
                self.assertEqual((default_output / name).read_bytes(),
                    (repeated_output / name).read_bytes(), name)

            secure_config = Path(directory) / 'secure.json'
            secure_config.write_text(json.dumps(dict(**base, policies=['naive', 'dp_laplace'],
                dp_noise_source='os_csprng')))
            secure_report = run(secure_config, Path(directory) / 'secure-run')
            secure_claim = secure_report['privacy_claims']['dp_laplace']
            self.assertFalse(secure_claim['noise_reproducible'])
            self.assertIn('OS CSPRNG', secure_claim['randomness'])
            self.assertIn('stated approximate-DP bound', secure_claim['randomness'])
            secure_rebuilt = regenerate(Path(directory) / 'secure-run',
                                        Path(directory) / 'secure-rebuilt')
            self.assertEqual(secure_rebuilt['privacy_claims']['dp_laplace'], secure_claim)
            self.assertIn('approximate-DP bound', secure_rebuilt['limitations'])

    def test_trial_interval_preserves_correlated_clusters(self):
        self.assertEqual(trial_interval([[0] * 8, [1] * 8]), [0, 1])


if __name__ == '__main__':
    unittest.main()
