"""Queue mechanics and inference boundaries for the autoscaler experiment."""
import tempfile
import unittest
from pathlib import Path
from research.simulation.scaler import (Config, Request, simulate, workload, load_imported,
    features, trial_interval, dp_laplace_parameters)


class ScalerTests(unittest.TestCase):
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
        self.assertAlmostEqual(parameters['laplace_scale'], 3.0)
        with self.assertRaises(ValueError):
            Config(dp_epsilon=0).validate()

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
            self.assertEqual(claim['delta'], 0.0)
            self.assertEqual(claim['release_count'], 4)
            self.assertIn('one added or removed Request record', claim['adjacency'])
            self.assertIn('ideal independent Laplace draws', claim['mechanism_design_claim'])
            self.assertEqual(claim['artifact_guarantee'], 'none: the reproducible experiment uses a deterministic seed that is recorded in public configuration')
            self.assertIn('publishes the experiment seed', claim['randomness'])
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

    def test_trial_interval_preserves_correlated_clusters(self):
        self.assertEqual(trial_interval([[0] * 8, [1] * 8]), [0, 1])


if __name__ == '__main__':
    unittest.main()
