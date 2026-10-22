"""Queue mechanics and inference boundaries for the autoscaler experiment."""
import tempfile
import unittest
from pathlib import Path
from research.simulation.scaler import Config, Request, simulate, workload, load_imported, features, trial_interval


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

    def test_trial_interval_preserves_correlated_clusters(self):
        self.assertEqual(trial_interval([[0] * 8, [1] * 8]), [0, 1])


if __name__ == '__main__':
    unittest.main()
