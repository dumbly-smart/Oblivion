import unittest
import json
import copy
import tempfile
from pathlib import Path

import numpy as np

from research.analysis.scaler_seed_replay import classifier_score, evaluate
from research.attacks.scaler_seed_replay import recover_noisy_signal
from research.simulation.run import run
from research.simulation.scaler import Config, Request, simulate


class SeedReplayTests(unittest.TestCase):
    def test_random_forest_profile_attack_classifies_disjoint_sessions(self):
        cfg = Config(duration=10, epoch=1, functions=2)

        def session(identifier, label):
            count = 1 if label == 0 else 12
            rows = [dict(epoch=epoch, instances=[count, count],
                scale_up=[count - 1, count - 1], scale_down=[0, 0],
                cold_starts=[count - 1, count - 1]) for epoch in range(10)]
            return dict(observer=rows, labels=[{'intensity': label}] * 10,
                        session_id=identifier)

        profile = [session(i, i // 2) for i in range(4)]
        target = [session(i, 0 if i < 6 else 1) for i in range(4, 8)]

        result = classifier_score(profile, target, 'intensity', cfg,
                                  replay_seed=False, model='forest')

        self.assertEqual(result['balanced_accuracy'], 1.0)

    def test_random_forest_seed_is_bounded_for_large_public_config_seeds(self):
        cfg = Config(duration=10, epoch=1, functions=2)

        def session(label):
            count = 1 if label == 0 else 12
            rows = [dict(epoch=epoch, instances=[count, count],
                scale_up=[count - 1, count - 1], scale_down=[0, 0],
                cold_starts=[count - 1, count - 1]) for epoch in range(10)]
            return dict(observer=rows, labels=[{'intensity': label}] * 10)

        profile = [session(i // 2) for i in range(4)]
        target = [session(0 if i < 2 else 1) for i in range(4)]
        result = classifier_score(profile, target, 'intensity', cfg,
            replay_seed=False, model='forest', random_state=2**40)

        self.assertEqual(result['balanced_accuracy'], 1.0)

    def test_public_capacity_changes_reveal_seed_debiased_ewma(self):
        cfg = Config(duration=4, epoch=1, service=1, initial=0, maximum=100,
                     functions=1, alpha=1, utilization=1, dp_epsilon=1000)
        requests = []
        expected = []
        for epoch, count in enumerate([10, 15, 20, 25]):
            expected.append(count)
            requests.extend(Request(epoch + 0.01 + i / 1000, 0) for i in range(count))
        policy_seed = 123
        rows = simulate(cfg, requests, 'dp_laplace', policy_seed)['observer']

        recovered = recover_noisy_signal(rows, cfg, policy_seed)

        self.assertEqual(recovered.shape, (4, 1))
        for actual, truth in zip(recovered[:, 0], expected):
            self.assertLess(abs(actual - truth), 0.51)

        malformed = copy.deepcopy(rows)
        malformed[1]['instances'][0] -= 1
        with self.assertRaises(ValueError):
            recover_noisy_signal(malformed, cfg, policy_seed)

    def test_no_scale_up_is_inverted_as_a_censored_upper_bound(self):
        cfg = Config(duration=4, epoch=1, service=1, initial=0, maximum=100,
                     functions=1, alpha=1, utilization=1, dp_epsilon=1)
        requests = [Request(epoch + 0.01 + i / 1000, 0)
                    for epoch, count in enumerate([10, 15, 0, 0])
                    for i in range(count)]
        policy_seed = 123
        rows = simulate(cfg, requests, 'dp_laplace', policy_seed)['observer']
        noise_rng = np.random.default_rng(policy_seed)
        noise = [float(noise_rng.laplace(0, 4)) for _ in range(4)]
        self.assertEqual(rows[2]['scale_up'], [0])

        recovered = recover_noisy_signal(rows, cfg, policy_seed)

        active = rows[1]['instances'][0]
        expected_upper = max(0.0, active - noise[2])
        self.assertAlmostEqual(recovered[2, 0], expected_upper / 2)

    def test_public_seed_makes_adjacent_inputs_deterministically_distinguishable(self):
        cfg = Config(duration=2, epoch=1, service=1, initial=0, maximum=100,
                     functions=1, alpha=1, utilization=1, dp_epsilon=1000)
        seed = 77
        empty = simulate(cfg, [], 'dp_laplace', seed)['observer']
        one_request = simulate(cfg, [Request(.1, 0)], 'dp_laplace', seed)['observer']

        self.assertNotEqual(empty, one_request)

    def test_analysis_uses_public_seed_and_keeps_labels_in_evaluation_layer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / 'config.json'
            config.write_text(json.dumps(dict(version=1, seed=809, trials=2, sessions=8,
                workloads=['uniform'], policies=['naive', 'dp_laplace'],
                simulation=dict(duration=4, dp_epsilon=2))))
            raw = root / 'raw'
            run(config, raw)
            report = evaluate(raw, root / 'analysis')

            pairs = {(row['policy'], row['attacker']) for row in report['summary']}
            self.assertEqual(pairs, {
                ('naive', 'centroid_public'),
                ('naive', 'forest_public'),
                ('dp_laplace', 'centroid_public'),
                ('dp_laplace', 'centroid_seed_replay'),
                ('dp_laplace', 'forest_public'),
                ('dp_laplace', 'forest_seed_replay'),
            })
            self.assertEqual(len(report['positive_controls']), 2)
            self.assertIn('seed derivation', report['methodology'])
            self.assertTrue((root / 'analysis' / 'artifact-sha256.json').exists())


if __name__ == '__main__':
    unittest.main()
