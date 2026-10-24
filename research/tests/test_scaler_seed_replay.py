import unittest
import json
import copy
import tempfile
from pathlib import Path

import numpy as np

from research.analysis.scaler_seed_replay import evaluate
from research.attacks.scaler_seed_replay import recover_noisy_signal
from research.simulation.run import run
from research.simulation.scaler import Config, Request, simulate


class SeedReplayTests(unittest.TestCase):
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
                ('naive', 'public_features'),
                ('dp_laplace', 'public_features'),
                ('dp_laplace', 'known_seed_replay'),
            })
            self.assertEqual(len(report['positive_controls']), 1)
            self.assertIn('seed derivation', report['methodology'])
            self.assertTrue((root / 'analysis' / 'artifact-sha256.json').exists())


if __name__ == '__main__':
    unittest.main()
