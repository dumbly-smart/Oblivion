import json
import tempfile
import unittest
from pathlib import Path

from research.analysis.scaler_epsilon_sweep import run_sweep


class EpsilonSweepTests(unittest.TestCase):
    def test_sweep_retains_paired_runs_and_per_epsilon_positive_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / 'sweep.json'
            config.write_text(json.dumps(dict(version=1, seed=809, trials=2,
                sessions=8, workloads=['uniform'], epsilons=[1.0, 2.0],
                simulation=dict(duration=4, functions=2))))

            report = run_sweep(config, root / 'results')

            self.assertEqual(report['epsilons'], [1.0, 2.0])
            self.assertTrue(report['paired_workloads'])
            self.assertEqual(len(report['summary']), 6)
            self.assertEqual(len(report['positive_controls']), 2)
            for epsilon in report['epsilons']:
                self.assertTrue((root / 'results' / f'epsilon-{epsilon:g}' /
                    'run' / 'observer.jsonl.gz').exists())


if __name__ == '__main__':
    unittest.main()
