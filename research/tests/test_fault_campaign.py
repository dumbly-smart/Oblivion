"""Fault campaigns must exercise one real assertion-bearing test per launch."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('fault_campaign', Path(__file__).resolve().parents[2] / 'scripts/evaluate_faults.py')
campaign = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(campaign)


class FaultCampaignTests(unittest.TestCase):
    def test_failed_atomic_publication_preserves_previous_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'trials.json'
            path.write_text('[1]\n')
            with patch.object(campaign.os, 'replace', side_effect=OSError('injected full filesystem')):
                with self.assertRaises(OSError):
                    campaign.atomic_json(path, [1, 2])
            self.assertEqual(path.read_text(), '[1]\n')
            campaign.atomic_json(path, [1, 2])
            self.assertEqual(__import__('json').loads(path.read_text()), [1, 2])

    def test_cargo_artifact_selects_only_integration_test(self):
        import json
        records = [dict(reason='compiler-artifact', target=dict(name='pipeline', kind=['test']), executable='/tmp/pipeline')]
        self.assertEqual(campaign.integration_artifact('\n'.join(map(json.dumps, records))), Path('/tmp/pipeline'))
        with self.assertRaises(ValueError):
            campaign.integration_artifact('')

    def test_zero_matching_tests_is_not_success(self):
        self.assertFalse(campaign.assertions_passed(0, 'running 0 tests\ntest result: ok. 0 passed; 0 failed'))
        self.assertFalse(campaign.assertions_passed(1, 'running 1 test\ntest result: FAILED. 0 passed; 1 failed'))
        self.assertTrue(campaign.assertions_passed(0, 'running 1 test\ntest result: ok. 1 passed; 0 failed'))

    def test_incomplete_or_duplicate_trial_set_rejected(self):
        rows = [dict(scenario='cover', trial=t, passed=True, wall_ns=100) for t in range(2)]
        report = campaign.summarize(rows, ['cover'], 2)
        self.assertEqual(report['cover']['assertion_passes'], 2)
        self.assertEqual(report['cover']['harness_wall_p99_ms'], .0001)
        self.assertGreater(report['cover']['failure_fraction_wilson95'][1], 0)
        for malformed in [rows[:-1], rows + [rows[0]]]:
            with self.assertRaises(ValueError):
                campaign.summarize(malformed, ['cover'], 2)

    def test_real_subprocess_failure_and_timeout_are_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = campaign.run_case([sys.executable, '-c', 'raise SystemExit(7)'], root/'failure', .5)
            self.assertEqual(row['returncode'], 7)
            self.assertFalse(row['passed'])
            row = campaign.run_case([sys.executable, '-c', 'import time; time.sleep(5)'], root/'timeout', .02)
            self.assertTrue(row['timed_out'])
            self.assertFalse(row['passed'])


if __name__ == '__main__':
    unittest.main()
