import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from scripts.measure_executor_resources import validate_trial, summarize_trials


class ExecutorResourcesTests(unittest.TestCase):
    def test_bad_schema_oracle_and_bounds(self):
        for value in ({}, {'calls': []}, {'calls': [{'oracle_passed': False}]}):
            with self.assertRaises(ValueError):
                validate_trial(value)
        with self.assertRaises(ValueError):
            summarize_trials([])

    @unittest.skipUnless(os.environ.get('EXECUTOR_RESOURCES_BINARY'), 'set EXECUTOR_RESOURCES_BINARY for actual Wasmtime test')
    def test_actual_oracles_success_fuel_trap_and_shape(self):
        binary = os.environ['EXECUTOR_RESOURCES_BINARY']
        for resource_class in ('small', 'medium', 'small_lowfuel'):
            for mode in ('control', 'protected'):
                completed = subprocess.run([binary, resource_class, mode, '1'], capture_output=True, text=True, check=True)
                trial = json.loads(completed.stdout); validate_trial(trial)
                self.assertEqual(len(trial['calls']), 12)
                for call in trial['calls']:
                    self.assertEqual(call['status'], 'OutOfFuel' if call['function'] == 5 or resource_class == 'small_lowfuel' and call['function'] != 0 else 'Success')
                    if mode == 'protected':
                        self.assertEqual(call['storage_events'], 128)
                        self.assertEqual(call['body_bytes'], 256 if resource_class == 'medium' else 64)
        for args in ([], ['small', 'bad', '1'], ['unknown', 'control', '1'], ['small', 'control', '-1']):
            self.assertNotEqual(subprocess.run([binary, *args], capture_output=True).returncode, 0)
