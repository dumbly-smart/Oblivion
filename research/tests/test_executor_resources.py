import json
import copy
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

    def test_setup_cpu_rss_and_public_class_bounds(self):
        valid = {'schema': 1, 'class': 'small', 'mode': 'protected', 'seed': 1, 'fuel': 100000,
                 'deadline_ms': 100, 'input_bytes': 64, 'output_bytes': 64, 'memory_limit_bytes': 65536,
                 'engine_ns': 1, 'compile_ns': [1]*6, 'fixture_wall_ns': 100,
                 'cpu_user_seconds': .001, 'cpu_system_seconds': .002, 'max_rss_kib': 1024,
                 'calls': [{'function': function, 'phase': phase, 'status': 'OutOfFuel' if function == 5 else 'Success',
                            'oracle_passed': True, 'wall_ns': 100, 'work_ns': 20, 'total_ns': 100,
                            'deadline_missed': False, 'body_bytes': 64, 'storage_events': 128}
                           for function in range(6) for phase in ('first', 'warm')]}
        self.valid_fixture = copy.deepcopy(valid)
        validate_trial(valid)
        for field, value in (('engine_ns', -1), ('engine_ns', True), ('compile_ns', [float('nan')]*6),
                             ('cpu_user_seconds', float('inf')), ('cpu_system_seconds', -.1),
                             ('max_rss_kib', -1), ('max_rss_kib', 1.5), ('fuel', 0), ('seed', -1)):
            changed = copy.deepcopy(valid); changed[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                validate_trial(changed)

    def test_invocation_cpu_schema_rejects_missing_and_invalid(self):
        # Reuse a valid schema-one fixture as the starting metadata, then require
        # the new version's additional stage/attempt CPU measurements.
        self.test_setup_cpu_rss_and_public_class_bounds()
        fixture = self.valid_fixture
        fixture.update(schema=2, engine_cpu_ns=1, compile_cpu_ns=[1]*6)
        for call in fixture['calls']:
            call.update(process_cpu_ns=1, thread_cpu_ns=1)
        validate_trial(fixture)
        for field in ('process_cpu_ns','thread_cpu_ns'):
            for value in (None, -1, True, float('nan')):
                changed=copy.deepcopy(fixture)
                if value is None:
                    del changed['calls'][0][field]
                else:
                    changed['calls'][0][field]=value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    validate_trial(changed)

    @unittest.skipUnless(os.environ.get('EXECUTOR_RESOURCES_BINARY'), 'set EXECUTOR_RESOURCES_BINARY for actual Wasmtime test')
    def test_actual_oracles_success_fuel_trap_and_shape(self):
        binary = os.environ['EXECUTOR_RESOURCES_BINARY']
        trials = []
        for resource_class in ('small', 'medium', 'small_lowfuel'):
            for mode in ('control', 'protected'):
                completed = subprocess.run([binary, resource_class, mode, '1'], capture_output=True, text=True, check=True)
                trial = json.loads(completed.stdout); validate_trial(trial)
                trial.update(cpu_user_seconds=.001, cpu_system_seconds=.001, max_rss_kib=1)
                trials.append(trial)
                self.assertEqual(trial['schema'], 2)
                self.assertGreater(trial['engine_cpu_ns'], 0)
                self.assertTrue(all(value > 0 for value in trial['compile_cpu_ns']))
                self.assertEqual(len(trial['calls']), 12)
                for call in trial['calls']:
                    self.assertGreater(call['process_cpu_ns'], 0)
                    self.assertGreater(call['thread_cpu_ns'], 0)
                    self.assertLessEqual(call['process_cpu_ns'], call['wall_ns']*64+10_000_000)
                    self.assertEqual(call['status'], 'OutOfFuel' if call['function'] == 5 or resource_class == 'small_lowfuel' and call['function'] != 0 else 'Success')
                    if mode == 'protected':
                        self.assertEqual(call['storage_events'], 128)
                        self.assertEqual(call['body_bytes'], 256 if resource_class == 'medium' else 64)
        for result, trial in zip(summarize_trials(trials), trials):
            successes = [call for call in trial['calls'] if call['status'] == 'Success']
            self.assertEqual(result['successful_real_calls'], len(successes))
            self.assertEqual(result['failed_calls'], 12-len(successes))
            self.assertAlmostEqual(result['all_attempt_cpu_per_success_ns']['mean'], sum(call['process_cpu_ns'] for call in trial['calls'])/len(successes))
            self.assertEqual(result['all_attempt_cpu_per_success_ns']['trials'], 1)
        for args in ([], ['small', 'bad', '1'], ['unknown', 'control', '1'], ['small', 'control', '-1']):
            self.assertNotEqual(subprocess.run([binary, *args], capture_output=True).returncode, 0)
