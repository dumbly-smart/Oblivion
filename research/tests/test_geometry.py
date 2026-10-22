"""Geometry analysis rejects correlated/partial trials and verifies resource accounting."""
import importlib.util
import os
import unittest
import json
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('geometry', Path(__file__).resolve().parents[2] / 'scripts/sweep_geometry.py')
g = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(g)

def measure_binaries(root, environment=None):
    """Prefer an explicit frozen build, then the current release examples."""
    environment = os.environ if environment is None else environment
    explicit = environment.get('OBLIVION_GEOMETRY_BIN_DIR')
    directories = ([Path(explicit)] if explicit else [
        root / 'target/release/examples',
        root / 'experiments/results/geometry-20261022/bin',
    ])
    for directory in directories:
        paths = tuple(directory / name for name in ['oram-measure', 'pir-measure'])
        if all(path.is_file() for path in paths):
            return paths
    raise FileNotFoundError(
        'Build release oram-measure and pir-measure examples, or set '
        'OBLIVION_GEOMETRY_BIN_DIR to a directory containing both executables; '
        f'searched: {directories}'
    )

class GeometryTests(unittest.TestCase):
    def test_grid_has_36_oram_and_six_pir_cells(self):
        cells = list(g.configurations())
        self.assertEqual(sum(kind == 'oram' for kind, _, _ in cells), 36)
        self.assertEqual(sum(kind == 'pir' for kind, _, _ in cells), 6)
        self.assertTrue(all(c['trials'] == 30 for _, _, c in cells))

    def test_pir_trial_metrics_sum_serial_work_and_bytes(self):
        rows = [dict(trial=t, query=q, generation_ns=10, server1_ns=20,
                     server2_ns=30, recovery_ns=40, query_payload_bytes=16,
                     response_payload_bytes=128, database_payload_bytes_per_server=4096)
                for t in range(2) for q in range(2)]
        metrics = g.pir_trials(rows, 2, 2)
        self.assertEqual(metrics['serial_total_ns'], [100, 100])
        self.assertEqual(metrics['two_server_scan_GB_s'], [163.84, 163.84])
        with self.assertRaises(ValueError):
            g.pir_trials(rows[:-1], 2, 2)
        with self.assertRaises(ValueError):
            g.pir_trials(rows + [rows[0]], 2, 2)

    def test_interval_resamples_trials(self):
        self.assertEqual(g.estimate([5] * 30)['ci95_trials'], [5, 5])
        with self.assertRaises(ValueError):
            g.estimate([1])


    def test_binary_selection_uses_current_release_and_explicit_frozen_build(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / 'target/release/examples'
            frozen = root / 'experiments/results/geometry-20261022/bin'
            for location in [release, frozen]:
                location.mkdir(parents=True)
                for name in ['oram-measure', 'pir-measure']:
                    (location/name).touch()
            self.assertEqual(measure_binaries(root, {})[0], release/'oram-measure')
            self.assertEqual(measure_binaries(root, {'OBLIVION_GEOMETRY_BIN_DIR': str(frozen)})[0], frozen/'oram-measure')
            (release/'pir-measure').unlink()
            self.assertEqual(measure_binaries(root, {})[0], frozen/'oram-measure')
            with self.assertRaises(FileNotFoundError):
                measure_binaries(root, {'OBLIVION_GEOMETRY_BIN_DIR': str(root/'missing')})
            (frozen/'pir-measure').unlink()
            with self.assertRaises(FileNotFoundError):
                measure_binaries(root, {})

    def test_reanalysis_rejects_modified_raw_and_derived_before_overwrite(self):
        for changed in ['private-samples.jsonl.gz', 'summary.json']:
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root/'private-samples.jsonl.gz').write_bytes(b'original raw')
                (root/'summary.json').write_text('{}')
                (root/'provenance.json').write_text('{}')
                g.write_manifest(root)
                baseline = (root/'sha256.json').read_bytes()
                (root/changed).write_bytes(b'changed')
                with patch.object(g, 'analyze') as analyze:
                    with self.assertRaisesRegex(ValueError, changed.replace('.', r'\.')):
                        g.reanalyze(root)
                    analyze.assert_not_called()
                self.assertEqual((root/'sha256.json').read_bytes(), baseline)
                self.assertEqual((root/changed).read_bytes(), b'changed')

    def test_reanalysis_requires_manifest_and_preserves_raw_fingerprints(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(g, 'analyze') as analyze:
                with self.assertRaises(FileNotFoundError):
                    g.reanalyze(root)
                analyze.assert_not_called()
            (root/'private-samples.jsonl.gz').write_bytes(b'original raw')
            (root/'summary.json').write_text('{}')
            (root/'provenance.json').write_text('{}')
            g.write_manifest(root)
            before = g.verify_manifest(root)
            with self.assertRaises(FileExistsError):
                g.write_manifest(root)
            with patch.object(g, 'analyze', side_effect=lambda path: (path/'summary.json').write_text('{"revision":2}')):
                g.reanalyze(root)
            after = g.verify_manifest(root)
            self.assertEqual(after['private-samples.jsonl.gz'], before['private-samples.jsonl.gz'])
            self.assertEqual(after['provenance.json'], before['provenance.json'])
            self.assertNotEqual(after['summary.json'], before['summary.json'])

    def test_reanalysis_does_not_accept_raw_changes_during_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'private-samples.jsonl.gz').write_bytes(b'original raw')
            (root/'summary.json').write_text('{}')
            g.write_manifest(root)
            baseline = (root/'sha256.json').read_bytes()
            def corrupt_raw(path):
                (path/'private-samples.jsonl.gz').write_bytes(b'changed during analysis')
            with patch.object(g, 'analyze', side_effect=corrupt_raw):
                with self.assertRaisesRegex(ValueError, 'immutable artifact changed'):
                    g.reanalyze(root)
            self.assertEqual((root/'sha256.json').read_bytes(), baseline)

    def test_measured_examples_reject_bounds_and_accept_legacy_oram(self):
        root = Path(__file__).resolve().parents[2]
        oram, pir = measure_binaries(root)
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            config = dict(version=1, blocks=8, block_bytes=64, operations=10,
                          warmup=1, trials=2, seed=5, workload='uniform')
            cfg = tmp/'config.json'
            cfg.write_text(json.dumps(config))
            subprocess.run([oram, cfg, tmp/'legacy'], check=True, capture_output=True)
            observed = json.loads((tmp/'legacy/config.json').read_text())
            self.assertEqual(observed['bucket_capacity'], 4)
            config['bucket_capacity'] = 0
            cfg.write_text(json.dumps(config))
            result = subprocess.run([oram, cfg, tmp/'invalid-oram'], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((tmp/'invalid-oram').exists())
            config = dict(version=1, count=64, record_bytes=64, trials=2,
                          queries_per_trial=2, seed=5)
            cfg.write_text(json.dumps(config))
            subprocess.run([pir, cfg, tmp/'pir'], check=True, capture_output=True)
            self.assertEqual(len((tmp/'pir/private-samples.jsonl').read_text().splitlines()), 4)
            for key,value in [('count',0), ('record_bytes', 0), ('trials',0), ('queries_per_trial',1001), ('seed',18446744073709551615), ('unknown',1)]:
                invalid=dict(config);invalid[key]=value;cfg.write_text(json.dumps(invalid))
                result=subprocess.run([pir,cfg,tmp/'invalid-pir'],capture_output=True)
                self.assertNotEqual(result.returncode,0,key)
                self.assertFalse((tmp/'invalid-pir').exists())

if __name__ == '__main__':
    unittest.main()
