"""Regenerate fitted autoscaler results from retained raw streams only."""
import gzip
import importlib.util
import json
from pathlib import Path
from unittest.mock import patch
import tempfile
import unittest
from research.simulation.run import run

SPEC=importlib.util.spec_from_file_location('regenerate_scaler',Path(__file__).resolve().parents[2]/'scripts/regenerate_scaler.py')
r=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(r)

class ScalerReanalysisTests(unittest.TestCase):
    def fixture(self,root):
        config=root/'config.json';config.write_text(json.dumps(dict(version=1,seed=71,trials=2,sessions=8,workloads=['uniform','zipf'],simulation=dict(duration=3))))
        source=root/'source';expected=run(config,source)
        (source/'report.json').unlink()
        for image in source.glob('*.png'):image.unlink()
        return source,expected

    def test_rebuild_matches_actual_model_without_report_or_simulation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source,expected=self.fixture(root);out=root/'rebuilt'
            with patch('research.simulation.run.simulate',side_effect=AssertionError('no new simulation allowed')):
                actual=r.regenerate(source,out)
            self.assertEqual(actual['summary'],expected['summary'])
            self.assertEqual(actual['trial_metrics'],expected['trial_metrics'])
            self.assertEqual(actual['positive_controls'],expected['positive_controls'])
            self.assertTrue((out/'pareto-hot.png').exists())
            self.assertTrue((out/'pareto-intensity.png').exists())
            self.assertFalse((source/'report.json').exists())
            with self.assertRaises(FileExistsError):r.regenerate(source,out)

    def test_incomplete_duplicate_and_private_observer_fields_fail_before_output(self):
        for mutation in ['missing','duplicate','private']:
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);source,_=self.fixture(root);path=source/'observer.jsonl.gz'
                with gzip.open(path,'rt') as stream:rows=[json.loads(line) for line in stream]
                if mutation=='missing':rows.pop()
                elif mutation=='duplicate':rows[-1]=rows[0]
                else:rows[0]['rows'][0]['queue_length']=3
                with gzip.open(path,'wt') as stream:stream.write(''.join(json.dumps(row)+'\n' for row in rows))
                with self.assertRaises(ValueError):r.regenerate(source,root/'must-not-exist'/'analysis')
                self.assertFalse((root/'must-not-exist').exists())

    def test_raw_private_metrics_must_match_recorded_requests_and_price(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source,_=self.fixture(root);path=source/'private.jsonl.gz'
            with gzip.open(path,'rt') as stream:rows=[json.loads(line) for line in stream]
            rows[0]['metrics']['completed']+=1
            with gzip.open(path,'wt') as stream:stream.write(''.join(json.dumps(row)+'\n' for row in rows))
            with self.assertRaises(ValueError):r.regenerate(source,root/'analysis')
            self.assertFalse((root/'analysis').exists())

if __name__=='__main__':unittest.main()
