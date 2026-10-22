"""Frozen-executable provenance and independent-setup correctness accounting."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('simplepir_campaign', Path(__file__).resolve().parents[2]/'scripts/simplepir_reference.py')
s = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(s)

class CampaignTests(unittest.TestCase):
    def test_frozen_executable_does_not_follow_rebuild_and_detects_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'original';source.write_bytes(b'first executable')
            frozen, hashes=s.freeze_executables(root, {'simplepir':source})
            source.write_bytes(b'rebuilt executable')
            self.assertEqual(frozen['simplepir'].read_bytes(),b'first executable')
            self.assertEqual(s.verify_executables(frozen,hashes),hashes)
            frozen['simplepir'].write_bytes(b'tampered')
            with self.assertRaises(RuntimeError):s.verify_executables(frozen,hashes)

    def test_correctness_requires_complete_unique_trial_query_sets(self):
        config={'trials':30,'queries_per_trial':3334}
        rows=[{'kind':'setup','trial':t} for t in range(30)]
        rows += [{'kind':'query','trial':t,'query':q,'correct':True} for t in range(30) for q in range(3334)]
        report=s.correctness_report(rows,config)
        self.assertEqual(report['queries'],100020)
        self.assertEqual(report['failures'],0)
        self.assertEqual(report['setup_trials'],30)
        self.assertEqual(report['setups_with_failure'],0)
        self.assertLess(report['iid_query_reference_only']['one_sided_95_upper'],0.00003)
        self.assertGreater(report['iid_setup_event_reference_only']['one_sided_95_upper'],0.09)
        for invalid in [rows[:-1],rows+[rows[-1]],rows[:-1]+[rows[-2]]]:
            with self.assertRaises(RuntimeError):s.correctness_report(invalid,config)
        rows[-1]['correct']=False
        report=s.correctness_report(rows,config)
        self.assertEqual(report['failures'],1)
        self.assertEqual(report['setups_with_failure'],1)

    def test_summary_keeps_setup_costs_separate_and_reports_failures(self):
        config={'trials':2,'queries_per_trial':2,'bootstrap_seed':1,'bootstrap_resamples':20}
        rows=[]
        for trial in range(2):
            rows.append(dict(kind='setup',trial=trial,database_build_ns=100,shared_init_ns=200,preprocessing_ns=300,offline_upload_bytes=400,offline_download_bytes=500))
            for query in range(2):
                rows.append(dict(kind='query',trial=trial,query=query,correct=True,generation_ns=1,server1_ns=2,server2_ns=3,recovery_ns=4,query_payload_bytes=5,response_payload_bytes=6,server_matrix_bytes_scanned=7))
        report=s.summarize(rows,config)
        self.assertEqual(report['latency_ns']['total_algorithm_ns']['mean'],10)
        self.assertEqual(report['setup_mean_ns']['preprocessing_ns'],300)
        self.assertEqual(report['setup_latency_ns']['preprocessing_ns']['trial_mean_95pct_bootstrap_ci'],[300,300])
        self.assertEqual(report['offline_bytes']['offline_download_bytes'],[500])
        self.assertTrue(report['all_correct'])
        rows[-1]['correct']=False
        self.assertFalse(s.summarize(rows,config)['all_correct'])

    def test_compression_preserves_rows_without_duplicate_aggregate(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);raw=root/'trial.jsonl';raw.write_text('{"correct":true}\n')
            compressed=s.compress_samples(raw)
            self.assertFalse(raw.exists())
            import gzip
            with gzip.open(compressed,'rt') as f:self.assertEqual(json.loads(f.read()),{'correct':True})

if __name__=='__main__':unittest.main()
