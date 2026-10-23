"""Matched genuine vendor ORAM comparison: bounded parsing and raw oracle checks."""
import importlib.util
from pathlib import Path
import tempfile
import subprocess
import json
import unittest

SPEC=importlib.util.spec_from_file_location('oram_reference',Path(__file__).resolve().parents[2]/'scripts/evaluate_oram_reference.py')
r=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(r)

class ReferenceTests(unittest.TestCase):
    def test_raw_complete_oracle_and_stash_histogram(self):
        rows=[dict(kind='setup',setup_ns=10,blocks=64,algorithm='path')]
        rows += [dict(kind='access',step=i,latency_ns=100+i,write=i%2==0,stash=i%3,correct=True) for i in range(16)]
        rows += [dict(kind='summary',measured_checks=16,initialization_checks=64,warmup_checks=2,final_audit_checks=64)]
        report=r.summarize_trial(rows,dict(blocks=64,operations=16,warmup=2),'path')
        self.assertEqual(sum(report['stash_histogram'].values()),16)
        self.assertEqual(report['max_measured_stash'],2)
        self.assertEqual(report['oracle_checks'],146)
        for invalid in [rows[:-1],rows[:3]+rows[4:],rows+[rows[1]]]:
            with self.assertRaises(ValueError):r.summarize_trial(invalid,dict(blocks=64,operations=16,warmup=2),'path')
        rows[1]['correct']=False
        with self.assertRaises(ValueError):r.summarize_trial(rows,dict(blocks=64,operations=16,warmup=2),'path')

    def test_genuine_both_algorithms_and_bounds(self):
        root=Path(__file__).resolve().parents[2];binary=root/'research/oram_reference/target/release/oblivion-oram-reference'
        self.assertTrue(binary.exists(),'build separate reference manifest first')
        with tempfile.TemporaryDirectory() as directory:
            tmp=Path(directory)
            for scheme in ['path','circuit']:
                out=tmp/f'{scheme}.jsonl'
                result=subprocess.run([binary,scheme,'64','16','2','123',out],capture_output=True)
                self.assertEqual(result.returncode,0,result.stderr.decode())
                rows=[json.loads(x) for x in out.read_text().splitlines()]
                report=r.summarize_trial(rows,dict(blocks=64,operations=16,warmup=2),scheme)
                self.assertEqual(report['measured_checks'],16)
            for args in [('path','0','16','2'),('path','65','16','2'),('path','64','0','2'),('path','64','16','1001'),('fake','64','16','2')]:
                out=tmp/'invalid'
                result=subprocess.run([binary,*args,'123',out],capture_output=True)
                self.assertNotEqual(result.returncode,0)
                self.assertFalse(out.exists())

if __name__=='__main__':unittest.main()
