import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from scripts.evaluate_epoch_system import analyze_trial, summarize

class EpochSystemTests(unittest.TestCase):
    def test_missing_or_malformed_trial_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises((ValueError,FileNotFoundError)):
                analyze_trial(Path(directory), {'participants':1,'epoch_ms':200,'real_percent':50,'epochs':4}, 1.)
        with self.assertRaises(ValueError):summarize([])

    @unittest.skipUnless(os.environ.get('EPOCH_SYSTEM_BINARY'),'set EPOCH_SYSTEM_BINARY for actual process integration')
    def test_actual_trial_cpu_goodput_zero_denominator_and_tampered_oracle(self):
        binary=os.environ['EPOCH_SYSTEM_BINARY']
        for percent in (0,50,100):
            with tempfile.TemporaryDirectory() as parent:
                output=Path(parent)/'trial';cell={'participants':2,'epoch_ms':200,'real_percent':percent,'epochs':2}
                completed=subprocess.run([binary,'demo-sweep',str(output),str(percent),'2','200','2','mixed'],capture_output=True,text=True)
                self.assertEqual(completed.returncode,0,completed.stderr)
                result=analyze_trial(output,cell,1.)
                self.assertEqual(result['real_successes'],4*percent//100)
                self.assertEqual(result['total_application_bytes'],4*(328+466+128*316))
                self.assertGreater(result['executor_process_cpu_ns'],0)
                if percent==0:self.assertIsNone(result['application_bytes_per_real_success'])
                else:self.assertGreater(result['application_bytes_per_real_success'],0)
                metadata=json.loads((output/'metadata.json').read_text());metadata['configuration']['epochs']=8
                (output/'metadata.json').write_text(json.dumps(metadata))
                with self.assertRaises(ValueError):analyze_trial(output,cell,1.)
