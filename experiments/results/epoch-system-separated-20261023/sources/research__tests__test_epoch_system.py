import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from scripts.evaluate_epoch_system import analyze_trial, summarize, validate_observer_row

class EpochSystemTests(unittest.TestCase):
    def test_missing_or_malformed_trial_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises((ValueError,FileNotFoundError)):
                analyze_trial(Path(directory), {'participants':1,'epoch_ms':200,'real_percent':50,'epochs':4}, 1.)
        with self.assertRaises(ValueError):summarize([])

    def test_observer_schema_rejects_private_timing_and_labels(self):
        public={'version':1,'epoch':0,'slot':0,'observer':'batch-pipe','request_bytes':164,'response_bytes':164,'batch_count':1,'latency_ns':100,'epoch_due_ns':200,'batch_sent_ns':200,'late_by_ns':0}
        validate_observer_row(public)
        for field in ('client_ready_ns','queue_wait_ns','arrival_to_response_ns','real','function'):
            with self.subTest(field=field),self.assertRaises(ValueError):validate_observer_row({**public,field:1})

    @unittest.skipUnless(os.environ.get('EPOCH_SYSTEM_BINARY'),'set EPOCH_SYSTEM_BINARY for actual process integration')
    def test_actual_trial_cpu_goodput_zero_denominator_and_tampered_oracle(self):
        binary=os.environ['EPOCH_SYSTEM_BINARY']
        for percent in (0,50,100):
            with tempfile.TemporaryDirectory() as parent:
                output=Path(parent)/'trial';cell={'participants':2,'epoch_ms':200,'real_percent':percent,'epochs':2}
                completed=subprocess.run([binary,'demo-sweep',str(output),str(percent),'2','200','2','mixed'],capture_output=True,text=True)
                self.assertEqual(completed.returncode,0,completed.stderr)
                result=analyze_trial(output,cell,1.)
                public_path=output/'envelope-observer.jsonl'
                public=[json.loads(line) for line in public_path.read_text().splitlines()]
                private=[json.loads(line) for line in (output/'client-private-latency.jsonl').read_text().splitlines()]
                self.assertEqual(len(public),len(private))
                for row,timing in zip(public,private):
                    self.assertTrue({'client_ready_ns','queue_wait_ns','arrival_to_response_ns'}.isdisjoint(row))
                    self.assertEqual(timing['arrival_to_response_ns'],timing['queue_wait_ns']+row['latency_ns'])
                original=public_path.read_text();public[0]['client_ready_ns']=0
                public_path.write_text(''.join(json.dumps(row)+'\n' for row in public))
                with self.assertRaises(ValueError):analyze_trial(output,cell,1.)
                public_path.write_text(original)
                self.assertEqual(result['real_successes'],4*percent//100)
                self.assertEqual(result['total_application_bytes'],4*(328+466+128*316))
                self.assertGreater(result['executor_process_cpu_ns'],0)
                if percent==0:self.assertIsNone(result['application_bytes_per_real_success'])
                else:self.assertGreater(result['application_bytes_per_real_success'],0)
                metadata=json.loads((output/'metadata.json').read_text());metadata['configuration']['epochs']=8
                (output/'metadata.json').write_text(json.dumps(metadata))
                with self.assertRaises(ValueError):analyze_trial(output,cell,1.)
