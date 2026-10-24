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

    def test_completed_masked_timeout_keeps_latency_and_failed_cpu(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory);cell={'participants':1,'epoch_ms':200,'real_percent':100,'epochs':1}
            def write(name,value):
                (path/name).write_text(json.dumps(value)+'\n')
            def rows(name,value):
                (path/name).write_text(''.join(json.dumps(row)+'\n' for row in value))
            write('metadata.json',{'configuration':{**cell,'mixed_functions':True,'class_ms':100}})
            summary={'real_invocations':1,'dummy_invocations':0,'successful_real_invocations':0,'failed_real_invocations':1,'successful_dummy_invocations':0,'failed_dummy_invocations':0,'offered_invocations':1,'completed_invocations':1,'functions_verified':0,'client_state_counters':[0],'epoch_ms':200,'epochs':1,'participants':1,'encrypted_pir_links':True,'processes':4,'measurement_wall_ns':300000000,'retains_runtime_errors':True}
            write('client-summary.json',summary)
            rows('envelope-observer.jsonl',[{'version':1,'epoch':0,'slot':0,'observer':'batch-pipe','request_bytes':164,'response_bytes':164,'batch_count':1,'latency_ns':100000000,'epoch_due_ns':200000000,'batch_sent_ns':200000000,'late_by_ns':0}])
            rows('client-ground-truth.jsonl',[{'epoch':0,'slot':0,'real':True,'function':0,'success':False}])
            rows('client-private-latency.jsonl',[{'version':1,'epoch':0,'slot':0,'client_ready_ns':0,'queue_wait_ns':200000000,'arrival_to_response_ns':300000000}])
            engine={'epoch':0,'slot':0,'real':True,'function':0,'status':'Timeout','registry_authenticated':True,'request_authenticated':True,'request_valid':True,'pir_queries_completed':2,'pir_application_frame_bytes':530,'storage_events':128,'storage_bytes':128*316}
            rows('executor-private.jsonl',[engine])
            rows('publication-private.jsonl',[{'epoch':0,'slot':0,'executor_process_cpu_ns':123,'publication_lateness_ns':1,'driver_work_overrun_ns':0}])
            rows('storage-observer.jsonl',[{'bytes':316,'direction':'read' if i<64 else 'write'} for i in range(128)])
            result=analyze_trial(path,cell,.3)
            self.assertEqual(result['completed_invocations'],1)
            self.assertEqual(result['failed_real_invocations'],1)
            self.assertEqual(result['real_successes'],0)
            self.assertEqual(result['real_goodput_per_second'],0)
            self.assertEqual(result['failed_executor_cpu_ns'],123)
            self.assertEqual(result['failure_causes'],{'Timeout':1})
            self.assertEqual(result['arrival_p50_ns'],300000000)
            self.assertIsNone(result['application_bytes_per_real_success'])
            self.assertIsNone(result['executor_cpu_ns_per_real_success'])
            report=summarize([result])[0]
            self.assertEqual(report['failed_executor_cpu_ns']['mean'],123)
            self.assertIsNone(report['executor_cpu_ns_per_real_success'])
            self.assertEqual(report['metric_missing_trials']['executor_cpu_ns_per_real_success'],1)
            engine['status']='Success';rows('executor-private.jsonl',[engine])
            with self.assertRaises(ValueError):analyze_trial(path,cell,.3)
            rows('client-ground-truth.jsonl',[{'epoch':0,'slot':0,'real':True,'function':0,'success':True}])
            summary.update(successful_real_invocations=1,failed_real_invocations=0,functions_verified=1)
            write('client-summary.json',summary)
            success=analyze_trial(path,cell,.3)
            mixed=summarize([result,success])[0]
            self.assertEqual(mixed['real_successes']['mean'],.5)
            self.assertEqual(mixed['application_bytes_per_real_success']['estimate'],2*(328+530+128*316))
            self.assertEqual(mixed['executor_cpu_ns_per_real_success']['estimate'],246)
            self.assertGreater(mixed['executor_cpu_ns_per_real_success']['undefined_denominator_bootstrap_resamples'],0)
            self.assertIsNone(mixed['executor_cpu_ns_per_real_success']['ci95'])
            self.assertEqual(mixed['conditional_mean_trial_executor_cpu_ns_per_real_success']['mean'],123)
            self.assertEqual(mixed['conditional_mean_trial_executor_cpu_ns_per_real_success']['undefined_trials'],1)
            self.assertEqual(mixed['metric_missing_trials']['application_bytes_per_real_success'],1)
            # Partial backend/PIR failure retains actual counts and unknown bytes;
            # it is not silently padded by the analysis into a successful shape.
            engine.update(status='Storage',registry_authenticated=False,pir_queries_completed=1,pir_application_frame_bytes=None,storage_events=64,storage_bytes=64*316)
            rows('executor-private.jsonl',[engine])
            rows('client-ground-truth.jsonl',[{'epoch':0,'slot':0,'real':True,'function':0,'success':False}])
            rows('storage-observer.jsonl',[{'bytes':316,'direction':'read'} for _ in range(64)])
            summary.update(successful_real_invocations=0,failed_real_invocations=1,functions_verified=0)
            write('client-summary.json',summary)
            partial=analyze_trial(path,cell,.3)
            self.assertFalse(partial['storage_full_shape'])
            self.assertEqual(partial['storage_events'],64)
            self.assertIsNone(partial['total_application_bytes'])
            self.assertEqual(partial['failed_executor_cpu_ns'],123)
            engine.update(status='Success',real=False,function=4,registry_authenticated=True,request_authenticated=False,request_valid=False,pir_queries_completed=2,pir_application_frame_bytes=530,storage_events=128,storage_bytes=128*316)
            rows('executor-private.jsonl',[engine])
            rows('storage-observer.jsonl',[{'bytes':316,'direction':'read' if i<64 else 'write'} for i in range(128)])
            sanitized=analyze_trial(path,cell,.3)
            self.assertEqual(sanitized['failure_causes'],{'RequestAuthentication':1})
            self.assertEqual(sanitized['real_invocations_offered'],1)
            self.assertEqual(sanitized['failed_real_invocations'],1)



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
                self.assertEqual(result['real_invocations_offered'],4*percent//100)
                self.assertEqual(result['real_successes']+result['failed_real_invocations'],4*percent//100)
                self.assertEqual(result['completed_invocations'],4)
                self.assertEqual(result['dummy_successes']+result['failed_dummy_invocations'],4-4*percent//100)
                engine=[json.loads(line) for line in (output/'executor-private.jsonl').read_text().splitlines()]
                expected_bytes=None if any(row['pir_application_frame_bytes'] is None for row in engine) else 4*328+sum(row['storage_bytes']+row['pir_application_frame_bytes'] for row in engine)
                self.assertEqual(result['total_application_bytes'],expected_bytes)
                self.assertGreater(result['executor_process_cpu_ns'],0)
                if result['real_successes']==0 or expected_bytes is None:self.assertIsNone(result['application_bytes_per_real_success'])
                else:self.assertGreater(result['application_bytes_per_real_success'],0)
                metadata=json.loads((output/'metadata.json').read_text());metadata['configuration']['epochs']=8
                (output/'metadata.json').write_text(json.dumps(metadata))
                with self.assertRaises(ValueError):analyze_trial(output,cell,1.)
