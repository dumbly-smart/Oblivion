"""Joint metadata/public-wire classifier and actual timer exporter checks."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from research.attacks.batch_load import BatchLoadAttack, features
from research.attacks.registry import PredictionResult

ROOT = Path(__file__).resolve().parents[2]
BINARY = ROOT/'target/release/examples/load_trace'


def trace(label):
    rows, emissions = [], []
    for epoch in range(2):
        frames = []
        for slot in range(8):
            frame = list(b'OBLV'+bytes([0,1,1,0])+epoch.to_bytes(8,'big')+slot.to_bytes(4,'big'))+[0]*144
            frame[20] = int(slot < label*4)
            frames.append(frame)
            rows.append(dict(type='arrival',epoch=epoch,slot=slot,arrived_ns=epoch*10000000+slot*100000,
                             destination='batcher',frame=frame))
        emissions.append(dict(type='emission',epoch=epoch,emitted_ns=(epoch+1)*10000000,destination='executor',frames=frames))
    return rows+emissions


class BatchLoadTests(unittest.TestCase):
    def profiles(self):
        return [dict(process_id=f'profile-{label}-{sample}',label=label,observations=trace(label))
                for label in range(3) for sample in range(2)]

    def test_profile_fitted_joint_classifier_has_standard_result_and_no_confidence(self):
        model = BatchLoadAttack().fit(self.profiles(),seed=123)
        result = model.run(trace(2), {'process_id':'independent-target'})
        self.assertIsInstance(result,PredictionResult)
        self.assertEqual(result.predictions,[2])
        self.assertIsNone(result.confidence)
        self.assertIn('wire_body_byte20_equals_one_fraction',result.metadata['feature_names'])
        self.assertEqual(len(features(trace(1))),len(result.metadata['feature_names']))

    def test_rejects_target_overlap_truth_fields_and_nonfinite_or_bad_shapes(self):
        model = BatchLoadAttack().fit(self.profiles())
        with self.assertRaises(ValueError): model.run(trace(1),{'process_id':'profile-0-0'})
        with self.assertRaises(ValueError): model.run(trace(1),{'process_id':'target','label':1})
        for mutate in ('truth','nonfinite','shape','early'):
            rows=copy.deepcopy(trace(1))
            if mutate=='truth': rows[0]['real']=True
            elif mutate=='nonfinite': rows[0]['arrived_ns']=float('nan')
            elif mutate=='shape': rows[0]['frame'].pop()
            else: rows[-2]['emitted_ns']=0
            with self.assertRaises(ValueError): features(rows)

    def test_run_accepts_explicit_authorized_profiles_without_pre_fit(self):
        result=BatchLoadAttack().run(trace(0),{'profiles':self.profiles(),'process_id':'heldout','seed':123})
        self.assertEqual(result.predictions,[0])

    def test_duplicate_profile_processes_and_unknown_labels_rejected(self):
        profiles=self.profiles();profiles[1]['process_id']=profiles[0]['process_id']
        with self.assertRaises(ValueError): BatchLoadAttack().fit(profiles)
        profiles=self.profiles();profiles[0]['label']=3
        with self.assertRaises(ValueError): BatchLoadAttack().fit(profiles)

    @unittest.skipUnless(BINARY.exists(),'build load_trace release example before integration check')
    def test_actual_protected_export_has_separate_truth_and_joint_fixed_shape(self):
        with tempfile.TemporaryDirectory() as temporary:
            truth=Path(temporary)/'truth.json'
            wire=subprocess.check_output([str(BINARY),'2','2','8','50','123','protected',str(truth),'test-process'])
            rows=[json.loads(line) for line in wire.splitlines()]
            vector=features(rows)
            self.assertGreater(len(vector),10)
            self.assertFalse(any('real' in row or 'real_percent' in row for row in rows))
            private=json.loads(truth.read_text());self.assertEqual(private['real_percent'],50)
            self.assertEqual(sum(r['real'] for r in private['requests']),8)


if __name__=='__main__': unittest.main()
