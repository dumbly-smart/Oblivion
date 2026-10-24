"""Strict per-server observations and whole-session profiling for PIR timing."""
import importlib.util
import os
from pathlib import Path
import tempfile
import subprocess
import unittest
from research.attacks.pir_timing import PirTimingAttack, FEATURE_MODES

class PirTimingTests(unittest.TestCase):
    def rows(self, prefix):
        rows=[];labels=[]
        for session in range(2):
            for step in range(30):
                label=step%3
                rows.append(dict(session=f'{prefix}{session}',step=step,server_ns=10+label,query_bytes=[label,0],visible_index=label))
                labels.append(label)
        return rows,labels

    def test_positive_control_and_all_feature_modes(self):
        profile,labels=self.rows('p');target,truth=self.rows('t')
        self.assertEqual(set(FEATURE_MODES),{'joint','timing_only','share_only','visible_index_only'})
        for mode in FEATURE_MODES:
            attack=PirTimingAttack(feature_mode=mode).fit(profile,dict(profile_labels=labels,profile_session_ids=['p0','p1']))
            result=attack.run(target,dict(target_session_ids=['t0','t1']))
            self.assertGreater(sum(a==b for a,b in zip(result.predictions,truth))/len(truth),.9)
            self.assertIsNone(result.confidence)
            self.assertIn('UNCALIBRATED',result.metadata['score_semantics'])

    def test_private_aux_and_shared_sessions_rejected(self):
        rows,labels=self.rows('p');aux=dict(profile_labels=labels,profile_session_ids=['p0','p1'])
        for key in ['label','index','second_share','recovery_ns','correct']:
            invalid=[dict(r) for r in rows];invalid[0][key]=0
            with self.assertRaises(ValueError):PirTimingAttack().fit(invalid,aux)
        model=PirTimingAttack().fit(rows,aux)
        with self.assertRaises(ValueError):model.run(rows,dict(target_session_ids=['p0','p1']))
        target,_=self.rows('t')
        with self.assertRaises(ValueError):model.run(target,dict(target_session_ids=['t0','t1'],target_labels=labels))
        with self.assertRaises(ValueError):model.run(target,dict(target_session_ids=['t0']))
        with self.assertRaises(ValueError):PirTimingAttack(feature_mode='private')

    def test_schema_bounds_fixed_shape_and_unique_steps(self):
        rows,labels=self.rows('p');aux=dict(profile_labels=labels,profile_session_ids=['p0','p1'])
        for field,value in [('query_bytes',[256]),('server_ns',-1),('server_ns',True),('visible_index',True),('session','')]:
            invalid=[dict(r) for r in rows];invalid[0][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):
                PirTimingAttack().fit(invalid,aux)
        for change in ['shape','step','aux']:
            invalid=[dict(r) for r in rows];knowledge=dict(aux)
            if change=='shape':invalid[0]['query_bytes']=[0]
            elif change=='step':invalid[1]['step']=0
            else:knowledge['profile_session_ids']=['p0',{}]
            with self.subTest(change=change),self.assertRaises(ValueError):
                PirTimingAttack().fit(invalid,knowledge)

    def test_exporter_bounds_and_observer_schema(self):
        root=Path(__file__).resolve().parents[2];binary=Path(os.environ.get('OBLIVION_PIR_TIMING_BIN', str(root/'target/release/examples/target_timing')))
        self.assertTrue(binary.is_file(),'build --example target_timing or set OBLIVION_PIR_TIMING_BIN')
        import json
        with tempfile.TemporaryDirectory() as directory:
            tmp=Path(directory)
            result=subprocess.run([binary,'pir','128','64','12','5','session',tmp/'sample'],capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            observer=[json.loads(x) for x in (tmp/'sample/observer.jsonl').read_text().splitlines()]
            private=[json.loads(x) for x in (tmp/'sample/private.jsonl').read_text().splitlines()]
            truth=[json.loads(x) for x in (tmp/'sample/truth.jsonl').read_text().splitlines()]
            self.assertEqual(len(observer),12)
            self.assertEqual({r['label'] for r in truth},{0,1,2})
            self.assertTrue(all(set(r)=={'session','step','server_ns','query_bytes','visible_index'} for r in observer))
            self.assertTrue(all(len(r['query_bytes'])==16 and r['visible_index'] is None for r in observer))
            self.assertTrue(all(r['correct'] for r in private))
            for args in [('pir','0','64','12'),('pir','128','0','12'),('pir','128','64','13'),('both','128','64','12')]:
                result=subprocess.run([binary,*args,'5','session',tmp/'invalid'],capture_output=True)
                self.assertNotEqual(result.returncode,0)
                self.assertFalse((tmp/'invalid').exists())

if __name__=='__main__':unittest.main()
