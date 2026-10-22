import copy
import gzip
import json
import os
from pathlib import Path
import subprocess
import tempfile
import hashlib
import sys
import unittest
from research.attacks.presence import intersect


def row(epoch=0, incoming=None):
    incoming = [2, 5] if incoming is None else incoming
    return {'mode': 'intermittent_control', 'epoch': epoch, 'incoming': incoming,
            'missing_slots': [i for i in range(8) if i not in incoming], 'outgoing': list(range(8)),
            'incoming_bytes': len(incoming)*164, 'outgoing_bytes': 1312,
            'emit_ns': (epoch+1)*10_000_000, 'late_by_ns': 0}


class PresenceTests(unittest.TestCase):
    def test_known_intersection_and_observer_equivalence(self):
        trace = [row(), row(1, [1, 5])]
        beacon = [{'epoch': i, 'event': True} for i in range(2)]
        for observer in ('incoming', 'missing_slots'):
            result = intersect(trace, beacon, observer=observer)
            self.assertEqual(result['candidates'], [5])
            self.assertEqual(result['scores'], {'5': 1.0})
        self.assertEqual(intersect(trace, beacon, observer='downstream')['candidates'], list(range(8)))
        self.assertEqual(len(intersect(trace, beacon, knowledge_events=1)['candidates']), 2)

    def test_no_beacon_and_all_participants(self):
        self.assertEqual(intersect([row()], [{'epoch': 0, 'event': False}])['candidates'], list(range(8)))
        self.assertEqual(intersect([row(incoming=list(range(8)))], [{'epoch': 0, 'event': True}])['candidates'], list(range(8)))

    def test_malformed_schema_bounds_and_truth(self):
        base = row(); event = [{'epoch': 0, 'event': True}]
        for field, value in [('owner', 5), ('epoch', True), ('incoming', [5, 5]),
                             ('incoming_bytes', 1), ('outgoing_bytes', float('nan')),
                             ('late_by_ns', -1), ('mode', 'unknown'), ('emit_ns', 2**64)]:
            changed = copy.deepcopy(base); changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                intersect([changed], event)
        for beacon in ([], [{'epoch': 0, 'event': 1}], [{'epoch': 0, 'event': True, 'owner': 5}]):
            with self.assertRaises(ValueError):
                intersect([base], beacon)
        for kwargs in ({'seed': -1}, {'seed': True}, {'knowledge_events': 0}, {'observer': 'truth'}):
            with self.assertRaises(ValueError):
                intersect([base], event, **kwargs)
        with self.assertRaises(ValueError):
            intersect([], [])
        with self.assertRaises(ValueError):
            intersect([base]*4097, event*4097)

    def test_raw_source_tamper_rejected_before_output_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root/'source'; (source/'raw').mkdir(parents=True)
            artifact = source/'raw'/'p50-s1.observer.jsonl.gz'
            with gzip.open(artifact, 'wt') as stream:
                stream.write('{}\n')
            (source/'provenance.json').write_text('{}\n')
            manifest = {str(path.relative_to(source)): hashlib.sha256(path.read_bytes()).hexdigest()
                        for path in source.rglob('*') if path.is_file()}
            (source/'artifact-sha256.json').write_text(json.dumps(manifest))
            # A still-valid gzip file was changed after the recorded fingerprint.
            with gzip.open(artifact, 'wt') as stream:
                stream.write('{"changed":true}\n')
            before = {str(path.relative_to(source)): path.read_bytes() for path in source.rglob('*') if path.is_file()}
            output_parent = root/'must-not-be-created'
            result = subprocess.run([sys.executable, '-m', 'research.analysis.presence', '--raw-source', str(source),
                                     '--out', str(output_parent/'analysis')], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output_parent.exists(), 'verification must precede all output mutations')
            self.assertIn('artifact digest mismatch', result.stderr)
            self.assertEqual(before, {str(path.relative_to(source)): path.read_bytes() for path in source.rglob('*') if path.is_file()})

    @unittest.skipUnless(os.environ.get('PRESENCE_BINARY'), 'set PRESENCE_BINARY for actual library integration')
    def test_actual_batcher_export_oracle(self):
        binary = os.environ['PRESENCE_BINARY']
        with tempfile.TemporaryDirectory() as directory:
            truth = Path(directory)/'truth'; beacon_path = Path(directory)/'beacon'
            completed = subprocess.run([binary, '1001', '64', '50', str(truth), str(beacon_path)], check=True, capture_output=True, text=True)
            observations = [json.loads(line) for line in completed.stdout.splitlines()]
            private = [json.loads(line) for line in truth.read_text().splitlines()]
            beacon = [json.loads(line) for line in beacon_path.read_text().splitlines()]
            self.assertEqual(len(observations), 192)
            owner = private[0]['owner']
            for mode in ('intermittent_control', 'fixed_rate_online', 'always_participating'):
                rows = [r for r in observations if r['mode'] == mode]
                oracle = [r for r in private if r['mode'] == mode]
                candidates = intersect(rows, beacon)['candidates']
                self.assertIn(owner, candidates)
                for public, secret, event in zip(rows, oracle, beacon):
                    self.assertEqual(secret['verified']+secret['cover_rejected'], 8)
                    self.assertEqual(public['incoming_bytes'], secret['verified']*164)
                    self.assertEqual(event['event'], owner in secret['real'])
                if mode == 'always_participating':
                    self.assertEqual(candidates, list(range(8)))
            from research.analysis.presence import summarize
            raw_root = Path(directory)/'retained'; (raw_root/'raw').mkdir(parents=True)
            stem = raw_root/'raw'/'p50-s1001'
            for suffix, text in (('observer', completed.stdout), ('truth', truth.read_text()), ('beacon', beacon_path.read_text())):
                with gzip.open(str(stem)+f'.{suffix}.jsonl.gz', 'wt') as stream:
                    stream.write(text)
            analysis = Path(directory)/'analysis'; analysis.mkdir()
            config = {'online_percent': [50], 'seeds': [1001], 'epochs': 64, 'knowledge_events': [None]}
            summarize(analysis, config, raw_out=raw_root)
            original_costs = (analysis/'costs.jsonl').read_text()
            summarize(analysis, config, raw_out=raw_root)
            self.assertEqual((analysis/'costs.jsonl').read_text(), original_costs)
            self.assertEqual(len(original_costs.splitlines()), 3)
            report = json.loads((analysis/'summary.json').read_text())
            self.assertTrue(all('wilson95' in result['accuracy'] for result in report['results']))
            for args in (['1001', '0', '50'], ['1001', '4097', '50'], ['1001', '10', '101']):
                self.assertNotEqual(subprocess.run([binary, *args, str(truth), str(beacon_path)], capture_output=True).returncode, 0)


if __name__ == '__main__':
    unittest.main()
