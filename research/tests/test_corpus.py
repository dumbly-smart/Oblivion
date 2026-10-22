"""Bounded corpus knowledge boundary and real AEAD integration checks."""
import gzip
import json
import shutil
from pathlib import Path
import tempfile
import unittest

import numpy as np

from research.analysis import corpus
from research.analysis.corpus import (export, load_records, make_trial, postings,
                                      require_controls, select_vocabulary, summarize)
from research.analysis.sse import read_observations

ROOT = Path(__file__).resolve().parents[2]
BINARY = ROOT/'target/release/examples/corpus'


class CorpusEvaluation(unittest.TestCase):
    def test_auxiliary_only_vocabulary_distinct_counts_and_real_shared_documents(self):
        documents = [{'tokens': frozenset('word'+chr(97+k) for k in range(12) if i < 20-k)} for i in range(24)]
        vocabulary = select_vocabulary(documents)
        self.assertEqual(len(vocabulary), 8)
        derived = postings(documents, vocabulary)
        self.assertEqual(len({len(p) for p in derived}), 8)
        self.assertTrue(all(0 in p for p in derived))
        self.assertNotIn('targetonly', vocabulary)

    def test_partition_disjoint_target_and_reproducible_auxiliary_drift(self):
        records = [{'digest': str(i), 'spam': i % 2 == 0,
                    'tokens': frozenset('word'+chr(97+k) for k in range(20) if i % 47 < 42-k)} for i in range(1800)]
        config = {'seed': 1234, 'documents': 128, 'keywords': 8, 'drift_spam_fractions': [.5, .9],
                  'profile_queries': 100, 'queries_per_session': 64, 'target_sessions': 2}
        aux, truth = make_trial(records, config, 0)
        self.assertEqual((aux, truth), make_trial(records, config, 0))
        target = set(truth['document_digests'])
        base = set(aux['matched']['document_digests'])
        for knowledge in aux.values():
            self.assertFalse(target.intersection(knowledge['document_digests']))
        for view in ('spam50', 'spam90'):
            self.assertFalse(base.intersection(aux[view]['document_digests']))
        self.assertAlmostEqual(aux['spam90']['spam_fraction'], 115/128)
        self.assertEqual(len(truth['target_sessions']), 2)
        self.assertEqual(aux['matched']['profile_labels'], aux['spam90']['profile_labels'])

    def test_source_digest_refuses_changed_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary)/'bad.zip'
            archive.write_bytes(b'not the public source')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                load_records(archive, {'source_sha256': '0'*64})

    def test_failed_positive_control_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'positive control failed'):
            require_controls([{'attack': 'count_volume', 'advantage_over_profile_majority': 0}])

    @unittest.skipUnless(BINARY.exists(), 'build the real corpus example before integration checks')
    def test_actual_shared_doc_ids_and_aead_dummy_padding(self):
        real = [[2, 7], [2], [7, 9], [], [3], [2, 3], [9], [1]]
        queries = [list(range(8)), list(reversed(range(8)))]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'wire.gz'
            export(BINARY, path, real, queries, 4, 123)
            sessions, updates = read_observations(path)
            self.assertEqual(updates, 32)
            self.assertTrue(all(o['count'] == 4 for values in sessions.values() for o in values))
            with gzip.open(path, 'rt') as stream:
                wire = [json.loads(line) for line in stream]
            self.assertTrue(all('keyword' not in row and 'postings' not in row for row in wire))
            self.assertEqual(len(sessions), 2)
            # Fresh CSPRNG client/index IDs produce unrelated wire on another run.
            second = Path(temporary)/'wire2.gz'
            export(BINARY, second, real, queries, 4, 123)
            with gzip.open(second, 'rt') as stream:
                second_first = json.loads(next(stream))
            self.assertNotEqual(wire[0]['request']['index_id'], second_first['request']['index_id'])
            self.assertNotEqual(wire[0]['request']['address'], second_first['request']['address'])
            self.assertNotEqual(wire[0]['request']['ciphertext'], second_first['request']['ciphertext'])

    @unittest.skipUnless(BINARY.exists(), 'build the real corpus example before integration checks')
    def test_real_exporter_rejects_truncation_and_duplicate_ids(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'wire.gz'
            with self.assertRaises(RuntimeError):
                export(BINARY, path, [[1, 2]]*8, [list(range(8))], 1, 42)
            with self.assertRaises(RuntimeError):
                export(BINARY, path, [[1, 1]]*8, [list(range(8))], None, 42)

    @unittest.skipUnless(BINARY.exists(), 'build the real corpus example before integration checks')
    def test_frozen_executable_survives_source_binary_replacement(self):
        real = [[2, 7], [2], [7, 9], [], [3], [2, 3], [9], [1]]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory/'mutable-corpus'
            shutil.copy2(BINARY, source)
            frozen, before = corpus.snapshot_binary(source, directory/'bin'/'corpus')
            self.assertNotEqual(source.stat().st_ino, frozen.stat().st_ino)
            source.unlink()
            source.write_text('#!/bin/sh\nexit 97\n')
            source.chmod(0o755)
            self.assertNotEqual(corpus.sha(source), before)
            path = directory/'wire.gz'
            export(frozen, path, real, [list(range(8))], 4, 123)
            sessions, updates = read_observations(path)
            self.assertEqual(updates, 32)
            self.assertEqual(len(sessions[0]), 8)
            self.assertEqual(corpus.sha(frozen), before)

    def test_trial_cluster_paired_drift_uncertainty(self):
        rows = []
        for trial in range(3):
            for mode in ('sse', 'padded_sse'):
                for view in ('matched', 'spam50'):
                    for session in range(2):
                        row = dict(trial=trial, mode=mode, view=view, attack='count_volume')
                        for key in ('accuracy', 'balanced_accuracy', 'top3_accuracy', 'majority_accuracy',
                                    'oracle_majority_accuracy', 'chance_accuracy', 'advantage_over_profile_majority',
                                    'mean_postings', 'mean_response_json_bytes', 'objective_gap'):
                            row[key] = trial/10 + (.1 if view == 'matched' else 0)
                        rows.append(row)
        summary, paired = summarize(rows, 3)
        self.assertEqual(summary[0]['split_resample_trials'], 3)
        self.assertTrue(all(np.isclose(item['accuracy_difference_vs_matched'], -.1) for item in paired))
        self.assertTrue(all(np.allclose(item['paired_trial_bootstrap_95'], [-.1, -.1]) for item in paired))


if __name__ == '__main__':
    unittest.main()
