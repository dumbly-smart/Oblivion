"""Adapter contract tests use the actual offline baseline implementations."""
import json
import subprocess
import sys
import unittest


class AttackRegistry(unittest.TestCase):
    def registry(self):
        from research.attacks import registry
        return registry

    def test_all_eleven_real_adapters_have_stable_descriptions(self):
        registry = self.registry()
        descriptions = registry.list_attacks()
        self.assertEqual([x['name'] for x in descriptions], sorted([
            'frequency', 'traffic', 'joint', 'count', 'searchpattern',
            'likelihood', 'iterativeLAP', 'exactboundedcomparison', 'chosenupdateassociation', 'presence', 'leafTiming']))
        for entry in descriptions:
            self.assertIn('not a published attack reproduction', entry['limitations'])
        self.assertEqual(json.loads(json.dumps(descriptions)), descriptions)

    def test_presence_adapter_preserves_trace_level_prediction_and_rejects_truth(self):
        from research.attacks.presence import intersect
        from research.tests.test_presence import row
        trace = [row(), row(1, [1, 5])]
        beacon = [{'epoch': i, 'event': True} for i in range(2)]
        result = self.registry().create_attack('presence').run(trace, {'beacon': beacon})
        self.assertEqual(result.predictions, [5])
        self.assertEqual(result.metadata['original_result'], intersect(trace, beacon, seed=90000))
        self.assertEqual(result.metadata['prediction_unit'], 'client identity for complete trace')
        self.assertIsNone(result.confidence)
        for aux in [{'beacon': beacon, 'owner': 5}, {'beacon': beacon, 'seed': True}, {}]:
            with self.assertRaises(ValueError):
                self.registry().create_attack('presence').run(trace, aux)

    def test_frequency_calls_original_and_does_not_call_binary_scores_confidence(self):
        from research.attacks.simple import FrequencyAttack
        rows = [{'tag': 9}] * 3 + [{'tag': 2}]
        aux = {'ranked_labels': [0, 1], 'majority': 0}
        result = self.registry().create_attack('frequency').run(rows, aux)
        expected = FrequencyAttack().run(rows, aux)
        self.assertEqual(result.predictions, expected.predictions)
        self.assertIsNone(result.confidence)
        self.assertEqual(result.metadata['original_scores'], expected.scores)
        self.assertEqual(json.loads(json.dumps(result.to_dict()))['predictions'], expected.predictions)

    def test_sse_rankings_are_preserved(self):
        from research.attacks.sse import CountVolumeAttack, SearchPatternFrequencyAttack
        rows = [{'tag': 'a', 'count': 7}] * 3 + [{'tag': 'b', 'count': 19}]
        aux = {'counts': [19, 7], 'query_counts': [1, 3], 'seed': 4}
        for name, cls in [('count', CountVolumeAttack), ('searchpattern', SearchPatternFrequencyAttack)]:
            expected = cls().run(rows, aux, seed=4)
            result = self.registry().create_attack(name).run(rows, aux)
            self.assertEqual(result.predictions, [r[0] for r in expected])
            self.assertEqual(result.metadata['rankings'], expected)
            self.assertIsNone(result.confidence)

    def test_inference_adapters_preserve_real_function_outputs(self):
        from research.attacks.inference import infer
        rows = [{'tag': str(i), 'count': [2, 8, 15][i]} for i in [2, 0, 1] * 3]
        aux = {'counts': [2, 8, 15], 'corpus_documents': 20, 'profile_labels': [0, 1, 2] * 8}
        expected = infer(rows, aux)
        for name, key in [('likelihood', 'likelihood_assignment'), ('iterativeLAP', 'iterative_hungarian_markov'), ('exactboundedcomparison', 'exact_markov_bound')]:
            result = self.registry().create_attack(name).run(rows, aux)
            self.assertEqual(result.metadata['rankings'], expected[key]['rankings'])
            self.assertEqual(result.metadata['original_result'], expected[key])

    def test_supervised_adapters_call_original_with_disjoint_profile_sessions(self):
        from research.attacks.simple import TrafficAttack
        from research.attacks.joint import JointAttack, FEATURES
        for name, cls, rows, labels in [
            ('traffic', TrafficAttack, [{'bytes': 4, 'latency_ns': 9}, {'bytes': 64, 'latency_ns': 7}], [1, 0]),
            ('joint', JointAttack, [{key: i for key in FEATURES} for i in range(9)], [0, 1, 2] * 3),
        ]:
            attack = self.registry().create_attack(name)
            with self.assertRaises(ValueError):
                attack.run(rows, {})
            attack.fit(rows, {'profile_labels': labels, 'profile_session_ids': ['profile']})
            with self.assertRaises(ValueError):
                attack.run(rows, {'target_session_ids': ['profile']})
            result = attack.run(rows, {'target_session_ids': ['target']})
            expected = cls().fit(rows, labels).run(rows, {})
            self.assertEqual(result.predictions, expected.predictions)
            self.assertEqual(result.metadata['original_scores'], expected.scores)

    def test_chosen_update_association_calls_real_recover_links(self):
        from research.attacks.linkability import recover_links
        rows = [
            {'mode': 'control', 'phase': 'past_search', 'slot': 0, 'request': {'tag': [1]}, 'response': {'entries': [{'address': [8]}]}},
            {'mode': 'control', 'phase': 'injected_update', 'injection': 0, 'request': {'stable_tag': [1], 'address': [9]}},
            {'mode': 'control', 'phase': 'fresh_search', 'slot': 0, 'request': {'tag': [1]}, 'response': {'entries': [{'address': [9]}]}},
        ]
        result = self.registry().create_attack('chosenupdateassociation').run(rows, {'mode': 'control'})
        expected = recover_links(rows, 'control')
        self.assertEqual(result.predictions, expected['before_predictions'])
        self.assertEqual(result.metadata['original_result'], expected)
        self.assertEqual(result.metadata['prediction_unit'], 'injected_update')
        rows[0]['request']['label'] = 0
        with self.assertRaises(ValueError):
            self.registry().create_attack('chosenupdateassociation').run(rows, {'mode': 'control'})

    def test_rejects_truth_invalid_numeric_and_bounded_inputs(self):
        attack = self.registry().create_attack('count')
        for rows, aux in [
            ([{'count': 2, 'label': 0}], {'counts': [2]}),
            ([{'count': 2}], {'counts': [2], 'target_labels': [0]}),
            ([{'count': float('nan')}], {'counts': [2]}),
            ([{'count': -1}], {'counts': [2]}),
            ([{'count': True}], {'counts': [2]}),
            ([{'count': 2}] * 10001, {'counts': [2]}),
            ([{'count': 2}], {'counts': []}),
            ([{'count': 2}], {'counts': [2], 'query_counts': [1, 2]}),
        ]:
            with self.subTest(rows=rows[:1], aux=aux), self.assertRaises(ValueError):
                attack.run(rows, aux)

    def test_plugins_register_real_adapters_and_reject_duplicate_names(self):
        from unittest.mock import patch
        registry = self.registry()
        with patch.dict(registry._REGISTRY):
            spec = registry.AttackSpec('custom_count', 'Local count adapter', ('count',), ('counts',))
            registry.register_attack(spec, lambda: registry.create_attack('count'))
            self.assertEqual(registry.create_attack('custom_count').run([{'count': 7}], {'counts': [19, 7]}).predictions, [1])
            with self.assertRaises(ValueError):
                registry.register_attack(spec, lambda: registry.create_attack('count'))
        with self.assertRaises(ValueError):
            registry.create_attack('missing')

    def test_multi_mode_link_fixture_validates_association_within_selected_mode(self):
        rows = []
        for mode in ['control', 'ggm']:
            rows.extend([
                {'mode': mode, 'phase': 'past_search', 'slot': 0, 'request': {'tag': [1]}, 'response': {'entries': [{'address': [8]}]}},
                {'mode': mode, 'phase': 'injected_update', 'request': {'address': [9]}},
                {'mode': mode, 'phase': 'fresh_search', 'slot': 0, 'request': {'tag': [1]}, 'response': {'entries': [{'address': [9]}]}},
            ])
        attack = self.registry().create_attack('chosenupdateassociation')
        self.assertEqual(attack.run(rows, {'mode': 'ggm'}).predictions, [0])

    def test_huge_integer_and_missing_profiles_are_rejected_cleanly(self):
        registry = self.registry()
        with self.assertRaises(ValueError):
            registry.create_attack('count').run([{'count': 10 ** 1000}], {'counts': [1]})
        traffic = registry.create_attack('traffic')
        with self.assertRaises(ValueError):
            traffic.fit([{'bytes': 1, 'latency_ns': 1}], {'profile_labels': [1]})
        for name in ['likelihood', 'iterativeLAP', 'exactboundedcomparison']:
            with self.assertRaises(ValueError):
                registry.create_attack(name).run([{'tag': 'a', 'count': 1}], {
                    'counts': [1] * 9, 'corpus_documents': 20, 'profile_labels': [0, 1]})

    def test_cli_lists_and_runs_json_roundtrip(self):
        def cli(*args, input=None):
            return subprocess.run([sys.executable, '-m', 'research.attacks', *args], input=input,
                                  capture_output=True, text=True)
        listed = cli('--list')
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertEqual(json.loads(listed.stdout), self.registry().list_attacks())
        payload = {'trace': [{'count': 7}], 'aux': {'counts': [19, 7]}}
        result = cli('--attack', 'count', input=json.dumps(payload))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['predictions'], [1])
        failed = cli('--attack', 'count', input='{"trace":[{"count":NaN}],"aux":{"counts":[1]}}')
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(failed.stdout, '')


if __name__ == '__main__':
    unittest.main()
