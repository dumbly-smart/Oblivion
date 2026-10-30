import unittest
from research.attacks.leaf_timing import LeafTimingAttack


class LeafTimingTests(unittest.TestCase):
    def rows(self, session, tags=(10, 20)):
        return [dict(session=session, tag=tags[int(i >= 72)], bytes=64, latency_ns=100+i%7) for i in range(96)]

    def test_positive_control_generalizes_across_permuted_whole_sessions(self):
        attack = LeafTimingAttack().fit(self.rows('profile'), {'profile_labels': [0]*72+[1]*24, 'profile_session_ids': ['profile']})
        result = attack.run(self.rows('target', (77, 3)), {'target_session_ids': ['target']})
        self.assertEqual(result.predictions, [0]*72+[1]*24)
        self.assertIsNone(result.confidence)
        self.assertIn('UNCALIBRATED', result.metadata['score_semantics'])

    def test_shared_sessions_truth_and_malformed_metrics_rejected(self):
        attack = LeafTimingAttack().fit(self.rows('profile'), {'profile_labels': [0]*72+[1]*24, 'profile_session_ids': ['profile']})
        for trace, aux in [(self.rows('profile'), {'target_session_ids': ['profile']}),
                           (self.rows('target'), {'target_session_ids': ['wrong']}),
                           ([dict(self.rows('target')[0], label=0)], {'target_session_ids': ['target']}),
                           ([dict(self.rows('target')[0], latency_ns=float('nan'))], {'target_session_ids': ['target']})]:
            with self.assertRaises(ValueError):
                attack.run(trace, aux)
        with self.assertRaises(ValueError):
            attack.run(self.rows('target'), {'target_session_ids': ['target'], 'labels': [0]})


if __name__ == '__main__':
    unittest.main()
