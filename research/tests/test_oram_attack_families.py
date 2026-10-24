"""Positive controls and observer-boundary tests for the frequency-only ORAM attack."""
import unittest

from research.analysis.oram_attack_families import TagFrequencyAttack


def rows(session, tags):
    return [{"session": session, "step": i, "tag": tag, "bytes": 100,
             "latency_ns": 1000 + i} for i, tag in enumerate(tags)]


class TagFrequencyAttackTests(unittest.TestCase):
    def test_tag_frequency_attack_succeeds_on_direct_address_control(self):
        profile_rows = rows("profile-a", [10, 10, 20, 20]) + rows("profile-b", [10, 10, 20, 20])
        labels = [1, 1, 0, 0] * 2
        target_rows = rows("target", [10, 20, 10, 20])
        attack = TagFrequencyAttack().fit(profile_rows, labels)
        predictions, scores = attack.run(target_rows, {"target"})
        self.assertEqual(predictions, [1, 0, 1, 0])
        self.assertGreater(scores[0], 0.5)
        self.assertLess(scores[1], 0.5)

    def test_target_sessions_must_be_disjoint_from_labeled_profile(self):
        profile_rows = rows("profile", [1, 1, 2, 2])
        attack = TagFrequencyAttack().fit(profile_rows, [1, 1, 0, 0])
        with self.assertRaises(ValueError):
            attack.run(profile_rows, {"profile"})

    def test_timing_and_byte_counts_do_not_change_frequency_scores(self):
        profile_rows = rows("profile", [1, 1, 2, 2])
        attack = TagFrequencyAttack().fit(profile_rows, [1, 1, 0, 0])
        target = rows("target", [1, 2])
        _, original = attack.run(target, {"target"})
        target[0]["latency_ns"] = 999_999_999
        target[0]["bytes"] = 1_000_000
        _, changed = attack.run(target, {"target"})
        self.assertEqual(original, changed)

    def test_private_labels_are_rejected_inside_observer_rows(self):
        profile_rows = rows("profile", [1, 1, 2, 2])
        profile_rows[0]["logical_address"] = 0
        with self.assertRaises(ValueError):
            TagFrequencyAttack().fit(profile_rows, [1, 1, 0, 0])


if __name__ == "__main__":
    unittest.main()
