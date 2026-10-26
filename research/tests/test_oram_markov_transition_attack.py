import unittest

from research.analysis.oram_markov_transition_attack import MarkovTransitionAttack
import research.analysis.oram_markov_transition_attack as transition_analysis


def rows_for(session, tags):
    return [
        {"session": session, "step": step, "tag": tag, "bytes": 64, "latency_ns": 100}
        for step, tag in enumerate(tags)
    ]


class MarkovTransitionAttackTests(unittest.TestCase):
    def test_preregistered_secondary_provenance_is_not_labeled_post_hoc(self):
        provenance = transition_analysis.analysis_provenance("preregistered-secondary")

        self.assertEqual(provenance["protocol_status"], "preregistered-secondary")
        self.assertIn("preregistered secondary", provenance["analysis"])
        self.assertNotIn("post-hoc", provenance["analysis"])
        self.assertIn("same experimental collection", provenance["limitations"])

    def test_post_hoc_provenance_remains_explicit(self):
        provenance = transition_analysis.analysis_provenance("post-hoc")

        self.assertEqual(provenance["protocol_status"], "post-hoc")
        self.assertIn("post-hoc", provenance["analysis"])

    def test_unknown_protocol_status_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "protocol status"):
            transition_analysis.analysis_provenance("preregistered")

    def test_previous_visible_tag_predicts_correlated_next_label(self):
        profile_rows = []
        profile_labels = []
        for session_id in range(4):
            tags = [10] * 20 + [20] * 20 + [10] * 20 + [20] * 20
            profile_rows.extend(rows_for(f"profile-{session_id}", tags))
            profile_labels.extend(int(tag == 10) for tag in tags)

        attack = MarkovTransitionAttack().fit(profile_rows, profile_labels)
        target_rows = rows_for("target", [10, 10, 20, 20])
        predictions, scores = attack.run(target_rows, {"target"})

        self.assertGreater(scores[1], 0.5)
        self.assertLess(scores[3], 0.5)
        self.assertEqual(predictions[1], 1)
        self.assertEqual(predictions[3], 0)

    def test_profile_and_target_sessions_must_be_disjoint(self):
        rows = rows_for("same", [10, 10, 20, 20])
        attack = MarkovTransitionAttack().fit(rows, [1, 1, 0, 0])

        with self.assertRaisesRegex(ValueError, "disjoint"):
            attack.run(rows, {"same"})

    def test_noncontiguous_profile_steps_are_rejected(self):
        rows = rows_for("profile", [10, 20, 10])
        rows[1]["step"] = 2

        with self.assertRaisesRegex(ValueError, "contiguous"):
            MarkovTransitionAttack().fit(rows, [1, 0, 1])


if __name__ == "__main__":
    unittest.main()
