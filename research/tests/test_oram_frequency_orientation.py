import unittest

from research.analysis.oram_frequency_orientation import (
    orientation_from_validation,
    select_profile_orientation,
)


def profile_rows(session_count=4):
    rows = []
    labels = []
    for session in range(session_count):
        rows.extend([
            {"session": session, "step": 0, "tag": 10 + session * 10,
             "bytes": 32, "latency_ns": 10},
            {"session": session, "step": 1, "tag": 11 + session * 10,
             "bytes": 32, "latency_ns": 12},
            {"session": session, "step": 2, "tag": 12 + session * 10,
             "bytes": 32, "latency_ns": 11},
            {"session": session, "step": 3, "tag": 13 + session * 10,
             "bytes": 32, "latency_ns": 13},
        ])
        labels.extend([0, 0, 1, 1])
    return rows, labels


class FrequencyOrientationTests(unittest.TestCase):
    def test_profile_only_cross_validation_defaults_on_uninformative_tags(self):
        rows, labels = profile_rows()
        selected = select_profile_orientation(rows, labels)
        self.assertEqual(selected.sign, 1)
        self.assertAlmostEqual(selected.validation_auc, 0.5)
        self.assertEqual(selected.validation_sessions, 4)
        self.assertEqual(selected.validation_observations, len(rows))

    def test_orientation_helper_can_detect_reversed_profile_score_direction(self):
        selected = orientation_from_validation([0, 0, 1, 1], [0.9, 0.8, 0.2, 0.1])
        self.assertEqual(selected.sign, -1)
        self.assertEqual(selected.validation_auc, 0.0)

    def test_single_class_or_misaligned_profile_validation_fails_closed(self):
        rows, labels = profile_rows()
        with self.assertRaises(ValueError):
            select_profile_orientation(rows, labels[:-1])
        with self.assertRaises(ValueError):
            orientation_from_validation([1, 1], [0.2, 0.8])

    def test_non_finite_validation_score_fails_closed(self):
        with self.assertRaises(ValueError):
            orientation_from_validation([0, 1], [0.1, float("nan")])


if __name__ == "__main__":
    unittest.main()
