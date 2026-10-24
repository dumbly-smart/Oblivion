"""Schema, observer boundary and session-split tests for ORAM timing replication."""
import unittest

from research.analysis import oram_isolated_replication as study


class IsolatedTraceTests(unittest.TestCase):
    def test_path_events_collapse_to_one_observer_row_per_logical_access(self):
        events = [
            {"step": 0, "direction": "read", "bucket": 0, "bytes": 128, "service_ns": 8},
            {"step": 0, "direction": "read", "bucket": 1, "bytes": 128, "service_ns": 9},
            {"step": 0, "direction": "read", "bucket": 3, "bytes": 128, "service_ns": 10},
            {"step": 0, "direction": "write", "bucket": 0, "bytes": 128, "service_ns": 7},
            {"step": 0, "direction": "write", "bucket": 1, "bytes": 128, "service_ns": 8},
            {"step": 0, "direction": "write", "bucket": 3, "bytes": 128, "service_ns": 10},
        ]
        private = [{"step": 0, "logical_address": 0, "write": False,
                    "oracle_verified": True, "latency_ns": 4, "stash": 0}]
        rows, labels = study.collapse_accesses("session-a", events, private)
        self.assertEqual(rows, [{
            "session": "session-a", "step": 0, "tag": 3, "bytes": 768, "latency_ns": 52,
        }])
        self.assertEqual(labels, [1])
        self.assertNotIn("logical_address", rows[0])

    def test_fixed_shape_direct_control_collapses_to_one_row(self):
        events = [
            {"step": 0, "direction": "read", "bucket": 1, "bytes": 128, "service_ns": 11},
            {"step": 0, "direction": "write", "bucket": 1, "bytes": 128, "service_ns": 13},
        ]
        private = [{"step": 0, "logical_address": 1, "write": True,
                    "oracle_verified": False, "latency_ns": 4}]
        rows, labels = study.collapse_accesses("session-b", events, private)
        self.assertEqual(rows[0]["tag"], 1)
        self.assertEqual(rows[0]["bytes"], 256)
        self.assertEqual(rows[0]["latency_ns"], 24)
        self.assertEqual(labels, [0])

    def test_malformed_paths_and_label_shape_are_rejected(self):
        events = [
            {"step": 0, "direction": "read", "bucket": 1, "bytes": 128, "service_ns": 10},
            {"step": 0, "direction": "write", "bucket": 2, "bytes": 128, "service_ns": 10},
        ]
        private = [{"step": 0, "logical_address": 1, "write": False,
                    "oracle_verified": True, "latency_ns": 4}]
        with self.assertRaises(ValueError):
            study.collapse_accesses("session-c", events, private)
        with self.assertRaises(ValueError):
            study.collapse_accesses("session-c", events, private[:0])

    def test_seeded_modes_must_have_identical_address_and_operation_schedules(self):
        first = [
            {"step": 0, "logical_address": 0, "write": False},
            {"step": 1, "logical_address": 1, "write": True},
        ]
        second = [dict(row) for row in first]
        self.assertIsNone(study.require_paired_schedules((first, second)))
        second[1]["logical_address"] = 0
        with self.assertRaises(ValueError):
            study.require_paired_schedules((first, second))


if __name__ == "__main__":
    unittest.main()
