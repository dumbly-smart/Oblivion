"""Schema, observer boundary and session-split tests for ORAM timing replication."""
import json
from datetime import datetime
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from research.analysis import oram_isolated_replication as study


class IsolatedTraceTests(unittest.TestCase):
    def test_cpu_affinity_configuration_requires_a_nonnegative_integer_or_null(self):
        for valid in (None, 0, 23):
            study.validate_service_cpu_affinity(valid)
        for invalid in (-1, True, 1.0, "2"):
            with self.assertRaises(ValueError):
                study.validate_service_cpu_affinity(invalid)

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
        self.assertIsNone(study.require_paired_schedules((first, second), address_count=8))
        second[1]["logical_address"] = 0
        with self.assertRaises(ValueError):
            study.require_paired_schedules((first, second), address_count=8)

    def test_larger_address_universe_maps_only_configured_hot_set_to_label(self):
        events = [
            {"step": 0, "direction": "read", "bucket": 1, "bytes": 128, "service_ns": 11},
            {"step": 0, "direction": "write", "bucket": 1, "bytes": 128, "service_ns": 13},
        ]
        private = [{"step": 0, "logical_address": 7, "write": True,
                    "oracle_verified": False, "latency_ns": 4}]
        rows, labels = study.collapse_accesses("session-eight", events, private, hot_addresses=[0, 1])
        self.assertEqual(labels, [0])
        self.assertEqual(set(rows[0]), {"session", "step", "tag", "bytes", "latency_ns"})
        private[0]["logical_address"] = 1
        rows, labels = study.collapse_accesses("session-eight", events, private, hot_addresses=[0, 1])
        self.assertEqual(labels, [1])

    def test_schedule_domain_is_bounded_by_declared_address_universe(self):
        schedule = [{"step": 0, "logical_address": 7, "write": False}]
        self.assertEqual(study.workload_signature(schedule, address_count=8), ((0, 7, False),))
        with self.assertRaises(ValueError):
            study.workload_signature(schedule, address_count=4)

    def test_host_context_is_saved_before_and_after_a_failed_mode_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            observation = {"run_start": study.host_snapshot(), "modes": {}}
            observation_path = base / "host-observation.json"
            with patch.object(study, "capture_mode", side_effect=RuntimeError("capture failed")):
                with self.assertRaisesRegex(RuntimeError, "capture failed"):
                    study.capture_mode_with_host_observation(
                        "oram", {}, {}, base, base, observation, observation_path,
                    )
            saved = json.loads(observation_path.read_text())
            mode = saved["modes"]["oram"]
            self.assertIsNotNone(datetime.fromisoformat(mode["before"]["observed_at_utc"]))
            self.assertIsNotNone(datetime.fromisoformat(mode["after"]["observed_at_utc"]))
            self.assertIn("cpu_model", mode["before"])
            self.assertIn("logical_cpu_count", mode["before"])
            self.assertIn("process_allowed_cpus", mode["before"])
            self.assertIn("load_average_1_5_15", mode["before"])


if __name__ == "__main__":
    unittest.main()
