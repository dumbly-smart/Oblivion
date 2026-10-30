"""Privacy boundaries and metric checks for long batcher population runs."""
import unittest

from research.analysis import population_sweep as study


class PopulationSweepTests(unittest.TestCase):
    def test_observer_export_removes_real_dummy_ground_truth(self):
        rows = [
            {"type": "arrival", "epoch": 0, "slot": 0, "planned_ns": 0,
             "arrived_ns": 1, "emitted_ns": 10, "queue_wait_ns": 9,
             "arrival_late_ns": 1, "real": True, "frame_bytes": 164},
            {"type": "emission", "epoch": 0, "due_ns": 10, "emitted_ns": 10,
             "late_ns": 0, "frames": 1, "dummy_frames": 0,
             "frame_bytes": 164, "batch_bytes": 164},
        ]
        visible, private = study.separate_observer_and_private(rows)
        self.assertNotIn("real", visible[0])
        self.assertNotIn("planned_ns", visible[0])
        self.assertNotIn("arrival_late_ns", visible[0])
        self.assertNotIn("dummy_frames", visible[1])
        self.assertEqual(private[0]["real"], True)
        self.assertEqual(private[0]["planned_ns"], 0)
        self.assertEqual(private[1]["dummy_frames"], 0)

    def test_trial_metrics_use_actual_arrivals_and_emissions(self):
        rows = [
            {"type": "arrival", "epoch": 0, "slot": 0, "planned_ns": 0,
             "arrived_ns": 2, "emitted_ns": 12, "queue_wait_ns": 10,
             "arrival_late_ns": 2, "real": True, "frame_bytes": 164},
            {"type": "arrival", "epoch": 0, "slot": 1, "planned_ns": 1,
             "arrived_ns": 3, "emitted_ns": 12, "queue_wait_ns": 9,
             "arrival_late_ns": 2, "real": False, "frame_bytes": 164},
            {"type": "emission", "epoch": 0, "due_ns": 10, "emitted_ns": 12,
             "late_ns": 2, "frames": 2, "dummy_frames": 1,
             "frame_bytes": 164, "batch_bytes": 328},
        ]
        visible, private = study.separate_observer_and_private(rows)
        self.assertNotIn("planned_ns", visible[0])
        summary = study.analyze_trial(visible, private, participants=2, period_ms=10)
        self.assertEqual(summary["frames"], 2)
        self.assertEqual(summary["real_frames"], 1)
        self.assertEqual(summary["dummy_frames"], 1)
        self.assertEqual(summary["fixed_frame_bytes"], 164)
        self.assertEqual(summary["batch_bytes"], 328)
        self.assertEqual(summary["queue_wait_p50_ns"], 9)
        self.assertEqual(summary["emission_late_p95_ns"], 2)

    def test_population_config_is_bounded_and_repeated(self):
        valid = {"seed": 10, "trials": 30, "period_ms": 10, "epochs": 100,
                 "real_percent": 50, "participants": [1, 8, 32, 64]}
        self.assertIsNone(study.validate_config(valid))
        invalid = dict(valid, participants=[1, 128])
        with self.assertRaises(ValueError):
            study.validate_config(invalid)

    def test_private_labels_must_align_with_observer_slots(self):
        rows = [
            {"type": "arrival", "epoch": 0, "slot": 0, "planned_ns": 0,
             "arrived_ns": 2, "emitted_ns": 12, "queue_wait_ns": 10,
             "arrival_late_ns": 2, "real": True, "frame_bytes": 164},
            {"type": "arrival", "epoch": 0, "slot": 1, "planned_ns": 1,
             "arrived_ns": 3, "emitted_ns": 12, "queue_wait_ns": 9,
             "arrival_late_ns": 2, "real": False, "frame_bytes": 164},
            {"type": "emission", "epoch": 0, "due_ns": 10, "emitted_ns": 12,
             "late_ns": 2, "frames": 2, "dummy_frames": 1,
             "frame_bytes": 164, "batch_bytes": 328},
        ]
        visible, private = study.separate_observer_and_private(rows)
        private[0]["slot"] = 7
        with self.assertRaises(ValueError):
            study.analyze_trial(visible, private, participants=2, period_ms=10)


if __name__ == "__main__":
    unittest.main()
