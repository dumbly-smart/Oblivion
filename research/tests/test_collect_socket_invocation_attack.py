import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from research.analysis import collect_socket_invocation_attack as collector
from research.analysis import invocation_context_attack as context_attack
from research.analysis.socket_invocation_attack import (
    FROZEN_CONFIG,
    StudyError,
    _positive_control_gates,
)


class SocketInvocationCollectionRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config = self.root / "config.json"
        self.config.write_text(json.dumps(FROZEN_CONFIG), encoding="utf-8")
        self.binary = self.root / "oblivion-harness"
        self.binary.write_bytes(b"test harness executable fingerprint\n")
        self.provenance_patch = patch.object(
            collector,
            "_capture_provenance",
            return_value={
                "source_commit": "test-commit",
                "source_hashes": {"test.rs": "a" * 64},
                "source_dirty_paths": [],
                "harness_binary_path": str(self.binary.resolve()),
                "binary_sha256": "b" * 64,
                "environment": {"python": "test"},
            },
        )
        self.provenance_patch.start()
        self.addCleanup(self.provenance_patch.stop)

    def tearDown(self):
        self.temporary.cleanup()

    def write_collection(self, output, modes):
        output.mkdir(parents=True)
        (output / "config.json").write_text(
            json.dumps(FROZEN_CONFIG), encoding="utf-8"
        )
        (output / "mode-selection.json").write_text(
            json.dumps({"version": 1, "modes": list(modes)}), encoding="utf-8"
        )
        for mode in modes:
            mode_directory = output / mode
            mode_directory.mkdir()
            (mode_directory / "partial-or-complete.txt").write_text(
                mode, encoding="utf-8"
            )

    @staticmethod
    def report(passed):
        auc_by_mode = {"A": 0.9, "B": 0.9 if passed else 0.69}
        metrics = {
            mode: {
                "mean_roc_auc": auc,
                "roc_auc_ci95": context_attack._bootstrap_interval(
                    [auc] * 30, 5000, 20261221
                ),
                "bootstrap_resamples": 5000,
                "per_trial": [{"roc_auc": auc} for _ in range(30)],
            }
            for mode, auc in auc_by_mode.items()
        }
        gates = _positive_control_gates(metrics)
        return {
            "version": 1,
            "phase": "positive_controls",
            "config": dict(FROZEN_CONFIG),
            "mode_selection": ["A", "B"],
            "feature_names": list(context_attack.FEATURE_NAMES),
            "positive_controls_passed": passed,
            "positive_control_gates": gates,
            "metrics_by_mode": metrics,
            "protected_scoring": (
                "not_in_control_phase" if passed else "omitted_control_failure"
            ),
            "attack": {
                "classifier": "RandomForestClassifier",
                "n_estimators": 500,
                "max_depth": 6,
                "min_samples_leaf": 2,
                "class_weight": "balanced",
                "n_jobs": 1,
                "model_seed": 20261220,
                "positive_class": 0,
                "classification_threshold": 0.5,
                "bootstrap_resamples": 5000,
                "bootstrap_seed": 20261221,
                "bootstrap_unit": "trial",
                "training_sessions": "0..1",
                "testing_sessions": "2..3",
            },
        }

    def test_failed_control_gate_never_invokes_protected_collection(self):
        calls = []

        def run_command(command, **kwargs):
            calls.append(command)
            self.write_collection(Path(command[3]), ("A", "B"))
            return subprocess.CompletedProcess(command, 0, "control collected", "")

        result = collector.run_experiment(
            self.config,
            self.binary,
            self.root / "failed-gate-bundle",
            command_runner=run_command,
            control_analyzer=lambda *args: self.report(False),
        )

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][-1], "A,B")
        self.assertEqual(result["status"], "stopped_control_failure")
        self.assertFalse(result["positive_controls_passed"])
        self.assertFalse((self.root / "failed-gate-bundle" / "protected-raw").exists())
        self.assertFalse(any(mode in result for mode in "CDEFG"))

    def test_inconsistent_or_protected_control_report_stops_before_target_collection(self):
        for case in ("protected_metrics", "lying_summary"):
            with self.subTest(case=case):
                calls = []

                def run_command(command, **kwargs):
                    calls.append(command)
                    self.write_collection(Path(command[3]), ("A", "B"))
                    return subprocess.CompletedProcess(command, 0, "controls", "")

                def invalid_analyzer(*args):
                    report = self.report(True)
                    if case == "protected_metrics":
                        report["metrics_by_mode"]["C"] = {}
                    else:
                        report["positive_controls_passed"] = False
                    return report

                result = collector.run_experiment(
                    self.config,
                    self.binary,
                    self.root / f"invalid-report-{case}",
                    command_runner=run_command,
                    control_analyzer=invalid_analyzer,
                )

                self.assertEqual(len(calls), 1)
                self.assertEqual(result["status"], "control_analysis_failed")
                self.assertEqual(result["phases"]["control_analysis"]["status"], "failed")
                self.assertFalse((self.root / f"invalid-report-{case}" / "protected-raw").exists())

    def test_passing_controls_run_protected_collection_in_a_separate_phase(self):
        calls = []

        def run_command(command, **kwargs):
            calls.append(command)
            modes = ("A", "B") if command[-1] == "A,B" else tuple("CDEFG")
            progress = json.loads(
                (Path(command[3]).parent / "experiment.json").read_text(
                    encoding="utf-8"
                )
            )
            if command[-1] == "A,B":
                self.assertEqual(progress["status"], "running_control_collection")
            else:
                self.assertEqual(progress["status"], "running_protected_collection")
                self.assertEqual(progress["phases"]["control_analysis"]["status"], "complete")
            self.write_collection(Path(command[3]), modes)
            return subprocess.CompletedProcess(command, 0, "phase collected", "")

        result = collector.run_experiment(
            self.config,
            self.binary,
            self.root / "passing-bundle",
            command_runner=run_command,
            control_analyzer=lambda *args: self.report(True),
        )

        self.assertEqual([command[-1] for command in calls], ["A,B", "C,D,E,F,G"])
        self.assertNotEqual(calls[0][3], calls[1][3])
        self.assertEqual(
            result["status"], "protected_collection_collected_pending_evaluation"
        )
        self.assertTrue(result["positive_controls_passed"])
        self.assertEqual(result["phases"]["control_collection"]["exit_code"], 0)
        self.assertEqual(result["phases"]["protected_collection"]["exit_code"], 0)
        self.assertTrue((self.root / "passing-bundle" / "control-raw-manifest.json").is_file())
        self.assertTrue((self.root / "passing-bundle" / "protected-raw-manifest.json").is_file())

    def test_failed_control_process_retains_partial_raw_files_and_stops(self):
        calls = []

        def run_command(command, **kwargs):
            calls.append(command)
            output = Path(command[3])
            output.mkdir()
            (output / "partial.txt").write_text("partial", encoding="utf-8")
            return subprocess.CompletedProcess(command, 7, "", "worker failed")

        result = collector.run_experiment(
            self.config,
            self.binary,
            self.root / "partial-bundle",
            command_runner=run_command,
            control_analyzer=lambda *args: self.fail("must not analyze a failed collection"),
        )

        self.assertEqual(len(calls), 1)
        self.assertEqual(result["status"], "control_collection_failed")
        self.assertEqual(result["phases"]["control_collection"]["exit_code"], 7)
        manifest = json.loads(
            (self.root / "partial-bundle" / "control-raw-manifest.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual([entry["path"] for entry in manifest["files"]], ["partial.txt"])
        self.assertTrue((self.root / "partial-bundle" / "control-collection.stderr.txt").is_file())

    def test_timed_out_control_process_records_partial_output_and_stops(self):
        calls = []

        def run_command(command, **kwargs):
            calls.append(command)
            output = Path(command[3])
            output.mkdir()
            (output / "partial.txt").write_text("still retained", encoding="utf-8")
            raise subprocess.TimeoutExpired(
                command,
                timeout=kwargs["timeout"],
                output="stdout before timeout",
                stderr="stderr before timeout",
            )

        result = collector.run_experiment(
            self.config,
            self.binary,
            self.root / "timeout-bundle",
            command_runner=run_command,
            control_analyzer=lambda *args: self.fail("must not analyze a timed-out collection"),
        )

        self.assertEqual(len(calls), 1)
        phase = result["phases"]["control_collection"]
        self.assertEqual(phase["status"], "timed_out")
        self.assertEqual(phase["timeout_seconds"], 3600)
        self.assertTrue((self.root / "timeout-bundle" / "control-raw" / "partial.txt").is_file())
        self.assertIn(
            "stderr before timeout",
            (self.root / "timeout-bundle" / "control-collection.stderr.txt").read_text(
                encoding="utf-8"
            ),
        )

    def test_failed_protected_process_is_preserved_as_incomplete(self):
        calls = []

        def run_command(command, **kwargs):
            calls.append(command)
            if command[-1] == "A,B":
                self.write_collection(Path(command[3]), ("A", "B"))
                return subprocess.CompletedProcess(command, 0, "controls", "")
            output = Path(command[3])
            output.mkdir()
            (output / "partial-target.txt").write_text("incomplete", encoding="utf-8")
            return subprocess.CompletedProcess(command, 9, "", "protected worker failed")

        result = collector.run_experiment(
            self.config,
            self.binary,
            self.root / "partial-target-bundle",
            command_runner=run_command,
            control_analyzer=lambda *args: self.report(True),
        )

        self.assertEqual([command[-1] for command in calls], ["A,B", "C,D,E,F,G"])
        self.assertEqual(result["status"], "protected_collection_failed")
        self.assertEqual(result["phases"]["protected_collection"]["exit_code"], 9)
        self.assertTrue(
            (self.root / "partial-target-bundle" / "protected-raw" / "partial-target.txt").is_file()
        )

    def test_existing_bundle_root_is_never_overwritten(self):
        existing = self.root / "existing"
        existing.mkdir()
        sentinel = existing / "sentinel.txt"
        sentinel.write_text("preserve", encoding="utf-8")
        calls = []

        with self.assertRaises(StudyError):
            collector.run_experiment(
                self.config,
                self.binary,
                existing,
                command_runner=lambda command, **kwargs: calls.append(command),
            )

        self.assertEqual(calls, [])
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve")

    def test_config_mismatch_fails_before_creating_a_bundle(self):
        self.config.write_text(
            json.dumps(dict(FROZEN_CONFIG, trials=29)), encoding="utf-8"
        )
        bundle = self.root / "invalid-config-bundle"
        with self.assertRaises(StudyError):
            collector.run_experiment(self.config, self.binary, bundle)
        self.assertFalse(bundle.exists())

    def test_command_and_collection_metadata_record_source_and_raw_hashes(self):
        calls = []

        def run_command(command, **kwargs):
            calls.append(command)
            self.write_collection(Path(command[3]), ("A", "B"))
            return subprocess.CompletedProcess(command, 0, "controls", "")

        with patch.object(
            collector,
            "_capture_provenance",
            return_value={
                "source_commit": "test-commit",
                "source_hashes": {"test.rs": "a" * 64},
                "source_dirty_paths": [],
                "harness_binary_path": str(self.binary.resolve()),
                "binary_sha256": "b" * 64,
                "environment": {"python": "test"},
            },
        ):
            result = collector.run_experiment(
                self.config,
                self.binary,
                self.root / "metadata-bundle",
                command_runner=run_command,
                control_analyzer=lambda *args: self.report(False),
            )

        control_phase = result["phases"]["control_collection"]
        self.assertEqual(control_phase["command"], calls[0])
        self.assertEqual(control_phase["mode_selection"], ["A", "B"])
        self.assertEqual(control_phase["status"], "complete")
        metadata = json.loads(
            (self.root / "metadata-bundle" / "experiment.json").read_text(encoding="utf-8")
        )
        self.assertEqual(metadata["provenance"]["source_commit"], "test-commit")
        self.assertEqual(
            metadata["provenance"]["harness_binary_path"], str(self.binary.resolve())
        )
        self.assertEqual(metadata["config_sha256"], collector.sha256_file(self.config))

    def test_dirty_source_refuses_collection_before_creating_the_bundle(self):
        bundle = self.root / "dirty-source-bundle"
        with patch.object(
            collector,
            "_capture_provenance",
            return_value={"source_dirty_paths": ["research/changed.py"]},
        ):
            with self.assertRaises(StudyError):
                collector.run_experiment(self.config, self.binary, bundle)
        self.assertFalse(bundle.exists())


if __name__ == "__main__":
    unittest.main()
