import hashlib
import gzip
import json
import tempfile
import unittest
from pathlib import Path

from research.analysis.oram_frequency_secondary_verifier import (
    SOURCE_FILES,
    _plan_hashes,
    _expected_raw_paths,
    compute_trial_metrics,
    _load_private_labels,
    validate_prediction_artifact,
    verify_raw_manifest,
)


class FrequencySecondaryVerifierTests(unittest.TestCase):
    def test_private_label_reader_accepts_unverified_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = (Path(directory) / "raw" / "oram" / "trial-00"
                    / "driver-00.jsonl.gz")
            path.parent.mkdir(parents=True)
            rows = [
                {"step": 0, "logical_address": 0, "write": False,
                 "oracle_verified": True},
                {"step": 1, "logical_address": 1, "write": True,
                 "oracle_verified": False},
            ]
            with gzip.open(path, "wt", encoding="utf-8") as stream:
                for row in rows:
                    stream.write(json.dumps(row) + "\n")

            labels = _load_private_labels(directory, "oram", 0, 0, {0}, 2)

            self.assertEqual(labels, [1, 0])

    def test_plan_hash_parser_preserves_inline_code_in_input_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = Path(directory) / "plan.md"
            lines = ["| Input | SHA-256 |", "| --- | --- |"]
            lines.extend(f"| `{source}` | `{index:064x}` |"
                         for index, source in enumerate(SOURCE_FILES, 1))
            lines.extend([
                f"| Rank-64 workload config | `{6:064x}` |",
                f"| Primary study `report.json` | `{7:064x}` |",
            ])
            plan.write_text("\n".join(lines) + "\n", encoding="utf-8")

            hashes = _plan_hashes(plan)

            self.assertIn("Primary study `report.json`", hashes)
            self.assertEqual(len(hashes), 6)

    def test_expected_raw_manifest_includes_each_observer_and_private_session(self):
        paths = _expected_raw_paths(("plaintext", "oram"), trials=2, sessions=4)

        self.assertEqual(len(paths), 2 * 2 * 4 * 2)
        self.assertIn("raw/oram/trial-01/observer-03.jsonl.gz", paths)
        self.assertIn("raw/plaintext/trial-00/driver-00.jsonl.gz", paths)

    def test_prediction_artifact_rejects_target_labels(self):
        artifact = {
            "target_sessions": ["oram-trial-00-session-04"],
            "orientation_sign_selected_from_profile_only": 1,
            "fixed_direction_scores": [0.1, 0.8],
            "oriented_scores": [0.1, 0.8],
            "predictions": [0, 1],
            "target_labels": [0, 1],
        }

        with self.assertRaisesRegex(ValueError, "unexpected prediction fields"):
            validate_prediction_artifact(
                artifact, ["oram-trial-00-session-04"], expected_observations=2
            )

    def test_trial_metrics_are_recomputed_from_predictions_and_private_labels(self):
        artifact = {
            "target_sessions": ["oram-trial-00-session-04"],
            "orientation_sign_selected_from_profile_only": 1,
            "fixed_direction_scores": [0.1, 0.8, 0.4, 0.9],
            "oriented_scores": [0.1, 0.8, 0.4, 0.9],
            "predictions": [0, 1, 0, 1],
        }
        validate_prediction_artifact(
            artifact, ["oram-trial-00-session-04"], expected_observations=4
        )

        metrics = compute_trial_metrics(artifact, [0, 0, 1, 1], [0, 1, 1, 1])

        self.assertAlmostEqual(metrics["auc"], 0.75)
        self.assertAlmostEqual(metrics["fixed_direction_auc"], 0.75)
        self.assertAlmostEqual(metrics["accuracy"], 0.5)
        self.assertAlmostEqual(metrics["fixed_direction_accuracy"], 0.5)
        self.assertAlmostEqual(metrics["balanced_accuracy"], 0.5)
        self.assertAlmostEqual(metrics["profile_majority_accuracy"], 0.5)
        self.assertAlmostEqual(metrics["target_majority_accuracy"], 0.5)

    def test_raw_manifest_rejects_missing_extra_or_changed_sessions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "raw" / "oram" / "trial-00" / "observer-00.jsonl.gz"
            raw.parent.mkdir(parents=True)
            raw.write_bytes(b"immutable raw session")
            rel = "raw/oram/trial-00/observer-00.jsonl.gz"
            manifest = {rel: hashlib.sha256(raw.read_bytes()).hexdigest()}

            verify_raw_manifest(root, manifest)
            raw.write_bytes(b"changed raw session")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                verify_raw_manifest(root, manifest)

            raw.write_bytes(b"immutable raw session")
            with self.assertRaisesRegex(ValueError, "manifest file set mismatch"):
                verify_raw_manifest(root, {**manifest, "raw/extra.jsonl.gz": "0" * 64})


if __name__ == "__main__":
    unittest.main()
