import gzip
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from research.analysis.verify_oram_isolated_bundle import verify_bundle


MODES = ("plaintext", "encrypt_only", "oram")


def write_jsonl_gzip(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True) + "\n")


def build_bundle(root):
    config = {
        "version": 1,
        "blocks": 4,
        "bucket_capacity": 4,
        "block_bytes": 64,
        "operations": 2,
        "warmup": 0,
        "sessions_per_trial": 2,
        "trials": 1,
        "seed": 7,
        "hot_addresses": [0],
        "service_cpu_affinity": 0,
        "primary_metric": "roc_auc",
        "positive_control_min_mean_auc": 0.8,
        "positive_control_ci_lower_must_exceed": 0.5,
    }
    (root / "config.json").write_text(json.dumps(config))
    raw_hashes = {}
    process_metadata = {}
    trials = []
    summary = []
    for mode in MODES:
        process_metadata[mode] = []
        predictions_dir = root / "predictions" / mode
        predictions_dir.mkdir(parents=True, exist_ok=True)
        (predictions_dir / "trial-00.json.gz").write_bytes(b"")
        prediction_path = predictions_dir / "trial-00.json.gz"
        with gzip.open(prediction_path, "wt", encoding="utf-8") as stream:
            json.dump({
                "target_sessions": [f"{mode}-trial-00-session-01"],
                "predictions": [1, 0],
                "scores_uncalibrated": [0.8, 0.2],
            }, stream)

        for session in range(2):
            driver_rows = [
                {"step": 0, "logical_address": 0, "write": False,
                 "oracle_verified": True, "latency_ns": 100},
                {"step": 1, "logical_address": 1, "write": True,
                 "oracle_verified": False, "latency_ns": 120},
            ]
            path_buckets = 2 if mode == "oram" else 1
            buckets = ([3, 4] if mode == "oram" else [0])
            events = []
            for step, private in enumerate(driver_rows):
                logical_bucket = private["logical_address"] if mode != "oram" else buckets
                path = logical_bucket if isinstance(logical_bucket, list) else [logical_bucket]
                for direction in ("read", "write"):
                    for bucket in path:
                        events.append({"step": step, "direction": direction,
                                       "bucket": bucket, "bytes": 316,
                                       "service_ns": 20 + step})
            trial_dir = root / "raw" / mode / "trial-00"
            driver_path = trial_dir / f"driver-{session:02}.jsonl.gz"
            observer_path = trial_dir / f"observer-{session:02}.jsonl.gz"
            write_jsonl_gzip(driver_path, driver_rows)
            write_jsonl_gzip(observer_path, events)
            for path in (driver_path, observer_path):
                relative = path.relative_to(root).as_posix()
                raw_hashes[relative] = hashlib.sha256(path.read_bytes()).hexdigest()

            process_metadata[mode].append({
                "trial": session,
                "controller_pid": 200 + session,
                "worker_pid": 100 + session,
                "request_bytes": 128,
                "response_bytes": 128,
                "bucket_bytes": 316,
                "service_cpu_affinity": 0,
                "service_allowed_cpus": "0",
                **({"events_per_access": 2} if mode != "oram" else {}),
                **({"path_buckets": path_buckets} if mode == "oram" else {}),
            })

        profile_sessions = [f"{mode}-trial-00-session-00"]
        target_sessions = [f"{mode}-trial-00-session-01"]
        trials.append({"mode": mode, "trial": 0, "profile_sessions": profile_sessions,
                       "target_sessions": target_sessions, "observations": 2,
                       "accuracy": 1.0, "balanced_accuracy": 1.0, "auc": 1.0})
        summary.append({"mode": mode, "trials": 1, "auc_mean": 1.0,
                        "auc_ci95_trials": [1.0, 1.0]})

    report = {
        "configuration": config,
        "positive_controls_passed": True,
        "raw_session_sha256": raw_hashes,
        "process_metadata": process_metadata,
        "trials": trials,
        "summary": summary,
    }
    (root / "report.json").write_text(json.dumps(report))
    return report


class IsolatedOramBundleVerifierTests(unittest.TestCase):
    def test_verifies_hashes_paired_schedules_shapes_and_trial_metrics(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_bundle(root)

            result = verify_bundle(root)

            self.assertEqual(result["raw_files_verified"], 12)
            self.assertEqual(result["paired_schedules_verified"], 2)
            self.assertEqual(result["service_process_records"], 6)
            self.assertTrue(result["positive_controls_passed"])

    def test_rejects_unpaired_schedule_even_when_its_hash_matches(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = build_bundle(root)
            changed = root / "raw/encrypt_only/trial-00/driver-00.jsonl.gz"
            write_jsonl_gzip(changed, [
                {"step": 0, "logical_address": 1, "write": False,
                 "oracle_verified": True, "latency_ns": 100},
                {"step": 1, "logical_address": 1, "write": True,
                 "oracle_verified": False, "latency_ns": 120},
            ])
            report["raw_session_sha256"][changed.relative_to(root).as_posix()] = (
                hashlib.sha256(changed.read_bytes()).hexdigest()
            )
            (root / "report.json").write_text(json.dumps(report))

            with self.assertRaisesRegex(ValueError, "paired workload schedules"):
                verify_bundle(root)

    def test_rejects_raw_file_changed_after_collection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_bundle(root)
            path = root / "raw/plaintext/trial-00/observer-00.jsonl.gz"
            path.write_bytes(path.read_bytes() + b"tamper")

            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                verify_bundle(root)

    def test_rejects_bootstrap_interval_not_recomputed_from_trial_scores(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = build_bundle(root)
            next(row for row in report["summary"] if row["mode"] == "oram")[
                "auc_ci95_trials"
            ] = [0.9, 1.0]
            (root / "report.json").write_text(json.dumps(report))

            with self.assertRaisesRegex(ValueError, "bootstrap interval"):
                verify_bundle(root)

    def test_rejects_malformed_observer_event_without_crashing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = build_bundle(root)
            path = root / "raw/plaintext/trial-00/observer-00.jsonl.gz"
            with gzip.open(path, "rt", encoding="utf-8") as stream:
                events = [json.loads(line) for line in stream]
            events[1] = None
            write_jsonl_gzip(path, events)
            report["raw_session_sha256"][path.relative_to(root).as_posix()] = (
                hashlib.sha256(path.read_bytes()).hexdigest()
            )
            (root / "report.json").write_text(json.dumps(report))

            with self.assertRaisesRegex(ValueError, "malformed observer event"):
                verify_bundle(root)

    def test_rejects_frame_shape_changing_between_service_processes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = build_bundle(root)
            record = report["process_metadata"]["oram"][0]
            record["request_bytes"] = 129
            record["response_bytes"] = 129
            (root / "report.json").write_text(json.dumps(report))

            with self.assertRaisesRegex(ValueError, "fixed frame shape"):
                verify_bundle(root)


if __name__ == "__main__":
    unittest.main()
