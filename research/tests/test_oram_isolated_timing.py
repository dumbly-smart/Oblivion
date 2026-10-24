"""Isolated server timing is captured at the bucket-service boundary."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class IsolatedOramTimingTests(unittest.TestCase):
    def test_real_oram_uses_a_separate_fixed_shape_bucket_process(self):
        root = Path(__file__).resolve().parents[2]
        binary = Path(os.environ.get("ORAM_MEASURE_BINARY", root / "target/release/examples/oram-measure"))
        self.assertTrue(binary.is_file(), "build --example oram-measure or set ORAM_MEASURE_BINARY")
        config = {
            "version": 1,
            "blocks": 32,
            "bucket_capacity": 4,
            "block_bytes": 64,
            "operations": 32,
            "warmup": 2,
            "trials": 1,
            "seed": 4501,
            "workload": "uniform",
            "backend": "isolated_process",
        }
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            cfg = base / "config.json"
            cfg.write_text(json.dumps(config))
            output = base / "trial"
            result = subprocess.run([str(binary), str(cfg), str(output)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            meta = json.loads((output / "isolated-service.json").read_text())
            rows = [json.loads(line) for line in (output / "isolated-observer-0.jsonl").read_text().splitlines()]
            private = [json.loads(line) for line in (output / "private-0.jsonl").read_text().splitlines()]
            per_access = 2 * meta["path_buckets"]
            self.assertNotEqual(meta["worker_pid"], meta["controller_pid"])
            self.assertNotEqual(meta["worker_pid"], os.getpid())
            self.assertEqual(meta["request_bytes"], meta["response_bytes"])
            self.assertEqual(len(rows), config["operations"] * per_access)
            self.assertEqual(len(private), config["operations"])
            for step in range(config["operations"]):
                access = [row for row in rows if row["step"] == step]
                self.assertEqual(len(access), per_access)
                self.assertEqual([r["direction"] for r in access], ["read"] * meta["path_buckets"] + ["write"] * meta["path_buckets"])
                self.assertEqual([r["bucket"] for r in access[:meta["path_buckets"]]],
                                 [r["bucket"] for r in access[meta["path_buckets"]:]])
                self.assertTrue(all(type(row["service_ns"]) is int and row["service_ns"] > 0 for row in access))
                self.assertTrue(all(row["bytes"] == meta["bucket_bytes"] for row in access))
                self.assertNotIn("logical_address", access[0])
                self.assertNotIn("write", access[0])
                if not private[step]["write"]:
                    self.assertTrue(private[step]["oracle_verified"])
                else:
                    self.assertFalse(private[step]["oracle_verified"])

    def test_fresh_skewed_workload_has_plaintext_and_encrypted_positive_controls(self):
        root = Path(__file__).resolve().parents[2]
        binary = Path(os.environ.get("ORAM_MEASURE_BINARY", root / "target/release/examples/oram-measure"))
        self.assertTrue(binary.is_file())
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            backend = "isolated_process"
            config = {
                    "version": 1, "blocks": 32, "bucket_capacity": 4,
                    "block_bytes": 64, "operations": 64, "warmup": 2,
                    "trials": 1, "seed": 88013, "workload": "two_record_skewed",
                    "backend": backend,
            }
            cfg = base / f"{backend}.json"
            cfg.write_text(json.dumps(config))
            output = base / backend
            result = subprocess.run([str(binary), str(cfg), str(output)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = [json.loads(line) for line in
                    (output / "isolated-observer-0.jsonl").read_text().splitlines()]
            labels = [json.loads(line)["logical_address"] for line in
                      (output / "private-0.jsonl").read_text().splitlines()]
            self.assertGreater(sum(label == 0 for label in labels), sum(label == 1 for label in labels))
            events_per_access = len(rows) // config["operations"]
            self.assertEqual(len(rows) % config["operations"], 0)
            for step in range(config["operations"]):
                access = [row for row in rows if row["step"] == step]
                self.assertEqual(len(access), events_per_access)
                self.assertEqual([row["direction"] for row in access],
                                 ["read"] * (events_per_access // 2) + ["write"] * (events_per_access // 2))
                self.assertTrue(all(row["service_ns"] > 0 for row in access))
                self.assertTrue(all("logical_address" not in row for row in access))

    def test_plaintext_and_encrypt_only_controls_use_same_fixed_access_shape(self):
        root = Path(__file__).resolve().parents[2]
        binary = Path(os.environ.get("ORAM_CONTROL_BINARY", root / "target/release/examples/oram-control"))
        self.assertTrue(binary.is_file(), "build --example oram-control or set ORAM_CONTROL_BINARY")
        config = {
            "version": 1, "blocks": 32, "bucket_capacity": 4, "block_bytes": 64,
            "operations": 64, "warmup": 2, "trials": 1, "seed": 20491,
            "workload": "two_record_skewed",
        }
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            metadatas = []
            for mode in ("plaintext", "encrypt_only"):
                cfg = base / f"{mode}.json"
                cfg.write_text(json.dumps(config))
                output = base / mode
                result = subprocess.run([str(binary), mode, str(cfg), str(output)],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                metadata = json.loads((output / "isolated-service.json").read_text())
                metadatas.append(metadata)
                rows = [json.loads(line) for line in
                        (output / "isolated-observer-0.jsonl").read_text().splitlines()]
                private = [json.loads(line) for line in
                           (output / "private-0.jsonl").read_text().splitlines()]
                self.assertEqual(len(rows), 2 * config["operations"])
                self.assertEqual(len(private), config["operations"])
                self.assertGreater(sum(row["logical_address"] == 0 for row in private),
                                   sum(row["logical_address"] == 1 for row in private))
                for step in range(config["operations"]):
                    access = [row for row in rows if row["step"] == step]
                    self.assertEqual([row["direction"] for row in access], ["read", "write"])
                    self.assertEqual(access[0]["bucket"], access[1]["bucket"])
                    self.assertTrue(all(row["service_ns"] > 0 for row in access))
                self.assertTrue(all(row["oracle_verified"] for row in private if not row["write"]))
            self.assertEqual(metadatas[0]["request_bytes"], metadatas[1]["request_bytes"])
            self.assertEqual(metadatas[0]["response_bytes"], metadatas[1]["response_bytes"])


if __name__ == "__main__":
    unittest.main()
