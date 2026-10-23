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


if __name__ == "__main__":
    unittest.main()
