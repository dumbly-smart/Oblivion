import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import numpy as np
from research.analysis.execution_timing import Centroid, interval, score, vector


class TimingTests(unittest.TestCase):
    def test_multiclass_control_and_balanced_scoring(self):
        labels = list(range(8)) * 2
        x = [[.1, 164, 164, 128, 40448, label] for label in labels]
        model = Centroid().fit(x, labels)
        self.assertEqual(score(model.rank(x), labels)["accuracy"], 1)
        self.assertEqual(score(model.rank(x), labels)["top3"], 1)
        self.assertEqual(interval([.125] * 30)["trial_bootstrap_95"], [.125, .125])

    def test_observer_rejects_label_fields(self):
        row = dict(version=1, step=0, response_ns=100, request_bytes=164, response_bytes=164, request_ciphertext=[], response_ciphertext=[], storage=[], visible_selector=None)
        self.assertEqual(len(vector(row)), 6)
        with self.assertRaises(ValueError):
            vector({**row, "class": 4})

    @unittest.skipUnless(os.environ.get("EXEC_TIMING_BINARY"), "set EXEC_TIMING_BINARY for actual Rust smoke")
    def test_actual_rust_eight_class_smoke(self):
        binary = str(Path(os.environ["EXEC_TIMING_BINARY"]).resolve())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "session"
            subprocess.run([binary, str(path), "17", "protected"], check=True, timeout=15)
            observer = [json.loads(x) for x in (path / "observer.jsonl").read_text().splitlines()]
            truth = [json.loads(x) for x in (path / "ground-truth.jsonl").read_text().splitlines()]
            self.assertEqual(sorted(x["class"] for x in truth), list(range(8)))
            for row in observer:
                self.assertEqual(row["request_bytes"], 228)
                self.assertEqual(row["response_bytes"], 228)
                self.assertEqual(len(row["storage"]), 128)
                self.assertIsNone(row["visible_selector"])
                self.assertGreaterEqual(row["response_ns"], 100_000_000)
            self.assertTrue(all(x["oracle_passed"] for x in truth))


if __name__ == "__main__":
    unittest.main()
