import gzip
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from research.attacks.sse import CountVolumeAttack, SearchPatternFrequencyAttack
from research.analysis.sse import cluster_interval, make_workload, metrics, read_observations, update_order


class SSEAttacks(unittest.TestCase):
    def test_count_positive_control_and_unknown_truth_not_needed(self):
        observations = [{"tag": "a", "count": 7}, {"tag": "b", "count": 19}]
        ranks = CountVolumeAttack().run(observations, {"counts": [19, 7]}, seed=4)
        self.assertEqual([r[0] for r in ranks], [1, 0])

    def test_padding_knowledge_removes_count_distance(self):
        attack = CountVolumeAttack()
        auxiliary = {"counts": [5, 8, 90]}
        a = attack.run([{"count": 96}] * 30, auxiliary, seed=17, pad_to=96)
        b = attack.run([{"count": 111}] * 30, auxiliary, seed=17, pad_to=96)
        self.assertEqual(a, b)
        self.assertEqual(set(r[0] for r in a), {0, 1, 2})

    def test_padded_count_attack_uses_known_majority_prior(self):
        ranks = CountVolumeAttack().run([{ "count": 96 }] * 10, {"counts": [5, 9], "query_counts": [2, 8]}, pad_to=96)
        self.assertEqual([r[0] for r in ranks], [1] * 10)

    def test_frequency_can_recover_even_when_counts_are_equal(self):
        observed = [{"tag": "x", "count": 96}] * 40 + [{"tag": "y", "count": 96}] * 10
        ranks = SearchPatternFrequencyAttack().run(observed, {"counts": [96, 96], "query_counts": [10, 40]})
        self.assertEqual([r[0] for r in ranks], [1] * 40 + [0] * 10)

    def test_clusters_and_metrics(self):
        self.assertEqual(cluster_interval([0, 1]), [0.0, 1.0])
        result = metrics([[0, 1], [0, 1], [1, 0]], [0, 0, 1], 2, 0)
        self.assertEqual(result["balanced_accuracy"], 1)
        self.assertAlmostEqual(result["majority_accuracy"], 2/3)
        with self.assertRaises(ValueError):
            metrics([], [1], 2, 0)

    def test_independent_seeded_corpora_and_whole_sessions(self):
        config = json.loads(Path("experiments/configs/sse-attacks.json").read_text())
        auxiliary, truth = make_workload(config, 3)
        self.assertEqual((auxiliary, truth), make_workload(config, 3))
        self.assertNotEqual(auxiliary["counts"], truth["target_counts"])
        self.assertEqual(len(truth["target_sessions"]), 2)
        self.assertEqual(len(auxiliary["profile_labels"]), 2048)
        self.assertFalse(set(auxiliary) & {"target_counts", "target_sessions"})

    def test_real_sse_dummy_postings_and_client_verification(self):
        binary = Path("target/release/examples/leakage")
        self.assertTrue(binary.is_file(), "build the release leakage example first")
        workload = {"counts": [2, 5], "queries": [[0, 1, 0]], "pad_to": 8,
                    "update_order": update_order([8, 8], 17)}
        result = subprocess.run([str(binary)], input=json.dumps(workload), capture_output=True, text=True, check=True)
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(sum(r["op"] == "add" for r in rows), 16)
        searches = [r for r in rows if r["op"] == "search"]
        self.assertEqual([len(r["response"]["entries"]) for r in searches], [8, 8, 8])
        self.assertEqual(searches[0]["request"]["tag"], searches[2]["request"]["tag"])
        self.assertNotEqual(searches[0]["request"]["tag"], searches[1]["request"]["tag"])
        for row in rows:
            self.assertFalse(set(row) & {"keyword", "label", "id", "real_count", "dummy"})
        for row in searches:
            self.assertTrue(all(len(e["ciphertext"]) == 24 for e in row["response"]["entries"]))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "observer.jsonl.gz"
            with gzip.open(path, "wt") as stream:
                stream.write(result.stdout)
            sessions, updates = read_observations(path)
            self.assertEqual(updates, 16)
            self.assertEqual([r["count"] for r in sessions[0]], [8, 8, 8])

    def test_real_sse_rejects_underpadding(self):
        workload = {"counts": [5], "queries": [[0]], "pad_to": 4, "update_order": [[0, 0]]}
        result = subprocess.run(["target/release/examples/leakage"], input=json.dumps(workload), capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid padding", result.stderr)


if __name__ == "__main__":
    unittest.main()
