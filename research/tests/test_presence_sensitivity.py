import json
import tempfile
import unittest
from pathlib import Path

from research.analysis.presence_sensitivity import evaluate, load_config


class PresenceSensitivityTests(unittest.TestCase):
    def test_evaluation_is_reproducible_session_split_and_labeled(self):
        config = {
            "schema": 1,
            "label": "synthetic explicitly labeled scenario",
            "seed": 713,
            "sessions": 36,
            "train_fraction": 0.33,
            "epochs": 24,
            "bootstrap_replicates": 200,
            "scenarios": [{
                "name": "positive_control",
                "description": "stable population, low-noise beacon, low churn, low missed-cover",
                "population": [6, 6],
                "beacon_sensitivity": 0.98,
                "beacon_false_positive": 0.02,
                "enrollment_churn": 0.02,
                "missed_cover_rate": 0.02,
                "owner_online_probability": 0.65,
            }],
            "positive_controls": ["positive_control"],
        }
        from research.analysis.presence_sensitivity import _sessions
        sessions, _, _ = _sessions(config, config["scenarios"][0], config["seed"])
        self.assertEqual(set(sessions[0]["observable"]), {"participants", "beacon"})
        self.assertNotIn("owner", sessions[0]["observable"])
        first = evaluate(config)
        second = evaluate(config)
        self.assertEqual(first, second)
        result = first["scenarios"][0]
        self.assertEqual(result["split"]["unit"], "whole independent session")
        self.assertEqual(result["split"]["train_sessions"], 12)
        self.assertEqual(result["split"]["test_sessions"], 24)
        self.assertGreater(result["attacker"]["accuracy"]["mean"], 0.5)
        self.assertTrue(first["positive_controls"][0]["lower_ci95_exceeds_uniform_random"])
        self.assertIn("simulated noisy beacon is not differential privacy", first["limitations"])

    def test_invalid_probabilities_rejected(self):
        with self.assertRaises(ValueError):
            load_config({"schema": 1, "scenarios": [{"beacon_sensitivity": 1.5}]})

    def test_cli_writes_deterministic_outputs(self):
        config = {"schema": 1, "label": "synthetic explicitly labeled", "seed": 4,
                  "sessions": 12, "train_fraction": 0.25, "epochs": 8,
                  "bootstrap_replicates": 100,
                  "scenarios": [{"name": "positive_control", "description": "tiny synthetic case",
                                 "population": [4, 4], "beacon_sensitivity": 0.9,
                                 "beacon_false_positive": 0.1, "enrollment_churn": 0.05,
                                 "missed_cover_rate": 0.1, "owner_online_probability": 0.7}]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(config))
            from research.analysis.presence_sensitivity import main
            out1, out2 = Path(directory) / "a", Path(directory) / "b"
            main(["--config", str(path), "--out", str(out1)])
            main(["--config", str(path), "--out", str(out2)])
            self.assertEqual((out1 / "summary.json").read_bytes(), (out2 / "summary.json").read_bytes())
