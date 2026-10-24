import gzip
import json
from dataclasses import asdict
from pathlib import Path
import tempfile
import unittest

from research.analysis.scaler_likelihood import evaluate
from research.simulation.scaler import Config, Request, simulate


class ScalerLikelihoodAnalysisTests(unittest.TestCase):
    def source(self, root, distinguishable_profiles=True):
        cfg = Config(duration=2, epoch=1, low_rate=1, high_rate=4)
        raw_config = {
            "version": 1, "seed": 81, "trials": 1, "sessions": 4,
            "workloads": ["zipf"], "policies": ["naive", "dp_laplace"],
            "dp_noise_source": "os_csprng", "simulation": asdict(cfg),
        }
        (root / "config.json").write_text(json.dumps(raw_config))
        observers = []
        truths = []
        session_classes = [(0, 0), (1, 1), (0, 0), (1, 1)]
        for session_id, (intensity, hot) in enumerate(session_classes):
            requests = []
            for epoch in range(2):
                count = 1 + 3 * intensity
                if not distinguishable_profiles and session_id < 2:
                    count = 2
                for index in range(count):
                    requests.append(asdict(Request(
                        time=epoch + .1 + .01 * index,
                        function=(0 if not distinguishable_profiles and session_id < 2
                                  else hot),
                        user_id=f"u-{session_id}-{index}",
                    )))
            labels = [
                {"epoch": epoch, "intensity": intensity, "hot": hot,
                 "arrivals": sum(1 for request in requests
                                 if int(request["time"]) == epoch),
                 "rate": float(1 + 3 * intensity)}
                for epoch in range(2)
            ]
            typed_requests = [Request(**request) for request in requests]
            for policy in ("naive", "dp_laplace"):
                result = simulate(
                    cfg, typed_requests, policy, 900 + session_id,
                    dp_noise_source="os_csprng",
                )
                observers.append({"trial": 0, "session": session_id,
                    "workload": "zipf", "policy": policy,
                    "rows": result["observer"]})
            truths.append({"trial": 0, "session": session_id,
                "workload": "zipf", "seed": 100 + session_id,
                "labels": labels, "requests": requests})
        for name, rows in (("observer.jsonl.gz", observers),
                           ("workloads-private.jsonl.gz", truths)):
            with gzip.open(root / name, "wt", encoding="utf-8") as stream:
                for row in rows:
                    stream.write(json.dumps(row) + "\n")
        return cfg

    @staticmethod
    def study_config(positive_control_min=0.6):
        return {
            "version": 1, "study_id": "unit-likelihood-fixture",
            "dp_noise_source": "os_csprng", "trials": 1, "sessions": 4,
            "profile_sessions": 2, "target_sessions": 2,
            "tasks": ["intensity", "hot"], "particles": 256,
            "sampler_seed": 3301, "primary_metric": "balanced_accuracy",
            "positive_control_min": positive_control_min,
        }

    def test_evaluator_runs_plaintext_control_before_dp_likelihood(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "raw"
            source.mkdir()
            self.source(source)
            config = root / "study.json"
            config.write_text(json.dumps(self.study_config()))

            report = evaluate(source, root / "analysis", config)

            self.assertTrue(report["positive_controls_passed"])
            self.assertEqual({row["policy"] for row in report["summary"]},
                             {"plaintext_counts", "dp_laplace"})
            self.assertTrue(all(row["passed"] for row in report["positive_controls"]))
            predictions = json.loads((root / "analysis/predictions.json").read_text())
            self.assertTrue(all("prediction" in row for row in predictions))
            self.assertGreater((root / "analysis/balanced-accuracy.png").stat().st_size,
                               1000)
            self.assertEqual(report["particle_filter_health"]["nonfinite_class_scores"], 0)

    def test_failed_positive_control_prevents_dp_scoring(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "raw"
            source.mkdir()
            self.source(source, distinguishable_profiles=False)
            config = root / "study.json"
            config.write_text(json.dumps(self.study_config()))

            report = evaluate(source, root / "analysis", config)

            self.assertFalse(report["positive_controls_passed"])
            self.assertFalse(report["dp_policy_evaluated"])
            self.assertEqual({row["policy"] for row in report["summary"]},
                             {"plaintext_counts"})


if __name__ == "__main__":
    unittest.main()
