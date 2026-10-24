"""Evaluate an independent tag-frequency-only attacker on retained ORAM traces."""
import argparse
from collections import Counter, defaultdict
import gzip
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import time

import numpy as np
from sklearn.metrics import accuracy_score, balanced_accuracy_score, roc_auc_score

from research.analysis.oram_isolated_replication import (
    MODES,
    bootstrap_interval,
    digest,
    load_trial,
    verify_paired_schedules,
)


class TagFrequencyAttack:
    """Infer hot/cold labels from tag frequencies in labeled profile sessions."""

    def fit(self, trace, labels):
        if len(trace) != len(labels) or set(labels) != {0, 1}:
            raise ValueError("both labeled classes are required for profiling")
        self.profile_sessions = {row["session"] for row in trace}
        if not self.profile_sessions:
            raise ValueError("complete profile sessions are required")
        self.tag_counts = defaultdict(Counter)
        for row, label in zip(trace, labels):
            if (set(row) != {"session", "step", "tag", "bytes", "latency_ns"}
                    or type(row["tag"]) is not int or label not in (0, 1)):
                raise ValueError("attacker input must contain only visible operation features")
            self.tag_counts[row["tag"]][label] += 1
        self.prior = (sum(labels) + 0.5) / (len(labels) + 1.0)
        return self

    def run(self, trace, target_sessions):
        sessions = {row["session"] for row in trace}
        if not hasattr(self, "tag_counts") or not target_sessions or sessions != set(target_sessions):
            raise ValueError("target whole-session identifiers must match observer rows")
        if sessions & self.profile_sessions:
            raise ValueError("profiling and target sessions must be disjoint")
        scores = []
        for row in trace:
            if (set(row) != {"session", "step", "tag", "bytes", "latency_ns"}
                    or type(row["tag"]) is not int):
                raise ValueError("attacker input must contain only visible operation features")
            counts = self.tag_counts[row["tag"]]
            total = counts[0] + counts[1]
            scores.append((counts[1] + 0.5) / (total + 1.0) if total else self.prior)
        return [int(score >= 0.5) for score in scores], scores


def evaluate_mode(mode, raw_root, config, output):
    trial_rows = []
    prediction_root = output / "predictions" / mode
    prediction_root.mkdir(parents=True, exist_ok=True)
    for trial in range(config["trials"]):
        rows, labels, session_ids = load_trial(
            raw_root, mode, trial, config["sessions_per_trial"], config["hot_addresses"]
        )
        profile_count = config["sessions_per_trial"] // 2
        profile_ids = set(session_ids[:profile_count])
        target_ids = set(session_ids[profile_count:])
        profile_rows = [row for row in rows if row["session"] in profile_ids]
        target_rows = [row for row in rows if row["session"] in target_ids]
        profile_labels = [label for row, label in zip(rows, labels) if row["session"] in profile_ids]
        target_labels = [label for row, label in zip(rows, labels) if row["session"] in target_ids]
        attack = TagFrequencyAttack().fit(profile_rows, profile_labels)
        predicted, scores = attack.run(target_rows, target_ids)
        majority = int(np.mean(profile_labels) >= 0.5)
        trial_rows.append({
            "trial": trial,
            "auc": float(roc_auc_score(target_labels, scores)),
            "balanced_accuracy": float(balanced_accuracy_score(target_labels, predicted)),
            "accuracy": float(accuracy_score(target_labels, predicted)),
            "profile_majority_accuracy": float(
                accuracy_score(target_labels, [majority] * len(target_labels))
            ),
            "profile_sessions": sorted(profile_ids),
            "target_sessions": sorted(target_ids),
            "observations": len(target_labels),
        })
        with gzip.open(prediction_root / f"trial-{trial:02}.json.gz", "wt", encoding="utf-8") as stream:
            json.dump({"target_sessions": sorted(target_ids), "predictions": predicted,
                       "scores_uncalibrated": scores}, stream)
    return {
        "mode": mode,
        "trials": len(trial_rows),
        "auc_mean": float(np.mean([row["auc"] for row in trial_rows])),
        "auc_ci95_trials": bootstrap_interval(
            [row["auc"] for row in trial_rows], config["seed"] + 101
        ),
        "balanced_accuracy_mean": float(np.mean(
            [row["balanced_accuracy"] for row in trial_rows]
        )),
        "balanced_accuracy_ci95_trials": bootstrap_interval(
            [row["balanced_accuracy"] for row in trial_rows], config["seed"] + 103
        ),
        "accuracy_mean": float(np.mean([row["accuracy"] for row in trial_rows])),
        "profile_majority_accuracy_mean": float(np.mean(
            [row["profile_majority_accuracy"] for row in trial_rows]
        )),
    }, trial_rows


def run(config_path, raw_root, output):
    started = time.time()
    config_path, raw_root, output = Path(config_path), Path(raw_root), Path(output)
    config = json.loads(config_path.read_text())
    if output.exists():
        raise ValueError("analysis output directory must be new")
    if not (raw_root / "raw").is_dir():
        raise ValueError("input directory must retain the three modes' raw sessions")
    config["address_distribution"] = {
        str(key): value for key, value in sorted(
            ((int(key), value) for key, value in config["address_distribution"].items())
        )
    }
    config["hot_addresses"] = sorted(config["hot_addresses"])
    verify_paired_schedules(
        raw_root / "raw", MODES, config["trials"], config["sessions_per_trial"],
        len(config["address_distribution"]),
    )
    output.mkdir(parents=True)
    (output / "config.json").write_text(json.dumps(config, indent=2) + "\n")
    (output / "predictions").mkdir()
    summaries, trials = [], []
    # Positive controls are evaluated first. ORAM is not scored if either fails.
    for mode in ("plaintext", "encrypt_only"):
        summary, mode_trials = evaluate_mode(mode, raw_root / "raw", config, output)
        summaries.append(summary)
        trials.extend({**row, "mode": mode} for row in mode_trials)
    controls_passed = all(
        summary["auc_mean"] >= config["positive_control_min_mean_auc"]
        and summary["auc_ci95_trials"][0] > config["positive_control_ci_lower_must_exceed"]
        for summary in summaries
    )
    if controls_passed:
        summary, mode_trials = evaluate_mode("oram", raw_root / "raw", config, output)
        summaries.append(summary)
        trials.extend({**row, "mode": "oram"} for row in mode_trials)
    raw_hashes = {
        str(path.relative_to(raw_root)): digest(path)
        for path in sorted((raw_root / "raw").rglob("*.jsonl.gz"))
    }
    report = {
        "configuration": config,
        "attack": "tag-frequency-only smoothed lookup; no timing, sizes, operation types, or target labels",
        "summary": summaries,
        "trials": trials,
        "positive_controls_passed": controls_passed,
        "defense_evaluated": controls_passed,
        "attacker_knowledge": "Labeled complete plaintext/encrypt-only profiling sessions; unlabeled whole target sessions; no target labels during prediction.",
        "target_labels": f"logical address in configured hot set {config['hot_addresses']} versus remaining addresses",
        "methodology": "Each of 30 trials has four complete profiling sessions and four disjoint target sessions per mode. Scores use only profile-session visible-tag counts with 0.5 smoothing; unseen tags receive the profile prior. AUC intervals bootstrap 30 fitted-trial means with 5,000 resamples. Positive controls run before ORAM.",
        "source_sha256": {
            str(path): digest(path)
            for path in (Path(__file__), Path(__file__).with_name("oram_isolated_replication.py"), config_path)
        },
        "raw_input_root": str(raw_root.resolve()),
        "raw_session_sha256": raw_hashes,
        "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "git_status": subprocess.check_output(["git", "status", "--porcelain"], text=True),
        "python": __import__("sys").version,
        "platform": platform.platform(),
        "numpy": np.__version__,
        "scikit_learn": __import__("sklearn").__version__,
        "elapsed_seconds": time.time() - started,
    }
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.config, args.raw, args.output)
    print(json.dumps({"output": str(args.output),
                      "positive_controls_passed": report["positive_controls_passed"],
                      "summary": report["summary"]}))


if __name__ == "__main__":
    main()
