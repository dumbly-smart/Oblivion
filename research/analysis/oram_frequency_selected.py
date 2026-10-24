"""Profile-only orientation selection for tag-frequency attacks on ORAM traces."""

import argparse
import gzip
import json
from pathlib import Path
import platform
import subprocess
import time

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import accuracy_score, balanced_accuracy_score, roc_auc_score

from research.analysis.oram_attack_families import TagFrequencyAttack
from research.analysis.oram_frequency_orientation import select_profile_orientation
from research.analysis.oram_isolated_replication import (
    MODES,
    bootstrap_interval,
    digest,
    load_trial,
    verify_paired_schedules,
)

ROOT = Path(__file__).resolve().parents[2]


def evaluate_mode(mode, raw_root, config, output):
    trial_rows = []
    predictions_root = output / "predictions" / mode
    predictions_root.mkdir(parents=True, exist_ok=True)
    profile_count = config["sessions_per_trial"] // 2

    for trial in range(config["trials"]):
        rows, labels, session_ids = load_trial(
            raw_root, mode, trial, config["sessions_per_trial"], config["hot_addresses"]
        )
        if len(session_ids) != config["sessions_per_trial"]:
            raise ValueError("loaded session count differs from preregistered configuration")
        profile_ids = set(session_ids[:profile_count])
        target_ids = set(session_ids[profile_count:])
        if profile_ids & target_ids or not profile_ids or not target_ids:
            raise ValueError("profile and target sessions must be non-empty and disjoint")
        profile_rows = [row for row in rows if row["session"] in profile_ids]
        profile_labels = [label for row, label in zip(rows, labels)
                          if row["session"] in profile_ids]
        target_rows = [row for row in rows if row["session"] in target_ids]
        target_labels = [label for row, label in zip(rows, labels)
                         if row["session"] in target_ids]

        # Selection sees labeled profile sessions only. Target labels enter metrics below.
        selection = select_profile_orientation(profile_rows, profile_labels)
        model = TagFrequencyAttack().fit(profile_rows, profile_labels)
        fixed_predictions, fixed_scores = model.run(target_rows, target_ids)
        oriented_scores = fixed_scores if selection.sign > 0 else [1.0 - x for x in fixed_scores]
        oriented_predictions = [int(score >= 0.5) for score in oriented_scores]
        majority = int(np.mean(profile_labels) >= 0.5)

        trial_rows.append({
            "trial": trial,
            "auc": float(roc_auc_score(target_labels, oriented_scores)),
            "fixed_direction_auc": float(roc_auc_score(target_labels, fixed_scores)),
            "balanced_accuracy": float(
                balanced_accuracy_score(target_labels, oriented_predictions)
            ),
            "accuracy": float(accuracy_score(target_labels, oriented_predictions)),
            "fixed_direction_accuracy": float(accuracy_score(target_labels, fixed_predictions)),
            "profile_majority_accuracy": float(
                accuracy_score(target_labels, [majority] * len(target_labels))
            ),
            "orientation_sign": selection.sign,
            "profile_validation_auc": selection.validation_auc,
            "profile_validation_sessions": selection.validation_sessions,
            "profile_validation_observations": selection.validation_observations,
            "profile_sessions": sorted(profile_ids),
            "target_sessions": sorted(target_ids),
            "observations": len(target_labels),
        })
        with gzip.open(predictions_root / f"trial-{trial:02}.json.gz", "wt", encoding="utf-8") as stream:
            json.dump({
                "target_sessions": sorted(target_ids),
                "orientation_sign_selected_from_profile_only": selection.sign,
                "fixed_direction_scores": fixed_scores,
                "oriented_scores": oriented_scores,
                "predictions": oriented_predictions,
            }, stream)

    def summarize_metric(name, seed):
        values = [row[name] for row in trial_rows]
        return {
            "mean": float(np.mean(values)),
            "ci95_trials": bootstrap_interval(values, seed),
        }

    return {
        "mode": mode,
        "trials": len(trial_rows),
        "auc": summarize_metric("auc", config["seed"] + 201),
        "fixed_direction_auc": summarize_metric("fixed_direction_auc", config["seed"] + 203),
        "balanced_accuracy": summarize_metric("balanced_accuracy", config["seed"] + 205),
        "accuracy_mean": float(np.mean([row["accuracy"] for row in trial_rows])),
        "fixed_direction_accuracy_mean": float(
            np.mean([row["fixed_direction_accuracy"] for row in trial_rows])
        ),
        "profile_majority_accuracy_mean": float(
            np.mean([row["profile_majority_accuracy"] for row in trial_rows])
        ),
        "reversed_orientation_trials": sum(row["orientation_sign"] < 0 for row in trial_rows),
        "trials_detail": trial_rows,
    }


def _plot(summary, destination):
    fig, axis = plt.subplots(figsize=(6.5, 4))
    modes = [row["mode"] for row in summary]
    means = np.asarray([row["auc"]["mean"] for row in summary])
    bounds = np.asarray([row["auc"]["ci95_trials"] for row in summary])
    axis.bar(modes, means, color=["#b65b43", "#b65b43", "#376d91"][:len(modes)])
    axis.errorbar(
        np.arange(len(modes)), means,
        yerr=np.maximum(0, np.asarray([means - bounds[:, 0], bounds[:, 1] - means])),
        fmt="none", color="black", capsize=4,
    )
    axis.axhline(0.5, color="gray", linestyle="--", label="AUC chance")
    axis.set(xticks=np.arange(len(modes)), xticklabels=modes, ylim=(0, 1.05), ylabel="ROC AUC")
    axis.legend()
    fig.tight_layout()
    fig.savefig(destination, dpi=160)
    plt.close(fig)


def run(config_path, raw_root, output):
    started = time.time()
    config_path, raw_root, output = Path(config_path), Path(raw_root), Path(output)
    config = json.loads(config_path.read_text())
    if (config.get("trials") != 30 or config.get("sessions_per_trial") != 8
            or config.get("primary_metric") != "roc_auc"
            or not (raw_root / "raw").is_dir()):
        raise ValueError("analysis requires the retained 30-trial, eight-session study")
    if output.exists():
        raise ValueError("analysis output directory must be new")

    config["address_distribution"] = {
        str(key): value for key, value in sorted(
            ((int(key), value) for key, value in config["address_distribution"].items())
        )
    }
    config["hot_addresses"] = sorted(config["hot_addresses"])
    trace_root = raw_root / "raw"
    verify_paired_schedules(
        trace_root, MODES, config["trials"], config["sessions_per_trial"],
        len(config["address_distribution"]),
    )
    output.mkdir(parents=True)
    (output / "config.json").write_text(json.dumps(config, indent=2) + "\n")
    (output / "predictions").mkdir()

    summaries = []
    # Evaluate leaky controls before the defense, and gate the defense result on them.
    for mode in ("plaintext", "encrypt_only"):
        summaries.append(evaluate_mode(mode, trace_root, config, output))
    controls_passed = all(
        summary["auc"]["mean"] >= config["positive_control_min_mean_auc"]
        and summary["auc"]["ci95_trials"][0]
        > config["positive_control_ci_lower_must_exceed"]
        for summary in summaries
    )
    if controls_passed:
        summaries.append(evaluate_mode("oram", trace_root, config, output))

    raw_hashes = {
        str(path.relative_to(raw_root)): digest(path)
        for path in sorted(trace_root.rglob("*.jsonl.gz"))
    }
    source_paths = [
        Path(__file__),
        Path(__file__).with_name("oram_attack_families.py"),
        Path(__file__).with_name("oram_frequency_orientation.py"),
        Path(__file__).with_name("oram_isolated_replication.py"),
        config_path,
    ]
    report = {
        "configuration": config,
        "attack": "tag-frequency-only classifier with score direction selected by leave-one-profile-session-out validation",
        "primary_metric": "target-session ROC AUC after profile-only orientation selection",
        "orientation_policy": "For each of four labeled profile sessions, fit on the other profile sessions and score the held-out session. Select sign from pooled out-of-fold profile scores; refit on all profile sessions. Target labels are not passed to selection or prediction.",
        "summary": summaries,
        "positive_controls_passed": controls_passed,
        "defense_evaluated": controls_passed,
        "attacker_knowledge": "Labeled complete profile sessions; unlabeled whole target sessions; profile labels may select score orientation; target labels remain evaluation-only.",
        "limitations": "Four profile sessions provide a small orientation-validation sample. A near-chance result is not a security proof; results cover only this classifier, observer and workload.",
        "raw_input_root": str(raw_root.resolve()),
        "raw_session_sha256": raw_hashes,
        "source_sha256": {str(path): digest(path) for path in source_paths},
        "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "git_status": subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True),
        "python": __import__("sys").version,
        "platform": platform.platform(),
        "numpy": np.__version__,
        "scikit_learn": __import__("sklearn").__version__,
        "elapsed_seconds": time.time() - started,
    }
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    _plot(summaries, output / "orientation-selection.png")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.config, args.raw, args.output)
    print(json.dumps({
        "output": str(args.output),
        "positive_controls_passed": report["positive_controls_passed"],
        "summary": [
            {key: value for key, value in item.items() if key != "trials_detail"}
            for item in report["summary"]
        ],
    }))


if __name__ == "__main__":
    main()
