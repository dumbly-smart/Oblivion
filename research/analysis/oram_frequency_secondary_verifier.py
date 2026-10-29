"""Independent integrity and metric checks for the rank-64 frequency analysis."""

import argparse
import gzip
import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
import sys

import numpy as np
from sklearn.metrics import accuracy_score, balanced_accuracy_score, roc_auc_score


ROOT = Path(__file__).resolve().parents[2]
PLAN = ROOT / "docs/ORAM_RANK64_FREQUENCY_ORIENTATION_SECONDARY_PLAN_20261030.md"
MODES = ("plaintext", "encrypt_only", "oram")
PREDICTION_FIELDS = {
    "target_sessions",
    "orientation_sign_selected_from_profile_only",
    "fixed_direction_scores",
    "oriented_scores",
    "predictions",
}
SOURCE_FILES = (
    "research/analysis/oram_frequency_selected.py",
    "research/analysis/oram_frequency_orientation.py",
    "research/analysis/oram_attack_families.py",
    "research/analysis/oram_isolated_replication.py",
)


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            value.update(block)
    return value.hexdigest()


def verify_raw_manifest(raw_root, manifest):
    """Require an exact raw-session file set and verify every recorded digest."""
    raw_root = Path(raw_root)
    actual_paths = sorted(
        str(path.relative_to(raw_root))
        for path in (raw_root / "raw").rglob("*.jsonl.gz")
    )
    if set(actual_paths) != set(manifest):
        missing = sorted(set(manifest) - set(actual_paths))
        extra = sorted(set(actual_paths) - set(manifest))
        raise ValueError(
            f"manifest file set mismatch: missing={missing[:3]} extra={extra[:3]}"
        )
    for relative in actual_paths:
        if digest(raw_root / relative) != manifest[relative]:
            raise ValueError(f"raw session hash mismatch: {relative}")
    return len(actual_paths)


def validate_prediction_artifact(artifact, expected_sessions, expected_observations):
    """Validate that a prediction file contains only target predictions."""
    if not isinstance(artifact, dict) or set(artifact) != PREDICTION_FIELDS:
        raise ValueError("unexpected prediction fields; target labels are evaluation-only")
    if artifact["target_sessions"] != list(expected_sessions):
        raise ValueError("prediction target sessions differ from the fixed split")
    sign = artifact["orientation_sign_selected_from_profile_only"]
    if type(sign) is not int or sign not in (-1, 1):
        raise ValueError("profile-only orientation sign must be -1 or 1")

    fixed = artifact["fixed_direction_scores"]
    oriented = artifact["oriented_scores"]
    predictions = artifact["predictions"]
    if not all(isinstance(values, list) for values in (fixed, oriented, predictions)):
        raise ValueError("scores and predictions must be arrays")
    if any(len(values) != expected_observations for values in (fixed, oriented, predictions)):
        raise ValueError("prediction array length differs from target observations")
    for fixed_score, oriented_score, prediction in zip(fixed, oriented, predictions):
        if (isinstance(fixed_score, bool) or not isinstance(fixed_score, (int, float))
                or not math.isfinite(fixed_score) or not 0.0 <= fixed_score <= 1.0):
            raise ValueError("fixed-direction scores must be finite probabilities")
        expected_score = fixed_score if sign == 1 else 1.0 - fixed_score
        if (isinstance(oriented_score, bool) or not isinstance(oriented_score, (int, float))
                or not math.isclose(oriented_score, expected_score, rel_tol=0.0, abs_tol=1e-12)):
            raise ValueError("oriented scores do not match the recorded profile-only sign")
        if type(prediction) is not int or prediction != int(oriented_score >= 0.5):
            raise ValueError("predicted classes do not match the oriented scores")
    return sign


def compute_trial_metrics(artifact, target_labels, profile_labels):
    """Recompute target metrics from the score file and private driver labels."""
    if len(artifact["predictions"]) != len(target_labels):
        raise ValueError("target prediction and label lengths differ")
    if not target_labels or set(target_labels) != {0, 1}:
        raise ValueError("target labels must include both binary classes")
    if not profile_labels or set(profile_labels) != {0, 1}:
        raise ValueError("profile labels must include both binary classes")

    fixed_scores = artifact["fixed_direction_scores"]
    oriented_scores = artifact["oriented_scores"]
    oriented_predictions = artifact["predictions"]
    fixed_predictions = [int(score >= 0.5) for score in fixed_scores]
    profile_majority = int(sum(profile_labels) / len(profile_labels) >= 0.5)
    majority_predictions = [profile_majority] * len(target_labels)
    return {
        "auc": float(roc_auc_score(target_labels, oriented_scores)),
        "fixed_direction_auc": float(roc_auc_score(target_labels, fixed_scores)),
        "balanced_accuracy": float(balanced_accuracy_score(target_labels, oriented_predictions)),
        "accuracy": float(accuracy_score(target_labels, oriented_predictions)),
        "fixed_direction_accuracy": float(accuracy_score(target_labels, fixed_predictions)),
        "profile_majority_accuracy": float(accuracy_score(target_labels, majority_predictions)),
        "orientation_sign": artifact["orientation_sign_selected_from_profile_only"],
        "target_hot_prevalence": float(sum(target_labels) / len(target_labels)),
        "target_majority_accuracy": float(max(
            sum(target_labels) / len(target_labels),
            1.0 - sum(target_labels) / len(target_labels),
        )),
    }


def _close(actual, expected, description):
    if not math.isclose(float(actual), float(expected), rel_tol=0.0, abs_tol=1e-12):
        raise ValueError(f"reported {description} differs from independent recomputation")


def _bootstrap_interval(values, seed, replicates=5000):
    data = np.asarray(values, dtype=float)
    rng = np.random.default_rng(seed)
    means = np.asarray([
        rng.choice(data, size=len(data), replace=True).mean()
        for _ in range(replicates)
    ])
    return [float(np.quantile(means, 0.025)), float(np.quantile(means, 0.975))]


def _expected_raw_paths(modes, trials, sessions):
    return {
        f"raw/{mode}/trial-{trial:02}/{kind}-{session:02}.jsonl.gz"
        for mode in modes for trial in range(trials) for session in range(sessions)
        for kind in ("observer", "driver")
    }


def _load_private_labels(raw_root, mode, trial, session_number, hot_addresses, operations):
    path = (Path(raw_root) / "raw" / mode / f"trial-{trial:02}"
            / f"driver-{session_number:02}.jsonl.gz")
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        rows = [json.loads(line) for line in stream]
    if len(rows) != operations:
        raise ValueError(f"private label count differs from config: {path}")
    labels = []
    for step, row in enumerate(rows):
        address = row.get("logical_address")
        is_write = row.get("write")
        oracle_verified = row.get("oracle_verified")
        if (row.get("step") != step or type(address) is not int
                or type(is_write) is not bool or type(oracle_verified) is not bool
                or oracle_verified != (not is_write)):
            raise ValueError(f"malformed private driver record: {path} step {step}")
        labels.append(int(address in hot_addresses))
    if set(labels) != {0, 1}:
        raise ValueError(f"private session labels do not include both classes: {path}")
    return labels


def _read_json_gz(path):
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        return json.load(stream)


def _plan_hashes(plan_path):
    text = Path(plan_path).read_text(encoding="utf-8")
    hashes = {}
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        columns = [column.strip() for column in line.strip("|").split("|")]
        if len(columns) == 2 and re.fullmatch(r"`?[0-9a-f]{64}`?", columns[1]):
            label = columns[0]
            if label.startswith("`") and label.endswith("`"):
                label = label[1:-1]
            hashes[label] = columns[1].strip("`")
    expected_labels = set(SOURCE_FILES) | {
        "Rank-64 workload config",
        "Primary study `report.json`",
    }
    if set(hashes) != expected_labels:
        raise ValueError("secondary analysis plan does not contain the complete pinned input set")
    return hashes


def _verify_plan_and_sources(repo_root, plan_path, config_path, report):
    repo_root = Path(repo_root).resolve()
    pinned = _plan_hashes(plan_path)
    pinned_paths = {
        **{relative: repo_root / relative for relative in SOURCE_FILES},
        "Rank-64 workload config": Path(config_path),
        "Primary study `report.json`": repo_root / (
            "experiments/results/oram-isolated-rank64-markov-replication-20261030/report.json"
        ),
    }
    for label, path in pinned_paths.items():
        if digest(path) != pinned[label]:
            raise ValueError(f"frozen plan input hash mismatch: {label}")

    source_hashes = report.get("source_sha256")
    if not isinstance(source_hashes, dict):
        raise ValueError("run report is missing source hashes")
    code_entries = {Path(name).name: value for name, value in source_hashes.items()
                    if Path(name).suffix == ".py"}
    expected_names = {Path(path).name for path in SOURCE_FILES}
    if set(code_entries) != expected_names:
        raise ValueError("run report source hash set differs from the plan")
    for relative in SOURCE_FILES:
        name = Path(relative).name
        expected = digest(repo_root / relative)
        if code_entries[name] != expected or expected != pinned[relative]:
            raise ValueError(f"analysis source hash mismatch: {relative}")
    config_entries = [value for name, value in source_hashes.items()
                      if Path(name).name == Path(config_path).name]
    if config_entries != [digest(config_path)]:
        raise ValueError("run report configuration hash differs from frozen inputs")


def _compare_trial_detail(detail, metrics, profile_sessions, target_sessions, observations):
    for key in ("auc", "fixed_direction_auc", "balanced_accuracy", "accuracy",
                "fixed_direction_accuracy", "profile_majority_accuracy"):
        _close(detail[key], metrics[key], f"trial {detail['trial']} {key}")
    if detail["orientation_sign"] != metrics["orientation_sign"]:
        raise ValueError(f"trial {detail['trial']} orientation differs from its prediction artifact")
    if detail["profile_sessions"] != profile_sessions or detail["target_sessions"] != target_sessions:
        raise ValueError(f"trial {detail['trial']} session split differs from the fixed split")
    if detail["observations"] != observations:
        raise ValueError(f"trial {detail['trial']} observation count differs from private labels")
    validation_auc = detail.get("profile_validation_auc")
    if (isinstance(validation_auc, bool) or not isinstance(validation_auc, (int, float))
            or not math.isfinite(validation_auc) or not 0.0 <= validation_auc <= 1.0):
        raise ValueError(f"trial {detail['trial']} has invalid profile validation AUC")


def _verify_summary(summary, metric_rows, seed, expected_mode):
    if summary.get("mode") != expected_mode or summary.get("trials") != len(metric_rows):
        raise ValueError(f"unexpected summary mode or trial count: {expected_mode}")
    detail_rows = summary.get("trials_detail")
    if not isinstance(detail_rows, list) or len(detail_rows) != len(metric_rows):
        raise ValueError(f"missing per-trial report rows: {expected_mode}")
    for index, (detail, metrics) in enumerate(zip(detail_rows, metric_rows)):
        if detail.get("trial") != index:
            raise ValueError(f"trial ordering mismatch: {expected_mode} trial {index}")
        # Split and observation fields are checked by the caller; this pass checks
        # each metric independently against the saved score artifact and private labels.
        for key in ("auc", "fixed_direction_auc", "balanced_accuracy", "accuracy",
                    "fixed_direction_accuracy", "profile_majority_accuracy"):
            _close(detail[key], metrics[key], f"{expected_mode} trial {index} {key}")
        if detail.get("orientation_sign") != metrics["orientation_sign"]:
            raise ValueError(f"{expected_mode} trial {index} orientation mismatch")

    for report_key, metric_key, metric_seed in (
        ("auc", "auc", seed + 201),
        ("fixed_direction_auc", "fixed_direction_auc", seed + 203),
        ("balanced_accuracy", "balanced_accuracy", seed + 205),
    ):
        values = [row[metric_key] for row in metric_rows]
        reported = summary[report_key]
        _close(reported["mean"], float(np.mean(values)), f"{expected_mode} {report_key} mean")
        expected_interval = _bootstrap_interval(values, metric_seed)
        for actual, expected in zip(reported["ci95_trials"], expected_interval):
            _close(actual, expected, f"{expected_mode} {report_key} interval")

    for report_key, metric_key in (
        ("accuracy_mean", "accuracy"),
        ("fixed_direction_accuracy_mean", "fixed_direction_accuracy"),
        ("profile_majority_accuracy_mean", "profile_majority_accuracy"),
    ):
        _close(summary[report_key], float(np.mean([row[metric_key] for row in metric_rows])),
               f"{expected_mode} {report_key}")
    reversed_count = sum(row["orientation_sign"] < 0 for row in metric_rows)
    if summary["reversed_orientation_trials"] != reversed_count:
        raise ValueError(f"{expected_mode} reversed-orientation count mismatch")


def verify_bundle(output_root, raw_root, config_path, plan_path=PLAN, repo_root=ROOT):
    """Verify hashes, target-only predictions, splits, and all reported metrics."""
    output_root, raw_root = Path(output_root), Path(raw_root)
    config_path = Path(config_path)
    report_path = output_root / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if report.get("raw_input_root") != str(raw_root.resolve()):
        raise ValueError("report refers to a different raw input root")
    if report.get("configuration") != config:
        raise ValueError("run configuration differs from the frozen workload")
    raw_count = verify_raw_manifest(raw_root, report.get("raw_session_sha256", {}))
    _verify_plan_and_sources(repo_root, plan_path, config_path, report)

    trials = config["trials"]
    sessions_per_trial = config["sessions_per_trial"]
    profile_count = sessions_per_trial // 2
    operations = config["operations"]
    hot_addresses = set(config["hot_addresses"])
    summaries = report.get("summary")
    if not isinstance(summaries, list):
        raise ValueError("run report has no summary array")
    modes = [row.get("mode") for row in summaries]
    if modes not in (list(MODES[:2]), list(MODES)):
        raise ValueError("summary contains an unexpected mode set or order")
    expected_raw_paths = _expected_raw_paths(modes, trials, sessions_per_trial)
    if set(report.get("raw_session_sha256", {})) != expected_raw_paths:
        raise ValueError("raw session manifest differs from the complete configured study")

    expected_prediction_paths = {
        f"predictions/{mode}/trial-{trial:02}.json.gz"
        for mode in modes for trial in range(trials)
    }
    actual_prediction_paths = {
        str(path.relative_to(output_root))
        for path in (output_root / "predictions").rglob("*") if path.is_file()
    }
    if actual_prediction_paths != expected_prediction_paths:
        raise ValueError("prediction artifact file set differs from the frozen modes and trials")

    recomputed_by_mode = {}
    for summary in summaries:
        mode = summary["mode"]
        trial_metrics = []
        for trial in range(trials):
            sessions = [f"{mode}-trial-{trial:02}-session-{i:02}"
                        for i in range(sessions_per_trial)]
            profile_sessions = sessions[:profile_count]
            target_sessions = sessions[profile_count:]
            labels_by_session = [
                _load_private_labels(raw_root, mode, trial, session, hot_addresses, operations)
                for session in range(sessions_per_trial)
            ]
            profile_labels = [label for labels in labels_by_session[:profile_count] for label in labels]
            target_labels = [label for labels in labels_by_session[profile_count:] for label in labels]
            observations = len(target_labels)
            artifact = _read_json_gz(
                output_root / "predictions" / mode / f"trial-{trial:02}.json.gz"
            )
            validate_prediction_artifact(artifact, target_sessions, observations)
            metrics = compute_trial_metrics(artifact, target_labels, profile_labels)
            detail = summary["trials_detail"][trial]
            _compare_trial_detail(
                detail, metrics, profile_sessions, target_sessions, observations
            )
            trial_metrics.append(metrics)
        _verify_summary(summary, trial_metrics, config["seed"], mode)
        recomputed_by_mode[mode] = trial_metrics

    controls = [summaries[0], summaries[1]]
    controls_passed = all(
        summary["auc"]["mean"] >= config["positive_control_min_mean_auc"]
        and summary["auc"]["ci95_trials"][0]
        > config["positive_control_ci_lower_must_exceed"]
        for summary in controls
    )
    if report.get("positive_controls_passed") is not controls_passed:
        raise ValueError("positive-control gate does not match recomputed controls")
    if report.get("defense_evaluated") is not controls_passed or ("oram" in modes) is not controls_passed:
        raise ValueError("defense evaluation does not match the positive-control gate")

    head = report.get("git_head")
    if not isinstance(head, str) or subprocess.run(
        ["git", "cat-file", "-e", f"{head}^{{commit}}"], cwd=repo_root,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    ).returncode != 0:
        raise ValueError("analysis source revision is not present in the local git history")

    return {
        "verification": "passed",
        "study": output_root.name,
        "report_sha256": digest(report_path),
        "raw_session_file_count": raw_count,
        "prediction_artifact_count": len(actual_prediction_paths),
        "private_truth_fields_in_prediction_artifacts": False,
        "trial_metrics_recomputed": sum(len(rows) for rows in recomputed_by_mode.values()),
        "modes": {
            mode: {
                "trials": len(rows),
                "mean_auc": float(np.mean([row["auc"] for row in rows])),
                "mean_fixed_direction_auc": float(np.mean(
                    [row["fixed_direction_auc"] for row in rows]
                )),
                "mean_balanced_accuracy": float(np.mean(
                    [row["balanced_accuracy"] for row in rows]
                )),
                "mean_target_hot_prevalence": float(np.mean(
                    [row["target_hot_prevalence"] for row in rows]
                )),
                "mean_target_majority_accuracy": float(np.mean(
                    [row["target_majority_accuracy"] for row in rows]
                )),
            }
            for mode, rows in recomputed_by_mode.items()
        },
        "source_revision": head,
        "plan_sha256": digest(plan_path),
        "verifier_sha256": digest(__file__),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--raw", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--plan", type=Path, default=PLAN)
    args = parser.parse_args()
    receipt = verify_bundle(args.output, args.raw, args.config, args.plan)
    destination = args.output / "independent-verification.json"
    with destination.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2)
        stream.write("\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
