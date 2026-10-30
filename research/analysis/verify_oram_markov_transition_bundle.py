"""Independently validate a saved one-step ORAM transition-attack bundle."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import math
from pathlib import Path

import numpy as np


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MODES = ("plaintext", "encrypt_only", "oram")
PRIMARY_METRIC = "mean per-trial ROC AUC with 5000-resample percentile bootstrap over trials"
EXPECTED_ATTACKER = (
    "For each target operation, use only the immediately preceding visible storage tag. "
    "Profile labeled sessions map that tag to the next hot/cold label with a single prior "
    "pseudo-observation; the first target operation uses the profile class prior."
)
EXPECTED_TRAINING = (
    "first half of each trial's whole sessions, with driver labels; target sessions are "
    "disjoint and labels are used only for scoring"
)
EXPECTED_LIMITATIONS = (
    "The transition attack and metric were specified before collection. This secondary "
    "analysis uses the same experimental collection as the primary temporal study and is "
    "not an independent collection from that primary analysis. The attack is a simple "
    "profile-based lookup, not a reproduction of a published attack. Near-chance scores "
    "do not prove cryptographic security or exclude other attacks."
)
FROZEN_SOURCE_HASHES = {
    "research/analysis/oram_markov_transition_attack.py":
        "fbd791e44e70ad4c3a8bb446b3a69bb9cc50ffbf8b000ed7005729592e9a8010",
    "research/analysis/oram_isolated_replication.py":
        "b07bf0ea683bd1064c92fd4043aae6fcbe3d7553237a3493fbb8dfcdb595a709",
    "research/attacks/leaf_timing.py":
        "353d3c21d5661e294f9af5afc610e73ea0a54a313f3230d2d72d5fb44fbe980a",
}
FROZEN_CONFIG_SHA256 = "d98f808f4450c77168953951a3d741e454573d8efca11616c6e80f7f3c6acf14"


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read JSON file {path}: {error}") from error


def _read_gzip_jsonl(path):
    rows = []
    try:
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError as error:
                    raise ValueError(f"invalid JSON at {path}:{line_number}") from error
    except (OSError, EOFError) as error:
        raise ValueError(f"cannot read compressed raw session {path}: {error}") from error
    return rows


def _same_number(actual, expected, field):
    if (type(actual) not in (int, float) or not math.isfinite(actual)
            or not math.isclose(actual, expected, rel_tol=1e-10, abs_tol=1e-10)):
        raise ValueError(f"reported {field} does not match independently recomputed value")


def _auc(labels, scores):
    positives = sum(labels)
    negatives = len(labels) - positives
    if not labels or positives == 0 or negatives == 0 or len(labels) != len(scores):
        raise ValueError("target labels and scores must contain aligned hot and cold classes")
    ordered = sorted(zip(scores, labels))
    positive_rank_sum = 0.0
    index = 0
    while index < len(ordered):
        end = index + 1
        while end < len(ordered) and ordered[end][0] == ordered[index][0]:
            end += 1
        average_rank = ((index + 1) + end) / 2
        positive_rank_sum += average_rank * sum(label for _, label in ordered[index:end])
        index = end
    return (positive_rank_sum - positives * (positives + 1) / 2) / (positives * negatives)


def _binary_metrics(labels, predictions):
    positives = sum(labels)
    negatives = len(labels) - positives
    if positives == 0 or negatives == 0 or len(labels) != len(predictions):
        raise ValueError("target labels and predictions must contain aligned hot and cold classes")
    true_positive = sum(label == 1 and predicted == 1
                        for label, predicted in zip(labels, predictions))
    true_negative = sum(label == 0 and predicted == 0
                        for label, predicted in zip(labels, predictions))
    accuracy = sum(label == predicted for label, predicted in zip(labels, predictions)) / len(labels)
    balanced = (true_positive / positives + true_negative / negatives) / 2
    return accuracy, balanced


def _bootstrap_interval(values, seed, replicates=5000):
    data = np.asarray(values, dtype=float)
    if data.size < 2:
        return [float(data.mean()), float(data.mean())]
    rng = np.random.default_rng(seed)
    means = np.asarray([
        rng.choice(data, size=len(data), replace=True).mean()
        for _ in range(replicates)
    ])
    return [float(np.quantile(means, 0.025)), float(np.quantile(means, 0.975))]


def _validate_config(config):
    try:
        trials = config["trials"]
        sessions = config["sessions_per_trial"]
        operations = config["operations"]
        blocks = config["blocks"]
        seed = config["seed"]
        hot_addresses = config["hot_addresses"]
    except (KeyError, TypeError) as error:
        raise ValueError("configuration is missing required study parameters") from error
    if (type(trials) is not int or trials < 1 or type(sessions) is not int
            or sessions < 2 or sessions % 2 or type(operations) is not int or operations < 1
            or type(blocks) is not int or blocks < 2 or type(seed) is not int
            or not isinstance(hot_addresses, list) or not hot_addresses
            or any(type(address) is not int for address in hot_addresses)
            or len(set(hot_addresses)) != len(hot_addresses)
            or not set(hot_addresses) < set(range(blocks))):
        raise ValueError("invalid workload parameters in transition config")
    return trials, sessions, operations, blocks, set(hot_addresses), seed


def _raw_hashes(raw_root):
    root = Path(raw_root).resolve()
    paths = sorted(root.rglob("*.jsonl.gz"))
    if not paths or any(path.is_symlink() for path in paths):
        raise ValueError("raw input must contain regular compressed session files")
    return {
        path.relative_to(root).as_posix(): _sha256(path)
        for path in paths
    }


def _source_hashes(config_path, expected_source_hashes):
    expected = dict(expected_source_hashes)
    config_key = str(config_path)
    if config_key not in expected:
        raise ValueError("expected frozen source hashes must include the supplied config path")
    paths = {
        key: (Path(config_path) if key == config_key else REPOSITORY_ROOT / key)
        for key in expected
    }
    actual = {key: _sha256(path) for key, path in paths.items()}
    if actual != expected:
        raise ValueError("frozen attack, collector, feature, or config source hash changed")
    return actual


def _read_session_labels(raw_root, mode, trial, session_number, operations, blocks, hot_addresses):
    path = (Path(raw_root) / mode / f"trial-{trial:02}"
            / f"driver-{session_number:02}.jsonl.gz")
    rows = _read_gzip_jsonl(path)
    if len(rows) != operations:
        raise ValueError(f"wrong operation count in private session {path}")
    labels = []
    for step, row in enumerate(rows):
        required = {"step", "logical_address", "write", "oracle_verified", "latency_ns"}
        if (not isinstance(row, dict) or not required <= set(row)
                or set(row) - required - {"stash"}
                or type(row["step"]) is not int or row["step"] != step
                or type(row["logical_address"]) is not int
                or not 0 <= row["logical_address"] < blocks
                or type(row["write"]) is not bool
                or type(row["oracle_verified"]) is not bool
                or row["oracle_verified"] == row["write"]
                or type(row["latency_ns"]) is not int or row["latency_ns"] < 0
                or ("stash" in row and (type(row["stash"]) is not int or row["stash"] < 0))):
            raise ValueError(f"malformed private driver row in {path} at operation {step}")
        labels.append(int(row["logical_address"] in hot_addresses))
    return labels


def _validate_collector_receipt(raw_root, config, raw_hashes):
    collector_root = Path(raw_root).resolve().parent
    captured_config = _read_json(collector_root / "config.json")
    collector_report = _read_json(collector_root / "report.json")
    receipt_path = collector_root / "independent-verification.json"
    receipt = _read_json(receipt_path)
    if captured_config != config or collector_report.get("configuration") != config:
        raise ValueError("transition config differs from the independently verified collector config")
    expected_paths = {f"raw/{path}": digest for path, digest in raw_hashes.items()}
    if collector_report.get("raw_session_sha256") != expected_paths:
        raise ValueError("collector raw hash manifest differs from transition input files")
    expected_count = len(raw_hashes)
    if (receipt.get("format_version") != 1 or receipt.get("modes") != list(MODES)
            or receipt.get("raw_files_verified") != expected_count
            or receipt.get("positive_controls_passed") is not True
            or type(receipt.get("source_and_binary_hashes_verified")) is not int
            or receipt.get("source_and_binary_hashes_verified") < 1
            or collector_report.get("positive_controls_passed") is not True):
        raise ValueError("collector's independent-verification receipt is incomplete or negative")
    return {
        "collector_report_sha256": _sha256(collector_root / "report.json"),
        "collector_receipt_sha256": _sha256(receipt_path),
        "raw_files_verified": expected_count,
    }


def _read_prediction(path):
    try:
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            artifact = json.load(stream)
    except (OSError, EOFError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read prediction artifact {path}: {error}") from error
    if not isinstance(artifact, dict) or set(artifact) != {"target_sessions", "predictions", "scores"}:
        raise ValueError("prediction artifact fields must contain target_sessions, predictions, and scores only")
    return artifact


def verify_bundle(raw_root, config_path, analysis_root, *, expected_source_hashes=None):
    """Check provenance, labels, saved scores, per-trial metrics, and summaries."""
    raw_root = Path(raw_root).resolve()
    config_path = Path(config_path)
    analysis_root = Path(analysis_root).resolve()
    report = _read_json(analysis_root / "report.json")
    config = _read_json(config_path)
    trials, sessions, operations, blocks, hot_addresses, seed = _validate_config(config)

    if expected_source_hashes is None:
        expected_source_hashes = dict(FROZEN_SOURCE_HASHES)
        expected_source_hashes[str(config_path)] = FROZEN_CONFIG_SHA256
    actual_sources = _source_hashes(config_path, expected_source_hashes)
    if report.get("source_sha256") != actual_sources:
        raise ValueError("transition report source hashes differ from frozen inputs")
    if report.get("configuration") != config:
        raise ValueError("transition report config differs from the frozen config")

    expected_analysis = {
        "protocol_status": "preregistered-secondary",
        "analysis": "preregistered secondary one-step profile transition lookup",
        "limitations": EXPECTED_LIMITATIONS,
        "sessions_reused_from_primary_study": True,
        "primary_metric": PRIMARY_METRIC,
        "attacker": EXPECTED_ATTACKER,
        "target_labels": f"logical address in configured hot set {config['hot_addresses']} versus remaining addresses",
        "features": ["immediately previous visible bucket/leaf identifier"],
        "attacker_training": EXPECTED_TRAINING,
    }
    for key, expected in expected_analysis.items():
        if report.get(key) != expected:
            raise ValueError(f"transition report does not match frozen protocol field {key}")

    raw_hashes = _raw_hashes(raw_root)
    expected_raw_paths = {
        f"{mode}/trial-{trial:02}/{kind}-{session:02}.jsonl.gz"
        for mode in MODES for trial in range(trials) for session in range(sessions)
        for kind in ("driver", "observer")
    }
    if set(raw_hashes) != expected_raw_paths:
        raise ValueError("raw files do not match the configured mode/trial/session set")
    if report.get("input_raw_sha256") != raw_hashes:
        raise ValueError("transition report raw input hashes do not match the saved traces")
    collector_info = _validate_collector_receipt(raw_root, config, raw_hashes)

    summaries = report.get("summary")
    if not isinstance(summaries, list) or len(summaries) not in (2, 3):
        raise ValueError("transition report must retain both controls and only score ORAM after they pass")
    reported_modes = [row.get("mode") if isinstance(row, dict) else None for row in summaries]
    if reported_modes not in (list(MODES[:2]), list(MODES)):
        raise ValueError("transition summaries must preserve control-first mode order")
    expected_modes = reported_modes

    expected_trial_rows = [(mode, trial) for mode in expected_modes for trial in range(trials)]
    report_trials = report.get("trials")
    if not isinstance(report_trials, list) or len(report_trials) != len(expected_trial_rows):
        raise ValueError("transition report has the wrong number of trial metric rows")
    by_trial = {}
    for row in report_trials:
        if (not isinstance(row, dict)
                or set(row) != {"trial", "mode", "auc", "accuracy", "balanced_accuracy",
                                "profile_majority_accuracy", "profile_sessions", "target_sessions"}
                or type(row["trial"]) is not int or row["mode"] not in MODES):
            raise ValueError("malformed transition per-trial report row")
        key = (row["mode"], row["trial"])
        if key in by_trial:
            raise ValueError("duplicate transition per-trial metric row")
        by_trial[key] = row
    if list(by_trial) != expected_trial_rows:
        raise ValueError("transition report trial order or coverage differs from frozen config")

    expected_prediction_files = {
        analysis_root / "predictions" / mode / f"trial-{trial:02}.json.gz"
        for mode in expected_modes for trial in range(trials)
    }
    actual_prediction_files = set((analysis_root / "predictions").rglob("*.json.gz"))
    if actual_prediction_files != expected_prediction_files:
        raise ValueError("saved prediction files do not match configured trials and modes")

    recomputed = {mode: [] for mode in expected_modes}
    predictions_verified = 0
    profile_count = sessions // 2
    expected_score_count = (sessions - profile_count) * operations
    for mode, trial in expected_trial_rows:
        profile_ids = [f"{mode}-trial-{trial:02}-session-{index:02}"
                       for index in range(profile_count)]
        target_ids = [f"{mode}-trial-{trial:02}-session-{index:02}"
                      for index in range(profile_count, sessions)]
        metric_row = by_trial[(mode, trial)]
        if metric_row["profile_sessions"] != profile_ids or metric_row["target_sessions"] != target_ids:
            raise ValueError("profile/target session split differs from the frozen whole-session split")

        profile_labels = [
            label
            for session in range(profile_count)
            for label in _read_session_labels(
                raw_root, mode, trial, session, operations, blocks, hot_addresses
            )
        ]
        target_labels = [
            label
            for session in range(profile_count, sessions)
            for label in _read_session_labels(
                raw_root, mode, trial, session, operations, blocks, hot_addresses
            )
        ]
        path = analysis_root / "predictions" / mode / f"trial-{trial:02}.json.gz"
        artifact = _read_prediction(path)
        if artifact["target_sessions"] != target_ids:
            raise ValueError("prediction artifact session identifiers differ from the target split")
        predictions, scores = artifact["predictions"], artifact["scores"]
        if (not isinstance(predictions, list) or not isinstance(scores, list)
                or len(predictions) != expected_score_count or len(scores) != expected_score_count
                or any(type(value) is not int or value not in (0, 1) for value in predictions)
                or any(type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1
                       for value in scores)):
            raise ValueError("prediction scores/classes do not match the fixed target operation count")
        expected_predictions = [int(score >= 0.5) for score in scores]
        if predictions != expected_predictions:
            raise ValueError("saved prediction classes do not match the frozen 0.5 score threshold")

        auc = _auc(target_labels, scores)
        accuracy, balanced_accuracy = _binary_metrics(target_labels, predictions)
        profile_majority = int(sum(profile_labels) / len(profile_labels) >= 0.5)
        majority_accuracy = sum(label == profile_majority for label in target_labels) / len(target_labels)
        for field, value in (
            ("auc", auc),
            ("accuracy", accuracy),
            ("balanced_accuracy", balanced_accuracy),
            ("profile_majority_accuracy", majority_accuracy),
        ):
            _same_number(metric_row.get(field), value, f"trial {mode}/{trial} {field}")
        recomputed[mode].append({
            "auc": auc,
            "accuracy": accuracy,
            "balanced_accuracy": balanced_accuracy,
            "profile_majority_accuracy": majority_accuracy,
        })
        predictions_verified += 1

    means = {}
    for summary in summaries:
        mode = summary["mode"]
        rows = recomputed[mode]
        aucs = [row["auc"] for row in rows]
        mode_means = {
            "auc_mean": float(np.mean(aucs)),
            "balanced_accuracy_mean": float(np.mean([row["balanced_accuracy"] for row in rows])),
            "accuracy_mean": float(np.mean([row["accuracy"] for row in rows])),
            "profile_majority_accuracy_mean": float(np.mean(
                [row["profile_majority_accuracy"] for row in rows]
            )),
        }
        if set(summary) != {"mode", "trials", "auc_mean", "auc_ci95_trials",
                            "balanced_accuracy_mean", "accuracy_mean",
                            "profile_majority_accuracy_mean"}:
            raise ValueError("transition summary has unexpected or missing fields")
        if summary["trials"] != trials:
            raise ValueError("transition summary trial count differs from config")
        for field, value in mode_means.items():
            _same_number(summary[field], value, f"{mode} summary {field}")
        interval = _bootstrap_interval(aucs, seed + 101)
        if (not isinstance(summary["auc_ci95_trials"], list)
                or len(summary["auc_ci95_trials"]) != 2):
            raise ValueError("transition AUC interval must have two percentile bounds")
        for actual, expected in zip(summary["auc_ci95_trials"], interval):
            _same_number(actual, expected, f"{mode} bootstrap interval")
        means[mode] = mode_means["auc_mean"]

    control_gate = all(
        summary["auc_mean"] >= 0.80 and summary["auc_ci95_trials"][0] > 0.50
        for summary in summaries if summary["mode"] in ("plaintext", "encrypt_only")
    )
    if (report.get("positive_controls_passed") is not control_gate
            or report.get("defense_evaluated") is not control_gate):
        raise ValueError("transition report positive-control status does not match recomputed gate")
    if control_gate != (expected_modes == list(MODES)):
        raise ValueError("Path ORAM must be evaluated exactly when the frozen controls pass")

    return {
        "format_version": 1,
        "verifier": "research.analysis.verify_oram_markov_transition_bundle",
        "verifier_sha256": _sha256(__file__),
        "protocol_status": report["protocol_status"],
        "raw_files_verified": collector_info["raw_files_verified"],
        "prediction_trials_verified": predictions_verified,
        "trials_per_mode": trials,
        "sessions_per_trial": sessions,
        "target_operations_per_trial": expected_score_count,
        "positive_controls_passed": control_gate,
        "defense_evaluated": "oram" in means,
        "recomputed_auc_mean": means,
        "collector_report_sha256": collector_info["collector_report_sha256"],
        "collector_receipt_sha256": collector_info["collector_receipt_sha256"],
        "transition_report_sha256": _sha256(analysis_root / "report.json"),
        "source_hashes_verified": actual_sources,
        "input_raw_sha256": raw_hashes,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", required=True, help="collector raw/ directory")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--analysis", required=True, type=Path, help="transition attack output directory")
    parser.add_argument("--receipt", type=Path, help="new receipt path; defaults inside --analysis")
    args = parser.parse_args()
    receipt_path = args.receipt or args.analysis / "independent-verification.json"
    if receipt_path.exists():
        raise ValueError("verification receipt path must be new; refusing to overwrite evidence")
    receipt = verify_bundle(args.raw, args.config, args.analysis)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "receipt": str(receipt_path),
        "raw_files_verified": receipt["raw_files_verified"],
        "prediction_trials_verified": receipt["prediction_trials_verified"],
        "positive_controls_passed": receipt["positive_controls_passed"],
        "recomputed_auc_mean": receipt["recomputed_auc_mean"],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
