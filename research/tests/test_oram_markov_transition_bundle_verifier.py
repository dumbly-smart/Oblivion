import gzip
import hashlib
import json
from pathlib import Path

import pytest

from research.analysis import verify_oram_markov_transition_bundle as verifier


MODES = ("plaintext", "encrypt_only", "oram")


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _write_jsonl_gzip(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row) + "\n")


def _make_valid_bundle(root, *, control_gate=True):
    raw_root = root / "collector" / "raw"
    config_path = root / "config.json"
    config = {
        "seed": 7,
        "trials": 2,
        "sessions_per_trial": 4,
        "operations": 4,
        "blocks": 2,
        "hot_addresses": [0],
    }
    config_path.write_text(json.dumps(config))

    raw_hashes = {}
    modes_to_emit = MODES if control_gate else MODES[:2]
    for mode in MODES:
        for trial in range(config["trials"]):
            for session_number in range(config["sessions_per_trial"]):
                session_root = raw_root / mode / f"trial-{trial:02}"
                driver = [
                    {
                        "step": step,
                        "logical_address": address,
                        "write": False,
                        "oracle_verified": True,
                        "latency_ns": 100 + step,
                    }
                    for step, address in enumerate((0, 1, 0, 1))
                ]
                observer = [
                    {
                        "step": step,
                        "direction": "read",
                        "bucket": step,
                        "bytes": 8,
                        "service_ns": 10,
                    }
                    for step in range(config["operations"])
                ]
                for kind, rows in (("driver", driver), ("observer", observer)):
                    path = session_root / f"{kind}-{session_number:02}.jsonl.gz"
                    _write_jsonl_gzip(path, rows)
                    raw_hashes[str(path.relative_to(raw_root))] = _sha256(path)

    collector_root = raw_root.parent
    (collector_root / "config.json").write_text(json.dumps(config))
    collector_raw_hashes = {f"raw/{key}": value for key, value in raw_hashes.items()}
    (collector_root / "report.json").write_text(json.dumps({
        "configuration": config,
        "positive_controls_passed": True,
        "raw_session_sha256": collector_raw_hashes,
    }))
    (collector_root / "independent-verification.json").write_text(json.dumps({
        "format_version": 1,
        "modes": list(MODES),
        "raw_files_verified": len(raw_hashes),
        "positive_controls_passed": True,
        "source_and_binary_hashes_verified": 5,
    }))

    analysis_root = root / "analysis"
    prediction_dir = analysis_root / "predictions"
    trial_rows = []
    mode_rows = []
    for mode in modes_to_emit:
        aucs = []
        accuracies = []
        balanced_accuracies = []
        majority_accuracies = []
        for trial in range(config["trials"]):
            profile_sessions = [
                f"{mode}-trial-{trial:02}-session-{index:02}" for index in (0, 1)
            ]
            target_sessions = [
                f"{mode}-trial-{trial:02}-session-{index:02}" for index in (2, 3)
            ]
            labels = [1, 0, 1, 0] * 2
            scores = ([0.9, 0.1, 0.9, 0.1] * 2 if control_gate or mode == "oram"
                      else [0.1, 0.9, 0.1, 0.9] * 2)
            predictions = [int(score >= 0.5) for score in scores]
            auc = 1.0 if control_gate or mode == "oram" else 0.0
            accuracy = auc
            balanced_accuracy = auc
            trial_row = {
                "trial": trial,
                "mode": mode,
                "auc": auc,
                "accuracy": accuracy,
                "balanced_accuracy": balanced_accuracy,
                "profile_majority_accuracy": 0.5,
                "profile_sessions": profile_sessions,
                "target_sessions": target_sessions,
            }
            trial_rows.append(trial_row)
            aucs.append(auc)
            accuracies.append(accuracy)
            balanced_accuracies.append(balanced_accuracy)
            majority_accuracies.append(0.5)
            path = prediction_dir / mode / f"trial-{trial:02}.json.gz"
            path.parent.mkdir(parents=True, exist_ok=True)
            with gzip.open(path, "wt", encoding="utf-8") as stream:
                json.dump({
                    "target_sessions": target_sessions,
                    "predictions": predictions,
                    "scores": scores,
                }, stream)
        mode_rows.append({
            "mode": mode,
            "trials": config["trials"],
            "auc_mean": sum(aucs) / len(aucs),
            "auc_ci95_trials": [1.0, 1.0] if all(aucs) else [0.0, 0.0],
            "balanced_accuracy_mean": sum(balanced_accuracies) / len(balanced_accuracies),
            "accuracy_mean": sum(accuracies) / len(accuracies),
            "profile_majority_accuracy_mean": sum(majority_accuracies) / len(majority_accuracies),
        })

    config_key = str(config_path)
    source_paths = {
        "research/analysis/oram_markov_transition_attack.py": verifier.REPOSITORY_ROOT
        / "research/analysis/oram_markov_transition_attack.py",
        "research/analysis/oram_isolated_replication.py": verifier.REPOSITORY_ROOT
        / "research/analysis/oram_isolated_replication.py",
        "research/attacks/leaf_timing.py": verifier.REPOSITORY_ROOT
        / "research/attacks/leaf_timing.py",
        config_key: config_path,
    }
    source_hashes = {key: _sha256(path) for key, path in source_paths.items()}
    analysis_root.mkdir(parents=True, exist_ok=True)
    report = {
        "protocol_status": "preregistered-secondary",
        "analysis": "preregistered secondary one-step profile transition lookup",
        "limitations": verifier.EXPECTED_LIMITATIONS,
        "sessions_reused_from_primary_study": True,
        "positive_controls_passed": control_gate,
        "defense_evaluated": control_gate,
        "primary_metric": verifier.PRIMARY_METRIC,
        "attacker": verifier.EXPECTED_ATTACKER,
        "target_labels": "logical address in configured hot set [0] versus remaining addresses",
        "features": ["immediately previous visible bucket/leaf identifier"],
        "attacker_training": verifier.EXPECTED_TRAINING,
        "configuration": config,
        "summary": mode_rows,
        "trials": trial_rows,
        "input_raw_sha256": raw_hashes,
        "source_sha256": source_hashes,
    }
    analysis_root.joinpath("report.json").write_text(json.dumps(report))
    return raw_root, config_path, analysis_root, source_hashes


def test_verifier_recomputes_saved_transition_metrics_from_private_labels(tmp_path):
    raw_root, config_path, analysis_root, expected_sources = _make_valid_bundle(tmp_path)

    receipt = verifier.verify_bundle(
        raw_root, config_path, analysis_root, expected_source_hashes=expected_sources
    )

    assert receipt["raw_files_verified"] == 48
    assert receipt["prediction_trials_verified"] == 6
    assert receipt["positive_controls_passed"] is True
    assert receipt["recomputed_auc_mean"] == {mode: 1.0 for mode in MODES}


def test_verifier_rejects_target_labels_embedded_in_prediction_artifacts(tmp_path):
    raw_root, config_path, analysis_root, expected_sources = _make_valid_bundle(tmp_path)
    path = analysis_root / "predictions/oram/trial-00.json.gz"
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        artifact = json.load(stream)
    artifact["labels"] = [1, 0] * 4
    with gzip.open(path, "wt", encoding="utf-8") as stream:
        json.dump(artifact, stream)

    with pytest.raises(ValueError, match="prediction artifact fields"):
        verifier.verify_bundle(
            raw_root, config_path, analysis_root, expected_source_hashes=expected_sources
        )


def test_verifier_rejects_scores_that_do_not_reproduce_reported_metrics(tmp_path):
    raw_root, config_path, analysis_root, expected_sources = _make_valid_bundle(tmp_path)
    path = analysis_root / "predictions/oram/trial-00.json.gz"
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        artifact = json.load(stream)
    artifact["scores"][0] = 0.1
    artifact["predictions"][0] = 0
    with gzip.open(path, "wt", encoding="utf-8") as stream:
        json.dump(artifact, stream)

    with pytest.raises(ValueError, match="reported trial"):
        verifier.verify_bundle(
            raw_root, config_path, analysis_root, expected_source_hashes=expected_sources
        )


def test_verifier_accepts_control_failure_without_scoring_oram(tmp_path):
    raw_root, config_path, analysis_root, expected_sources = _make_valid_bundle(
        tmp_path, control_gate=False
    )

    receipt = verifier.verify_bundle(
        raw_root, config_path, analysis_root, expected_source_hashes=expected_sources
    )

    assert receipt["positive_controls_passed"] is False
    assert receipt["defense_evaluated"] is False
    assert "oram" not in receipt["recomputed_auc_mean"]
