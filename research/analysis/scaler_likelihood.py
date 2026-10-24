"""Evaluate a known-policy Poisson/DP-filter attack on autoscaler traces."""

import argparse
import gzip
import hashlib
import json
import math
from pathlib import Path
import platform
import subprocess
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from research.attacks.scaler_likelihood import (  # noqa: E402
    CappedNoiseLikelihoodAttack,
    capped_noise_pmf,
)
from research.simulation.run import score  # noqa: E402
from research.simulation.scaler import (  # noqa: E402
    Config,
    Request,
    bounded_arrival_counts,
    dp_laplace_parameters,
    features,
    trial_interval,
    validate_requests,
)


INPUT_FILES = ("config.json", "observer.jsonl.gz", "workloads-private.jsonl.gz")
STUDY_FIELDS = {
    "version", "study_id", "dp_noise_source", "trials", "sessions",
    "profile_sessions", "target_sessions", "tasks", "particles",
    "sampler_seed", "primary_metric", "positive_control_min",
}


def read_jsonl(path):
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        return [json.loads(line) for line in stream]


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _study_config(path, raw, noise_source):
    config = json.loads(Path(path).read_text())
    if (not isinstance(config, dict) or set(config) != STUDY_FIELDS
            or type(config["version"]) is not int or config["version"] != 1
            or not isinstance(config["study_id"], str) or not config["study_id"]
            or config["dp_noise_source"] != noise_source
            or noise_source != "os_csprng"
            or config["trials"] != raw.get("trials")
            or config["sessions"] != raw.get("sessions")
            or config["profile_sessions"] != config["sessions"] // 2
            or config["target_sessions"] != config["sessions"] - config["profile_sessions"]
            or config["primary_metric"] != "balanced_accuracy"
            or not isinstance(config["tasks"], list) or not config["tasks"]
            or any(task not in ("intensity", "hot") for task in config["tasks"])
            or len(set(config["tasks"])) != len(config["tasks"])
            or type(config["particles"]) is not int
            or not 100 <= config["particles"] <= 1_000_000
            or type(config["sampler_seed"]) is not int or config["sampler_seed"] < 0
            or type(config["positive_control_min"]) not in (int, float)
            or not 0 <= config["positive_control_min"] <= 1):
        raise ValueError("invalid or mismatched predeclared likelihood study config")
    return config


def _raw_count_matrix(request_rows, cfg):
    requests = [Request(**row) for row in request_rows]
    validate_requests(requests, cfg)
    horizon = math.ceil(cfg.duration / cfg.epoch)
    counts = np.zeros((horizon, cfg.functions), dtype=np.int64)
    for request in requests:
        epoch = min(horizon - 1,
                    max(0, math.ceil(request.time / cfg.epoch) - 1))
        counts[epoch, request.function] += 1
    return counts.tolist()


def _records(source, raw, cfg):
    policies = ("naive", "dp_laplace")
    expected = {
        (trial, session, workload, policy)
        for trial in range(raw["trials"])
        for session in range(raw["sessions"])
        for workload in raw["workloads"]
        for policy in policies
    }
    observers = {}
    for record in read_jsonl(source / "observer.jsonl.gz"):
        if (not isinstance(record, dict)
                or set(record) != {"trial", "session", "workload", "policy", "rows"}):
            raise ValueError("invalid public observer record")
        key = (record["trial"], record["session"], record["workload"], record["policy"])
        if key not in expected or key in observers:
            if record.get("policy") in policies:
                raise ValueError("duplicate or out-of-range public session")
            continue
        rows = record["rows"]
        if not isinstance(rows, list) or len(rows) != math.ceil(cfg.duration / cfg.epoch):
            raise ValueError("observer session does not cover the fixed horizon")
        for epoch, row in enumerate(rows):
            features(row)
            if type(row.get("epoch")) is not int or row["epoch"] != epoch:
                raise ValueError("observer epochs must be contiguous and ordered")
        observers[key] = rows
    if set(observers) != expected:
        raise ValueError("incomplete naive/DP observer sessions")

    truth_expected = {
        (trial, session, workload)
        for trial in range(raw["trials"])
        for session in range(raw["sessions"])
        for workload in raw["workloads"]
    }
    truths = {}
    for record in read_jsonl(source / "workloads-private.jsonl.gz"):
        if (not isinstance(record, dict)
                or set(record) != {"trial", "session", "workload", "seed", "labels", "requests"}):
            raise ValueError("invalid private workload record")
        key = (record["trial"], record["session"], record["workload"])
        if key not in truth_expected or key in truths:
            raise ValueError("duplicate or out-of-range private workload session")
        if (not isinstance(record["labels"], list)
                or len(record["labels"]) != math.ceil(cfg.duration / cfg.epoch)
                or not isinstance(record["requests"], list)):
            raise ValueError("private workload session has invalid shape")
        validate_requests([Request(**request) for request in record["requests"]], cfg)
        truths[key] = record
    if set(truths) != truth_expected:
        raise ValueError("incomplete private workload sessions")
    return observers, truths


def _session_id(trial, session, workload):
    return f"trial-{trial}:session-{session}:workload-{workload}"


def _score_mode(profile, target, task, mode, cfg, pmf, study, seed):
    attack = CappedNoiseLikelihoodAttack(task).fit(profile)
    predictions = []
    truths = []
    for target_record in target:
        session_id = target_record["session_id"]
        if mode == "plaintext_counts":
            log_scores = attack.score_visible_counts(
                target_record["raw_counts"], session_id,
            )
        elif mode == "dp_laplace":
            log_scores = attack.score_dp_observer(
                target_record["observer"], session_id, cfg, pmf,
                particles=study["particles"], seed=seed,
            )
        else:
            raise ValueError("unknown likelihood observer mode")
        prediction = max(log_scores, key=log_scores.get)
        predictions.extend([prediction] * len(target_record["labels"]))
        truths.extend(label[task] for label in target_record["labels"])
        target_record["prediction_record"] = {
            "trial": target_record["trial"], "session": target_record["session"],
            "workload": target_record["workload"], "policy": mode,
            "prediction": prediction,
            "class_log_likelihoods": {
                str(key): value if math.isfinite(value) else None
                for key, value in log_scores.items()
            },
            "nonfinite_classes": [key for key, value in log_scores.items()
                                  if not math.isfinite(value)],
            "likelihood_method": "exact Poisson count likelihood" if mode == "plaintext_counts"
                else "bootstrap particle filter; Monte Carlo likelihood estimate",
        }
    majority = int(np.bincount(np.concatenate([
        np.asarray([label[task] for label in session["labels"]])
        for session in profile
    ])).argmax())
    return score(np.asarray(predictions), np.asarray(truths), majority)


def _summarize(rows):
    result = []
    keys = sorted({(row["workload"], row["task"], row["policy"]) for row in rows})
    for workload, task, policy in keys:
        group = [row for row in rows if
                 (row["workload"], row["task"], row["policy"])
                 == (workload, task, policy)]
        result.append({
            "workload": workload, "task": task, "policy": policy,
            "independent_trials": len(group),
            "balanced_accuracy": float(np.mean([row["balanced_accuracy"] for row in group])),
            "balanced_accuracy_ci95": trial_interval(
                [[row["balanced_accuracy"]] for row in group]),
            "accuracy": float(np.mean([row["accuracy"] for row in group])),
            "majority_accuracy": float(np.mean([row["majority_accuracy"] for row in group])),
            "chance_balanced_accuracy": 0.5,
        })
    return result


def _plot_summary(output, summary):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    panels = sorted({(row["workload"], row["task"]) for row in summary})
    fig, axes = plt.subplots(1, len(panels), figsize=(max(6, 2.5 * len(panels)), 4),
                             squeeze=False)
    colors = {"plaintext_counts": "#4477aa", "noiseless_scaler": "#228833",
              "dp_laplace": "#cc6677"}
    for axis, (workload, task) in zip(axes[0], panels):
        rows = [row for row in summary
                if row["workload"] == workload and row["task"] == task]
        means = [row["balanced_accuracy"] for row in rows]
        lower = [max(0, mean - row["balanced_accuracy_ci95"][0])
                 for mean, row in zip(means, rows)]
        upper = [max(0, row["balanced_accuracy_ci95"][1] - mean)
                 for mean, row in zip(means, rows)]
        axis.bar(range(len(rows)), means,
                 color=[colors.get(row["policy"], "#999999") for row in rows],
                 yerr=[lower, upper], capsize=2)
        axis.axhline(0.5, color="black", linestyle="--", linewidth=0.8)
        axis.set_xticks(range(len(rows)),
                        [row["policy"].replace("_", "\n") for row in rows],
                        rotation=35, ha="right", fontsize=7)
        axis.set_ylim(0, 1)
        axis.set_title(f"{workload}: {task}")
        axis.set_ylabel("Balanced accuracy")
    fig.suptitle("CSPRNG autoscaler likelihood attack")
    fig.tight_layout()
    fig.savefig(output / "balanced-accuracy.png", dpi=160)
    plt.close(fig)


def evaluate(source, output, study_config):
    source = Path(source).resolve()
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError("choose a fresh analysis output directory")
    input_hashes = {name: _sha(source / name) for name in INPUT_FILES}
    raw = json.loads((source / "config.json").read_text())
    noise_source = raw.get("dp_noise_source", "seeded_experiment")
    study = _study_config(study_config, raw, noise_source)
    cfg = Config(**raw["simulation"])
    cfg.validate()
    if (cfg.functions != 2 or not isinstance(raw.get("workloads"), list)
            or not isinstance(raw.get("trials"), int)
            or not isinstance(raw.get("sessions"), int)
            or "naive" not in raw.get("policies", [])
            or "dp_laplace" not in raw.get("policies", [])):
        raise ValueError("likelihood analysis needs a two-pool CSPRNG run and both policies")
    observers, truths = _records(source, raw, cfg)
    params = dp_laplace_parameters(cfg)
    pmf = capped_noise_pmf(params["geometric_cap"],
                           params["geometric_numerator"],
                           params["geometric_denominator"])

    trial_rows = []
    prediction_records = []
    # The clear per-function count control is completed and checked first.
    for trial in range(raw["trials"]):
        for workload_index, workload in enumerate(raw["workloads"]):
            sessions = []
            for session in range(raw["sessions"]):
                truth = truths[(trial, session, workload)]
                requests = truth["requests"]
                typed = [Request(**request) for request in requests]
                sessions.append({
                    "session": session,
                    "session_id": _session_id(trial, session, workload),
                    "trial": trial, "workload": workload,
                    "labels": truth["labels"],
                    "raw_counts": _raw_count_matrix(requests, cfg),
                    "dp_counts": bounded_arrival_counts(typed, cfg).tolist(),
                    "observer": observers[(trial, session, workload, "dp_laplace")],
                })
            split = study["profile_sessions"]
            profile, target = sessions[:split], sessions[split:]
            tasks = [task for task in study["tasks"]
                     if task != "hot" or workload != "uniform"]
            for task_index, task in enumerate(tasks):
                profile_control = [{
                    "session_id": session["session_id"],
                    "labels": session["labels"],
                    "arrival_counts": session["raw_counts"],
                } for session in profile]
                target_control = [{
                    **session,
                    "observer": observers[(trial, session["session"], workload, "naive")],
                } for session in target]
                control = _score_mode(profile_control, target_control, task,
                                      "plaintext_counts", cfg, pmf, study, 0)
                trial_rows.append(dict(trial=trial, workload=workload, task=task,
                    policy="plaintext_counts", **control))
                prediction_records.extend(
                    session.pop("prediction_record") for session in target_control)
    control_summary = [row for row in _summarize(trial_rows)
                       if row["policy"] == "plaintext_counts"]
    controls = [{
        "workload": row["workload"], "task": row["task"],
        "balanced_accuracy": row["balanced_accuracy"],
        "ci95": row["balanced_accuracy_ci95"],
        "passed": row["balanced_accuracy"] >= study["positive_control_min"]
            and row["balanced_accuracy_ci95"][0] > 0.5,
    } for row in control_summary]
    positive_controls_passed = bool(controls) and all(row["passed"] for row in controls)

    if positive_controls_passed:
        for trial in range(raw["trials"]):
            for workload_index, workload in enumerate(raw["workloads"]):
                sessions = []
                for session in range(raw["sessions"]):
                    truth = truths[(trial, session, workload)]
                    typed = [Request(**request) for request in truth["requests"]]
                    sessions.append({
                        "session": session,
                        "session_id": _session_id(trial, session, workload),
                        "trial": trial, "workload": workload,
                        "labels": truth["labels"],
                        "arrival_counts": bounded_arrival_counts(typed, cfg).tolist(),
                        "observer": observers[(trial, session, workload, "dp_laplace")],
                    })
                split = study["profile_sessions"]
                profile, target = sessions[:split], sessions[split:]
                tasks = [task for task in study["tasks"]
                         if task != "hot" or workload != "uniform"]
                for task_index, task in enumerate(tasks):
                    profile_dp = [{
                        "session_id": session["session_id"],
                        "labels": session["labels"],
                        "arrival_counts": session["arrival_counts"],
                    } for session in profile]
                    target_dp = [{**session,
                        "session_id": session["session_id"]}
                        for session in target]
                    seed_words = np.random.SeedSequence([
                        study["sampler_seed"], trial, workload_index,
                        task_index,
                    ]).generate_state(1)
                    scores = _score_mode(
                        profile_dp, target_dp, task, "dp_laplace", cfg, pmf,
                        study, int(seed_words[0]),
                    )
                    trial_rows.append(dict(trial=trial, workload=workload,
                        task=task, policy="dp_laplace", **scores))
                    prediction_records.extend(
                        session.pop("prediction_record") for session in target_dp)

    if input_hashes != {name: _sha(source / name) for name in INPUT_FILES}:
        raise ValueError("raw source artifacts changed during evaluation")
    source_files = [
        "research/analysis/scaler_likelihood.py",
        "research/attacks/scaler_likelihood.py",
        "research/simulation/scaler.py",
        "research/simulation/run.py",
    ]
    report = {
        "study_configuration": study,
        "study_config_sha256": _sha(study_config),
        "input_sha256": input_hashes,
        "source_sha256": {name: _sha(ROOT / name) for name in source_files},
        "git_head": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "python": platform.python_version(), "platform": platform.platform(),
        "primary_metric": "balanced_accuracy",
        "dp_noise_source": noise_source,
        "positive_controls_passed": positive_controls_passed,
        "positive_controls": controls,
        "dp_policy_evaluated": positive_controls_passed,
        "summary": _summarize(trial_rows),
        "trial_metrics": trial_rows,
        "particle_filter_health": {
            "target_sessions_scored": sum(
                row["policy"] == "dp_laplace" for row in prediction_records),
            "class_scores": sum(
                len(row["class_log_likelihoods"])
                for row in prediction_records if row["policy"] == "dp_laplace"),
            "nonfinite_class_scores": sum(
                len(row["nonfinite_classes"])
                for row in prediction_records if row["policy"] == "dp_laplace"),
            "sessions_with_all_class_scores_nonfinite": sum(
                len(row["nonfinite_classes"]) == 2
                for row in prediction_records if row["policy"] == "dp_laplace"),
            "particle_count": study["particles"],
        },
        "attacker_model": "class-conditional independent Poisson arrivals with Gamma(0.5, 0.5) smoothed rates; DP mode uses a bootstrap particle filter over exact finite capped-noise PMF",
        "attacker_knowledge": "Public scaler configuration and policy; four labeled whole profiling sessions per trial; target uses only public instance-count rows for DP and clear per-pool counts for the plaintext positive control. Target labels are used only after predictions are fixed.",
        "uncertainty": "95% percentile bootstrap intervals over independent trial-level balanced-accuracy scores; particle-filter Monte Carlo likelihood estimates are conditioned on the recorded particle count and sampler seed.",
        "limitations": "Synthetic Poisson-thinned workloads; small whole-session profile set; approximate particle likelihood can degenerate to zero under rare transcripts; independent per-pool model omits cross-pool dependence; this is not an optimal attack, a DP audit, or a privacy proof. The positive control exposes exact per-pool counts.",
    }
    output.mkdir(parents=True)
    (output / "study-config.json").write_text(json.dumps(study, indent=2) + "\n")
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    (output / "predictions.json").write_text(json.dumps(prediction_records, indent=2) + "\n")
    _plot_summary(output, report["summary"])
    manifest = {path.name: _sha(path) for path in output.iterdir() if path.is_file()}
    (output / "artifact-sha256.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("raw_source", type=Path)
    parser.add_argument("new_output", type=Path)
    parser.add_argument("--study-config", type=Path, required=True)
    args = parser.parse_args()
    result = evaluate(args.raw_source, args.new_output, args.study_config)
    print(json.dumps({"positive_controls_passed": result["positive_controls_passed"],
                      "summaries": len(result["summary"]),
                      "dp_policy_evaluated": result["dp_policy_evaluated"]}, indent=2))
