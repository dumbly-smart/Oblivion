"""Independent Path ORAM timing study with fresh workloads and positive controls."""
import argparse
from collections import Counter, defaultdict
import gzip
import hashlib
import json
from pathlib import Path
import platform
import math
import subprocess
import tempfile
import time

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, balanced_accuracy_score, roc_auc_score

ROOT = Path(__file__).resolve().parents[2]
MODES = ("plaintext", "encrypt_only", "oram")


def collapse_accesses(session, events, private, hot_addresses=(0,)):
    """Collapse one fixed Path ORAM/control access to a labeled-free observer row."""
    if not isinstance(session, str) or not 1 <= len(session) <= 128:
        raise ValueError("invalid observer session identifier")
    if not isinstance(events, list) or not events or not isinstance(private, list) or not private:
        raise ValueError("non-empty observer events and private labels are required")
    by_step = defaultdict(list)
    for event in events:
        if (not isinstance(event, dict)
                or set(event) != {"step", "direction", "bucket", "bytes", "service_ns"}
                or type(event["step"]) is not int or event["step"] < 0
                or event["direction"] not in ("read", "write")
                or any(type(event[key]) is not int or event[key] < 0
                       for key in ("bucket", "bytes", "service_ns"))
                or event["bytes"] == 0):
            raise ValueError("strict isolated observer event schema required")
        by_step[event["step"]].append(event)
    if len(by_step) != len(private) or set(by_step) != set(range(len(private))):
        raise ValueError("one contiguous observer group per private operation required")
    rows, labels = [], []
    for step, private_row in enumerate(private):
        required = {"step", "logical_address", "write", "oracle_verified", "latency_ns"}
        if (not isinstance(private_row, dict)
                or not required <= set(private_row)
                or set(private_row) - required - {"stash"}
                or private_row["step"] != step
                or type(private_row["logical_address"]) is not int
                or private_row["logical_address"] < 0
                or type(private_row["write"]) is not bool
                or type(private_row["oracle_verified"]) is not bool
                or type(private_row["latency_ns"]) is not int
                or private_row["latency_ns"] < 0
                or private_row["oracle_verified"] == private_row["write"]
                or ("stash" in private_row and
                    (type(private_row["stash"]) is not int or private_row["stash"] < 0))):
            raise ValueError("strict private driver schema required")
        access = by_step[step]
        if len(access) < 2 or len(access) % 2:
            raise ValueError("each access must contain equal read and write paths")
        half = len(access) // 2
        reads, writes = access[:half], access[half:]
        if ([event["direction"] for event in reads] != ["read"] * half
                or [event["direction"] for event in writes] != ["write"] * half
                or [event["bucket"] for event in reads] != [event["bucket"] for event in writes]):
            raise ValueError("read and write paths must have identical visible shape")
        rows.append({
            "session": session,
            "step": step,
            "tag": reads[-1]["bucket"],
            "bytes": sum(event["bytes"] for event in access),
            "latency_ns": sum(event["service_ns"] for event in access),
        })
        labels.append(int(private_row["logical_address"] in hot_addresses))
    return rows, labels


def feature_rows(rows):
    """Build unlabeled tag-frequency and short-window temporal features."""
    grouped = defaultdict(list)
    for row in rows:
        if (not isinstance(row, dict)
                or set(row) != {"session", "step", "tag", "bytes", "latency_ns"}
                or not isinstance(row["session"], str)
                or any(type(row[key]) is not int or row[key] < 0
                       for key in ("step", "tag", "bytes", "latency_ns"))):
            raise ValueError("strict attacker-visible operation rows required")
        grouped[row["session"]].append(row)
    matrix = []
    for session in sorted(grouped):
        ordered = sorted(grouped[session], key=lambda row: row["step"])
        if [row["step"] for row in ordered] != list(range(len(ordered))):
            raise ValueError("attacker-visible steps must be contiguous")
        tags = [row["tag"] for row in ordered]
        frequencies = Counter(tags)
        for index, row in enumerate(ordered):
            recent = tags[max(0, index - 15):index]
            features = [
                frequencies[row["tag"]] / len(ordered),
                row["tag"],
                row["bytes"],
                np.log1p(row["latency_ns"]),
                sum(tag == row["tag"] for tag in recent),
            ]
            for lag in range(1, 5):
                prev = ordered[index - lag] if index >= lag else None
                features.extend([
                    prev["tag"] if prev else -1,
                    np.log1p(prev["latency_ns"]) if prev else 0.0,
                ])
            for width in (4, 8, 16):
                window = ordered[max(0, index - width + 1):index + 1]
                features.extend([
                    len({item["tag"] for item in window}) / len(window),
                    float(np.mean([np.log1p(item["latency_ns"]) for item in window])),
                ])
            matrix.append(features)
    return np.asarray(matrix, dtype=float)


class TemporalLeafTimingAttack:
    """Bounded nonlinear per-access classifier with whole-session disjointness."""
    def fit(self, trace, labels):
        if len(trace) != len(labels) or set(labels) != {0, 1}:
            raise ValueError("both labeled classes are required for profiling")
        self.profile_sessions = {row["session"] for row in trace}
        self.model = RandomForestClassifier(
            n_estimators=128, max_depth=8, min_samples_leaf=5,
            class_weight="balanced", random_state=1907, n_jobs=1,
        ).fit(feature_rows(trace), labels)
        return self

    def run(self, trace, target_sessions):
        sessions = {row["session"] for row in trace}
        if not hasattr(self, "model") or not target_sessions or sessions != set(target_sessions):
            raise ValueError("target whole-session identifiers must match observer rows")
        if sessions & self.profile_sessions:
            raise ValueError("profiling and target sessions must be disjoint")
        matrix = feature_rows(trace)
        return self.model.predict(matrix).tolist(), self.model.predict_proba(matrix)[:, 1].tolist()


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            value.update(block)
    return value.hexdigest()


def bootstrap_interval(values, seed, replicates=5000):
    data = np.asarray(values, dtype=float)
    if data.size < 2:
        return [float(data.mean()), float(data.mean())]
    rng = np.random.default_rng(seed)
    means = np.asarray([
        rng.choice(data, size=len(data), replace=True).mean()
        for _ in range(replicates)
    ])
    return [float(np.quantile(means, 0.025)), float(np.quantile(means, 0.975))]


def load_trial(raw_root, mode, trial, sessions, hot_addresses):
    rows, labels, ids = [], [], []
    for session_number in range(sessions):
        session = f"{mode}-trial-{trial:02}-session-{session_number:02}"
        directory = raw_root / mode / f"trial-{trial:02}"
        event_path = directory / f"observer-{session_number:02}.jsonl.gz"
        private_path = directory / f"driver-{session_number:02}.jsonl.gz"
        with gzip.open(event_path, "rt", encoding="utf-8") as stream:
            events = [json.loads(line) for line in stream]
        with gzip.open(private_path, "rt", encoding="utf-8") as stream:
            private = [json.loads(line) for line in stream]
        operation_rows, operation_labels = collapse_accesses(
            session, events, private, hot_addresses
        )
        rows.extend(operation_rows)
        labels.extend(operation_labels)
        ids.append(session)
    return rows, labels, ids


def workload_signature(private, address_count):
    if not private:
        raise ValueError("non-empty private schedule required")
    signature = []
    for step, row in enumerate(private):
        if (row.get("step") != step or type(row.get("logical_address")) is not int
                or row["logical_address"] < 0 or row["logical_address"] >= address_count
                or type(row.get("write")) is not bool):
            raise ValueError("invalid private workload schedule")
        signature.append((row["step"], row["logical_address"], row["write"]))
    return tuple(signature)


def require_paired_schedules(private_sequences, address_count=2):
    if len(private_sequences) < 2:
        raise ValueError("at least two paired workloads required")
    signatures = [workload_signature(rows, address_count) for rows in private_sequences]
    if any(signature != signatures[0] for signature in signatures[1:]):
        raise ValueError("seeded workload schedules differ between configurations")


def verify_paired_schedules(raw_root, modes, trials, sessions, address_count=2):
    for trial in range(trials):
        for session in range(sessions):
            sequences = []
            for mode in modes:
                path = raw_root / mode / f"trial-{trial:02}" / f"driver-{session:02}.jsonl.gz"
                with gzip.open(path, "rt", encoding="utf-8") as stream:
                    sequences.append([json.loads(line) for line in stream])
            require_paired_schedules(sequences, address_count)


def capture_mode(mode, config, binaries, output, temporary):
    executable = binaries["oram"] if mode == "oram" else binaries["control"]
    result_root = output / "raw" / mode
    result_root.mkdir(parents=True)
    manifest = []
    for trial in range(config["trials"]):
        run_config = {
            "version": 1, "blocks": config["blocks"],
            "bucket_capacity": config["bucket_capacity"],
            "block_bytes": config["block_bytes"],
            "operations": config["operations"], "warmup": config["warmup"],
            "trials": config["sessions_per_trial"],
            "seed": config["seed"] + trial * config["sessions_per_trial"],
            "workload": "markov_distribution" if config.get("address_persistence", 0.0) > 0.0
            else "configured_distribution",
            "address_persistence": config.get("address_persistence", 0.0),
            "address_distribution": config["address_distribution"],
            "hot_addresses": config["hot_addresses"],
            "read_probability": config["read_probability"],
        }
        if mode == "oram":
            run_config["backend"] = "isolated_process"
        config_path = temporary / f"{mode}-{trial:02}.json"
        config_path.write_text(json.dumps(run_config, sort_keys=True))
        run_output = temporary / f"{mode}-output-{trial:02}"
        if mode == "oram":
            command = [str(executable), str(config_path), str(run_output)]
        else:
            command = [str(executable), mode, str(config_path), str(run_output)]
        subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)
        metadata = json.loads((run_output / "isolated-service.json").read_text())
        manifest.append(metadata)
        trial_dir = result_root / f"trial-{trial:02}"
        trial_dir.mkdir()
        for session in range(config["sessions_per_trial"]):
            event_source = run_output / f"isolated-observer-{session}.jsonl"
            driver_source = run_output / f"private-{session}.jsonl"
            with event_source.open(encoding="utf-8") as source, gzip.open(
                trial_dir / f"observer-{session:02}.jsonl.gz", "wt", encoding="utf-8"
            ) as destination:
                for line in source:
                    destination.write(line)
            with driver_source.open(encoding="utf-8") as source, gzip.open(
                trial_dir / f"driver-{session:02}.jsonl.gz", "wt", encoding="utf-8"
            ) as destination:
                for line in source:
                    destination.write(line)
    return manifest


def evaluate_mode(mode, raw_root, config):
    trials = []
    predictions_dir = raw_root.parent / "predictions" / mode
    predictions_dir.mkdir(parents=True, exist_ok=True)
    for trial in range(config["trials"]):
        rows, labels, session_ids = load_trial(
            raw_root, mode, trial, config["sessions_per_trial"], config["hot_addresses"]
        )
        profile_count = config["sessions_per_trial"] // 2
        profile_ids, target_ids = set(session_ids[:profile_count]), set(session_ids[profile_count:])
        profile_rows = [row for row in rows if row["session"] in profile_ids]
        target_rows = [row for row in rows if row["session"] in target_ids]
        profile_labels = [label for row, label in zip(rows, labels) if row["session"] in profile_ids]
        target_labels = [label for row, label in zip(rows, labels) if row["session"] in target_ids]
        attack = TemporalLeafTimingAttack().fit(profile_rows, profile_labels)
        predicted, scores = attack.run(target_rows, target_ids)
        majority = int(np.mean(profile_labels) >= 0.5)
        row = {
            "trial": trial, "mode": mode,
            "accuracy": float(accuracy_score(target_labels, predicted)),
            "balanced_accuracy": float(balanced_accuracy_score(target_labels, predicted)),
            "auc": float(roc_auc_score(target_labels, scores)),
            "profile_majority_accuracy": float(accuracy_score(target_labels, [majority] * len(target_labels))),
            "profile_sessions": sorted(profile_ids), "target_sessions": sorted(target_ids),
            "observations": len(target_labels),
        }
        trials.append(row)
        with gzip.open(predictions_dir / f"trial-{trial:02}.json.gz", "wt", encoding="utf-8") as stream:
            json.dump({"target_sessions": sorted(target_ids), "predictions": predicted,
                       "scores_uncalibrated": scores}, stream)
    summary = {
        "mode": mode, "trials": len(trials),
        "auc_mean": float(np.mean([row["auc"] for row in trials])),
        "auc_ci95_trials": bootstrap_interval([row["auc"] for row in trials], config["seed"] + 47),
        "balanced_accuracy_mean": float(np.mean([row["balanced_accuracy"] for row in trials])),
        "balanced_accuracy_ci95_trials": bootstrap_interval(
            [row["balanced_accuracy"] for row in trials], config["seed"] + 53
        ),
        "profile_majority_accuracy_mean": float(
            np.mean([row["profile_majority_accuracy"] for row in trials])
        ),
    }
    return summary, trials


def run(config_path, output, oram_binary, control_binary):
    started = time.time()
    config = json.loads(Path(config_path).read_text())
    distribution = config.get("address_distribution", {"0": 0.75, "1": 0.25})
    hot_addresses = config.get("hot_addresses", [0])
    read_probability = config.get("read_probability", 0.5)
    address_persistence = config.get("address_persistence", 0.0)
    try:
        numeric_distribution = {int(address): weight for address, weight in distribution.items()}
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError("address_distribution must map contiguous address ids to weights") from error
    if (config.get("trials") != 30 or config.get("sessions_per_trial") != 8
            or config.get("primary_metric") != "roc_auc"
            or config.get("positive_control_ci_lower_must_exceed") != 0.5
            or config.get("positive_control_min_mean_auc", 0) <= 0.5
            or not isinstance(read_probability, (int, float))
            or isinstance(read_probability, bool)
            or not math.isfinite(read_probability)
            or not 0.0 <= read_probability <= 1.0
            or not isinstance(address_persistence, (int, float))
            or isinstance(address_persistence, bool)
            or not math.isfinite(address_persistence)
            or not 0.0 <= address_persistence <= 1.0
            or not isinstance(hot_addresses, list) or not hot_addresses
            or any(type(address) is not int for address in hot_addresses)
            or sorted(numeric_distribution) != list(range(len(numeric_distribution)))
            or any(not isinstance(weight, (int, float)) or isinstance(weight, bool)
                   or not math.isfinite(weight) or weight <= 0 for weight in numeric_distribution.values())
            or not math.isclose(sum(numeric_distribution.values()), 1.0, abs_tol=1e-12)
            or any(address not in numeric_distribution for address in hot_addresses)
            or len(set(hot_addresses)) != len(hot_addresses)):
        raise ValueError("recorded study requires 30 trials, eight sessions and the declared primary metric")
    hot_mass = sum(numeric_distribution[address] for address in hot_addresses)
    if not 0.0 < hot_mass < 1.0:
        raise ValueError("hot/cold labels must both have nonzero probability")
    config["address_distribution"] = {str(address): numeric_distribution[address]
                                      for address in sorted(numeric_distribution)}
    config["hot_addresses"] = sorted(hot_addresses)
    config["read_probability"] = read_probability
    config["address_persistence"] = address_persistence
    output = Path(output)
    if output.exists():
        raise ValueError("output directory must be new to preserve raw data")
    output.mkdir(parents=True)
    (output / "config.json").write_text(json.dumps(config, indent=2) + "\n")
    (output / "predictions").mkdir()
    all_trials, summaries, process_metadata = [], [], {}
    with tempfile.TemporaryDirectory(prefix="oblivion-oram-replication-") as temporary_name:
        temporary = Path(temporary_name)
        binaries = {"oram": Path(oram_binary).resolve(), "control": Path(control_binary).resolve()}
        for mode in ("plaintext", "encrypt_only"):
            process_metadata[mode] = capture_mode(mode, config, binaries, output, temporary)
        verify_paired_schedules(
            output / "raw", ("plaintext", "encrypt_only"),
            config["trials"], config["sessions_per_trial"], len(numeric_distribution),
        )
        for mode in ("plaintext", "encrypt_only"):
            summary, trials = evaluate_mode(mode, output / "raw", config)
            summaries.append(summary)
            all_trials.extend(trials)
        control_passed = all(
            summary["auc_mean"] >= config["positive_control_min_mean_auc"]
            and summary["auc_ci95_trials"][0] > 0.5
            for summary in summaries
        )
        if not control_passed:
            report = {
                "configuration": config, "summary": summaries, "trials": all_trials,
                "positive_controls_passed": False,
                "defense_evaluated": False,
                "interpretation": "Positive controls did not clear the preregistered criterion; no ORAM defense result was evaluated.",
            }
            (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            return report
        process_metadata["oram"] = capture_mode("oram", config, binaries, output, temporary)
        verify_paired_schedules(
            output / "raw", MODES, config["trials"], config["sessions_per_trial"],
            len(numeric_distribution),
        )
        summary, trials = evaluate_mode("oram", output / "raw", config)
        summaries.append(summary)
        all_trials.extend(trials)
    inputs = [
        Path(__file__), ROOT / "research/attacks/leaf_timing.py",
        Path(oram_binary), Path(control_binary), Path(config_path),
    ]
    source_hashes = {str(path.resolve().relative_to(ROOT)) if path.resolve().is_relative_to(ROOT) else path.name: digest(path)
                     for path in inputs}
    raw_hashes = {
        str(path.relative_to(output)): digest(path)
        for path in sorted((output / "raw").rglob("*.jsonl.gz"))
    }
    if not raw_hashes:
        raise RuntimeError("experiment completed without retained raw sessions")
    report = {
        "configuration": config, "summary": summaries, "trials": all_trials,
        "positive_controls_passed": True,
        "defense_evaluated": True,
        "primary_metric": config["primary_metric"],
        "attack_features": [
            "within-session frequency of visible bucket leaf/address",
            "visible leaf/address identifier",
            "aggregate fixed-shape bytes per logical access",
            "bucket-handler-only service time",
            "previous four visible identifiers and service times",
            "recent visible identifier repetition and 4/8/16-access windows",
        ],
        "attacker_knowledge": "Labeled complete plaintext/encrypt-only profiling sessions; unlabeled whole target sessions; no private operation labels during fit/prediction.",
        "target_labels": f"logical address in configured hot set {config['hot_addresses']} versus remaining logical addresses",
        "attacker_model": "RandomForestClassifier(n_estimators=128, max_depth=8, min_samples_leaf=5, class_weight=balanced, random_state=1907, n_jobs=1)",
        "methodology": f"30 seeded attack trials per mode; each trial uses four complete profile sessions and four disjoint target sessions, eight sessions total. The same seeded hot/cold and read/write workload (read probability {read_probability}) is run in every mode; each session has fresh process state and fresh ORAM state or AEAD key. Primary metric is AUC; intervals bootstrap the 30 fitted-trial means. All baseline controls are run and scored before ORAM.",
        "timing_scope": "Local separate bucket-service process; handler-only time excludes pipe waiting, Path ORAM controller work, request parsing and response encoding. Not remote timing.",
        "limitations": "Synthetic configured address distribution; local process IPC and in-memory bucket service; only short-window temporal features; one binary classifier family. Each reported result applies only to its configured address universe and hot/cold partition. This is not a cryptographic security proof, remote-network experiment, or general workload result.",
        "process_metadata": process_metadata,
        "source_sha256": source_hashes,
        "raw_session_sha256": raw_hashes,
        "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "git_status": subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True),
        "python": __import__("sys").version, "platform": platform.platform(),
        "numpy": np.__version__, "scikit_learn": __import__("sklearn").__version__,
        "cpu": platform.processor(), "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
        "elapsed_seconds": time.time() - started,
    }
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(7, 4))
    labels = [row["mode"] for row in summaries]
    means = [row["auc_mean"] for row in summaries]
    intervals = [row["auc_ci95_trials"] for row in summaries]
    lower = [mean - interval[0] for mean, interval in zip(means, intervals)]
    upper = [interval[1] - mean for mean, interval in zip(means, intervals)]
    ax.bar(labels, means, yerr=[lower, upper], capsize=4)
    ax.axhline(0.5, color="gray", linestyle="--")
    ax.set(ylabel="AUC (primary metric)", ylim=(0, 1.05))
    fig.tight_layout()
    fig.savefig(output / "auc.png", dpi=150)
    plt.close(fig)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "experiments/configs/oram-isolated-replication.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--oram-binary", type=Path, default=ROOT / "target/release/examples/oram-measure")
    parser.add_argument("--control-binary", type=Path, default=ROOT / "target/release/examples/oram-control")
    args = parser.parse_args()
    report = run(args.config, args.output, args.oram_binary, args.control_binary)
    print(json.dumps({"output": str(args.output), "positive_controls_passed": report["positive_controls_passed"],
                      "summary": report["summary"]}))


if __name__ == "__main__":
    main()
