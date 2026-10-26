"""Paired pinned/unpinned ORAM leaf/timing crossover with positive controls."""
import argparse
import gzip
import hashlib
import json
import math
import os
import pathlib
import platform
import random
import shutil
import subprocess
import tarfile
import tempfile
import time

import numpy as np

from research.analysis import oram_isolated_replication as replication

ROOT = pathlib.Path(__file__).resolve().parents[2]
MODES = ("plaintext", "encrypt_only", "oram")
CONDITIONS = ("pinned", "unpinned")


def counterbalanced_condition_orders(trials, seed):
    if type(trials) is not int or trials < 2 or trials % 2:
        raise ValueError("counterbalanced crossover requires a positive even trial count")
    orders = [("pinned", "unpinned")] * (trials // 2)
    orders += [("unpinned", "pinned")] * (trials // 2)
    random.Random(seed).shuffle(orders)
    return orders


def paired_auc_summary(pinned_auc, unpinned_auc, seed):
    if len(pinned_auc) != len(unpinned_auc) or not pinned_auc:
        raise ValueError("paired AUC vectors must have equal nonzero length")
    if any(not math.isfinite(value) for value in (*pinned_auc, *unpinned_auc)):
        raise ValueError("paired AUC values must be finite")
    differences = [pinned - unpinned for pinned, unpinned in zip(pinned_auc, unpinned_auc)]
    return {
        "trials": len(differences),
        "pinned_minus_unpinned_mean": float(np.mean(differences)),
        "ci95_paired_difference": replication.bootstrap_interval(differences, seed),
        "paired_trial_differences": differences,
    }


def read_private_schedule(path):
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        return [json.loads(line) for line in stream]


def verify_crossover_schedules(raw_root, trials, sessions, address_count, include_oram):
    modes = MODES if include_oram else MODES[:2]
    for trial in range(trials):
        for session in range(sessions):
            sequences = []
            for condition in CONDITIONS:
                for mode in modes:
                    path = raw_root / condition / mode / f"trial-{trial:02}" / f"driver-{session:02}.jsonl.gz"
                    sequences.append(read_private_schedule(path))
            replication.require_paired_schedules(sequences, address_count)


def current_allowed_cpus():
    status = pathlib.Path("/proc/self/status").read_text()
    for line in status.splitlines():
        if line.startswith("Cpus_allowed_list:\t"):
            return line.split("\t", 1)[1]
    raise RuntimeError("cannot read process CPU affinity")


def cpu_ids(mask):
    result = set()
    for component in mask.split(","):
        ends = [int(value) for value in component.split("-")]
        result.update(range(ends[0], ends[-1] + 1))
    return result


def run(config_path, output, oram_binary, control_binary):
    started = time.time()
    config_path = pathlib.Path(config_path)
    config = json.loads(config_path.read_text())
    trials = config.get("trials")
    sessions = config.get("sessions_per_trial")
    cpu = config.get("service_cpu_affinity")
    order_seed = config.get("order_seed")
    if (type(trials) is not int or trials != 30 or sessions != 8 or type(sessions) is not int
            or type(order_seed) is not int or config.get("primary_metric") != "paired_auc_delta"
            or type(cpu) is not int or cpu < 0):
        raise ValueError("crossover config requires 30 trials, 8 sessions, an order seed, and a CPU id")
    replication.validate_service_cpu_affinity(cpu)
    if shutil.which("taskset") is None:
        raise RuntimeError("taskset is required for the pinned condition")
    if cpu not in cpu_ids(current_allowed_cpus()):
        raise RuntimeError("preregistered CPU is outside the current allowed affinity set")
    config["address_distribution"] = {
        str(int(address)): weight for address, weight in config["address_distribution"].items()
    }
    config["hot_addresses"] = sorted(config["hot_addresses"])
    orders = counterbalanced_condition_orders(trials, order_seed)
    output = pathlib.Path(output)
    if output.exists():
        raise ValueError("output directory must be new to preserve raw results")
    output.mkdir(parents=True)
    (output / "predictions").mkdir()
    (output / "config.json").write_text(json.dumps(config, indent=2) + "\n")
    binaries = {"oram": pathlib.Path(oram_binary).resolve(), "control": pathlib.Path(control_binary).resolve()}
    base_config = dict(config)
    process_metadata = {f"{condition}:{mode}": [] for condition in CONDITIONS for mode in MODES}
    condition_configs = {
        "pinned": {**base_config, "service_cpu_affinity": cpu},
        "unpinned": {**base_config, "service_cpu_affinity": None},
    }
    with tempfile.TemporaryDirectory(prefix="oblivion-oram-affinity-crossover-") as temp:
        temporary = pathlib.Path(temp)
        for trial, condition_order in enumerate(orders):
            for condition in condition_order:
                for mode in MODES[:2]:
                    process_metadata[f"{condition}:{mode}"].extend(
                        replication.capture_mode(
                            mode, condition_configs[condition], binaries, output, temporary,
                            trial_indices=[trial], condition=condition,
                        )
                    )
        address_count = len(config["address_distribution"])
        verify_crossover_schedules(output / "raw", trials, sessions, address_count, False)

        summaries, all_trials = {}, {}
        controls_passed = True
        for condition in CONDITIONS:
            condition_root = output / "raw" / condition
            summaries[condition], all_trials[condition] = {}, {}
            for mode in MODES[:2]:
                summary, rows = replication.evaluate_mode(
                    mode, condition_root, condition_configs[condition],
                    output / "predictions" / condition / mode,
                )
                summaries[condition][mode] = summary
                all_trials[condition][mode] = rows
                controls_passed &= (
                    summary["auc_mean"] >= config["positive_control_min_mean_auc"]
                    and summary["auc_ci95_trials"][0] > config["positive_control_ci_lower_must_exceed"]
                )
        if not controls_passed:
            (output / "report.json").write_text(json.dumps({
                "configuration": config, "positive_controls_passed": False,
                "defense_evaluated": False, "control_summaries": summaries,
                "condition_order": orders,
                "interpretation": "At least one positive control failed in a condition; ORAM was not collected.",
            }, indent=2) + "\n")
            return {"positive_controls_passed": False, "defense_evaluated": False}

        for trial, condition_order in enumerate(orders):
            for condition in condition_order:
                process_metadata[f"{condition}:oram"].extend(
                    replication.capture_mode(
                        "oram", condition_configs[condition], binaries, output, temporary,
                        trial_indices=[trial], condition=condition,
                    )
                )
        verify_crossover_schedules(output / "raw", trials, sessions, address_count, True)
        for condition in CONDITIONS:
            condition_root = output / "raw" / condition
            summary, rows = replication.evaluate_mode(
                "oram", condition_root, condition_configs[condition],
                output / "predictions" / condition / "oram",
            )
            summaries[condition]["oram"] = summary
            all_trials[condition]["oram"] = rows

    paired = paired_auc_summary(
        [row["auc"] for row in all_trials["pinned"]["oram"]],
        [row["auc"] for row in all_trials["unpinned"]["oram"]],
        config["seed"] + 901,
    )
    for condition in CONDITIONS:
        for mode in MODES:
            records = process_metadata[f"{condition}:{mode}"]
            expected = cpu if condition == "pinned" else None
            if len(records) != trials or any(row["service_cpu_affinity"] != expected for row in records):
                raise RuntimeError(f"incorrect service affinity metadata for {condition}/{mode}")
            if expected is not None and any(row["service_allowed_cpus"] != str(expected) for row in records):
                raise RuntimeError(f"effective service affinity mismatch for {condition}/{mode}")

    inputs = [Path(__file__), Path(replication.__file__), ROOT / "research/attacks/leaf_timing.py",
              pathlib.Path(oram_binary), pathlib.Path(control_binary), config_path]
    source_hashes = {
        str(path.resolve().relative_to(ROOT)) if path.resolve().is_relative_to(ROOT) else path.name:
        replication.digest(path)
        for path in inputs
    }
    raw_hashes = {
        str(path.relative_to(output)): replication.digest(path)
        for path in sorted((output / "raw").rglob("*.jsonl.gz"))
    }
    order_rows = [{"trial": i, "first_condition": order[0], "second_condition": order[1]}
                  for i, order in enumerate(orders)]
    report = {
        "configuration": config, "summaries": summaries, "paired_auc_difference": paired,
        "primary_metric": "paired_auc_delta",
        "positive_controls_passed": True, "defense_evaluated": True,
        "condition_order": order_rows,
        "condition_order_counts": {condition: sum(row["first_condition"] == condition for row in order_rows)
                                    for condition in CONDITIONS},
        "attacker_knowledge": "Labeled complete plaintext/encrypt-only profiling sessions within each affinity condition; unlabeled target sessions; no private operation labels during prediction.",
        "timing_scope": "Local isolated bucket service; handler-only timer; not network timing. Only service-process affinity differs.",
        "limitations": "Single shared Linux host; pinned core is not reserved; host scheduling/frequency/thermal/SMT activity remains uncontrolled. Paired schedules do not pair OS-random ORAM state. This is not a security proof.",
        "process_metadata": process_metadata, "source_sha256": source_hashes,
        "raw_session_sha256": raw_hashes,
        "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "git_status": subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True),
        "platform": platform.platform(), "python": __import__("sys").version,
        "numpy": np.__version__, "elapsed_seconds": time.time() - started,
    }
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(7, 4))
    labels, means, intervals = [], [], []
    for condition in CONDITIONS:
        summary = summaries[condition]["oram"]
        labels.append(condition)
        means.append(summary["auc_mean"])
        intervals.append(summary["auc_ci95_trials"])
    ax.bar(labels, means, yerr=[[m - i[0] for m, i in zip(means, intervals)],
                                [i[1] - m for m, i in zip(means, intervals)]], capsize=4)
    ax.axhline(0.5, color="gray", linestyle="--")
    ax.set(ylabel="ORAM attack AUC", ylim=(0, 1.05), title="Counterbalanced service-affinity crossover")
    fig.tight_layout()
    fig.savefig(output / "auc.png", dpi=160)
    plt.close(fig)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--oram-binary", type=pathlib.Path, default=ROOT / "target/release/examples/oram-measure")
    parser.add_argument("--control-binary", type=pathlib.Path, default=ROOT / "target/release/examples/oram-control")
    args = parser.parse_args()
    result = run(args.config, args.output, args.oram_binary, args.control_binary)
    print(json.dumps({
        "output": str(args.output), "positive_controls_passed": result["positive_controls_passed"],
        "defense_evaluated": result["defense_evaluated"],
        "paired_auc_difference": result.get("paired_auc_difference"),
    }))


if __name__ == "__main__":
    main()
