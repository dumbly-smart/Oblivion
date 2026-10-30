"""Repeated local epoch-batcher timing across client-population sizes."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import time

import numpy as np

ROOT = Path(__file__).resolve().parents[2]


def validate_config(config):
    if (not isinstance(config, dict)
            or type(config.get("seed")) is not int
            or type(config.get("trials")) is not int or not 1 <= config["trials"] <= 1000
            or type(config.get("period_ms")) is not int or not 2 <= config["period_ms"] <= 1000
            or type(config.get("epochs")) is not int or not 1 <= config["epochs"] <= 1024
            or type(config.get("real_percent")) is not int or config["real_percent"] not in (0, 50, 100)
            or not isinstance(config.get("participants"), list) or not config["participants"]
            or any(type(value) is not int or not 1 <= value <= 64 for value in config["participants"])
            or len(set(config["participants"])) != len(config["participants"])):
        raise ValueError("invalid bounded population-sweep configuration")
    return None


def separate_observer_and_private(rows):
    visible, private = [], []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("JSON object required")
        if row.get("type") == "arrival":
            required = {"type", "epoch", "slot", "planned_ns", "arrived_ns",
                        "emitted_ns", "queue_wait_ns", "arrival_late_ns", "real", "frame_bytes"}
            if set(row) != required or type(row["real"]) is not bool:
                raise ValueError("invalid arrival record")
            private.append({
                "type": "arrival", "epoch": row["epoch"], "slot": row["slot"],
                "planned_ns": row["planned_ns"], "arrival_late_ns": row["arrival_late_ns"],
                "real": row["real"],
            })
            visible.append({
                key: value for key, value in row.items()
                if key not in {"real", "planned_ns", "arrival_late_ns"}
            })
        elif row.get("type") == "emission":
            required = {"type", "epoch", "due_ns", "emitted_ns", "late_ns",
                        "frames", "dummy_frames", "frame_bytes", "batch_bytes"}
            if set(row) != required or type(row["dummy_frames"]) is not int:
                raise ValueError("invalid emission record")
            private.append({"type": "emission", "epoch": row["epoch"],
                            "dummy_frames": row["dummy_frames"]})
            visible.append({key: value for key, value in row.items() if key != "dummy_frames"})
        else:
            raise ValueError("unknown batcher trace record")
    return visible, private


def _quantile(values, percentile):
    if not values:
        raise ValueError("non-empty metric sample required")
    ordered = sorted(values)
    return ordered[(len(ordered) - 1) * percentile // 100]


def analyze_trial(visible, private, participants, period_ms):
    if (not visible or not private or len(visible) + len(private) == 0
            or any("real" in row or "dummy_frames" in row for row in visible)):
        raise ValueError("non-empty observer trace with private labels separated required")
    arrivals = [row for row in visible if row["type"] == "arrival"]
    emissions = [row for row in visible if row["type"] == "emission"]
    private_arrivals = [row for row in private if row["type"] == "arrival"]
    private_emissions = [row for row in private if row["type"] == "emission"]
    if (len(arrivals) != participants * len(emissions)
            or len(private_arrivals) != len(arrivals)
            or len(private_emissions) != len(emissions)
            or not emissions):
        raise ValueError("inconsistent participant, epoch, or private trace counts")
    arrival_fields = ("epoch", "slot", "arrived_ns", "emitted_ns",
                      "queue_wait_ns", "frame_bytes")
    emission_fields = ("epoch", "due_ns", "emitted_ns", "late_ns", "frames",
                       "frame_bytes", "batch_bytes")
    for row in arrivals:
        if any(type(row[field]) is not int or row[field] < 0 for field in arrival_fields):
            raise ValueError("invalid visible arrival metric")
    for row in emissions:
        if any(type(row[field]) is not int or row[field] < 0 for field in emission_fields):
            raise ValueError("invalid visible emission metric")
    if [row["epoch"] for row in emissions] != list(range(len(emissions))):
        raise ValueError("emission epochs must be contiguous and ordered")
    visible_ids = [(row["epoch"], row["slot"]) for row in arrivals]
    private_ids = [(row["epoch"], row["slot"]) for row in private_arrivals]
    if len(set(visible_ids)) != len(visible_ids) or set(visible_ids) != set(private_ids):
        raise ValueError("private real/dummy labels must align with visible client arrivals")
    frame_sizes = {row["frame_bytes"] for row in arrivals + emissions}
    if len(frame_sizes) != 1:
        raise ValueError("fixed envelope size changed")
    frame_bytes = frame_sizes.pop()
    wait_ns, arrival_late_ns = [], []
    real_count = 0
    for epoch in range(len(emissions)):
        visible_epoch = [row for row in arrivals if row["epoch"] == epoch]
        private_epoch = [row for row in private_arrivals if row["epoch"] == epoch]
        if len(visible_epoch) != participants or len({row["slot"] for row in visible_epoch}) != participants:
            raise ValueError("every participant must emit one frame per epoch")
        if {row["slot"] for row in visible_epoch} != set(range(participants)):
            raise ValueError("participant slot set changed")
        for row in visible_epoch:
            if row["queue_wait_ns"] != row["emitted_ns"] - row["arrived_ns"]:
                raise ValueError("queue-wait measurement mismatch")
            wait_ns.append(row["queue_wait_ns"])
        for row in private_epoch:
            if (type(row.get("planned_ns")) is not int or row["planned_ns"] < 0
                    or type(row.get("arrival_late_ns")) is not int or row["arrival_late_ns"] < 0):
                raise ValueError("invalid private schedule metric")
            arrival_late_ns.append(row["arrival_late_ns"])
        real_count += sum(row["real"] for row in private_epoch)
        emission = emissions[epoch]
        if (private_emissions[epoch]["epoch"] != epoch
                or emission["frames"] != participants
                or emission["batch_bytes"] != participants * frame_bytes
                or private_emissions[epoch]["dummy_frames"] != participants - sum(
                    row["real"] for row in private_epoch
                )):
            raise ValueError("batch shape or dummy accounting mismatch")
    elapsed_ns = emissions[-1]["emitted_ns"]
    if elapsed_ns <= 0:
        raise ValueError("non-positive measured interval")
    frames = len(arrivals)
    dummy_count = sum(row["dummy_frames"] for row in private_emissions)
    late_ns = [row["late_ns"] for row in emissions]
    return {
        "participants": participants, "epochs": len(emissions), "frames": frames,
        "real_frames": real_count, "dummy_frames": dummy_count,
        "fixed_frame_bytes": frame_bytes,
        "batch_bytes": sum(row["batch_bytes"] for row in emissions),
        "elapsed_ns": elapsed_ns,
        "frames_per_second": frames * 1e9 / elapsed_ns,
        "real_frames_per_second": real_count * 1e9 / elapsed_ns,
        "queue_wait_p50_ns": _quantile(wait_ns, 50),
        "queue_wait_p95_ns": _quantile(wait_ns, 95),
        "queue_wait_p99_ns": _quantile(wait_ns, 99),
        "arrival_late_p95_ns": _quantile(arrival_late_ns, 95),
        "emission_late_p95_ns": _quantile(late_ns, 95),
        "maximum_batch_bytes": max(row["batch_bytes"] for row in emissions),
    }


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def bootstrap(values, seed, samples=5000):
    data = np.asarray(values, dtype=float)
    rng = np.random.default_rng(seed)
    means = np.asarray([
        rng.choice(data, size=len(data), replace=True).mean()
        for _ in range(samples)
    ])
    return [float(np.quantile(means, 0.025)), float(np.quantile(means, 0.975))]


def summarize(rows, config):
    summaries = []
    for participants in config["participants"]:
        group = [row for row in rows if row["participants"] == participants]
        if len(group) != config["trials"]:
            raise ValueError("missing population trials")
        item = {"participants": participants, "trials": len(group)}
        for metric in ("frames_per_second", "real_frames_per_second",
                       "queue_wait_p95_ns", "queue_wait_p99_ns",
                       "emission_late_p95_ns", "maximum_batch_bytes"):
            values = [row[metric] for row in group]
            item[metric] = {
                "mean": float(np.mean(values)),
                "ci95_trials": bootstrap(values, config["seed"] + participants + len(metric)),
            }
        summaries.append(item)
    return summaries


def run(config_path, output, binary=None):
    started = time.time()
    config = json.loads(Path(config_path).read_text())
    validate_config(config)
    output = Path(output)
    if output.exists():
        raise ValueError("output must be new to preserve raw measurements")
    output.mkdir(parents=True)
    (output / "raw").mkdir()
    if binary is None or not Path(binary).is_file():
        subprocess.run(
            ["cargo", "build", "--locked", "--release", "-p", "oblivion-batcher",
             "--example", "batch_measure"],
            cwd=ROOT, check=True,
        )
        binary = ROOT / "target/release/examples/batch_measure"
    binary = Path(binary).resolve()
    (output / "config.json").write_text(json.dumps(config, indent=2) + "\n")
    source_paths = [
        *sorted((ROOT / "crates/oblivion-batcher/src").rglob("*.rs")),
        ROOT / "crates/oblivion-batcher/Cargo.toml",
        ROOT / "crates/oblivion-batcher/examples/batch_measure.rs",
        ROOT / "research/analysis/population_sweep.py",
        Path(config_path),
        binary,
        ROOT / "Cargo.lock",
    ]
    metadata = {
        "config": config,
        "source_sha256": {str(path.resolve().relative_to(ROOT)) if path.resolve().is_relative_to(ROOT) else path.name: sha(path)
                          for path in source_paths},
        "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "git_status": subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True),
        "rustc": subprocess.check_output(["rustc", "--version", "--verbose"], text=True),
        "python": sys.version, "numpy": np.__version__, "platform": platform.platform(),
        "cpu": platform.processor(),
        "methodology": "Local process runs the real epoch batcher with authenticated endpoints. Each session has independent seeded arrival phases. One envelope per configured participant per epoch; raw observer data and ground-truth real/dummy labels are stored separately.",
        "limitations": "All simulated clients and the batcher run in one local process; no network, WASM executor, ORAM store, provider bill or concurrent cross-machine clients are measured.",
    }
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    launches, trial_metrics = [], []
    for population_index, participants in enumerate(config["participants"]):
        population_dir = output / "raw" / f"participants-{participants:02}"
        population_dir.mkdir()
        for trial in range(config["trials"]):
            seed = config["seed"] + population_index * 100_000 + trial
            args = [
                str(binary), str(config["period_ms"]), str(config["epochs"]),
                str(participants), str(config["real_percent"]), str(seed),
            ]
            before = time.monotonic_ns()
            result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=120)
            wall_ns = time.monotonic_ns() - before
            record = {
                "participants": participants, "trial": trial, "seed": seed,
                "command": args, "returncode": result.returncode,
                "wall_ns_including_process_startup": wall_ns,
                "stderr": result.stderr,
            }
            launches.append(record)
            if result.returncode:
                continue
            source_rows = [json.loads(line) for line in result.stdout.splitlines()]
            observer_rows, private_rows = separate_observer_and_private(source_rows)
            summary = analyze_trial(observer_rows, private_rows, participants, config["period_ms"])
            summary.update(trial=trial, seed=seed, process_wall_ns=wall_ns)
            trial_metrics.append(summary)
            for kind, rows in (("observer", observer_rows), ("private", private_rows)):
                with gzip.open(population_dir / f"{kind}-trial-{trial:02}.jsonl.gz",
                               "wt", encoding="utf-8") as stream:
                    for row in rows:
                        stream.write(json.dumps(row, separators=(",", ":")) + "\n")
            (population_dir / f"launch-{trial:02}.json").write_text(
                json.dumps(record, indent=2) + "\n"
            )
    if any(row["returncode"] for row in launches):
        report = {
            "status": "incomplete-launch-failure", "launches": launches,
            "successful_trials": len(trial_metrics), "configuration": config,
        }
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        raise RuntimeError("one or more population trials failed; failures and completed raw data retained")
    summaries = summarize(trial_metrics, config)
    report = {
        "status": "complete", "configuration": config, "summary": summaries,
        "trials": trial_metrics, "launches": launches,
        "primary_metrics": ["queue_wait_p95_ns", "frames_per_second"],
        "uncertainty": "95% bootstrap intervals over 30 independent process-trial means per population.",
        "real_dummy_labels_separated": True,
        "cost": "Not estimated: provider pricing and external deployment were not available; local process wall time is reported separately.",
        "elapsed_seconds": time.time() - started,
        "raw_sha256": {
            str(path.relative_to(output)): sha(path)
            for path in sorted((output / "raw").rglob("*.jsonl.gz"))
        },
    }
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    metadata["completed_unix_ns"] = time.time_ns()
    metadata["binary_sha256_after_run"] = sha(binary)
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    make_figure(summaries, output / "population-throughput-latency.png")
    return report


def make_figure(summaries, output):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    populations = [row["participants"] for row in summaries]
    throughput = [row["frames_per_second"]["mean"] for row in summaries]
    p95 = [row["queue_wait_p95_ns"]["mean"] / 1e6 for row in summaries]
    fig, left = plt.subplots(figsize=(7, 4))
    right = left.twinx()
    left.plot(populations, throughput, marker="o", color="tab:blue", label="frames/s")
    right.plot(populations, p95, marker="s", color="tab:orange", label="p95 queue wait")
    left.set(xlabel="Configured clients per epoch", ylabel="Emitted frames/s")
    right.set_ylabel("p95 queue wait (ms)")
    left.grid(alpha=0.2)
    fig.tight_layout()
    fig.savefig(output, dpi=160)
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "experiments/configs/population-sweep-20261025.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--binary", type=Path)
    args = parser.parse_args()
    report = run(args.config, args.output, args.binary)
    print(json.dumps({"output": str(args.output), "status": report["status"],
                      "summary": report["summary"]}))


if __name__ == "__main__":
    main()
