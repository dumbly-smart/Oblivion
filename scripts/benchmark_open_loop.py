#!/usr/bin/env python3
"""Capture fresh-process runtime/batching trials and immutable launch provenance."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def command(args):
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else result.stderr.strip()

def source_hash():
    paths = sorted(p for p in (ROOT / "crates").rglob("*") if p.is_file())
    paths += [ROOT / "Cargo.toml", ROOT / "Cargo.lock"]
    digest = hashlib.sha256()
    for path in paths:
        digest.update(str(path.relative_to(ROOT)).encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()

def provenance(config, binary, args):
    return {
        "schema_version": 1, "configuration": config, "command": args,
        "recorded_before_launch_unix_ns": time.time_ns(),
        "binary_sha256_before_launch": sha(binary),
        "source_tree_sha256_before_launch": source_hash(),
        "runner_sha256": sha(Path(__file__)),
        "analysis_sha256": sha(ROOT / "research/analysis/open_loop.py"),
        "config_sha256": hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest(),
        "rustc": command(["rustc", "--version", "--verbose"]),
        "git_head": command(["git", "rev-parse", "HEAD"]),
        "git_status": command(["git", "status", "--porcelain"]),
        "platform": platform.platform(), "python": sys.version,
        "cpuinfo": Path("/proc/cpuinfo").read_text() if Path("/proc/cpuinfo").exists() else None,
        "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
        "memory_page_bytes": os.sysconf("SC_PAGE_SIZE"),
        "isolation": "shared host; sequential launches; no CPU affinity; other experiments may run concurrently",
        "crypto_randomness": "fresh OS endpoint/session keys every process; workload phases separately seeded",
    }

def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")

def copy_matrix(source, output):
    if output.exists():
        raise ValueError(f"copy destination already exists: {output}")
    entries = {}
    for path in sorted(source.rglob("*")):
        if path.is_file():
            entries[str(path.relative_to(source))] = sha(path)
    shutil.copytree(source, output)
    for relative, digest in entries.items():
        if sha(output / relative) != digest:
            raise ValueError("artifact copy digest mismatch")
    write_json(output / "copy-provenance.json", {
        "source": str(source.resolve()), "copied_to": str(output.resolve()),
        "copied_unix_ns": time.time_ns(), "files_sha256": entries,
        "policy": "byte-preserving copy; original metadata retained; historical source/provenance not rewritten",
        "runner_sha256": sha(Path(__file__)),
    })
    print(f"Copied verified matrix: {output}", flush=True)

def run_runtime(config, output):
    output.mkdir()
    (output / "bin").mkdir()
    binary = output / "bin/oblivion-server"
    shutil.copy2(ROOT / "target/release/oblivion-server", binary)
    metadata = provenance(config, binary, sys.argv)
    write_json(output / "metadata.json", metadata)
    write_json(output / "config.json", config)
    jobs = [(profile, trial) for profile in config["open_loop"] for trial in range(config["trials"])]
    random.Random(config["seed"]).shuffle(jobs)
    outcomes = []
    for order, (profile, trial) in enumerate(jobs):
        trial_output = output / profile["name"] / f"trial-{trial:03}"
        trial_output.parent.mkdir(exist_ok=True)
        args = [str(binary.resolve()), "open-loop", str(trial_output.resolve()), str(profile["interval_ms"]), str(profile["count"]), str(profile["queue_capacity"])]
        before = time.monotonic_ns()
        result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=30)
        record = {"order": order, "profile": profile["name"], "trial": trial, "command": args,
                  "process_wall_ns_including_startup_teardown": time.monotonic_ns()-before,
                  "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
        outcomes.append(record)
        write_json(output / "launches.json", outcomes)
        print(f"Runtime {order+1}/{len(jobs)} {profile['name']} trial={trial} status={result.returncode}", flush=True)
    metadata.update(binary_sha256_after_run=sha(binary), source_tree_sha256_after_run=source_hash(), completed_unix_ns=time.time_ns())
    write_json(output / "metadata.json", metadata)
    return all(record["returncode"] == 0 for record in outcomes)

def run_batch(config, output):
    output.mkdir()
    (output / "bin").mkdir()
    binary = output / "bin/batch_measure"
    shutil.copy2(ROOT / "target/release/examples/batch_measure", binary)
    metadata = provenance(config, binary, sys.argv)
    write_json(output / "metadata.json", metadata)
    write_json(output / "config.json", config)
    jobs = [(period, percent, trial) for period in config["batch_period_ms"] for percent in config["batch_real_percent"] for trial in range(config["trials"])]
    random.Random(config["seed"] + 1).shuffle(jobs)
    outcomes = []
    for order, (period, percent, trial) in enumerate(jobs):
        trial_output = output / f"epoch-{period}ms-real-{percent}" / f"trial-{trial:03}"
        trial_output.mkdir(parents=True)
        seed = config["seed"] + trial
        args = [str(binary.resolve()), str(period), str(config["batch_epochs"]), str(config["batch_participants"]), str(percent), str(seed)]
        before = time.monotonic_ns()
        with (trial_output / "raw.jsonl").open("w") as raw:
            result = subprocess.run(args, cwd=ROOT, stdout=raw, stderr=subprocess.PIPE, text=True, timeout=30)
        record = {"order": order, "period_ms": period, "real_percent": percent, "trial": trial,
                  "seed": seed, "command": args, "returncode": result.returncode, "stderr": result.stderr,
                  "process_wall_ns": time.monotonic_ns()-before}
        outcomes.append(record)
        write_json(trial_output / "launch.json", record)
        write_json(output / "launches.json", outcomes)
        print(f"Batch {order+1}/{len(jobs)} E={period} real={percent} trial={trial} status={result.returncode}", flush=True)
    metadata.update(binary_sha256_after_run=sha(binary), source_tree_sha256_after_run=source_hash(), completed_unix_ns=time.time_ns())
    write_json(output / "metadata.json", metadata)
    return all(record["returncode"] == 0 for record in outcomes)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    parser.add_argument("--mode", choices=["all", "runtime", "batch", "copy"], default="all")
    parser.add_argument("--runtime-output", type=Path, default=ROOT / "experiments/results/runtime-open-loop-current")
    parser.add_argument("--batch-output", type=Path, default=ROOT / "experiments/results/batch-epoch-current")
    parser.add_argument("--matrix-source", type=Path, default=Path("/tmp/oblivion-runtime-validation-txlc0y4w"))
    parser.add_argument("--matrix-output", type=Path, default=ROOT / "experiments/results/runtime-matrix-current")
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    if not args.skip_build:
        if args.mode in ("all", "runtime"):
            subprocess.run(["cargo", "build", "--locked", "--release", "-p", "oblivion-server"], cwd=ROOT, check=True)
        if args.mode in ("all", "batch"):
            subprocess.run(["cargo", "build", "--locked", "--release", "-p", "oblivion-batcher", "--example", "batch_measure"], cwd=ROOT, check=True)
    ok = True
    if args.mode in ("all", "copy"):
        copy_matrix(args.matrix_source, args.matrix_output)
    if args.mode in ("all", "runtime"):
        ok = run_runtime(config, args.runtime_output) and ok
    if args.mode in ("all", "batch"):
        ok = run_batch(config, args.batch_output) and ok
    if args.mode != "copy":
        subprocess.run([sys.executable, "-m", "research.analysis.open_loop", "--runtime", str(args.runtime_output), "--batch", str(args.batch_output)], cwd=ROOT, check=True)
    if not ok:
        raise SystemExit("some trials failed; recorded failures remain in launches.json")
if __name__ == "__main__":
    main()
