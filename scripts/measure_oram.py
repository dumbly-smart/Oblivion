#!/usr/bin/env python3
"""Capture source/hardware metadata then run the real Rust ORAM experiment."""
import argparse
import hashlib
import json
import platform
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output exists: choose a new directory to preserve raw data")
    # Hash uncommitted implementation too; git HEAD alone is insufficient.
    inputs = sorted(set([*ROOT.glob("crates/**/*"), *ROOT.glob("scripts/*.py"), *ROOT.glob("research/**/*.py"), ROOT / "Cargo.toml", ROOT / "Cargo.lock"]))
    digest = hashlib.sha256()
    for file in inputs:
        if file.is_file() and "__pycache__" not in file.parts:
            digest.update(str(file.relative_to(ROOT)).encode() + b"\0" + file.read_bytes() + b"\0")
    config = json.loads(args.config.read_text())
    metadata = {
        "schema_version": 1, "git_head": command("git", "rev-parse", "HEAD"),
        "git_status": command("git", "status", "--porcelain"), "source_sha256": digest.hexdigest(),
        "rustc": command("rustc", "--version", "--verbose"), "platform": platform.platform(),
        "cpu": Path("/proc/cpuinfo").read_text() if Path("/proc/cpuinfo").exists() else platform.processor(),
        "configuration": config, "output": str(args.output.resolve()),
        "methodology": "Per-session fresh cryptographic state; seeded workload only. Initialization/warm-up excluded. Wall-clock operation latency. Observer events buffered in memory then written between accesses. No network measurement. Quantiles use lower sample order statistic; no general performance claim from smoke runs.",
        "threat_model": "A, simulated trusted controller; untrusted bucket observer",
    }
    subprocess.run(["cargo", "run", "--locked", "--release", "-p", "oblivion-store", "--example", "oram-measure", "--", str(args.config.resolve()), str(args.output.resolve())], cwd=ROOT, check=True)
    (args.output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")


if __name__ == "__main__":
    main()
