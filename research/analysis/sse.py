#!/usr/bin/env python3
"""Generate real SSE traces and score separate observer/auxiliary/target files."""
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import platform
import random
import subprocess
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from research.attacks.sse import CountVolumeAttack, SearchPatternFrequencyAttack

ROOT = Path(__file__).resolve().parents[2]
MODES = ("exact_count_control", "sse", "padded_sse")


def dump(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def metrics(rankings, labels, classes, majority):
    if len(rankings) != len(labels) or not labels:
        raise ValueError("unaligned predictions")
    correct = [ranking[0] == label for ranking, label in zip(rankings, labels)]
    recalls = [np.mean([ok for ok, label in zip(correct, labels) if label == c]) for c in range(classes) if c in labels]
    return {"accuracy": float(np.mean(correct)), "balanced_accuracy": float(np.mean(recalls)),
            "top3_accuracy": float(np.mean([label in ranking[:3] for ranking, label in zip(rankings, labels)])),
            "majority_accuracy": labels.count(majority) / len(labels),
            "advantage_over_profile_majority": float(np.mean(correct)) - labels.count(majority) / len(labels),
            "oracle_majority_accuracy": max(Counter(labels).values()) / len(labels),
            "chance_accuracy": 1 / classes, "chance_top3_accuracy": min(3 / classes, 1),
            "samples": len(labels)}


def cluster_interval(values, seed=8723, samples=5000):
    """Input is one mean per independent trial, never individual queries."""
    rng = np.random.default_rng(seed)
    values = np.asarray(values, dtype=float)
    draws = rng.choice(values, (samples, len(values)), replace=True).mean(axis=1)
    return list(map(float, np.quantile(draws, [.025, .975])))


def make_workload(config, trial):
    rng = random.Random(config["seed"] + trial)
    probabilities = list(config["posting_probabilities"])
    rng.shuffle(probabilities)
    n = config["public_corpus_documents"]
    sample_counts = lambda: [sum(rng.random() < p for _ in range(n)) for p in probabilities]
    auxiliary_counts, target_counts = sample_counts(), sample_counts()
    # This synthetic prior is deliberately independent of document popularity.
    weights = list(range(1, config["keywords"] + 1))
    rng.shuffle(weights)
    labels = list(range(config["keywords"]))
    profile = rng.choices(labels, weights=weights, k=config["profile_queries"])
    queries = [rng.choices(labels, weights=weights, k=config["queries_per_session"]) for _ in range(config["target_sessions"])]
    auxiliary = {"counts": auxiliary_counts, "query_counts": [profile.count(c) for c in labels],
                 "profiling_session": "independent-public-query-profile", "profile_labels": profile}
    truth = {"target_counts": target_counts, "target_sessions": queries}
    return auxiliary, truth


def update_order(totals, seed):
    rng = random.Random(seed)
    counts = [0] * len(totals)
    result = []
    active = [k for k, n in enumerate(totals) if n]
    while active:
        keyword = rng.choice(active)
        result.append([keyword, counts[keyword]])
        counts[keyword] += 1
        if counts[keyword] == totals[keyword]:
            active.remove(keyword)
    return result


def read_observations(path):
    sessions = {}
    updates = 0
    with gzip.open(path, "rt") as stream:
        for line in stream:
            row = json.loads(line)
            if row["op"] == "add":
                updates += 1
                continue
            entries = row["response"]["entries"]
            count = len(entries)
            if count != sum(epoch["count"] for epoch in row["request"]["epochs"]):
                raise ValueError("wire count mismatch")
            if any(entry["ciphertext"] is None for entry in entries):
                raise ValueError("missing encrypted posting")
            view = {"tag": bytes(row["request"]["tag"]).hex(), "count": count,
                    "request_json_bytes": row["request_json_bytes"],
                    "response_json_bytes": row["response_json_bytes"], "server_ns": row["server_ns"]}
            sessions.setdefault(row["session"], []).append(view)
    return sessions, updates


def generate(config_path, output, binary):
    config = json.loads(config_path.read_text())
    if config["keywords"] != len(config["posting_probabilities"]):
        raise ValueError("invalid keyword probabilities")
    output.mkdir(parents=True, exist_ok=False)
    dump(output / "config.json", config)
    for trial in range(config["trials"]):
        auxiliary, truth = make_workload(config, trial)
        directory = output / f"trial-{trial:02}"
        directory.mkdir()
        dump(directory / "auxiliary.json", auxiliary)
        dump(directory / "ground-truth.json", truth)
        for mode in MODES:  # positive control physically executed first
            counts = auxiliary["counts"] if mode == "exact_count_control" else truth["target_counts"]
            pad = config["pad_to"] if mode == "padded_sse" else None
            if pad is not None and max(counts) > pad:
                raise ValueError("padding limit exceeded; do not silently truncate")
            workload = {"counts": counts, "queries": truth["target_sessions"], "pad_to": pad,
                        "update_order": update_order([pad if pad is not None else n for n in counts], config["seed"] + trial)}
            # Input is a trusted driver specification, never passed to attacks.
            with gzip.open(directory / f"{mode}.jsonl.gz", "wb", compresslevel=6) as wire:
                process = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                process.stdin.write(json.dumps(workload).encode())
                process.stdin.close()
                for block in iter(lambda: process.stdout.read(65536), b""):
                    wire.write(block)
                if process.wait() != 0:
                    raise RuntimeError(f"SSE exporter failed: {trial}/{mode}")
        print(f"SSE trial {trial + 1}/{config['trials']}", flush=True)
    sources = ["crates/oblivion-sse/src/lib.rs", "crates/oblivion-sse/examples/leakage.rs", "research/attacks/sse.py", "research/analysis/sse.py", str(config_path.relative_to(ROOT))]
    manifest = {"hardware": platform.platform(), "machine": platform.machine(), "processor": platform.processor(),
                "cpuinfo": next((line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), 'unknown'),
                "python": sys.version, "numpy": np.__version__, "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
                "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "source_sha256": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in sources},
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "command": ".venv/bin/python -m research.analysis.sse generate experiments/configs/sse-attacks.json experiments/results/sse-attacks --binary target/release/examples/leakage",
                "randomness": "Workloads seeded per trial; cryptographic keys and index identities freshly sampled from OsRng, hence ciphertext bytes vary on regeneration.",
                "artifacts_sha256": {str(p.relative_to(output)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(output.rglob('*')) if p.is_file()}}
    dump(output / "provenance.json", manifest)


def evaluate(directory):
    config = json.loads((directory / "config.json").read_text())
    records = []
    for mode in MODES:
        for trial in range(config["trials"]):
            path = directory / f"trial-{trial:02}"
            auxiliary = json.loads((path / "auxiliary.json").read_text())
            truth = json.loads((path / "ground-truth.json").read_text())
            sessions, updates = read_observations(path / f"{mode}.jsonl.gz")
            majority = max(range(config["keywords"]), key=lambda c: auxiliary["query_counts"][c])
            for session, observations in sessions.items():
                for name, attack in [("count_volume", CountVolumeAttack()), ("search_pattern_frequency", SearchPatternFrequencyAttack())]:
                    rankings = attack.run(observations, auxiliary, seed=trial * 100 + session,
                                          pad_to=config["pad_to"] if mode == "padded_sse" else None)
                    # Only scoring receives the target labels, after predictions exist.
                    score = metrics(rankings, truth["target_sessions"][session], config["keywords"], majority)
                    score.update(attack=name, mode=mode, trial=trial, session=session, updates=updates,
                                 mean_postings=float(np.mean([o["count"] for o in observations])),
                                 mean_response_json_bytes=float(np.mean([o["response_json_bytes"] for o in observations])),
                                 mean_request_json_bytes=float(np.mean([o["request_json_bytes"] for o in observations])),
                                 mean_server_ns=float(np.mean([o["server_ns"] for o in observations])))
                    records.append(score)
        control = [r["accuracy"] - r["majority_accuracy"] for r in records if r["mode"] == mode and r["attack"] == "count_volume"]
        if mode == "exact_count_control" and np.mean(control) <= .2:
            raise RuntimeError("count attack positive control failed")
    frequency_control = [r["advantage_over_profile_majority"] for r in records if r["mode"] == "exact_count_control" and r["attack"] == "search_pattern_frequency"]
    if np.mean(frequency_control) <= .1:
        raise RuntimeError("search-pattern frequency positive control failed")
    summary = []
    for mode in MODES:
        for attack in ("count_volume", "search_pattern_frequency"):
            rows = [r for r in records if r["mode"] == mode and r["attack"] == attack]
            item = {"mode": mode, "attack": attack, "independent_trials": config["trials"], "target_sessions": len(rows)}
            for key in ["accuracy", "advantage_over_profile_majority", "balanced_accuracy", "top3_accuracy", "majority_accuracy", "oracle_majority_accuracy", "chance_accuracy", "chance_top3_accuracy", "mean_postings", "mean_response_json_bytes", "mean_request_json_bytes", "mean_server_ns"]:
                trial_means = [np.mean([r[key] for r in rows if r["trial"] == t]) for t in range(config["trials"])]
                item[key] = float(np.mean(trial_means))
                item[key + "_cluster_bootstrap_95"] = cluster_interval(trial_means, samples=config["bootstrap_samples"])
            summary.append(item)
    report = {"config": config, "summary": summary, "session_metrics": records,
              "method": "Equal-weight trial means; 5000 bootstrap resamples of whole independent trials; two whole target sessions remain together. Public corpus counts independently sampled from target corpus except explicitly exact-count positive control. Labeled public query profile is an independent entire session. No target label is passed to an attack.",
              "limitations": "Synthetic small vocabulary and shared distributions; no real corpus. Offline query-frequency ranking uses the entire unlabeled target session. Count attack models number of encrypted postings, not plaintext byte lengths. Fixed padding uses genuine encrypted dummy postings in a static build and leaves tags, update traffic, timing and storage visible. No IHOP/IKK/MLE reproduction, no joint-system guarantee, no active injection attack or cryptographic proof. Chance-like results only apply to these features and attackers."}
    dump(directory / "report.json", report)
    plot(report, directory / "sse-attacks.png")
    dump(directory / "analysis-provenance.json", {"source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "attack_sha256": hashlib.sha256((ROOT/'research/attacks/sse.py').read_bytes()).hexdigest(), "report_sha256": hashlib.sha256((directory/'report.json').read_bytes()).hexdigest(), "plot_sha256": hashlib.sha256((directory/'sse-attacks.png').read_bytes()).hexdigest()})
    print(json.dumps(summary, indent=2))
    return report


def plot(report, path):
    fig, axes = plt.subplots(1, 2, figsize=(11, 4))
    for axis, attack in zip(axes, ("count_volume", "search_pattern_frequency")):
        rows = [r for r in report["summary"] if r["attack"] == attack]
        values = np.array([r["accuracy"] for r in rows])
        bounds = np.array([r["accuracy_cluster_bootstrap_95"] for r in rows]).T
        x = np.arange(len(rows))
        axis.bar(x, values, color=["#c55b45", "#326a96", "#599674"])
        axis.errorbar(x, values, yerr=np.maximum(0, [values-bounds[0], bounds[1]-values]), fmt="none", color="black", capsize=4)
        axis.axhline(rows[0]["chance_accuracy"], color="gray", linestyle=":", label="uniform chance")
        axis.plot(x, [r["majority_accuracy"] for r in rows], "k--", label="profile majority")
        axis.set(xticks=x, xticklabels=["exact aux control", "SSE", "padded SSE"], ylim=(0, 1.05), ylabel="query recovery accuracy", title=attack.replace("_", " "))
        axis.legend(fontsize=8)
    fig.suptitle("Actual GGM SSE · 30 independent trial clusters · 95% bootstrap intervals")
    fig.tight_layout()
    fig.savefig(path, dpi=170)
    plt.close(fig)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["generate", "evaluate"])
    parser.add_argument("path", type=Path)
    parser.add_argument("output", type=Path, nargs="?")
    parser.add_argument("--binary", type=Path, default=Path("target/release/examples/leakage"))
    args = parser.parse_args()
    if args.action == "generate":
        if args.output is None:
            parser.error("generate requires output directory")
        generate(args.path.resolve(), args.output.resolve(), args.binary.resolve())
        evaluate(args.output.resolve())
    else:
        evaluate(args.path)
