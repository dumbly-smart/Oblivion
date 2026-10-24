"""Actual eight-class executor timing experiment; immutable binary per campaign."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import numpy as np

FEATURES = ("response_seconds", "request_bytes", "response_bytes", "storage_count", "storage_bytes", "visible_selector")


def vector(row):
    allowed = {"version", "step", "response_ns", "request_bytes", "response_bytes", "request_ciphertext", "response_ciphertext", "storage", "visible_selector"}
    if set(row) != allowed:
        raise ValueError("observer schema")
    return [row["response_ns"] / 1e9, row["request_bytes"], row["response_bytes"], len(row["storage"]), sum(x["bytes"] for x in row["storage"]), row["visible_selector"] or 0]


class Centroid:
    """Fixed public units; selector dominates in intentionally disclosed control."""
    def fit(self, x, y):
        x, y = np.asarray(x, dtype=float), np.asarray(y)
        self.centers = np.asarray([x[y == k].mean(axis=0) for k in range(8)])
        # Sizes/counts are scaled by public class geometry; latency in seconds.
        self.scale = np.array([1., 164., 164., 128., 128. * 316., 1.])
        return self

    def rank(self, x):
        distances = ((np.asarray(x)[:, None, :] - self.centers[None, :, :]) / self.scale) ** 2
        return np.argsort(distances.sum(axis=2), axis=1, kind="stable")


def score(rank, labels):
    labels = np.asarray(labels)
    correct = rank[:, 0] == labels
    return {"accuracy": float(correct.mean()), "balanced_accuracy": float(np.mean([correct[labels == k].mean() for k in range(8)])), "top3": float(np.mean(np.any(rank[:, :3] == labels[:, None], axis=1))), "success_only_accuracy": float(correct[labels < 5].mean()), "error_only_accuracy": float(correct[labels >= 5].mean())}


def interval(values):
    values = np.asarray(values)
    rng = np.random.default_rng(81273)
    samples = values[rng.integers(0, len(values), (5000, len(values)))].mean(axis=1)
    return {"mean": float(values.mean()), "trial_bootstrap_95": np.quantile(samples, [.025, .975]).tolist()}


def load_session(path):
    observer = [json.loads(x) for x in (path / "observer.jsonl").read_text().splitlines()]
    truth = [json.loads(x) for x in (path / "ground-truth.jsonl").read_text().splitlines()]
    if [r["step"] for r in observer] != [r["step"] for r in truth]:
        raise ValueError("alignment")
    return [vector(r) for r in observer], [r["class"] for r in truth]


def evaluate(root, mode, trials):
    records = []
    for trial in range(trials):
        sessions = [load_session(root / mode / f"{trial}-{s}") for s in range(4)]
        model = Centroid().fit(sum((x for x, _ in sessions[:2]), []), sum((y for _, y in sessions[:2]), []))
        x = sum((x for x, _ in sessions[2:]), [])
        y = sum((y for _, y in sessions[2:]), [])
        records.append({"trial": trial, **score(model.rank(x), y)})
    return {"trials": records, "metrics": {k: interval([r[k] for r in records]) for k in records[0] if k != "trial"}, "chance": 1 / 8, "majority": 1 / 8, "top3_chance": 3 / 8}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(binary, output, trials):
    output.mkdir(parents=True, exist_ok=False)
    (output / "bin").mkdir()
    fixed = output / "bin" / "timing_measure"
    shutil.copy2(binary, fixed)
    sources = [Path("crates/oblivion-exec/examples/timing_measure.rs"), Path(__file__), Path("Cargo.lock"), *Path("crates/oblivion-exec/src").rglob("*.rs"), *Path("crates/oblivion-batcher/src").rglob("*.rs"), *Path("crates/oblivion-store/src").rglob("*.rs")]
    provenance = {"binary_sha256_before": digest(fixed), "source_hashes": {str(p): digest(p) for p in sources}, "command": sys.argv, "python": sys.version, "numpy": np.__version__, "platform": platform.platform(), "cpu": Path("/proc/cpuinfo").read_text(), "rustc": subprocess.check_output(["rustc", "--version", "--verbose"], text=True), "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(), "trials": trials, "sessions": 4, "observations_per_session": 8, "workload_seed": 20261021, "resource_isolation": "shared host, no affinity", "started_unix": time.time()}
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2))
    report = {"features": FEATURES, "method": "fixed-unit nearest centroid, independent two-profile/two-target sessions; 5000 bootstrap resamples of fitted-model trial means", "modes": {}}
    for mode in ("control", "protected"):
        (output / mode).mkdir()
        for trial in range(trials):
            for session in range(4):
                target = output / mode / f"{trial}-{session}"
                command = [str(fixed.resolve()), str(target), str(20261021 + 100 * trial + session), mode]
                start = time.monotonic()
                result = subprocess.run(command, capture_output=True, text=True, timeout=20)
                (output / mode / f"{trial}-{session}.launch.json").write_text(json.dumps({"command": command, "returncode": result.returncode, "wall_seconds": time.monotonic() - start, "stderr": result.stderr}))
                if result.returncode:
                    raise RuntimeError(result.stderr)
            print(mode, trial + 1, "/", trials, flush=True)
        report["modes"][mode] = evaluate(output, mode, trials)
        (output / "report.json").write_text(json.dumps(report, indent=2))
        if mode == "control" and report["modes"][mode]["metrics"]["accuracy"]["mean"] < .9:
            raise RuntimeError("positive control failed; protected campaign not started")
    provenance["binary_sha256_after"] = digest(fixed)
    provenance["finished_unix"] = time.time()
    if provenance["binary_sha256_after"] != provenance["binary_sha256_before"]:
        raise RuntimeError("binary changed")
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2))
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(6, 4))
    for i, mode in enumerate(("control", "protected")):
        metric = report["modes"][mode]["metrics"]["accuracy"]
        mean, (lo, hi) = metric["mean"], metric["trial_bootstrap_95"]
        ax.bar(i, mean)
        ax.errorbar(i, mean, yerr=[[mean-lo], [hi-mean]], color="black", capsize=5)
    ax.axhline(1/8, linestyle="--", color="gray", label="balanced chance")
    ax.set(xticks=[0, 1], xticklabels=["visible selector control", "protected"], ylabel="Eight-class accuracy", ylim=(0, 1.05))
    ax.legend(); fig.tight_layout(); fig.savefig(output / "execution-timing.png"); plt.close(fig)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--binary", type=Path, default=Path("target/release/examples/timing_measure"))
    parser.add_argument("--trials", type=int, default=30)
    args = parser.parse_args()
    if not 1 <= args.trials <= 100:
        raise ValueError("trials")
    run(args.binary, args.output, args.trials)


if __name__ == "__main__":
    main()
