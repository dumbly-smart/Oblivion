#!/usr/bin/env python3
"""Leaf-distribution diagnostics, not a cryptographic security test."""
import argparse
import json
from pathlib import Path
import numpy as np
from scipy import stats
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def leaves(directory, trial):
    config = json.loads((directory / "config.json").read_text())
    count = 1 << (config["blocks"] - 1).bit_length()
    events = [json.loads(line) for line in (directory / f"observer-{trial}.jsonl").open()]
    result = [e["bucket"] - (count - 1) for e in events if e["direction"] == "read" and e["bucket"] >= count - 1]
    if len(result) != config["operations"]:
        raise ValueError("unexpected trace shape")
    return count, np.array(result)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("uniform", type=Path)
    parser.add_argument("same", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(exist_ok=False)
    configs = [json.loads((p / "config.json").read_text()) for p in [args.uniform, args.same]]
    reports = []
    for trial in range(min(c["trials"] for c in configs)):
        n, a = leaves(args.uniform, trial)
        m, b = leaves(args.same, trial)
        if n != m or n < 2:
            raise ValueError("need identical geometry with >= 2 leaves")
        counts = [np.bincount(x, minlength=n) for x in [a, b]]
        mask = counts[0] + counts[1] > 0
        report = {"trial": trial, "uniform_chi2_p": float(stats.chisquare(counts[0]).pvalue), "same_chi2_p": float(stats.chisquare(counts[1]).pvalue), "homogeneity_p": float(stats.chi2_contingency(np.array(counts)[:, mask]).pvalue), "uniform_lag1": float(np.corrcoef(a[:-1], a[1:])[0, 1]), "same_lag1": float(np.corrcoef(b[:-1], b[1:])[0, 1])}
        reports.append(report)
    # Wilson uncertainty for the probability that consecutive leaves coincide.
    comparisons = []
    for directory in [args.uniform, args.same]:
        _, values = leaves(directory, 0)
        successes = int(np.count_nonzero(values[1:] == values[:-1]))
        total = len(values) - 1
        p = successes / total
        z = 1.959963984540054
        center = (p + z*z/(2*total))/(1+z*z/total)
        radius = z*np.sqrt(p*(1-p)/total+z*z/(4*total*total))/(1+z*z/total)
        comparisons.append({"consecutive_equal":p, "wilson_95":[center-radius,center+radius],"uniform_expectation":1/n})
    result = {"diagnostics":reports,"first_trial_coincidences":comparisons,"limitations":"Unadjusted exploratory p-values; finite samples and low power cannot establish independence or indistinguishability. No timing or compositional privacy claim. OS crypto randomness makes exact traces non-reproducible, while workload seeds remain fixed."}
    (args.output / "diagnostics.json").write_text(json.dumps(result, indent=2)+"\n")
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    for directory, label in [(args.uniform,"uniform logical accesses"),(args.same,"repeated logical address")]:
        n, values = leaves(directory, 0)
        axes[0].plot(np.arange(n), np.bincount(values,minlength=n), label=label, alpha=.7)
        rows = [json.loads(line) for line in (directory/"summary.jsonl").open()]
        axes[1].plot([r["trial"] for r in rows], [r["read"]["p95_ns"]/1000 for r in rows], marker="o",label=label)
    axes[0].set(xlabel="visible leaf",ylabel="access count",title="Leaf histogram (first trial)")
    axes[1].set(xlabel="independent trial",ylabel="read p95 (µs)",title="Local memory backend latency")
    for axis in axes: axis.legend(fontsize=7)
    fig.tight_layout()
    fig.savefig(args.output/"oram-diagnostics.png",dpi=160)
    plt.close(fig)


if __name__ == "__main__": main()
