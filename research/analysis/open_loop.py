#!/usr/bin/env python3
"""Summarize raw process/component trials; bootstrap whole trial statistics."""
import argparse
import hashlib
import json
from pathlib import Path
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines()]

def interval(values, seed=20261021):
    values = np.asarray(values, dtype=float)
    estimates = np.random.default_rng(seed).choice(values, size=(5000, len(values)), replace=True).mean(axis=1)
    return {"mean": float(values.mean()), "trial_bootstrap_95": list(map(float, np.quantile(estimates, [.025, .975]))), "trials": len(values)}

def quantiles(values):
    return dict(zip(("p50", "p95", "p99"), map(float, np.quantile(values, [.5, .95, .99]))))

def dump(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")

def runtime(directory):
    launches = json.loads((directory / "launches.json").read_text())
    records = []
    for launch in launches:
        if launch["returncode"]:
            continue
        path = directory / launch["profile"] / f"trial-{launch['trial']:03}"
        summary = json.loads((path / "open-loop-summary.json").read_text())
        offers = rows(path / "offered-arrivals.jsonl")
        latency = rows(path / "open-loop-latencies.jsonl")
        assert len(offers) == summary["offered"]
        assert len(latency) == summary["completed"] == summary["admitted"]
        assert summary["admitted"] + summary["dropped"] == summary["offered"]
        assert len(rows(path / "storage-observer.jsonl")) == len(latency) * 16 * 8
        private = rows(path / "executor-private.jsonl")
        assert len(private) == len(latency)
        duration = summary["wall_ns"] / 1e9
        record = {"profile": launch["profile"], "trial": launch["trial"],
                  "offered": summary["offered"], "admitted": summary["admitted"], "dropped": summary["dropped"],
                  "errors": summary["errors"], "drop_fraction": summary["dropped"] / summary["offered"],
                  "slo_failures_including_drops": summary["slo_failures_including_drops"],
                  "slo_failure_fraction": summary["slo_failures_including_drops"] / summary["offered"],
                  "successes_per_second": summary["successes"] / duration,
                  "completed_per_second": summary["completed"] / duration,
                  "wall_seconds": duration, "process_wall_ms": launch["process_wall_ns_including_startup_teardown"] / 1e6,
                  "mean_queue_ms": float(np.mean([row["queue_wait_ns"] / 1e6 for row in latency])),
                  "mean_service_ms": float(np.mean([row["service_ns"] / 1e6 for row in latency])),
                  "first_service_ms": latency[0]["service_ns"] / 1e6,
                  "subsequent_mean_service_ms": float(np.mean([row["service_ns"] / 1e6 for row in latency[1:]])) if len(latency) > 1 else None,
                  "mean_end_to_end_ms": float(np.mean([row["end_to_end_ns"] / 1e6 for row in latency])),
                  "cpu_seconds_observed": summary["cpu_seconds_observed"], "cpu_ticks_observed": summary["cpu_ticks_observed"],
                  "sampled_rss_mib": summary["peak_sampled_aggregate_rss_kib"] / 1024 if summary["peak_sampled_aggregate_rss_kib"] is not None else None,
                  "producer_late_p99_ms": float(np.quantile([row["arrival_late_ns"] / 1e6 for row in offers], .99)),
                  "deadline_misses": sum(row["deadline_missed"] for row in private),
                  "private_status_counts": {status: sum(row["status"] == status for row in private) for status in sorted({row["status"] for row in private})}}
        record.update({f"end_to_end_{key}_ms": value for key, value in quantiles([row["end_to_end_ns"] / 1e6 for row in latency]).items()})
        records.append(record)
    aggregates = []
    for profile in sorted({row["profile"] for row in launches}):
        group = [row for row in records if row["profile"] == profile]
        numeric = [key for key, value in group[0].items() if isinstance(value, (int, float)) and key != "trial"] if group else []
        aggregates.append({"profile": profile, "successful_trials": len(group),
                           "failed_trials": sum(row["profile"] == profile and row["returncode"] != 0 for row in launches),
                           "metrics": {key: interval([row[key] for row in group]) for key in numeric}})
    report = {"summary": aggregates, "trials": records,
              "methodology": "5000-resample percentile bootstrap of equal-weight independent whole-process trial statistics. Latency quantiles first computed per trial, then mean and CI across trials. Includes first invocation; warm comparison separately excludes first admitted invocation only. No cross-session train/test or privacy conclusion.",
              "limits": "Fresh process but precompiled WASM before readiness; first vs subsequent execution is not a cold compilation experiment. CPU uses discrete procfs ticks and excludes startup/teardown; sampled aggregate RSS can miss peaks/count shared pages repeatedly. Shared host and other experiments may cause interference. Failures remain explicit; admitted latency excludes dropped requests, SLO failure fraction includes them."}
    dump(directory / "analysis.json", report)
    if aggregates and records:
        fig, axes = plt.subplots(1, 3, figsize=(12, 3.8))
        for axis, key, title in zip(axes, ("mean_end_to_end_ms", "drop_fraction", "successes_per_second"), ("Admitted latency (ms)", "Dropped / offered", "Successful completions / s")):
            means = [row["metrics"][key]["mean"] for row in aggregates]
            low = [row["metrics"][key]["trial_bootstrap_95"][0] for row in aggregates]
            high = [row["metrics"][key]["trial_bootstrap_95"][1] for row in aggregates]
            x = np.arange(len(means))
            axis.bar(x, means, color=["#397695", "#bd6749"][:len(means)])
            axis.errorbar(x, means, yerr=np.maximum(0, np.array([np.array(means)-low, np.array(high)-means])), fmt="none", color="black", capsize=4)
            axis.set(xticks=x, xticklabels=[row["profile"] for row in aggregates], ylabel=title)
        fig.tight_layout();fig.savefig(directory / "offered-load.png", dpi=180);plt.close(fig)
    return report

def batch(directory):
    config = json.loads((directory / "config.json").read_text())
    launches = json.loads((directory / "launches.json").read_text())
    records = []
    for launch in launches:
        if launch["returncode"]:
            continue
        path = directory / f"epoch-{launch['period_ms']}ms-real-{launch['real_percent']}" / f"trial-{launch['trial']:03}"
        raw = rows(path / "raw.jsonl")
        arrivals = [row for row in raw if row["type"] == "arrival"]
        emissions = [row for row in raw if row["type"] == "emission"]
        assert len(arrivals) == config["batch_epochs"] * config["batch_participants"]
        assert len(emissions) == config["batch_epochs"]
        assert all(row["frames"] == config["batch_participants"] and row["frame_bytes"] in (164, 228) and row["batch_bytes"] == config["batch_participants"] * row["frame_bytes"] for row in emissions)
        dummy = sum(row["dummy_frames"] for row in emissions)
        assert dummy == len(arrivals) * (100-launch["real_percent"]) // 100
        waits = [row["queue_wait_ns"] / 1e6 for row in arrivals]
        period = launch["period_ms"]
        record = {"period_ms": period, "real_percent": launch["real_percent"], "trial": launch["trial"],
                  "arrivals": len(arrivals), "dummy_frames": dummy, "real_frames": len(arrivals)-dummy,
                  "mean_queue_ms": float(np.mean(waits)), "ideal_uniform_mean_ms": period / 2,
                  "excess_mean_vs_ideal_ms": float(np.mean(waits)) - period / 2,
                  "mean_emission_late_ms": float(np.mean([row["emitted_ns"]-row["due_ns"] for row in emissions])) / 1e6,
                  "max_emission_late_ms": max(row["emitted_ns"]-row["due_ns"] for row in emissions) / 1e6,
                  "mean_arrival_late_ms": float(np.mean([row["arrival_late_ns"] for row in arrivals])) / 1e6,
                  "process_wall_ms": launch["process_wall_ns"] / 1e6}
        record.update({f"queue_{key}_ms": value for key, value in quantiles(waits).items()})
        records.append(record)
    aggregates = []
    for period in config["batch_period_ms"]:
        for percent in config["batch_real_percent"]:
            group = [row for row in records if row["period_ms"] == period and row["real_percent"] == percent]
            numeric = [key for key in group[0] if key not in ("period_ms", "real_percent", "trial")] if group else []
            aggregates.append({"period_ms": period, "real_percent": percent, "successful_trials": len(group),
                               "failed_trials": sum(row["period_ms"] == period and row["real_percent"] == percent and row["returncode"] != 0 for row in launches),
                               "metrics": {key: interval([row[key] for row in group]) for key in numeric}})
    report = {"summary": aggregates, "trials": records,
              "methodology": "Actual EpochBatcher and monotonic OS timers; eight OS-keyed encrypted endpoints per process, fixed per-client frames. Seeded independent uniform planned phases each epoch. 5000-resample percentile bootstrap of equal-weight trial means, not independent-message resampling. Matching trial seeds across periods/real ratios are common random numbers, not independent cells.",
              "limits": "Batching component only; no fabricated WASM/PIR/ORAM work. Queue time spans actual submission until emit return; allocation, crypto, decryption verification, preceding-epoch work and host scheduling can shift actual arrival phases. Ideal E/2 applies to exact uniform arrivals and punctual boundaries; it is a reference, not a guaranteed wall-clock result. Real/dummy labels are experiment ground truth, not untrusted observer features. No external-clock accuracy or privacy proof."}
    dump(directory / "analysis.json", report)
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    for percent in config["batch_real_percent"]:
        group = [row for row in aggregates if row["real_percent"] == percent and row["successful_trials"]]
        for axis, key in zip(axes, ("mean_queue_ms", "mean_emission_late_ms")):
            means = np.array([row["metrics"][key]["mean"] for row in group])
            bounds = np.array([row["metrics"][key]["trial_bootstrap_95"] for row in group]).T
            axis.errorbar([row["period_ms"] for row in group], means, yerr=np.maximum(0, np.array([means-bounds[0], bounds[1]-means])), marker="o", capsize=4, label=f"{percent}% real")
    axes[0].plot(config["batch_period_ms"], np.array(config["batch_period_ms"])/2, "k--", label="ideal E/2")
    axes[0].set(xlabel="Epoch period E (ms)", ylabel="Mean batching queue wait (ms)")
    axes[1].set(xlabel="Epoch period E (ms)", ylabel="Mean emission lateness (ms)")
    for axis in axes:axis.legend(fontsize=8);axis.grid(alpha=.2)
    fig.tight_layout();fig.savefig(directory / "batching-overhead-vs-epoch.png", dpi=180);fig.savefig(directory / "batching-overhead-vs-epoch.pdf");plt.close(fig)
    return report

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=Path)
    parser.add_argument("--batch", type=Path)
    args = parser.parse_args()
    for directory, analyze in ((args.runtime, runtime), (args.batch, batch)):
        if directory is not None and (directory / "launches.json").exists():
            report = analyze(directory)
            dump(directory / "analysis-provenance.json", {"analysis_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "numpy": np.__version__, "matplotlib": matplotlib.__version__, "resamples": 5000, "bootstrap_seed": 20261021, "independent_unit": "whole trial", "successful_trials": len(report["trials"])})
            print(f"Analyzed {directory}: {len(report['trials'])} successful trials")
if __name__ == "__main__":
    main()
