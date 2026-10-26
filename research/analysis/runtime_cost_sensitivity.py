"""Normalize measured full-path CPU use into explicit cost sensitivities."""
import argparse
import hashlib
import json
import math
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = ROOT / "experiments/results/runtime-population-extended-20261024"


def cpu_cost_usd_per_1000_successes(cpu_seconds_per_1000_successes, usd_per_vcpu_hour):
    values = (cpu_seconds_per_1000_successes, usd_per_vcpu_hour)
    if any(not isinstance(value, (int, float)) or isinstance(value, bool)
           or not math.isfinite(value) or value < 0 for value in values):
        raise ValueError("CPU amount and explicit vCPU-hour price must be finite and nonnegative")
    return cpu_seconds_per_1000_successes * usd_per_vcpu_hour / 3600


def _validated_rows(rows):
    if not rows:
        raise ValueError("each profile must contain trial records")
    result = []
    for row in rows:
        cpu = row.get("cpu_seconds_observed")
        offered, admitted, dropped = row.get("offered"), row.get("admitted"), row.get("dropped")
        statuses = row.get("private_status_counts")
        success = statuses.get("Success", 0) if isinstance(statuses, dict) else None
        slo = row.get("slo_failure_fraction")
        rss = row.get("sampled_rss_mib")
        if (not isinstance(cpu, (int, float)) or isinstance(cpu, bool) or not math.isfinite(cpu) or cpu < 0
                or any(type(v) is not int or v < 0 for v in (offered, admitted, dropped))
                or offered == 0 or admitted + dropped != offered
                or type(success) is not int or success < 0 or success > admitted
                or not isinstance(slo, (int, float)) or isinstance(slo, bool)
                or not math.isfinite(slo) or not 0 <= slo <= 1
                or (rss is not None and (not isinstance(rss, (int, float)) or isinstance(rss, bool)
                                         or not math.isfinite(rss) or rss < 0))):
            raise ValueError("invalid full-path runtime trial resource or outcome fields")
        result.append({"cpu": float(cpu), "offered": offered, "admitted": admitted,
                       "dropped": dropped, "success": success, "slo": float(slo),
                       "rss": None if rss is None else float(rss)})
    return result


def summarize_profile(rows, resamples=5000, seed=20261026, rates=()):
    trials = _validated_rows(rows)
    if type(resamples) is not int or resamples < 1:
        raise ValueError("bootstrap resamples must be a positive integer")
    n = len(trials)
    cpu = np.array([row["cpu"] for row in trials])
    offers = np.array([row["offered"] for row in trials], dtype=float)
    success = np.array([row["success"] for row in trials], dtype=float)
    dropped = np.array([row["dropped"] for row in trials], dtype=float)
    slo = np.array([row["slo"] for row in trials])
    rng = np.random.default_rng(seed)
    samples = rng.integers(0, n, size=(resamples, n))

    def cpu_per_1000_successes(indices):
        denominator = success[indices].sum()
        return None if denominator == 0 else float(cpu[indices].sum() * 1000 / denominator)

    point_success_cpu = cpu_per_1000_successes(np.arange(n))
    success_boot = [cpu_per_1000_successes(indices) for indices in samples]
    success_boot = np.array([value for value in success_boot if value is not None])
    cpu_per_1000_offers = float(cpu.sum() * 1000 / offers.sum())
    offer_boot = cpu[samples].sum(axis=1) * 1000 / offers[samples].sum(axis=1)
    slo_fraction = float(np.average(slo, weights=offers))
    slo_boot = (slo[samples] * offers[samples]).sum(axis=1) / offers[samples].sum(axis=1)
    rss_rows = [row["rss"] for row in trials if row["rss"] is not None]
    rss_summary = None
    if rss_rows:
        rss_values = np.array(rss_rows)
        rss_samples = rng.integers(0, len(rss_values), size=(resamples, len(rss_values)))
        rss_summary = {
            "mean_sampled_rss_mib": float(rss_values.mean()),
            "trial_bootstrap_95": np.quantile(rss_values[rss_samples].mean(axis=1), [.025, .975]).tolist(),
            "interpretation": "sampled process-tree RSS; not cloud-billable memory or a peak guarantee",
        }
    result = {
        "trials": n, "offers": int(offers.sum()), "successes": int(success.sum()),
        "dropped": int(dropped.sum()),
        "observed_cpu_seconds": float(cpu.sum()),
        "cpu_seconds_per_1000_successes": point_success_cpu,
        "cpu_seconds_per_1000_successes_ci95": None if len(success_boot) == 0 else
            np.quantile(success_boot, [.025, .975]).tolist(),
        "cpu_seconds_per_1000_offers": cpu_per_1000_offers,
        "cpu_seconds_per_1000_offers_ci95": np.quantile(offer_boot, [.025, .975]).tolist(),
        "offered_slo_failure_fraction": slo_fraction,
        "offered_slo_failure_fraction_ci95": np.quantile(slo_boot, [.025, .975]).tolist(),
        "sampled_rss": rss_summary,
        "price_scenarios": [
            {"label": rate["label"], "usd_per_vcpu_hour": rate["usd_per_vcpu_hour"],
             "usd_per_1000_successes": None if point_success_cpu is None else
                cpu_cost_usd_per_1000_successes(point_success_cpu, rate["usd_per_vcpu_hour"]),
             "usd_per_1000_successes_ci95": None if point_success_cpu is None else
                np.quantile([cpu_cost_usd_per_1000_successes(value, rate["usd_per_vcpu_hour"])
                             for value in success_boot], [.025, .975]).tolist()}
            for rate in rates
        ],
    }
    return result


def read_rates(path):
    if path is None:
        return []
    rates = json.loads(Path(path).read_text())
    if not isinstance(rates, list) or not rates:
        raise ValueError("rate file must be a nonempty JSON array")
    labels = set()
    for rate in rates:
        if (not isinstance(rate, dict) or not isinstance(rate.get("label"), str)
                or not rate["label"] or rate["label"] in labels
                or not isinstance(rate.get("usd_per_vcpu_hour"), (int, float))
                or isinstance(rate.get("usd_per_vcpu_hour"), bool)
                or not math.isfinite(rate["usd_per_vcpu_hour"])
                or rate["usd_per_vcpu_hour"] < 0):
            raise ValueError("each rate requires a unique label and finite nonnegative USD/vCPU-hour value")
        labels.add(rate["label"])
    return rates


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(input_dir, output, rates_path=None):
    input_dir, output = Path(input_dir), Path(output)
    if output.exists():
        raise ValueError("output directory must be new")
    manifest = json.loads((input_dir / "artifact-sha256.json").read_text())
    for name in ("analysis.json", "config.json", "raw-trials.tar.gz"):
        if digest(input_dir / name) != manifest[name]:
            raise ValueError(f"input artifact hash mismatch: {name}")
    analysis = json.loads((input_dir / "analysis.json").read_text())
    config = json.loads((input_dir / "config.json").read_text())
    if config.get("trial_unit") != "one fresh executor process per profile and trial":
        raise ValueError("unexpected independent trial unit")
    if len(analysis.get("trials", [])) != 60:
        raise ValueError("expected the retained 30-trial, two-profile experiment")
    rates = read_rates(rates_path)
    result = {}
    for profile in sorted({row["profile"] for row in analysis["trials"]}):
        rows = [row for row in analysis["trials"] if row["profile"] == profile]
        if len(rows) != config["trials"]:
            raise ValueError(f"profile {profile} does not contain the configured trial count")
        result[profile] = summarize_profile(rows, seed=config["seed"] + len(result) * 997,
                                            rates=rates)
    output.mkdir(parents=True)
    report = {
        "input_directory": str(input_dir),
        "input_sha256": {name: digest(input_dir / name) for name in ("analysis.json", "config.json", "raw-trials.tar.gz")},
        "rate_input_sha256": None if rates_path is None else digest(rates_path),
        "trial_unit": "fresh full-path executor process; whole-process bootstrap",
        "resource_scope": "Linux procfs CPU ticks for driver+executor+two PIR children; excludes startup/teardown CPU; sampled aggregate RSS",
        "normalization": "observed process-tree CPU seconds divided by successful outputs and scaled to 1,000 successes; ratio of sums",
        "statistical_method": "5,000 bootstrap resamples of whole trial processes, seed derived from the source experiment seed",
        "rate_scenarios": rates,
        "profiles": result,
        "limitations": [
            "Resource observations come from a single shared-host local experiment and are not provider billing measurements.",
            "RSS is sampled process-tree memory, not billed memory or a peak guarantee.",
            "No network egress, storage rent, idle capacity, autoscaler instance-seconds, startup/teardown CPU, or provider price is included.",
            "Dollar values are emitted only when explicit analyst-supplied USD per vCPU-hour scenarios are provided.",
        ],
    }
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    provenance = {
        "analysis_script_sha256": digest(__file__),
        "input_artifact_manifest_sha256": digest(input_dir / "artifact-sha256.json"),
        "git_head": __import__("subprocess").check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "python": __import__("sys").version,
        "numpy": np.__version__,
        "method": "deterministic CPU resource normalization and optional explicit price coefficients; no new system collection",
    }
    (output / "analysis-provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    profiles = list(result)
    values = [result[name]["cpu_seconds_per_1000_successes"] for name in profiles]
    intervals = [result[name]["cpu_seconds_per_1000_successes_ci95"] for name in profiles]
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar(profiles, values, yerr=[[value - ci[0] for value, ci in zip(values, intervals)],
                                   [ci[1] - value for value, ci in zip(values, intervals)]], capsize=4)
    ax.set_ylabel("Observed process-tree CPU seconds / 1,000 successful invocations")
    ax.set_title("Normalized local compute use (not provider-billed cost)")
    ax.tick_params(axis="x", rotation=12)
    fig.tight_layout()
    fig.savefig(output / "cpu-per-1000-successes.png", dpi=160)
    plt.close(fig)
    fig, ax = plt.subplots(figsize=(6, 4.5))
    for profile, metrics in result.items():
        ax.scatter(metrics["offered_slo_failure_fraction"], metrics["cpu_seconds_per_1000_offers"], s=55)
        ax.annotate(profile, (metrics["offered_slo_failure_fraction"], metrics["cpu_seconds_per_1000_offers"]),
                    xytext=(5, 5), textcoords="offset points", fontsize=8)
    ax.set(xlabel="Offered-load SLO failure fraction",
           ylabel="Observed CPU seconds / 1,000 offers",
           title="Normalized resource use vs offered-load failure")
    fig.tight_layout()
    fig.savefig(output / "cpu-vs-slo-failure.png", dpi=160)
    plt.close(fig)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rates", type=Path,
                        help="optional JSON array of explicit USD per vCPU-hour scenario rates")
    args = parser.parse_args()
    report = run(args.input, args.output, args.rates)
    print(json.dumps({"output": str(args.output), "profiles": report["profiles"]}, indent=2))


if __name__ == "__main__":
    main()
