#!/usr/bin/env python3
"""Independently validate a persistent SSE journal benchmark report.

The verifier checks the frozen schedule, per-trial invariants, fresh-process
recovery evidence, and all reported descriptive statistics. It validates that
the runner's bootstrap intervals are present, finite, nonnegative, ordered, and
associated with the expected seeds. It does not reproduce Rust's ``StdRng``
bootstrap stream.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path
from typing import Any


class VerificationError(ValueError):
    """Raised when a report violates the benchmark protocol or its summaries."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _finite_nonnegative(value: Any, label: str) -> float:
    _require(_is_number(value), f"{label} must be numeric")
    converted = float(value)
    _require(math.isfinite(converted) and converted >= 0, f"{label} must be finite and nonnegative")
    return converted


def _quantile_sorted(values: list[float], probability: float) -> float:
    if len(values) == 1:
        return values[0]
    position = (len(values) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    weight = position - lower
    return values[lower] * (1.0 - weight) + values[upper] * weight


def _statistics(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"count": 0}
    ordered = sorted(values)
    return {
        "count": len(ordered),
        "mean": sum(ordered) / len(ordered),
        "p50": _quantile_sorted(ordered, 0.50),
        "p95": _quantile_sorted(ordered, 0.95),
        "p99": _quantile_sorted(ordered, 0.99),
    }


def _numbers(sample: dict[str, Any], key: str, label: str) -> list[float]:
    value = sample.get(key)
    _require(isinstance(value, list), f"{label}.{key} must be an array")
    return [_finite_nonnegative(item, f"{label}.{key}[{index}]") for index, item in enumerate(value)]


def summarize_samples(samples: list[dict[str, Any]], index_sizes: list[int]) -> list[dict[str, Any]]:
    output = []
    for index_size in index_sizes:
        rows = [sample for sample in samples if sample["index_size"] == index_size]
        recovery_trial_medians = [
            _quantile_sorted(sorted(_numbers(row, "recovery_open_ns", "sample")), 0.5)
            for row in rows
        ]
        fields: dict[str, list[float]] = {
            "journal_record_bytes_written": [float(row["journal_record_bytes_written"]) for row in rows],
            "journal_byte_amplification": [float(row["journal_byte_amplification"]) for row in rows],
            "index_build_ns": [float(row["index_build_ns"]) for row in rows],
            "prepare_add_ns": [],
            "server_insert_ns": [],
            "finish_add_ns": [],
            "recovery_open_ns_all_processes_descriptive": [],
            "recovery_open_trial_median_ns": recovery_trial_medians,
            "recovery_process_total_ns_descriptive": [],
        }
        for row in rows:
            summary_keys = {
                "prepare_add_ns": "prepare_add_ns",
                "server_insert_ns": "server_insert_ns",
                "finish_add_ns": "finish_add_ns",
                "recovery_open_ns": "recovery_open_ns_all_processes_descriptive",
                "recovery_process_total_ns": "recovery_process_total_ns_descriptive",
            }
            for field, summary_key in summary_keys.items():
                fields[summary_key].extend(_numbers(row, field, "sample"))
        output.append(
            {
                "index_size": index_size,
                "trial_count": len(rows),
                **{key: _statistics(values) for key, values in fields.items()},
            }
        )
    return output


def _assert_summary(actual: Any, expected: list[dict[str, Any]], index_sizes: list[int]) -> None:
    _require(isinstance(actual, list) and len(actual) == len(expected), "summary length does not match configured sizes")
    trial_metrics = {
        "journal_record_bytes_written": 0,
        "journal_byte_amplification": 1,
        "index_build_ns": 2,
        "recovery_open_trial_median_ns": 3,
    }
    for position, expected_row in enumerate(expected):
        actual_row = actual[position]
        size = index_sizes[position]
        label = f"summary[{position}] size {size}"
        _require(isinstance(actual_row, dict), f"{label} must be an object")
        _require(actual_row.get("index_size") == size, f"{label} has wrong size")
        _require(actual_row.get("trial_count") == expected_row["trial_count"], f"{label} has wrong trial count")
        for metric, expected_stats in expected_row.items():
            if metric in ("index_size", "trial_count"):
                continue
            actual_stats = actual_row.get(metric)
            _require(isinstance(actual_stats, dict), f"{label}.{metric} must be an object")
            for stat_name, expected_value in expected_stats.items():
                actual_value = actual_stats.get(stat_name)
                _require(actual_value == expected_value if stat_name == "count" else _is_number(actual_value),
                         f"{label}.{metric}.{stat_name} is missing or invalid")
                if stat_name != "count":
                    _require(
                        math.isclose(float(actual_value), float(expected_value), rel_tol=1e-12, abs_tol=1e-9),
                        f"{label}.{metric}.{stat_name} disagrees with raw samples",
                    )
        for metric, seed_offset in trial_metrics.items():
            stats = actual_row[metric]
            interval = stats.get("mean_bootstrap_ci95")
            seed = 202_610_280_001 + size + seed_offset
            _require(stats.get("bootstrap_replicates") == 5000, f"{label}.{metric} has wrong bootstrap count")
            _require(stats.get("bootstrap_seed") == seed, f"{label}.{metric} has wrong bootstrap seed")
            _require(isinstance(interval, list) and len(interval) == 2, f"{label}.{metric} needs a 95% interval")
            low = _finite_nonnegative(interval[0], f"{label}.{metric}.CI low")
            high = _finite_nonnegative(interval[1], f"{label}.{metric}.CI high")
            _require(low <= high, f"{label}.{metric} bootstrap interval is reversed")


def verify_report(
    report: dict[str, Any],
    expected_config: dict[str, Any] | None = None,
    expected_revision: str | None = None,
) -> dict[str, int | str]:
    """Validate a report and return compact counts for callers and tests."""
    _require(isinstance(report, dict), "report must be a JSON object")
    _require(report.get("schema_version") == 1, "unsupported report schema")
    config = report.get("configuration")
    _require(isinstance(config, dict), "report configuration is missing")
    if expected_config is not None:
        _require(config == expected_config, "report configuration differs from the frozen config")
    sizes = config.get("index_sizes")
    trials = config.get("trials")
    recovery_repetitions = config.get("recovery_repetitions")
    _require(isinstance(sizes, list) and sizes and all(isinstance(n, int) and n > 0 for n in sizes),
             "configuration index_sizes must contain positive integers")
    _require(len(set(sizes)) == len(sizes), "configuration index_sizes contains duplicates")
    _require(isinstance(trials, int) and trials > 0, "configuration trials must be positive")
    _require(isinstance(recovery_repetitions, int) and recovery_repetitions > 0,
             "configuration recovery_repetitions must be positive")

    revision = report.get("source_revision")
    _require(isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision) is not None,
             "source revision must be a 40-character lowercase Git hash")
    if expected_revision is not None:
        _require(revision == expected_revision, "source revision differs from the expected frozen revision")
    _require(report.get("tracked_source_dirty") is False, "benchmark source was dirty during collection")
    environment = report.get("environment")
    _require(isinstance(environment, dict), "environment metadata is missing")
    for key in ("architecture", "cpu_model", "logical_cpus", "os", "rustc"):
        _require(key in environment and environment[key], f"environment metadata is missing {key}")

    samples = report.get("samples")
    expected_count = trials * len(sizes)
    _require(isinstance(samples, list) and len(samples) == expected_count,
             f"sample coverage expected {expected_count} rows")
    by_pair: dict[tuple[int, int], dict[str, Any]] = {}
    all_pids: list[int] = []
    for row_index, sample in enumerate(samples):
        label = f"samples[{row_index}]"
        _require(isinstance(sample, dict), f"{label} must be an object")
        trial = sample.get("trial")
        size = sample.get("index_size")
        _require(isinstance(trial, int) and 0 <= trial < trials, f"{label} has invalid trial")
        _require(size in sizes, f"{label} has an unconfigured index size")
        pair = (trial, size)
        _require(pair not in by_pair, f"duplicate trial/index-size sample {pair}")
        by_pair[pair] = sample

        generation = 2 * size
        _require(sample.get("generation") == generation, f"{label} generation must equal twice index size")
        logical_input_bytes = _finite_nonnegative(sample.get("logical_input_bytes"), f"{label}.logical_input_bytes")
        journal_bytes = _finite_nonnegative(
            sample.get("journal_record_bytes_written"), f"{label}.journal_record_bytes_written"
        )
        retained_bytes = _finite_nonnegative(sample.get("retained_journal_bytes"), f"{label}.retained_journal_bytes")
        journal_records = sample.get("journal_records_written")
        retained_records = sample.get("retained_journal_records")
        _require(isinstance(journal_records, int) and journal_records >= 0, f"{label} journal record count is invalid")
        _require(isinstance(retained_records, int) and retained_records >= 0,
                 f"{label} retained record count is invalid")
        _require(logical_input_bytes == 34 * size,
                 f"{label} logical input bytes do not match the 34-byte posting workload")
        _require(journal_records == generation + 1,
                 f"{label} journal record count disagrees with generation")
        _require(sample.get("anchor_compare_and_swap_calls") == generation + 1,
                 f"{label} anchor compare-and-swap count disagrees with generation")
        _require(sample.get("anchor_load_calls_during_recovery") == recovery_repetitions,
                 f"{label} has wrong recovery anchor-load count")
        _require(retained_records <= journal_records,
                 f"{label} retained record count exceeds total records")
        _require(retained_bytes <= journal_bytes,
                 f"{label} retained bytes exceed bytes written")

        checkpoints = sample.get("checkpoint_generations")
        _require(checkpoints == list(range(0, generation + 1, 256)), f"{label} checkpoint schedule is invalid")
        for key in ("prepare_add_ns", "server_insert_ns", "finish_add_ns"):
            values = _numbers(sample, key, label)
            _require(len(values) == size, f"{label}.{key} must have one value per posting")
        for key in ("recovery_open_ns", "recovery_process_total_ns"):
            values = _numbers(sample, key, label)
            _require(len(values) == recovery_repetitions, f"{label}.{key} has wrong repetition count")
        _require(
            all(total >= opened for total, opened in zip(sample["recovery_process_total_ns"], sample["recovery_open_ns"])),
            f"{label} process recovery time is less than in-process open time",
        )
        pids = sample.get("recovery_child_pids")
        _require(isinstance(pids, list) and len(pids) == recovery_repetitions,
                 f"{label} has wrong recovery child PID count")
        _require(all(isinstance(pid, int) and pid > 0 for pid in pids), f"{label} has invalid child PID")
        _require(len(set(pids)) == recovery_repetitions, f"{label} recovery child PIDs are not distinct")
        all_pids.extend(pids)

        for key in ("initialization_ns", "index_build_ns"):
            _finite_nonnegative(sample.get(key), f"{label}.{key}")
        amplification = _finite_nonnegative(sample.get("journal_byte_amplification"),
                                            f"{label}.journal_byte_amplification")
        expected_amplification = journal_bytes / logical_input_bytes
        _require(
            math.isclose(amplification, expected_amplification, rel_tol=1e-12, abs_tol=1e-12),
            f"{label} journal-byte amplification disagrees with raw byte counts",
        )

    required_pairs = {(trial, size) for trial in range(trials) for size in sizes}
    _require(set(by_pair) == required_pairs, "sample coverage has missing trial/index-size pairs")
    _require(len(set(all_pids)) == len(all_pids), "a recovery child PID was reused across samples")
    expected_summary = summarize_samples(samples, sizes)
    _assert_summary(report.get("summary"), expected_summary, sizes)
    return {"sample_count": expected_count, "summary_count": len(sizes), "trial_group_count": trials,
            "source_revision": revision}


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="report.json emitted by sse-journal-benchmark")
    parser.add_argument("config", type=Path, help="the frozen benchmark configuration JSON")
    parser.add_argument("--expected-revision", help="expected source commit used to build the runner")
    args = parser.parse_args()
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        config = json.loads(args.config.read_text(encoding="utf-8"))
        counts = verify_report(report, config, args.expected_revision)
    except (OSError, json.JSONDecodeError, VerificationError) as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1

    print(
        f"verified {counts['sample_count']} samples across {counts['trial_group_count']} trials "
        f"and {counts['summary_count']} index sizes; source {counts['source_revision']}"
    )
    for row in report["summary"]:
        print(
            f"size={row['index_size']} postings: "
            f"journal_amplification_mean={row['journal_byte_amplification']['mean']:.4f}x, "
            f"build_mean_s={row['index_build_ns']['mean'] / 1e9:.3f}, "
            f"build_ci95_s={[round(v / 1e9, 3) for v in row['index_build_ns']['mean_bootstrap_ci95']]}, "
            f"recovery_open_mean_ms={row['recovery_open_trial_median_ns']['mean'] / 1e6:.3f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
