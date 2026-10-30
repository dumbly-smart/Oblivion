#!/usr/bin/env python3
"""Collect the preregistered socket attack in controls-first phases."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping, Sequence

from research.analysis import invocation_context_attack as context_attack
from research.analysis.invocation_boundary_attack import StudyError
from research.analysis.socket_invocation_attack import (
    FROZEN_CONFIG,
    _positive_control_gates,
    analyze_controls,
    _read_json_artifact,
    _validate_frozen_config,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
COLLECTION_TIMEOUT_SECONDS = 3600


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode(
        "utf-8"
    )


def _write_json(path: Path, value: object) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(_json_bytes(value))
    temporary.replace(path)


def _source_paths(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--", "Cargo.toml", "Cargo.lock", "crates", "examples/wasm-functions"],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise StudyError("cannot enumerate tracked source files")
    tracked = {
        item.decode("utf-8")
        for item in result.stdout.split(b"\0")
        if item
    }
    paths = {
        item
        for item in tracked
        if item in {"Cargo.toml", "Cargo.lock"}
        or (item.startswith("crates/") and item.endswith((".rs", ".toml", ".wat")))
        or item.startswith("examples/wasm-functions/")
    }
    paths.update(
        {
            "research/requirements.lock",
            "research/analysis/invocation_boundary_attack.py",
            "research/analysis/invocation_context_attack.py",
            "research/analysis/socket_invocation_attack.py",
            "research/analysis/collect_socket_invocation_attack.py",
        }
    )
    return sorted(paths)


def _command_output(command: Sequence[str], root: Path) -> str | None:
    try:
        result = subprocess.run(
            list(command), cwd=root, capture_output=True, text=True, check=False
        )
    except OSError:
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _capture_provenance(harness_binary: Path) -> dict:
    root = REPO_ROOT
    source_hashes = {}
    for relative in _source_paths(root):
        path = root / relative
        if not path.is_file():
            raise StudyError(f"source file needed for provenance is missing: {relative}")
        source_hashes[relative] = sha256_file(path)

    commit = _command_output(["git", "rev-parse", "HEAD"], root)
    if commit is None:
        raise StudyError("cannot record source commit")
    dirty_output = _command_output(
        ["git", "status", "--porcelain", "--untracked-files=normal"], root
    )
    if dirty_output is None:
        raise StudyError("cannot record worktree state")

    packages = {}
    for distribution in ("numpy", "scipy", "scikit-learn", "cryptography"):
        try:
            packages[distribution] = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError:
            packages[distribution] = None

    try:
        load_average = list(os.getloadavg())
    except (AttributeError, OSError):
        load_average = None
    return {
        "source_commit": commit,
        "source_hashes": source_hashes,
        "source_dirty_paths": [line[3:] for line in dirty_output.splitlines()],
        "harness_binary_path": str(harness_binary.resolve()),
        "binary_sha256": sha256_file(harness_binary),
        "environment": {
            "python": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "packages": packages,
            "os": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "logical_cpu_count": os.cpu_count(),
            "load_average_1_5_15": load_average,
            "rustc": _command_output(["rustc", "--version"], root),
        },
    }


def _file_manifest(directory: Path) -> dict:
    files = []
    if directory.exists():
        if directory.is_symlink() or not directory.is_dir():
            raise StudyError("collection output is not a real directory")
        for path in sorted(directory.rglob("*")):
            if path.is_symlink():
                raise StudyError("collection output contains a symbolic link")
            if path.is_file():
                files.append(
                    {
                        "path": path.relative_to(directory).as_posix(),
                        "size_bytes": path.stat().st_size,
                        "sha256": sha256_file(path),
                    }
                )
    return {"files": files, "file_count": len(files)}


def _validate_collection_output(directory: Path, modes: Sequence[str]) -> None:
    if not directory.is_dir():
        raise StudyError("collector returned success without its output directory")
    collected_config = _read_json_artifact(directory / "config.json")
    _validate_frozen_config(collected_config)
    expected = {"version": 1, "modes": list(modes)}
    selection = _read_json_artifact(directory / "mode-selection.json")
    if (
        set(selection) != {"version", "modes"}
        or type(selection.get("version")) is not int
        or selection != expected
    ):
        raise StudyError("collector output has a different mode selection")
    for mode in modes:
        if not (directory / mode).is_dir():
            raise StudyError(f"collector output is missing mode {mode}")
    for mode in set("ABCDEFG") - set(modes):
        if (directory / mode).exists():
            raise StudyError(f"collector output unexpectedly contains mode {mode}")


def _validate_control_report(report: Mapping[str, object]) -> bool:
    if not isinstance(report, Mapping):
        raise StudyError("control analyzer returned a non-object report")
    if (
        type(report.get("version")) is not int
        or report.get("version") != 1
        or report.get("phase") != "positive_controls"
        or report.get("mode_selection") != ["A", "B"]
    ):
        raise StudyError("control analyzer returned an incompatible report")
    try:
        _validate_frozen_config(report["config"])
    except (KeyError, TypeError) as error:
        raise StudyError("control report does not carry the frozen config") from error
    if report.get("feature_names") != list(context_attack.FEATURE_NAMES):
        raise StudyError("control report has a different feature vector")
    expected_attack = {
        "classifier": "RandomForestClassifier",
        "n_estimators": 500,
        "max_depth": 6,
        "min_samples_leaf": 2,
        "class_weight": "balanced",
        "n_jobs": 1,
        "model_seed": 20261220,
        "positive_class": 0,
        "classification_threshold": 0.5,
        "bootstrap_resamples": 5000,
        "bootstrap_seed": 20261221,
        "bootstrap_unit": "trial",
        "training_sessions": "0..1",
        "testing_sessions": "2..3",
    }
    if report.get("attack") != expected_attack:
        raise StudyError("control report has a different frozen attacker configuration")
    metrics = report.get("metrics_by_mode")
    if not isinstance(metrics, Mapping) or set(metrics) != {"A", "B"}:
        raise StudyError("control report must contain only A/B metrics")
    for mode in "AB":
        metric = metrics[mode]
        if not isinstance(metric, Mapping):
            raise StudyError(f"control metrics for {mode} are malformed")
        trials = metric.get("per_trial")
        if (
            not isinstance(trials, list)
            or len(trials) != FROZEN_CONFIG["trials"]
            or metric.get("bootstrap_resamples") != 5000
        ):
            raise StudyError(f"control metrics for {mode} do not cover the frozen trials")
        values = []
        for trial in trials:
            value = trial.get("roc_auc") if isinstance(trial, Mapping) else None
            if (
                isinstance(value, bool)
                or not isinstance(value, (float, int))
                or not math.isfinite(value)
                or not 0.0 <= value <= 1.0
            ):
                raise StudyError(f"control trial AUC for {mode} is invalid")
            values.append(float(value))
        expected_mean = math.fsum(values) / len(values)
        actual_mean = metric.get("mean_roc_auc")
        if (
            isinstance(actual_mean, bool)
            or not isinstance(actual_mean, (float, int))
            or not math.isfinite(actual_mean)
            or not math.isclose(actual_mean, expected_mean, rel_tol=0.0, abs_tol=1e-12)
        ):
            raise StudyError(f"control mean AUC for {mode} disagrees with trial metrics")
        expected_interval = context_attack._bootstrap_interval(values, 5000, 20261221)
        actual_interval = metric.get("roc_auc_ci95")
        if (
            not isinstance(actual_interval, list)
            or len(actual_interval) != 2
            or any(
                isinstance(value, bool)
                or not isinstance(value, (float, int))
                or not math.isfinite(value)
                or not math.isclose(value, expected, rel_tol=0.0, abs_tol=1e-12)
                for value, expected in zip(actual_interval, expected_interval, strict=True)
            )
        ):
            raise StudyError(f"control bootstrap interval for {mode} is inconsistent")
    expected_gates = _positive_control_gates(metrics)
    gates = report.get("positive_control_gates")
    if not isinstance(gates, Mapping) or set(gates) != {"A", "B"}:
        raise StudyError("control report must contain only A/B gates")
    for mode in "AB":
        if not isinstance(gates[mode], Mapping) or dict(gates[mode]) != expected_gates[mode]:
            raise StudyError(f"control gate for {mode} is malformed")
    passed = all(gate["passed"] for gate in expected_gates.values())
    if report.get("positive_controls_passed") is not passed:
        raise StudyError("control report summary disagrees with its gates")
    expected_protected_status = (
        "not_in_control_phase" if passed else "omitted_control_failure"
    )
    if report.get("protected_scoring") != expected_protected_status:
        raise StudyError("control report has an invalid protected-scoring status")
    return passed


def _write_phase_logs(bundle: Path, name: str, stdout: object, stderr: object) -> None:
    for stream_name, value in (("stdout", stdout), ("stderr", stderr)):
        if isinstance(value, bytes):
            text = value.decode("utf-8", errors="replace")
        else:
            text = "" if value is None else str(value)
        (bundle / f"{name}-collection.{stream_name}.txt").write_text(
            text, encoding="utf-8"
        )


def _collect_phase(
    bundle: Path,
    config_path: Path,
    harness_binary: Path,
    name: str,
    modes: Sequence[str],
    command_runner: Callable[..., object],
) -> dict:
    output = bundle / ("control-raw" if name == "control" else "protected-raw")
    command = [
        str(harness_binary),
        "system-tcp",
        str(config_path),
        str(output),
        ",".join(modes),
    ]
    started = _utc_now()
    try:
        process = command_runner(
            command,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=COLLECTION_TIMEOUT_SECONDS,
        )
        exit_code = process.returncode
        stdout = getattr(process, "stdout", "")
        stderr = getattr(process, "stderr", "")
        launch_error = None
        status_override = None
    except subprocess.TimeoutExpired as error:
        exit_code = None
        stdout = error.stdout
        stderr = error.stderr
        launch_error = f"collector exceeded {COLLECTION_TIMEOUT_SECONDS} seconds"
        status_override = "timed_out"
    except (OSError, subprocess.SubprocessError) as error:
        exit_code = None
        stdout = ""
        stderr = str(error)
        launch_error = f"{type(error).__name__}: {error}"
        status_override = "launch_failed"
    _write_phase_logs(bundle, name, stdout, stderr)

    error = launch_error
    status = status_override or ("launch_failed" if launch_error else "collection_failed")
    if launch_error is None and exit_code == 0:
        try:
            _validate_collection_output(output, modes)
        except StudyError as validation_error:
            status = "invalid_output"
            error = str(validation_error)
        else:
            status = "complete"

    try:
        manifest = _file_manifest(output)
    except (StudyError, OSError) as manifest_error:
        manifest = {"files": [], "file_count": 0, "error": str(manifest_error)}
        status = "invalid_output"
        error = str(manifest_error)
    manifest_path = bundle / f"{name}-raw-manifest.json"
    _write_json(manifest_path, manifest)
    return {
        "phase": f"{name}_collection",
        "started_utc": started,
        "completed_utc": _utc_now(),
        "command": command,
        "mode_selection": list(modes),
        "timeout_seconds": COLLECTION_TIMEOUT_SECONDS,
        "working_directory": str(REPO_ROOT),
        "output_directory": output.relative_to(bundle).as_posix(),
        "exit_code": exit_code,
        "status": status,
        "error": error,
        "stdout_file": f"{name}-collection.stdout.txt",
        "stderr_file": f"{name}-collection.stderr.txt",
        "stdout_sha256": sha256_file(bundle / f"{name}-collection.stdout.txt"),
        "stderr_sha256": sha256_file(bundle / f"{name}-collection.stderr.txt"),
        "raw_manifest_file": manifest_path.name,
        "raw_manifest": manifest,
    }


def run_experiment(
    config_path: Path,
    harness_binary: Path,
    new_bundle_root: Path,
    *,
    command_runner: Callable[..., object] | None = None,
    control_analyzer: Callable[..., dict] | None = None,
) -> dict:
    """Collect A/B first, then collect C–G only after the frozen controls pass."""
    source_config = Path(config_path).resolve()
    binary = Path(harness_binary).resolve()
    bundle = Path(new_bundle_root).resolve()
    if bundle.exists():
        raise StudyError("socket attack bundle root already exists")
    try:
        config_bytes = source_config.read_bytes()
        config = json.loads(config_bytes)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise StudyError("cannot read frozen socket attack config") from error
    if not isinstance(config, dict):
        raise StudyError("frozen socket attack config must be an object")
    _validate_frozen_config(config)
    if not binary.is_file():
        raise StudyError("harness binary is missing")

    runner = command_runner or subprocess.run
    analyzer = control_analyzer or analyze_controls
    provenance = _capture_provenance(binary)
    if provenance["source_dirty_paths"]:
        raise StudyError("socket study collection requires a clean source worktree")
    bundle.mkdir(parents=True, exist_ok=False)
    (bundle / "config.json").write_bytes(config_bytes)
    document = {
        "version": 1,
        "status": "running_control_collection",
        "started_utc": _utc_now(),
        "config": FROZEN_CONFIG,
        "config_sha256": hashlib.sha256(config_bytes).hexdigest(),
        "provenance": provenance,
        "phases": {},
    }
    _write_json(bundle / "experiment.json", document)

    control_phase = _collect_phase(
        bundle, source_config.resolve(), binary.resolve(), "control", ("A", "B"), runner
    )
    document["phases"]["control_collection"] = control_phase
    document["status"] = "running_control_analysis"
    _write_json(bundle / "experiment.json", document)
    if control_phase["status"] != "complete":
        document["status"] = "control_collection_failed"
        document["completed_utc"] = _utc_now()
        _write_json(bundle / "experiment.json", document)
        return document

    analysis_started = _utc_now()
    try:
        report = analyzer(
            FROZEN_CONFIG,
            bundle / "control-raw",
            bundle / "control-analysis",
        )
        controls_passed = _validate_control_report(report)
        _write_json(bundle / "control-gate.json", dict(report))
        analysis_status = "complete"
        analysis_error = None
    except Exception as error:  # Preserve the raw phase and terminate before targets.
        report = None
        controls_passed = False
        analysis_status = "failed"
        analysis_error = f"{type(error).__name__}: {error}"
    control_analysis = {
        "started_utc": analysis_started,
        "completed_utc": _utc_now(),
        "status": analysis_status,
        "error": analysis_error,
        "positive_controls_passed": controls_passed if report is not None else None,
    }
    if report is not None:
        control_analysis["report_sha256"] = sha256_file(bundle / "control-gate.json")
    control_analysis["analysis_manifest"] = _file_manifest(bundle / "control-analysis")
    document["phases"]["control_analysis"] = control_analysis
    document["positive_controls_passed"] = (
        controls_passed if analysis_status == "complete" else None
    )
    if analysis_status != "complete":
        document["status"] = "control_analysis_failed"
        document["completed_utc"] = _utc_now()
        _write_json(bundle / "experiment.json", document)
        return document
    if not controls_passed:
        document["status"] = "stopped_control_failure"
        document["completed_utc"] = _utc_now()
        _write_json(bundle / "experiment.json", document)
        return document

    document["status"] = "running_protected_collection"
    _write_json(bundle / "experiment.json", document)
    protected_phase = _collect_phase(
        bundle,
        source_config.resolve(),
        binary.resolve(),
        "protected",
        tuple("CDEFG"),
        runner,
    )
    document["phases"]["protected_collection"] = protected_phase
    document["status"] = (
        "protected_collection_collected_pending_evaluation"
        if protected_phase["status"] == "complete"
        else "protected_collection_failed"
    )
    document["completed_utc"] = _utc_now()
    _write_json(bundle / "experiment.json", document)
    return document


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Collect the socket invocation attack with A/B controls first."
    )
    parser.add_argument("config", type=Path)
    parser.add_argument("harness", type=Path)
    parser.add_argument("new_bundle_root", type=Path)
    arguments = parser.parse_args(argv)
    try:
        result = run_experiment(
            arguments.config, arguments.harness, arguments.new_bundle_root
        )
    except (StudyError, OSError) as error:
        print(f"collection rejected: {error}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "bundle_root": str(arguments.new_bundle_root.resolve()),
                "status": result["status"],
                "positive_controls_passed": result.get("positive_controls_passed"),
            },
            sort_keys=True,
        )
    )
    return 0 if result["status"] in {
        "stopped_control_failure",
        "protected_collection_collected_pending_evaluation",
    } else 1


if __name__ == "__main__":
    raise SystemExit(main())
