"""Independent integrity and metric checks for isolated ORAM study bundles."""

import argparse
import gzip
import hashlib
import json
import math
from pathlib import Path

import numpy as np


MODES = ("plaintext", "encrypt_only", "oram")
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read JSON file {path}: {error}") from error


def _read_jsonl_gzip(path):
    rows = []
    try:
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError as error:
                    raise ValueError(f"invalid JSON at {path}:{line_number}") from error
    except (OSError, EOFError) as error:
        raise ValueError(f"cannot read compressed session {path}: {error}") from error
    return rows


def _same_number(actual, expected, field):
    if type(actual) not in (int, float) or not math.isfinite(actual) or not math.isclose(
        actual, expected, rel_tol=1e-10, abs_tol=1e-10
    ):
        raise ValueError(f"reported {field} does not match independently recomputed value")


def _auc(labels, scores):
    positives = sum(labels)
    negatives = len(labels) - positives
    if positives == 0 or negatives == 0:
        raise ValueError("target sessions must contain both hot and cold classes")
    ordered = sorted(zip(scores, labels))
    positive_rank_sum = 0.0
    index = 0
    while index < len(ordered):
        end = index + 1
        while end < len(ordered) and ordered[end][0] == ordered[index][0]:
            end += 1
        average_rank = ((index + 1) + end) / 2
        positive_rank_sum += average_rank * sum(label for _, label in ordered[index:end])
        index = end
    return (positive_rank_sum - positives * (positives + 1) / 2) / (positives * negatives)


def _bootstrap_interval(values, seed, replicates=5000):
    data = np.asarray(values, dtype=float)
    if data.size < 2:
        return [float(data.mean()), float(data.mean())]
    rng = np.random.default_rng(seed)
    means = np.asarray([
        rng.choice(data, size=len(data), replace=True).mean()
        for _ in range(replicates)
    ])
    return [float(np.quantile(means, 0.025)), float(np.quantile(means, 0.975))]


def _session_paths(root, mode, trial, session):
    base = Path("raw") / mode / f"trial-{trial:02}"
    return (
        root / base / f"driver-{session:02}.jsonl.gz",
        root / base / f"observer-{session:02}.jsonl.gz",
    )


def verify_bundle(bundle):
    """Verify collected raw data, paired schedules, event shape, and saved scores."""
    root = Path(bundle).resolve()
    report = _read_json(root / "report.json")
    config = _read_json(root / "config.json")
    if report.get("configuration") != config:
        raise ValueError("report configuration differs from captured config.json")
    if report.get("positive_controls_passed") is not True:
        raise ValueError("collector did not pass its positive-control gate")

    try:
        trials = config["trials"]
        sessions = config["sessions_per_trial"]
        operations = config["operations"]
        address_count = config["blocks"]
        hot_addresses = set(config["hot_addresses"])
        service_cpu = config["service_cpu_affinity"]
        if (type(trials) is not int or trials < 1 or type(sessions) is not int
                or sessions < 2 or sessions % 2 or type(operations) is not int
                or operations < 1 or type(address_count) is not int or address_count < 2
                or type(service_cpu) is not int or service_cpu < 0
                or not hot_addresses or not hot_addresses < set(range(address_count))):
            raise ValueError("invalid workload parameters in config.json")
    except (KeyError, TypeError) as error:
        raise ValueError("config.json is missing required study parameters") from error

    raw_hashes = report.get("raw_session_sha256")
    expected_raw_paths = {
        f"raw/{mode}/trial-{trial:02}/{kind}-{session:02}.jsonl.gz"
        for mode in MODES for trial in range(trials) for session in range(sessions)
        for kind in ("driver", "observer")
    }
    if not isinstance(raw_hashes, dict) or set(raw_hashes) != expected_raw_paths:
        raise ValueError("raw SHA-256 manifest does not match the configured session set")
    for relative, expected_hash in raw_hashes.items():
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise ValueError("raw SHA-256 manifest contains an unsafe path")
        path = root / relative_path
        if not path.is_file() or _sha256(path) != expected_hash:
            raise ValueError(f"raw SHA-256 mismatch or missing file: {relative}")

    expected_prediction_files = {
        root / "predictions" / mode / f"trial-{trial:02}.json.gz"
        for mode in MODES for trial in range(trials)
    }
    for path in expected_prediction_files:
        if not path.is_file():
            raise ValueError(f"missing saved prediction file: {path.relative_to(root)}")

    process_metadata = report.get("process_metadata")
    if not isinstance(process_metadata, dict) or set(process_metadata) != set(MODES):
        raise ValueError("process metadata must include exactly the three study modes")
    all_frame_shapes = set()
    for mode in MODES:
        records = process_metadata[mode]
        if not isinstance(records, list) or len(records) != trials * sessions:
            raise ValueError(f"wrong service process record count for {mode}")
        per_session = [0] * sessions
        access_shapes = set()
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                raise ValueError(f"malformed service process record for {mode}")
            session_index = record.get("trial")
            expected_session_index = index % sessions
            if type(session_index) is not int or session_index != expected_session_index:
                raise ValueError(f"service metadata order/session index is invalid for {mode}")
            per_session[session_index] += 1
            request_bytes = record.get("request_bytes")
            response_bytes = record.get("response_bytes")
            bucket_bytes = record.get("bucket_bytes")
            if (type(request_bytes) is not int or request_bytes <= 0
                    or type(response_bytes) is not int or response_bytes <= 0
                    or type(bucket_bytes) is not int or bucket_bytes <= 0):
                raise ValueError(f"invalid byte lengths in {mode} process metadata")
            all_frame_shapes.add((request_bytes, response_bytes, bucket_bytes))
            if (record.get("worker_pid") == record.get("controller_pid")
                    or type(record.get("worker_pid")) is not int
                    or type(record.get("controller_pid")) is not int
                    or request_bytes != response_bytes
                    or record.get("service_cpu_affinity") != service_cpu
                    or record.get("service_allowed_cpus") != str(service_cpu)):
                raise ValueError(f"invalid process isolation or fixed frame metadata for {mode}")
            if mode == "oram":
                if type(record.get("path_buckets")) is not int or record["path_buckets"] < 1:
                    raise ValueError("ORAM process metadata is missing a valid path length")
                access_shapes.add(record["path_buckets"])
            elif record.get("events_per_access") != 2:
                raise ValueError(f"direct control must expose two bucket events per access: {mode}")
            else:
                access_shapes.add(record["events_per_access"] // 2)
        if per_session != [trials] * sessions:
            raise ValueError(f"service process records do not cover each session in every {mode} trial")
        if len(access_shapes) != 1:
            raise ValueError(f"fixed access shape changed between {mode} service processes")
    if len(all_frame_shapes) != 1:
        raise ValueError("request, response, or bucket byte lengths violate the fixed frame shape")

    profile_count = sessions // 2
    expected_schedules = {}
    private_sessions = 0
    observer_sessions = 0
    for mode in MODES:
        records = process_metadata[mode]
        for trial in range(trials):
            for session in range(sessions):
                driver_path, observer_path = _session_paths(root, mode, trial, session)
                private_rows = _read_jsonl_gzip(driver_path)
                observer_rows = _read_jsonl_gzip(observer_path)
                if len(private_rows) != operations:
                    raise ValueError(f"wrong operation count in {driver_path}")
                schedule = []
                for step, row in enumerate(private_rows):
                    if (not isinstance(row, dict)
                            or not {"step", "logical_address", "write", "oracle_verified", "latency_ns"} <= set(row)
                            or set(row) - {"step", "logical_address", "write", "oracle_verified", "latency_ns", "stash"}
                            or row.get("step") != step
                            or type(row.get("logical_address")) is not int
                            or not 0 <= row["logical_address"] < address_count
                            or type(row.get("write")) is not bool
                            or type(row.get("oracle_verified")) is not bool
                            or row["oracle_verified"] == row["write"]
                            or type(row.get("latency_ns")) is not int or row["latency_ns"] < 0):
                        raise ValueError(f"malformed private driver record at {driver_path}:{step + 1}")
                    schedule.append((row["logical_address"], row["write"]))

                schedule_key = (trial, session)
                if mode == MODES[0]:
                    expected_schedules[schedule_key] = schedule
                elif expected_schedules.get(schedule_key) != schedule:
                    raise ValueError("paired workload schedules differ between modes")

                metadata = records[trial * sessions + session]
                path_buckets = metadata.get("path_buckets", 1)
                event_count = operations * 2 * path_buckets
                if len(observer_rows) != event_count:
                    raise ValueError(f"wrong observer event count in {observer_path}")
                expected_bytes = metadata["bucket_bytes"]
                for event in observer_rows:
                    if (not isinstance(event, dict)
                            or set(event) != {"step", "direction", "bucket", "bytes", "service_ns"}
                            or type(event.get("step")) is not int
                            or not 0 <= event["step"] < operations
                            or event.get("direction") not in ("read", "write")
                            or type(event.get("bucket")) is not int or event["bucket"] < 0
                            or event.get("bytes") != expected_bytes
                            or type(event.get("service_ns")) is not int or event["service_ns"] <= 0):
                        raise ValueError(f"malformed observer event in {observer_path}")
                for step in range(operations):
                    events = observer_rows[step * 2 * path_buckets:(step + 1) * 2 * path_buckets]
                    reads, writes = events[:path_buckets], events[path_buckets:]
                    if ([event["direction"] for event in reads] != ["read"] * path_buckets
                            or [event["direction"] for event in writes] != ["write"] * path_buckets
                            or any(event["step"] != step for event in events)
                            or [event["bucket"] for event in reads]
                            != [event["bucket"] for event in writes]):
                        raise ValueError(f"fixed-shape read/write paths differ at {observer_path}:{step}")
                private_sessions += 1
                observer_sessions += 1

    trial_rows = report.get("trials")
    if not isinstance(trial_rows, list) or len(trial_rows) != len(MODES) * trials:
        raise ValueError("trial metric records do not match configured trial count")
    indexed_trials = {}
    for row in trial_rows:
        if not isinstance(row, dict) or row.get("mode") not in MODES:
            raise ValueError("malformed trial metric record")
        key = (row["mode"], row.get("trial"))
        if key in indexed_trials or type(key[1]) is not int or not 0 <= key[1] < trials:
            raise ValueError("duplicate or invalid mode/trial metric record")
        indexed_trials[key] = row

    recomputed_auc = {mode: [] for mode in MODES}
    for mode in MODES:
        for trial in range(trials):
            row = indexed_trials.get((mode, trial))
            if row is None:
                raise ValueError(f"missing saved metrics for {mode} trial {trial}")
            target_sessions = [f"{mode}-trial-{trial:02}-session-{session:02}"
                              for session in range(profile_count, sessions)]
            profile_sessions = [f"{mode}-trial-{trial:02}-session-{session:02}"
                               for session in range(profile_count)]
            if row.get("target_sessions") != target_sessions or row.get("profile_sessions") != profile_sessions:
                raise ValueError(f"profile/target split differs from the frozen whole-session split for {mode}")
            prediction_path = root / "predictions" / mode / f"trial-{trial:02}.json.gz"
            try:
                with gzip.open(prediction_path, "rt", encoding="utf-8") as stream:
                    predictions = json.load(stream)
            except (OSError, EOFError, json.JSONDecodeError) as error:
                raise ValueError(f"cannot read predictions for {mode} trial {trial}: {error}") from error
            if (not isinstance(predictions, dict)
                    or set(predictions) != {"target_sessions", "predictions", "scores_uncalibrated"}
                    or predictions["target_sessions"] != target_sessions):
                raise ValueError(f"prediction artifact exposes extra data or wrong sessions for {mode}")
            predicted = predictions["predictions"]
            scores = predictions["scores_uncalibrated"]
            expected_count = operations * len(target_sessions)
            if (not isinstance(predicted, list) or not isinstance(scores, list)
                    or len(predicted) != expected_count or len(scores) != expected_count
                    or any(type(value) is not int or value not in (0, 1) for value in predicted)
                    or any(type(value) not in (int, float) or not math.isfinite(value) for value in scores)
                    or row.get("observations") != expected_count):
                raise ValueError(f"malformed target predictions for {mode} trial {trial}")
            labels = []
            for session in range(profile_count, sessions):
                driver_path, _ = _session_paths(root, mode, trial, session)
                for private in _read_jsonl_gzip(driver_path):
                    labels.append(int(private["logical_address"] in hot_addresses))
            if len(labels) != expected_count:
                raise ValueError(f"target labels have the wrong size for {mode} trial {trial}")
            auc = _auc(labels, scores)
            accuracy = sum(pred == label for pred, label in zip(predicted, labels)) / expected_count
            positives = sum(labels)
            negatives = expected_count - positives
            true_positive = sum(pred == 1 and label == 1 for pred, label in zip(predicted, labels))
            true_negative = sum(pred == 0 and label == 0 for pred, label in zip(predicted, labels))
            balanced_accuracy = (true_positive / positives + true_negative / negatives) / 2
            _same_number(row.get("auc"), auc, "trial AUC")
            _same_number(row.get("accuracy"), accuracy, "trial accuracy")
            _same_number(row.get("balanced_accuracy"), balanced_accuracy, "trial balanced accuracy")
            recomputed_auc[mode].append(auc)

    summary_rows = report.get("summary")
    if not isinstance(summary_rows, list) or len(summary_rows) != len(MODES):
        raise ValueError("mode summary does not contain all three study arms")
    summaries = {row.get("mode"): row for row in summary_rows if isinstance(row, dict)}
    if set(summaries) != set(MODES):
        raise ValueError("mode summary has missing or duplicate study arms")
    for mode in MODES:
        summary = summaries[mode]
        if summary.get("trials") != trials:
            raise ValueError(f"wrong trial count in {mode} summary")
        _same_number(summary.get("auc_mean"), sum(recomputed_auc[mode]) / trials, "mean AUC")
        interval = summary.get("auc_ci95_trials")
        if (not isinstance(interval, list) or len(interval) != 2
                or any(type(value) not in (int, float) or not math.isfinite(value) for value in interval)
                or interval[0] > interval[1]):
            raise ValueError(f"invalid bootstrap interval for {mode}")
        expected_interval = _bootstrap_interval(recomputed_auc[mode], config["seed"] + 47)
        if any(not math.isclose(actual, expected, rel_tol=1e-10, abs_tol=1e-10)
               for actual, expected in zip(interval, expected_interval)):
            raise ValueError(f"bootstrap interval differs from recomputed trial AUCs for {mode}")
    control_threshold = config["positive_control_min_mean_auc"]
    lower_threshold = config["positive_control_ci_lower_must_exceed"]
    for mode in ("plaintext", "encrypt_only"):
        interval = summaries[mode]["auc_ci95_trials"]
        if summaries[mode]["auc_mean"] < control_threshold or interval[0] <= lower_threshold:
            raise ValueError(f"positive-control threshold failed for {mode}")

    source_hashes = report.get("source_sha256", {})
    if not isinstance(source_hashes, dict):
        raise ValueError("source SHA-256 manifest must be an object")
    verified_sources = 0
    for relative, expected_hash in source_hashes.items():
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise ValueError("source SHA-256 manifest contains an unsafe path")
        source_path = REPOSITORY_ROOT / relative_path
        if not source_path.is_file() or _sha256(source_path) != expected_hash:
            raise ValueError(f"source/binary SHA-256 mismatch or missing file: {relative}")
        verified_sources += 1

    return {
        "format_version": 1,
        "modes": list(MODES),
        "trials_per_mode": trials,
        "sessions_per_trial": sessions,
        "operations_per_session": operations,
        "raw_files_verified": len(raw_hashes),
        "private_sessions_verified": private_sessions,
        "observer_sessions_verified": observer_sessions,
        "paired_schedules_verified": trials * sessions,
        "service_process_records": sum(len(process_metadata[mode]) for mode in MODES),
        "prediction_trials_verified": len(trial_rows),
        "source_and_binary_hashes_verified": verified_sources,
        "positive_controls_passed": True,
        "recomputed_auc_mean": {
            mode: sum(recomputed_auc[mode]) / trials for mode in MODES
        },
        "oram_auc_interval": summaries["oram"]["auc_ci95_trials"],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path,
                        help="new verification JSON path; existing files are never overwritten")
    arguments = parser.parse_args(argv)
    result = verify_bundle(arguments.bundle)
    result["verifier_sha256"] = _sha256(Path(__file__))
    result["verifier"] = "research/analysis/verify_oram_isolated_bundle.py"
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with arguments.output.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write("\n")
    except FileExistsError as error:
        raise ValueError(f"refusing to overwrite verification result: {arguments.output}") from error
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
