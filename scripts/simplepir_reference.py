#!/usr/bin/env python3
"""Fetch a pinned genuine reference and run an oracle-checked local comparison."""
import argparse
import datetime
import hashlib
import gzip
import math
import shutil
import json
import os
from pathlib import Path
import random
import statistics
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "research/pir_reference"
PIN = json.loads((REFERENCE / "pin.json").read_text())


def run(command, *, cwd=ROOT, log=None, timeout=300):
    result = subprocess.run([str(x) for x in command], cwd=cwd, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    if log:
        Path(log).write_text(result.stdout)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {command}\n{result.stdout}")
    return result.stdout.strip()


def fetch():
    checkout = REFERENCE / "upstream"
    if not checkout.exists():
        run(["git", "clone", "--no-checkout", PIN["repository"], checkout])
        run(["git", "checkout", "--detach", PIN["commit"]], cwd=checkout)
    actual = run(["git", "rev-parse", "HEAD"], cwd=checkout)
    if actual != PIN["commit"]:
        raise RuntimeError(f"reference commit mismatch: {actual}")
    if run(["git", "status", "--porcelain"], cwd=checkout):
        raise RuntimeError("refusing a modified reference checkout")
    return checkout


def percentile(values, fraction):
    values = sorted(values)
    position = (len(values) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    return values[lower] + (values[upper] - values[lower]) * (position - lower)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def freeze_executables(output, binaries):
    directory = output / 'bin'
    directory.mkdir(exist_ok=False)
    frozen = {}
    for scheme, original in binaries.items():
        frozen[scheme] = directory / original.name
        shutil.copy2(original, frozen[scheme])
    return frozen, {scheme: digest(path) for scheme, path in frozen.items()}


def verify_executables(binaries, expected):
    actual = {scheme: digest(path) for scheme, path in binaries.items()}
    if actual != expected:
        raise RuntimeError('frozen measurement executable changed')
    return actual


def compress_samples(path):
    destination = Path(str(path)+'.gz')
    with path.open('rb') as source, gzip.GzipFile(filename=str(destination),mode='wb',mtime=0) as target:
        shutil.copyfileobj(source,target)
    path.unlink()
    return destination


def binomial_reference(failures, samples):
    # Descriptive IID reference only: queries sharing a setup need not satisfy it.
    z = 1.959963984540054
    p = failures / samples
    denominator = 1 + z*z/samples
    center = (p + z*z/(2*samples))/denominator
    half = z*math.sqrt(p*(1-p)/samples + z*z/(4*samples*samples))/denominator
    return {'wilson_95_interval':[max(0.0,center-half),min(1.0,center+half)],
            'one_sided_95_upper': -math.expm1(math.log(.05)/samples) if failures == 0 else None,
            'assumption':'IID homogeneous Bernoulli events only; conditional reference, not a cryptographic failure guarantee'}


def correctness_report(rows, config):
    trials, count = config['trials'], config['queries_per_trial']
    setups = [r for r in rows if r['kind']=='setup']
    queries = [r for r in rows if r['kind']=='query']
    if len(setups)!=trials or {r['trial'] for r in setups} != set(range(trials)):
        raise RuntimeError('incomplete or duplicate setup trials')
    if len(queries)!=trials*count or {(r['trial'],r['query']) for r in queries} != {(t,q) for t in range(trials) for q in range(count)}:
        raise RuntimeError('incomplete or duplicate trial/query set')
    if any(type(r.get('correct')) is not bool for r in queries):
        raise RuntimeError('missing boolean full-record oracle result')
    failures = sum(not r['correct'] for r in queries)
    setup_failures = len({r['trial'] for r in queries if not r['correct']})
    return {'queries':len(queries),'failures':failures,'observed_failure_fraction':failures/len(queries),
            'setup_trials':trials,'setups_with_failure':setup_failures,
            'iid_query_reference_only':binomial_reference(failures,len(queries)),
            'iid_setup_event_reference_only':binomial_reference(setup_failures,trials),
            'dependence_caveat':'Queries reuse each setup/shared matrix/hint; 100k query outcomes are not 100k independent setup trials. The setup event is any observed failure in this configured finite workload. Fresh OS randomness and fresh processes do not prove an IID noise model or worst-case correctness.'}

def metric(rows, field, config):
    values = [row[field] for row in rows]
    trial_means = [statistics.mean(row[field] for row in rows if row["trial"] == trial)
                   for trial in range(config["trials"])]
    rng = random.Random(config["bootstrap_seed"])
    boots = [statistics.mean(rng.choices(trial_means, k=len(trial_means)))
             for _ in range(config["bootstrap_resamples"])]
    return {"mean": statistics.mean(values), "median": statistics.median(values),
            "p95": percentile(values, .95), "sample_stddev": statistics.stdev(values) if len(values)>1 else 0.0,
            "trial_mean_95pct_bootstrap_ci": [percentile(boots, .025), percentile(boots, .975)]}


def summarize(rows, config):
    queries = [row for row in rows if row["kind"] == "query"]
    setups = [row for row in rows if row["kind"] == "setup"]
    if len(setups) != config["trials"] or len(queries) != config["trials"] * config["queries_per_trial"]:
        raise RuntimeError("incomplete trial/sample count")
    correctness = correctness_report(rows, config)
    for row in queries:
        row["total_algorithm_ns"] = sum(row[key] for key in ["generation_ns", "server1_ns", "server2_ns", "recovery_ns"])
        row["server_total_ns"] = row["server1_ns"] + row["server2_ns"]
    result = {"trials": len(setups), "query_samples": len(queries), "all_correct": correctness["failures"] == 0, "correctness":correctness,
              "latency_ns": {field: metric(queries, field, config) for field in
                             ["generation_ns", "server1_ns", "server2_ns", "server_total_ns", "recovery_ns", "total_algorithm_ns"]},
              "setup_latency_ns": {field:metric(setups,field,config) for field in ["database_build_ns", "shared_init_ns", "preprocessing_ns"]},
              "setup_mean_ns": {field: statistics.mean(row[field] for row in setups)
                                for field in ["database_build_ns", "shared_init_ns", "preprocessing_ns"]},
              "communication_bytes": {field: sorted(set(row[field] for row in queries))
                                      for field in ["query_payload_bytes", "response_payload_bytes"]},
              "offline_bytes": {field: sorted(set(row[field] for row in setups))
                                for field in ["offline_upload_bytes", "offline_download_bytes"]},
              "server_bytes_scanned_per_query": sorted(set(row["server_matrix_bytes_scanned"] for row in queries))}
    online = queries[0]["query_payload_bytes"] + queries[0]["response_payload_bytes"]
    offline = setups[0]["offline_upload_bytes"] + setups[0]["offline_download_bytes"]
    result["total_protocol_bytes_amortized_per_query"] = {
        str(n): online + offline / n for n in [1, 16, 1000, 1000000]}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch-only", action="store_true")
    parser.add_argument("--config", type=Path, default=ROOT / "experiments/configs/simplepir-reference-small.json")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    checkout = fetch()
    if args.fetch_only:
        print(checkout)
        return
    config = json.loads(args.config.read_text())
    if config["record_bytes"] != 8 or config["reference_commit"] != PIN["commit"]:
        raise RuntimeError("this adapter requires 64-bit records and the pinned reference")
    for key, maximum in [("count", 1000000), ("trials", 1000), ("queries_per_trial", 10000), ("bootstrap_resamples", 100000)]:
        if not isinstance(config[key], int) or not 1 <= config[key] <= maximum:
            raise RuntimeError(f"invalid bounded configuration: {key}")
    if not args.output:
        parser.error("--output NEW_DIRECTORY required unless --fetch-only")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "config.json").write_text(json.dumps(config, indent=2) + "\n")
    commands = []
    def logged(command, cwd, name):
        commands.append({"argv": [str(x) for x in command], "cwd": str(cwd), "log": name})
        return run(command, cwd=cwd, log=output / name)
    build = REFERENCE / "build"
    build.mkdir(exist_ok=True)
    source_paths = [Path(__file__), REFERENCE / 'go/main.go', REFERENCE / 'go/go.mod',
                    REFERENCE / 'naive/src/main.rs', REFERENCE / 'naive/Cargo.toml',
                    ROOT/'Cargo.toml', ROOT/'Cargo.lock', ROOT/'crates/oblivion-pir/Cargo.toml']
    source_paths += sorted((ROOT/'crates/oblivion-pir/src').rglob('*.rs'))
    source_before_build = {str(path.relative_to(ROOT)):digest(path) for path in source_paths}
    go_binary = build / "simplepir-reference"
    logged(["go", "build", "-o", go_binary, "."], REFERENCE / "go", "build-go.log")
    logged(["cargo", "build", "--release", "--manifest-path", REFERENCE / "naive/Cargo.toml"], ROOT, "build-naive.log")
    naive_binary = REFERENCE / "naive/target/release/oblivion-naive-pir-reference"
    if {str(path.relative_to(ROOT)):digest(path) for path in source_paths} != source_before_build:
        raise RuntimeError('adapter/dependency source changed during build; retry with stable source')
    frozen, executable_hashes = freeze_executables(output, {'simplepir':go_binary,'naive_xor':naive_binary})
    go_binary, naive_binary = frozen['simplepir'], frozen['naive_xor']
    metadata = {"schema_version": 1, "source_before_build_sha256":source_before_build,
                "executable_before_sha256":executable_hashes, "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "reference": PIN, "reference_commit_metadata": run(["git", "show", "-s", "--format=fuller", "HEAD"], cwd=checkout),
                "reference_source_sha256": {}, "adapter_sha256": {}, "go": run(["go", "version"]),
                "go_env": run(["go", "env", "CGO_ENABLED", "GOOS", "GOARCH", "GOMAXPROCS"]),
                "cc": run([os.environ.get("CC", "cc"), "--version"]), "rustc": run(["rustc", "--version", "--verbose"]),
                "platform": run(["uname", "-a"]), "cpuinfo": Path("/proc/cpuinfo").read_text(),
                "meminfo": Path("/proc/meminfo").read_text(), "git_head": run(["git", "rev-parse", "HEAD"]),
                "git_status": run(["git", "status", "--porcelain"]),
                "limitations": ["shared host; no CPU affinity; cached in-process microbenchmark, no network/AEAD", "Go+cgo and Rust implementations differ", "two XOR servers measured serially; no parallel wall-clock claim", "SimplePIR real preprocessing, uncompressed shared matrix accounted separately", "database distribution/replication excluded from PIR communication for both schemes"]}
    for path in sorted((checkout / "pir").iterdir()):
        if path.is_file():
            metadata["reference_source_sha256"][path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    for path in [Path(__file__), REFERENCE / "go/main.go", REFERENCE / "go/go.mod", REFERENCE / "naive/src/main.rs", REFERENCE / "naive/Cargo.toml", ROOT / "crates/oblivion-pir/src/lib.rs"]:
        metadata["adapter_sha256"][str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    # Durable source/executable/config evidence precedes the first measurement.
    metadata['configuration'] = config
    metadata['commands_before_measurement'] = list(commands)
    (output/'metadata-before.json').write_text(json.dumps(metadata,indent=2)+'\n')
    collected = {"simplepir": [], "naive_xor": []}
    rng = random.Random(config["order_seed"])
    for trial in range(config["trials"]):
        order = ["simplepir", "naive_xor"]
        rng.shuffle(order)
        seed = config["seed"] + trial * config["queries_per_trial"] * 7919
        for scheme in order:
            verify_executables(frozen, executable_hashes)
            filename = f"{scheme}-{trial:02d}.jsonl"
            samples = output / filename
            if scheme == "simplepir":
                command = [go_binary, "-count", config["count"], "-trials", 1, "-queries", config["queries_per_trial"], "-seed", seed, "-output", samples]
            else:
                command = [naive_binary, samples, config["count"], 1, config["queries_per_trial"], seed]
            logged(command, ROOT, f"{scheme}-{trial:02d}.log")
            rows = [json.loads(line) for line in samples.read_text().splitlines()]
            for row in rows:
                row["trial"] = trial
                collected[scheme].append(row)
            if config.get('compress_raw', False):
                compress_samples(samples)
        print(f"completed trial {trial + 1}/{config['trials']}", flush=True)
    summaries = {}
    for scheme, rows in collected.items():
        summaries[scheme] = summarize(rows, config)
        if config.get("write_aggregate", True):
            (output / f"{scheme}-samples.jsonl").write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows))
    (output / "summary.json").write_text(json.dumps(summaries, indent=2) + "\n")
    metadata['executable_after_sha256'] = verify_executables(frozen, executable_hashes)
    metadata['source_after_sha256'] = {str(path.relative_to(ROOT)):digest(path) for path in source_paths}
    metadata['measurement_sources_unchanged_after_build'] = metadata['source_after_sha256'] == source_before_build
    metadata["commands"] = commands
    metadata["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    metadata["result_sha256"] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(output.iterdir()) if path.is_file()}
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(output)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"SimplePIR reference run failed: {error}", file=sys.stderr)
        sys.exit(1)
