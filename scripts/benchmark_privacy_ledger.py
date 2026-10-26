#!/usr/bin/env python3
"""Measure persistent privacy-ledger commit latency and storage growth."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from research.simulation.privacy_ledger import PersistentUserPrivacyLedger  # noqa: E402


def cpu_model():
    path = Path('/proc/cpuinfo')
    if path.exists():
        for line in path.read_text().splitlines():
            if line.startswith('model name'):
                return line.split(':', 1)[1].strip()
    return platform.processor() or 'unknown'


def host_snapshot():
    try:
        load = os.getloadavg()
    except (AttributeError, OSError):
        load = None
    return dict(
        observed_at_utc=datetime.now(timezone.utc).isoformat(),
        platform=platform.platform(),
        machine=platform.machine(),
        processor=platform.processor(),
        cpu_model=cpu_model(),
        logical_cpu_count=os.cpu_count(),
        allowed_cpus=sorted(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else None,
        load_average_1_5_15=list(load) if load else None,
    )


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def percentile_summary(samples_ns):
    values_ms = np.asarray(samples_ns, dtype=np.float64) / 1_000_000
    return dict(
        trials=len(samples_ns),
        p50_ms=float(np.percentile(values_ms, 50)),
        p95_ms=float(np.percentile(values_ms, 95)),
        p99_ms=float(np.percentile(values_ms, 99)),
        mean_ms=float(np.mean(values_ms)),
        stdev_ms=float(statistics.stdev(values_ms)) if len(values_ms) > 1 else 0.0,
        throughput_releases_per_second=float(1_000_000_000 * len(samples_ns)
                                             / sum(samples_ns)),
    )


def create_benchmark_key(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        remaining = memoryview(secrets.token_bytes(32))
        while remaining:
            written = stream.write(remaining)
            remaining = remaining[written:]


def run(output, seed, trials, user_counts):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    source_paths = [Path(__file__).resolve(),
                    ROOT / 'research/simulation/privacy_ledger.py']
    source_hashes_before = {
        str(path.relative_to(ROOT)): sha256(path) for path in source_paths}
    config = dict(
        version=1,
        seed=seed,
        trials=trials,
        users_per_release=user_counts,
        release_epsilon=0.01,
        release_delta=0.000001,
        max_user_epsilon=100.0,
        max_user_delta=0.9,
        deterministic_synthetic_principal_ids=True,
        ledger_hmac_key_source='fresh OS CSPRNG key in private temporary directory',
        timed_region='PersistentUserPrivacyLedger.record including SQLite FULL synchronous commit',
        percentile_method='NumPy linear percentile over per-release elapsed milliseconds',
    )
    (output / 'config.json').write_text(json.dumps(config, indent=2) + '\n')
    before = host_snapshot()
    cases = []
    for user_count in user_counts:
        with tempfile.TemporaryDirectory(prefix='oblivion-ledger-bench-') as temporary:
            private_dir = Path(temporary)
            private_dir.chmod(0o700)
            key_path = private_dir / 'ledger.key'
            database_path = private_dir / 'ledger.sqlite3'
            create_benchmark_key(key_path)
            ledger = PersistentUserPrivacyLedger(
                database_path, key_path,
                max_epsilon=config['max_user_epsilon'],
                max_delta=config['max_user_delta'])
            principals = tuple(f'benchmark-principal-{index:06d}'
                               for index in range(user_count))
            latencies_ns = []
            for trial in range(trials):
                release_id = f'benchmark-seed-{seed}:{user_count}:{trial}'
                start = time.perf_counter_ns()
                ledger.record(release_id, principals,
                              config['release_epsilon'], config['release_delta'])
                latencies_ns.append(time.perf_counter_ns() - start)
            database_bytes = database_path.stat().st_size
            summary = ledger.summary()
            cases.append(dict(
                users_per_release=user_count,
                latency=percentile_summary(latencies_ns),
                raw_latency_ns=latencies_ns,
                final_database_bytes=database_bytes,
                bytes_per_distinct_principal=(database_bytes / user_count
                                              if user_count else None),
                cumulative_release_count=summary['release_count'],
                max_user_release_count=summary['max_user_release_count'],
                max_user_epsilon=summary['max_user_epsilon'],
                max_user_delta=summary['max_user_delta'],
                ledger_key_fingerprint=summary['ledger_key_fingerprint'],
            ))
    after = host_snapshot()
    source_hashes_after = {
        str(path.relative_to(ROOT)): sha256(path) for path in source_paths}
    if source_hashes_before != source_hashes_after:
        raise RuntimeError('benchmark source changed during collection')
    git_status = subprocess.check_output(
        ['git', 'status', '--porcelain'], cwd=ROOT, text=True).splitlines()
    git_status_paths = [line[3:].split(' -> ')[-1] for line in git_status]
    report = dict(
        configuration=config,
        environment=dict(
            python=sys.version,
            sqlite=sqlite3.sqlite_version,
            numpy=np.__version__,
            platform=platform.platform(),
            machine=platform.machine(),
            processor=platform.processor(),
            cpu_model=cpu_model(),
            logical_cpu_count=os.cpu_count(),
            before=before,
            after=after,
        ),
        provenance=dict(
            source_sha256=source_hashes_after,
            source_unchanged_during_collection=True,
            git_head=subprocess.check_output(
                ['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
            git_dirty=bool(git_status),
            git_dirty_paths=git_status_paths,
            output_location=str(output.resolve()),
            key_material_saved=False,
        ),
        methodology=('Each case creates a fresh temporary ledger and CSPRNG key. '
                     'It commits the configured number of releases over a fixed '
                     'deterministic set of synthetic principal IDs. The database '
                     'grows across trials; only record() is timed. No network, '
                     'identity verifier, workload generation, or report writing '
                     'is included in the timer.'),
        limitations=('Single-host local SQLite microbenchmark; timings include '
                     'filesystem and scheduler noise and do not predict remote '
                     'deployment throughput. Temporary key and database are '
                     'deleted after each case. Storage bytes are the database '
                     'file size after the final commit, not backup/WAL overhead.'),
        cases=cases,
    )
    report_path = output / 'results.json'
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    manifest = {path.name: sha256(path) for path in output.iterdir() if path.is_file()}
    (output / 'artifact-sha256.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True,
                        help='new result directory')
    parser.add_argument('--seed', type=int, default=20261026,
                        help='seed for deterministic synthetic identity labels')
    parser.add_argument('--trials', type=int, default=30)
    parser.add_argument('--users-per-release', type=int, nargs='+',
                        default=[1, 16, 64, 256])
    args = parser.parse_args()
    if args.seed < 0 or args.trials < 1:
        parser.error('seed must be nonnegative and trials must be positive')
    if (not args.users_per_release or any(n < 0 or n > 4096
                                          for n in args.users_per_release)
            or len(set(args.users_per_release)) != len(args.users_per_release)):
        parser.error('users-per-release values must be unique integers in 0..4096')
    report = run(args.output, args.seed, args.trials, args.users_per_release)
    print(json.dumps({
        'output': str(args.output),
        'cases': [{
            'users_per_release': case['users_per_release'],
            'p50_ms': case['latency']['p50_ms'],
            'p95_ms': case['latency']['p95_ms'],
            'p99_ms': case['latency']['p99_ms'],
            'database_bytes': case['final_database_bytes'],
        } for case in report['cases']],
    }, indent=2))


if __name__ == '__main__':
    main()
