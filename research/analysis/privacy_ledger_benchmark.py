"""Independently verify and plot persistent privacy-ledger microbenchmarks."""
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import platform
import subprocess
import sys

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[2]


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def close(left, right):
    return math.isclose(float(left), float(right), rel_tol=1e-12, abs_tol=1e-12)


def verify(source):
    source = Path(source)
    config_bytes = (source / 'config.json').read_bytes()
    results_bytes = (source / 'results.json').read_bytes()
    config = json.loads(config_bytes)
    report = json.loads(results_bytes)
    manifest = json.loads((source / 'artifact-sha256.json').read_text())
    checked_inputs = {
        'config.json': hashlib.sha256(config_bytes).hexdigest(),
        'results.json': hashlib.sha256(results_bytes).hexdigest(),
    }
    if manifest != checked_inputs:
        raise ValueError('collection manifest does not exactly match config/results inputs')
    if config != report.get('configuration'):
        raise ValueError('results configuration differs from frozen config artifact')
    if report.get('provenance', {}).get('source_unchanged_during_collection') is not True:
        raise ValueError('collection did not establish stable source hashes')

    cases = report.get('cases')
    if not isinstance(cases, list) or len(cases) != len(config['users_per_release']):
        raise ValueError('case list does not match configured principal counts')
    verified = []
    for expected_users, case in zip(config['users_per_release'], cases):
        if case.get('users_per_release') != expected_users:
            raise ValueError('case order or principal count differs from configuration')
        samples = case.get('raw_latency_ns')
        if (not isinstance(samples, list) or len(samples) != config['trials']
                or any(type(value) is not int or value <= 0 for value in samples)):
            raise ValueError('raw per-release latency samples are malformed')
        ms = np.asarray(samples, dtype=np.float64) / 1_000_000
        latency = case.get('latency', {})
        recomputed = dict(
            trials=len(samples),
            p50_ms=float(np.percentile(ms, 50)),
            p95_ms=float(np.percentile(ms, 95)),
            p99_ms=float(np.percentile(ms, 99)),
            mean_ms=float(np.mean(ms)),
            throughput_releases_per_second=float(1_000_000_000 * len(samples)
                                                 / sum(samples)),
        )
        for key, value in recomputed.items():
            if key == 'trials':
                if latency.get(key) != value:
                    raise ValueError(f'{key} disagrees for {expected_users} users')
            elif not close(latency.get(key), value):
                raise ValueError(f'{key} disagrees for {expected_users} users')
        if (case.get('cumulative_release_count') != config['trials']
                or case.get('max_user_release_count') != config['trials']):
            raise ValueError(f'release accounting disagrees for {expected_users} users')
        if (not close(case.get('max_user_epsilon'),
                      config['release_epsilon'] * config['trials'])
                or not close(case.get('max_user_delta'),
                             config['release_delta'] * config['trials'])):
            raise ValueError(f'composed user budget disagrees for {expected_users} users')
        if not isinstance(case.get('final_database_bytes'), int) or case['final_database_bytes'] <= 0:
            raise ValueError(f'invalid database size for {expected_users} users')
        verified.append(dict(users_per_release=expected_users, **recomputed,
                             final_database_bytes=case['final_database_bytes']))

    source_status = {}
    expected_sources = {
        'scripts/benchmark_privacy_ledger.py',
        'research/simulation/privacy_ledger.py',
    }
    if set(report.get('provenance', {}).get('source_sha256', {})) != expected_sources:
        raise ValueError('collection source list contains an unexpected path')
    for relative, expected_hash in report['provenance']['source_sha256'].items():
        path = ROOT / relative
        if not path.resolve().is_relative_to(ROOT):
            raise ValueError('collection source path escapes the repository root')
        source_status[relative] = dict(
            collection_sha256=expected_hash,
            current_sha256=sha256(path) if path.is_file() else None,
            matches_current=(path.is_file() and sha256(path) == expected_hash),
        )
    return dict(
        schema_version=1,
        source_result_sha256=hashlib.sha256(results_bytes).hexdigest(),
        source_config_sha256=hashlib.sha256(config_bytes).hexdigest(),
        raw_input_manifest_verified=True,
        primary_metrics_recomputed=True,
        release_accounting_recomputed=True,
        source_sha256_comparison=source_status,
        cases=verified,
    )


def plot(source, output):
    source = Path(source)
    report = json.loads((source / 'results.json').read_text())
    cases = report['cases']
    users = [case['users_per_release'] for case in cases]
    if any(count <= 0 for count in users):
        raise ValueError('log-scale plot requires positive users-per-release values')
    p50 = [case['latency']['p50_ms'] for case in cases]
    p95 = [case['latency']['p95_ms'] for case in cases]
    p99 = [case['latency']['p99_ms'] for case in cases]
    storage = [case['final_database_bytes'] for case in cases]
    figure, left = plt.subplots(figsize=(8.2, 5.0))
    left.plot(users, p50, marker='o', label='p50 commit latency')
    left.plot(users, p95, marker='s', label='p95 commit latency')
    left.plot(users, p99, marker='^', label='p99 commit latency')
    left.set_xscale('log', base=2)
    left.set_yscale('log')
    left.set_xlabel('Authenticated principals charged per release')
    left.set_ylabel('SQLite transaction latency (ms, log scale)')
    left.grid(True, which='both', alpha=.25)
    right = left.twinx()
    right.plot(users, storage, color='black', linestyle='--', marker='x',
               label='database bytes after 30 releases')
    right.set_yscale('log')
    right.set_ylabel('SQLite database bytes (log scale)')
    left.legend(loc='upper left')
    right.legend(loc='lower right')
    figure.suptitle('Persistent user-privacy ledger microbenchmark')
    figure.tight_layout()
    figure.savefig(output, dpi=170)
    plt.close(figure)


def analyze(source):
    source = Path(source)
    audit = verify(source)
    derived_paths = [source / name for name in (
        'ledger-overhead.png', 'verification.json', 'derived-sha256.json')]
    if any(path.is_symlink() for path in derived_paths):
        raise ValueError('refusing to overwrite a symlinked derived artifact')
    analysis_source = Path(__file__).resolve()
    audit['analysis_provenance'] = dict(
        source_sha256=sha256(analysis_source),
        git_head=subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
    )
    figure = source / 'ledger-overhead.png'
    plot(source, figure)
    audit['generated_at_utc'] = datetime.now(timezone.utc).isoformat()
    audit['analysis_environment'] = dict(
        python=sys.version,
        platform=platform.platform(),
        numpy=np.__version__,
        matplotlib=matplotlib.__version__,
    )
    audit['plot_sha256'] = sha256(figure)
    verification = source / 'verification.json'
    verification.write_text(json.dumps(audit, indent=2) + '\n')
    derived_manifest = {
        'ledger-overhead.png': sha256(figure),
        'verification.json': sha256(verification),
    }
    (source / 'derived-sha256.json').write_text(
        json.dumps(derived_manifest, indent=2) + '\n')
    return audit


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('result_directory', type=Path)
    arguments = parser.parse_args()
    report = analyze(arguments.result_directory)
    print(json.dumps({
        'raw_input_manifest_verified': report['raw_input_manifest_verified'],
        'primary_metrics_recomputed': report['primary_metrics_recomputed'],
        'plot_sha256': report['plot_sha256'],
        'cases': len(report['cases']),
    }, indent=2))
