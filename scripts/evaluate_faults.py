#!/usr/bin/env python3
"""Repeat actual process fault tests; harness wall times are not request latency."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = [
    'executor_bootstrap_and_partial_frames_have_bounded_lifetimes',
    'duplicate_and_skipped_epochs_fail_closed_without_second_execution',
    'lost_pir_server_returns_authenticated_zero_error_without_user_state',
    'abandoned_response_pipe_cannot_hold_executor_forever',
    'late_frame_after_idle_timeout_cannot_resume_session',
    'tampered_authenticated_frame_runs_cover_and_next_real_state_is_untouched',
    'eof_midway_through_multi_client_epoch_is_rejected',
]


def integration_artifact(output):
    candidates = []
    for line in output.splitlines():
        record = json.loads(line)
        target = record.get('target', {})
        if record.get('reason') == 'compiler-artifact' and target.get('name') == 'pipeline' and 'test' in target.get('kind', []) and record.get('executable'):
            candidates.append(Path(record['executable']))
    if len(candidates) != 1:
        raise ValueError('expected exactly one pipeline integration-test artifact')
    return candidates[0]


def assertions_passed(returncode, stdout):
    return returncode == 0 and bool(re.search(r'^running 1 test$', stdout, re.MULTILINE)) and bool(re.search(r'^test result: ok\. 1 passed; 0 failed(?:;|$)', stdout, re.MULTILINE))


def run_case(command, output, timeout):
    output.mkdir()
    started = time.monotonic_ns()
    with (output/'stdout.log').open('w') as stdout, (output/'stderr.log').open('w') as stderr:
        child = subprocess.Popen(command, cwd=ROOT, stdout=stdout, stderr=stderr, start_new_session=True)
        timed_out = False
        try:
            returncode = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(child.pid, signal.SIGKILL)
            returncode = child.wait()
    return dict(command=command, returncode=returncode, timed_out=timed_out,
                wall_ns=time.monotonic_ns()-started,
                passed=not timed_out and assertions_passed(returncode, (output/'stdout.log').read_text()))


def wilson(failures, count):
    z = 1.959963984540054
    p = failures/count
    denominator = 1+z*z/count
    center = (p+z*z/(2*count))/denominator
    radius = z*math.sqrt(p*(1-p)/count+z*z/(4*count*count))/denominator
    return [max(0, center-radius), min(1, center+radius)]


def summarize(rows, scenarios, trials):
    expected = {(name, trial) for name in scenarios for trial in range(trials)}
    if len(rows) != len(expected) or {(r['scenario'], r['trial']) for r in rows} != expected:
        raise ValueError('missing, duplicate or unexpected fault trial')
    report = {}
    for name in scenarios:
        subset = [r for r in rows if r['scenario'] == name]
        times = sorted(r['wall_ns']/1e6 for r in subset)
        passed = sum(r['passed'] for r in subset)
        report[name] = dict(trials=trials, assertion_passes=passed, assertion_failures=trials-passed,
                            failure_fraction_wilson95=wilson(trials-passed, trials),
                            **{f'harness_wall_p{p}_ms': times[(len(times)-1)*p//100] for p in [50, 95, 99]})
    return report


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic_json(path, value):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, prefix=path.name+'.', delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(value, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def source_hash():
    paths = sorted(p for p in (ROOT/'crates').rglob('*') if p.is_file() and ('src' in p.parts or 'tests' in p.parts))
    paths += [ROOT/'Cargo.toml', ROOT/'Cargo.lock', Path(__file__)]
    digest = hashlib.sha256()
    for path in paths:
        digest.update(str(path.relative_to(ROOT)).encode()+b'\0'+path.read_bytes()+b'\0')
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--trials', type=int, default=30)
    parser.add_argument('--seed', type=int, default=20261023)
    parser.add_argument('--timeout', type=float, default=12)
    args = parser.parse_args()
    if not 2 <= args.trials <= 1000 or not 1 <= args.timeout <= 60 or platform.system() != 'Linux':
        parser.error('Linux required; trials 2..1000; timeout 1..60 seconds')
    args.output.mkdir(exist_ok=False)
    build = subprocess.run(['cargo', 'test', '--locked', '-p', 'oblivion-server', '--test', 'pipeline', '--no-run', '--message-format=json'], cwd=ROOT, capture_output=True, text=True)
    (args.output/'build.stdout.log').write_text(build.stdout)
    (args.output/'build.stderr.log').write_text(build.stderr)
    build.check_returncode()
    binary = integration_artifact(build.stdout)
    server = ROOT/'target/debug/oblivion-server'
    metadata = dict(schema_version=1, trials=args.trials, seed=args.seed, timeout_seconds=args.timeout,
                    scenarios=SCENARIOS, test_binary=str(binary), test_binary_sha256=sha(binary),
                    server_binary_sha256=sha(server), source_sha256_before=source_hash(),
                    git_head=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                    platform=platform.platform(), cpuinfo=Path('/proc/cpuinfo').read_text(),
                    methodology='Fresh test subprocess per shuffled trial. Each test launches actual workers and asserts its named fault behavior. Wilson interval on trial assertion failures; short tails descriptive. Harness wall time includes setup, fault waits, assertions and cleanup; not response latency. Active failures can reveal availability and partial execution; no indistinguishability claim.')
    atomic_json(args.output/'metadata.json', metadata)
    jobs = [(name, trial) for name in SCENARIOS for trial in range(args.trials)]
    random.Random(args.seed).shuffle(jobs)
    rows = []
    for order, (name, trial) in enumerate(jobs):
        directory = args.output/f'{order:03}-{name}-{trial}'
        row = run_case([str(binary), name, '--exact', '--nocapture', '--test-threads=1'], directory, args.timeout)
        row.update(scenario=name, trial=trial, order=order)
        atomic_json(directory/'record.json', row)
        rows.append(row)
        atomic_json(args.output/'trials.json', rows)
        print(f'{order+1}/{len(jobs)} {name} trial={trial} passed={row["passed"]}', flush=True)
    metadata.update(source_sha256_after=source_hash(), test_binary_sha256_after=sha(binary), server_binary_sha256_after=sha(server))
    atomic_json(args.output/'metadata.json', metadata)
    atomic_json(args.output/'report.json', summarize(rows, SCENARIOS, args.trials))
    if not all(r['passed'] for r in rows) or metadata['source_sha256_before'] != metadata['source_sha256_after'] or metadata['server_binary_sha256'] != metadata['server_binary_sha256_after'] or metadata['test_binary_sha256'] != metadata['test_binary_sha256_after']:
        raise SystemExit('fault assertion or source/binary stability check failed; evidence retained')


if __name__ == '__main__':
    main()
