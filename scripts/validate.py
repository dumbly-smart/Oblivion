#!/usr/bin/env python3
"""Run actual quality gates with fixture builds and frozen-source provenance."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = 'research/oram_reference/Cargo.toml'
FIXTURES = {
    'PRESENCE_BINARY': 'target/release/examples/presence',
    'EXECUTOR_RESOURCES_BINARY': 'target/release/examples/resource_measure',
    'EXEC_TIMING_BINARY': 'target/release/examples/timing_measure',
    'EPOCH_SYSTEM_BINARY': 'target/release/oblivion-server',
}


def digest(root=ROOT):
    paths = set()
    for directory in ('crates', 'research', 'scripts', 'examples', '.github', 'experiments/configs'):
        for path in (root/directory).rglob('*'):
            if path.is_file() and path.suffix in ('.rs', '.py', '.toml', '.lock', '.wat', '.json', '.yml', '.yaml') and not any(part in path.parts for part in ('target', 'upstream', '__pycache__')):
                paths.add(path)
    paths.update(path for path in (root/'Cargo.toml', root/'Cargo.lock') if path.is_file())
    result = hashlib.sha256()
    for path in sorted(paths):
        result.update(str(path.relative_to(root)).encode()+b'\0'+path.read_bytes()+b'\0')
    return result.hexdigest()


def commands(with_reference=True):
    result = [
        ['cargo', 'fmt', '--all', '--check'],
        ['cargo', 'clippy', '--locked', '--workspace', '--all-targets', '--', '-D', 'warnings'],
        ['cargo', 'test', '--locked', '--workspace'],
        ['cargo', 'build', '--locked', '--release', '--workspace', '--bins', '--examples'],
    ]
    if with_reference:
        result += [
            ['cargo', 'fmt', '--manifest-path', REFERENCE, '--', '--check'],
            ['cargo', 'clippy', '--locked', '--manifest-path', REFERENCE, '--all-targets', '--', '-D', 'warnings'],
            ['cargo', 'test', '--locked', '--manifest-path', REFERENCE],
            ['cargo', 'build', '--locked', '--release', '--manifest-path', REFERENCE],
        ]
    return result+[
        [sys.executable, '-m', 'unittest', 'discover', '-s', 'research/tests'],
        ['cargo', 'test', '--locked', '--release', '-p', 'oblivion-store', 'million_operation_oracle', '--', '--ignored', '--exact'],
    ]


def dump(path, value):
    temporary = path.with_name(path.name+'.tmp')
    temporary.write_text(json.dumps(value, indent=2)+'\n')
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--with-reference', action='store_true', default=True, help='validate the separate GPL reference benchmark workspace (enabled by default)')
    args = parser.parse_args()
    args.output.mkdir(exist_ok=False)
    before = digest()
    environment = os.environ.copy()
    environment.update({name: str((ROOT/path).resolve()) for name, path in FIXTURES.items()})
    metadata = dict(schema_version=2, source_sha256_before=before, platform=platform.platform(), python=sys.version,
                    configuration='locked workspace + real release fixtures + explicit million-operation stress',
                    include_reference=args.with_reference, fixture_environment={name: environment[name] for name in FIXTURES},
                    digest_scope='source, guest WAT, manifests/locks, CI and experiment configs; caches/upstream/result snapshots excluded',
                    output=str(args.output.resolve()))
    dump(args.output/'metadata.json', metadata)
    records = []
    for index, command in enumerate(commands(args.with_reference)):
        print('Running', ' '.join(command), flush=True)
        started = time.monotonic()
        log = args.output/f'{index}.log'
        with log.open('w') as output:
            result = subprocess.run(command, cwd=ROOT, env=environment, stdout=output, stderr=subprocess.STDOUT)
        records.append(dict(command=command, exit_code=result.returncode, elapsed_seconds=time.monotonic()-started, log=log.name))
        dump(args.output/'commands.json', records)
    metadata['source_sha256_after'] = digest()
    dump(args.output/'metadata.json', metadata)
    raise SystemExit(int(any(row['exit_code'] for row in records) or before != metadata['source_sha256_after']))


if __name__ == '__main__':
    main()
