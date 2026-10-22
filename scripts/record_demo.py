#!/usr/bin/env python3
"""Record one real local integration demo and render its observed events as video."""
import argparse
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import selectors
import shlex
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def version(args):
    result = subprocess.run(args, capture_output=True, text=True, check=True)
    return (result.stdout or result.stderr).strip()


def records(path):
    if not path.exists():
        return []
    lines = path.read_text().splitlines()
    result = []
    for line in lines:
        try:
            result.append(json.loads(line))
        except json.JSONDecodeError:
            # The subprocess can be between write calls; retry on the next poll.
            break
    return result


def render(artifact, command, events, elapsed, summary, evidence):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    intro = 5
    end = intro + math.ceil(elapsed) + 7
    flow = '3 clients -> encrypted epoch batch -> trusted executor -> encrypted responses'
    subflow = '                                   | two PIR servers + Path ORAM state'
    with tempfile.TemporaryDirectory(prefix='oblivion-demo-') as temporary:
        frames = Path(temporary)
        for second in range(end):
            fig = plt.figure(figsize=(12.8, 7.2), dpi=100, facecolor='#101827')
            fig.text(.05, .91, 'OBLIVION / recorded local integration demo',
                     color='#6ee7c4', fontsize=24, weight='bold', family='monospace')
            fig.text(.05, .85, 'Data-driven terminal visualization of an actual subprocess run',
                     color='white', fontsize=14, family='monospace')
            fig.text(.05, .77, flow + '\n' + subflow, color='#b8c7e0', fontsize=12,
                     family='monospace', linespacing=1.6)
            fig.text(.05, .66, '$ ' + shlex.join(command[:2]) + ' ... 50 3 mixed',
                     color='#f5d780', fontsize=13, family='monospace')
            shown = [event for event in events if event['elapsed_s'] <= max(0, second - intro)]
            lines = [f"[{event['elapsed_s']:6.2f}s] {event['text']}" for event in shown[-8:]]
            if second < intro:
                lines = ['One measured run; 8 epochs; 3 enrolled clients; 50% real requests.',
                         'Mixed WASM functions; SSE discovery + PIR + ORAM + padded responses.',
                         'Progress below appears only when completed private rows are observed.']
            elif second >= intro + elapsed:
                lines = [f"Exit status: 0 | elapsed {elapsed:.3f} seconds",
                         f"Client oracle verified: {summary['real_invocations']} real, "
                         f"{summary['dummy_invocations']} dummy invocations",
                         f"Functions verified: {summary['functions_verified']} | "
                         f"SSE searches verified: {summary['sse_searches_verified']}",
                         f"Actual storage events: {evidence['storage_events']} | "
                         f"fixed request/response bytes: {summary['request_bytes']}",
                         f"Per-client state counters: {summary['client_state_counters']}",
                         'Raw bytes, timed events, terminalcast and hashes accompany this video.']
            fig.text(.05, .59, '\n'.join(lines), color='#e4ebf5', fontsize=14,
                     family='monospace', va='top', linespacing=1.7)
            fig.text(.05, .12, 'Trusted process simulation; no hardware TEE. PIR servers must not collude.',
                     color='#f5b7b1', fontsize=12, family='monospace')
            fig.text(.05, .07, 'API / inherited-pipe integration evidence; not a screen recording or privacy proof.',
                     color='#b8c7e0', fontsize=12, family='monospace')
            fig.savefig(frames / f'{second:04d}.png', facecolor=fig.get_facecolor())
            if second == end - 2:
                fig.savefig(artifact / 'representative-frame.png', facecolor=fig.get_facecolor())
            plt.close(fig)
        encode = ['ffmpeg', '-hide_banner', '-loglevel', 'error', '-framerate', '1',
                  '-i', str(frames / '%04d.png'), '-c:v', 'libx264', '-preset', 'veryfast',
                  '-crf', '24', '-pix_fmt', 'yuv420p', '-r', '24', '-movflags', '+faststart',
                  str(artifact / 'demo.mp4')]
        subprocess.run(encode, check=True)
    probe = subprocess.run(['ffprobe', '-v', 'error', '-show_format', '-show_streams',
                            '-of', 'json', str(artifact / 'demo.mp4')],
                           check=True, capture_output=True, text=True)
    (artifact / 'ffprobe.json').write_text(probe.stdout)
    return {'render_command': encode, 'duration_seconds': end,
            'video_sha256': digest(artifact / 'demo.mp4'),
            'video_bytes': (artifact / 'demo.mp4').stat().st_size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path, help='new demo output directory')
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        parser.error('output directory must not exist')
    artifact = ROOT / 'docs' / 'artifacts' / ('demo-' + output.name)
    if artifact.exists():
        parser.error(f'artifact directory already exists: {artifact}')
    binary = ROOT / 'target' / 'release' / 'oblivion-server'
    if not binary.is_file():
        parser.error('build first: cargo build --release -p oblivion-server')
    # Check rendering dependencies before starting the measured subprocess.
    import matplotlib
    versions = {'python': sys.version, 'matplotlib': matplotlib.__version__,
                'ffmpeg': version(['ffmpeg', '-version']).splitlines()[0],
                'ffprobe': version(['ffprobe', '-version']).splitlines()[0],
                'rustc': version(['rustc', '--version'])}
    output.parent.mkdir(parents=True, exist_ok=True)
    artifact.mkdir(parents=True)
    command = [str(binary), 'demo-sse', str(output), '50', '3', 'mixed']
    source_paths = sorted(path for path in (ROOT / 'crates').rglob('*') if path.is_file())
    source_paths += [ROOT / 'Cargo.toml', ROOT / 'Cargo.lock', Path(__file__).resolve()]
    manifest = {str(path.relative_to(ROOT)): digest(path) for path in source_paths}
    provenance = {'schema_version': 1, 'recorded_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
                  'command': command, 'cwd': str(ROOT), 'binary_sha256': digest(binary),
                  'source_files_sha256_before_launch': manifest, 'tool_versions': versions,
                  'trials': 1, 'configuration': {'mode': 'demo-sse', 'real_percent': 50,
                                               'participants': 3, 'mixed_functions': True, 'epochs': 8},
                  'scope': 'actual local API / inherited-pipe integration demonstration',
                  'video_kind': 'data-driven terminal visualization, not screen recording',
                  'assumptions': ['trusted process simulation; no hardware TEE',
                                  'two PIR servers must not collude'],
                  'progress_semantics': 'counts of flushed executor-private rows observed by recorder; not exact execution timestamps'}
    save(artifact / 'provenance.json', provenance)
    started = time.monotonic()
    events = []
    with (artifact / 'events.jsonl').open('w') as event_log, (artifact / 'terminal.cast').open('w') as cast:
        cast.write(json.dumps({'version': 2, 'width': 110, 'height': 32,
                               'timestamp': int(time.time()), 'title': 'OBLIVION actual local demo',
                               'env': {'TERM': 'xterm-256color'}}) + '\n')

        def event(text, kind='observation'):
            entry = {'elapsed_s': round(time.monotonic() - started, 6), 'kind': kind, 'text': text}
            events.append(entry)
            event_log.write(json.dumps(entry) + '\n'); event_log.flush()
            cast.write(json.dumps([entry['elapsed_s'], 'o', text + '\r\n']) + '\n'); cast.flush()

        event('$ ' + shlex.join(command), 'command')
        process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        selector = selectors.DefaultSelector()
        streams = {'stdout': (artifact / 'stdout.log').open('wb'),
                   'stderr': (artifact / 'stderr.log').open('wb')}
        for name in streams:
            selector.register(getattr(process, name), selectors.EVENT_READ, name)
        completed = 0
        try:
            while selector.get_map() or process.poll() is None:
                if time.monotonic() - started > 120:
                    process.kill()
                    raise TimeoutError('demo exceeded the 120 second recording bound')
                for key, _ in selector.select(.05):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    streams[key.data].write(chunk); streams[key.data].flush()
                    event(chunk.decode('utf-8', errors='replace').rstrip(), key.data)
                private = records(output / 'executor-private.jsonl')
                if len(private) != completed:
                    completed = len(private)
                    successful = sum(row.get('status') == 'Success' for row in private)
                    event(f'Observed completed invocations: {completed}/24; successful: {successful}')
            returncode = process.wait()
        finally:
            if process.poll() is None:
                process.kill(); process.wait()
            selector.close()
            for stream in streams.values():
                stream.close()
        elapsed = time.monotonic() - started
        event(f'Subprocess exited with status {returncode}', 'exit')
    provenance.update({'returncode': returncode, 'elapsed_seconds': elapsed})
    save(artifact / 'provenance.json', provenance)
    if returncode:
        raise SystemExit(f'demo failed; inspect {artifact}')
    summary = json.loads((output / 'client-summary.json').read_text())
    private = records(output / 'executor-private.jsonl')
    truth = records(output / 'client-ground-truth.jsonl')
    storage = records(output / 'storage-observer.jsonl')
    evidence = {'completed_private_invocations': len(private),
                'successful_private_invocations': sum(row.get('status') == 'Success' for row in private),
                'ground_truth_invocations': len(truth), 'storage_events': len(storage),
                'client_summary': summary,
                'raw_output_sha256': {str(path.relative_to(output)): digest(path)
                                      for path in sorted(output.rglob('*')) if path.is_file()}}
    save(artifact / 'evidence.json', evidence)
    if len(private) != 24 or len(truth) != 24 or evidence['successful_private_invocations'] != 24:
        raise RuntimeError('recorded demo lacks all 24 successful invocations')
    provenance['render'] = render(artifact, command, events, elapsed, summary, evidence)
    save(artifact / 'provenance.json', provenance)
    (artifact / 'captions.txt').write_text(
        'OBLIVION recorded local integration demo\n\n' + '\n'.join(
            f"{event['elapsed_s']:.3f}s {event['text']}" for event in events) +
        '\n\nClient summary:\n' + json.dumps(summary, indent=2) +
        '\n\nTrusted process simulation, no hardware TEE; PIR servers must not collude.\n'
        'Video is a data-driven visualization of this run, not a screen recording.\n')
    print(f'Actual demo output: {output}\nRecording artifacts: {artifact}\nVideo: {artifact / "demo.mp4"}')


if __name__ == '__main__':
    main()
