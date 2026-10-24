"""Reproducible actual-batcher synthetic presence experiment, stdlib only."""
import argparse
import gzip
import hashlib
import json
import math
from pathlib import Path
import platform
import random
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from research.attacks.presence import MODES, intersect


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def ci(values, seed=812, binomial=False):
    rng = random.Random(seed); n = len(values)
    boot = sorted(sum(rng.choices(values, k=n))/n for _ in range(2000))
    result = {'mean': sum(values)/n, 'ci95': [boot[49], boot[1949]], 'unit': 'whole independent trial'}
    if binomial:
        proportion = result['mean']; z = 1.959963984540054
        center = (proportion+z*z/(2*n))/(1+z*z/n)
        width = z*math.sqrt(proportion*(1-proportion)/n+z*z/(4*n*n))/(1+z*z/n)
        result['wilson95'] = [max(0, center-width), min(1, center+width)]
    return result


def read_jsonl(path):
    with gzip.open(path, 'rt') as stream:
        return [json.loads(line) for line in stream]


def verify_retained_artifacts(source, config):
    """Verify retained data; an ignored measurement executable is not reanalysis input."""
    source = source.resolve()
    manifest = json.loads((source/'artifact-sha256.json').read_text())
    if not isinstance(manifest, dict) or not manifest:
        raise ValueError('invalid artifact manifest')
    verified = 0
    verified_data = 0
    for name, expected in manifest.items():
        if (not isinstance(name, str) or not name or Path(name).is_absolute()
                or '..' in Path(name).parts
                or not isinstance(expected, str) or len(expected) != 64
                or any(character not in '0123456789abcdef' for character in expected)):
            raise ValueError('invalid artifact manifest entry')
        artifact = (source/name).resolve()
        if not artifact.is_relative_to(source):
            raise ValueError(f'artifact path outside source: {name}')
        if not artifact.is_file():
            # Only this exact historical manifest entry can lack local bytes.
            # Its expected hash must subsequently match verified provenance.
            if name == 'bin/presence' and not artifact.exists():
                continue
            raise ValueError(f'artifact path missing or outside source: {name}')
        if digest(artifact) != expected:
            raise ValueError(f'artifact digest mismatch: {name}')
        verified += 1
        verified_data += name != 'bin/presence'
    required = {'provenance.json'}
    for percent in config['online_percent']:
        for seed in config['seeds']:
            for channel in ('observer', 'truth', 'beacon'):
                required.add(f'raw/p{percent}-s{seed}.{channel}.jsonl.gz')
    missing = required-set(manifest)
    if missing:
        raise ValueError(f'consumed artifacts missing from manifest: {sorted(missing)}')
    # provenance.json has already passed its recorded digest before it is trusted.
    provenance = json.loads((source/'provenance.json').read_text())
    expected_binary = provenance.get('binary_sha256') if isinstance(provenance, dict) else None
    if (not isinstance(expected_binary, str) or len(expected_binary) != 64
            or any(character not in '0123456789abcdef' for character in expected_binary)):
        raise ValueError('invalid measurement executable fingerprint in verified provenance')
    if 'bin/presence' in manifest and manifest['bin/presence'] != expected_binary:
        raise ValueError('measurement executable manifest/provenance fingerprints disagree')
    binary = (source/'bin/presence').resolve()
    if not binary.is_relative_to(source):
        raise ValueError('measurement executable path outside source')
    if binary.exists() and not binary.is_file():
        raise ValueError('measurement executable is not a file')
    available = binary.is_file()
    if available and digest(binary) != expected_binary:
        raise ValueError('measurement executable digest mismatch: bin/presence')
    return {'verified_artifacts': verified, 'verified_data_artifacts': verified_data,
            'measurement_executable': {'path': 'bin/presence', 'available': available,
                                       'verified': available, 'expected_sha256': expected_binary}}


def summarize(out, config, raw_out=None):
    raw_out = out if raw_out is None else raw_out
    # Evaluate the intermittent positive control before defended predictions.
    control_checks = []
    for percent in config['online_percent']:
        successes = []
        for seed in config['seeds']:
            stem = raw_out/'raw'/f'p{percent}-s{seed}'
            rows = [r for r in read_jsonl(str(stem)+'.observer.jsonl.gz') if r['mode'] == MODES[0]]
            owner = read_jsonl(str(stem)+'.truth.jsonl.gz')[0]['owner']
            beacon = read_jsonl(str(stem)+'.beacon.jsonl.gz')
            prediction = intersect(rows, beacon, seed=90000)
            successes.append(int(prediction['ranking'][0] == owner))
        check = {'online_percent': percent, **ci(successes, binomial=True)}
        control_checks.append(check)
        if check['ci95'][0] <= .125:
            raise RuntimeError('positive control did not exceed chance')
    (out/'positive-control-first.json').write_text(json.dumps(control_checks, indent=2)+'\n')
    results = []; trial_metrics = []; trial_costs = []
    for percent in config['online_percent']:
        cells = {}
        for seed in config['seeds']:
            stem = raw_out/'raw'/f'p{percent}-s{seed}'
            observations = read_jsonl(str(stem)+'.observer.jsonl.gz')
            truth = read_jsonl(str(stem)+'.truth.jsonl.gz')
            beacon = read_jsonl(str(stem)+'.beacon.jsonl.gz')
            owner = truth[0]['owner']
            for mode in MODES:
                rows = [r for r in observations if r['mode'] == mode]
                private = [r for r in truth if r['mode'] == mode]
                if len(rows) != config['epochs'] or len(private) != len(rows):
                    raise ValueError('incomplete trial')
                for row, latent, event in zip(rows, private, beacon):
                    assert latent['owner'] == owner and latent['seed'] == seed
                    assert set(latent['real']) <= set(latent['online'])
                    assert event['event'] == (owner in latent['real'])
                    expected = list(range(8)) if mode == 'always_participating' else latent['online']
                    assert row['incoming'] == expected
                    assert latent['verified'] == len(expected)
                    assert latent['cover_rejected'] == 8-len(expected)
                for knowledge in config['knowledge_events']:
                    for observer in ('incoming', 'missing_slots', 'downstream'):
                        prediction = intersect(rows, beacon, knowledge_events=knowledge, observer=observer, seed=90000)
                        candidates = prediction['candidates']; ranking = prediction['ranking']
                        assert owner in candidates
                        key = (mode, knowledge, observer)
                        metric = {'online_percent': percent, 'seed': seed, 'mode': mode, 'knowledge_events': knowledge,
                                  'observer': observer, 'owner': owner, **prediction,
                                  'accuracy': int(bool(ranking) and ranking[0] == owner), 'top3': int(owner in ranking[:3]),
                                  'candidate_count': len(candidates), 'majority_accuracy': int(owner == 0)}
                        cells.setdefault(key, []).append(metric); trial_metrics.append(metric)
                costs = {'mode': mode, 'online_percent': percent, 'seed': seed,
                         'incoming_bytes': sum(r['incoming_bytes'] for r in rows),
                         'downstream_bytes': sum(r['outgoing_bytes'] for r in rows),
                         'batcher_cover_bytes': sum(r['cover_rejected']*164 for r in private),
                         'authenticated_dummy_bytes': sum(r['authenticated_dummy_frames']*164 for r in private),
                         'real_frames': sum(len(r['real']) for r in private)}
                trial_costs.append(costs)
        for (mode, knowledge, observer), values in cells.items():
            results.append({'online_percent': percent, 'mode': mode, 'knowledge_events': knowledge, 'observer': observer,
                            'trials': len(values), 'chance': .125, 'top3_chance': .375,
                            **{name: ci([v[name] for v in values], binomial=name != 'candidate_count') for name in ('accuracy', 'top3', 'candidate_count', 'majority_accuracy')}})
    (out/'costs.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in trial_costs))
    # Positive control must succeed before interpreting defended comparisons.
    controls = [r for r in results if r['mode'] == MODES[0] and r['knowledge_events'] is None and r['observer'] == 'incoming']
    if not all(r['accuracy']['ci95'][0] > .125 for r in controls):
        raise RuntimeError('positive control did not exceed chance')
    (out/'trial-metrics.json').write_text(json.dumps(trial_metrics, indent=2)+'\n')
    (out/'summary.json').write_text(json.dumps({'positive_control_passed': True, 'score_semantics': 'UNCALIBRATED', 'results': results}, indent=2)+'\n')


def run(binary, config_path, out):
    config = json.loads(config_path.read_text())
    if out.exists():
        raise ValueError('output already exists: preserve historical artifacts')
    (out/'raw').mkdir(parents=True); (out/'bin').mkdir(); (out/'sources').mkdir()
    immutable = out/'bin'/'presence'; shutil.copyfile(binary, immutable); immutable.chmod(0o555)
    files = ['crates/oblivion-batcher/examples/presence.rs', 'crates/oblivion-batcher/src/lib.rs',
             'crates/oblivion-batcher/src/envelope.rs', 'research/attacks/presence.py', 'research/analysis/presence.py',
             'research/tests/test_presence.py', 'Cargo.lock', 'Cargo.toml', 'crates/oblivion-batcher/Cargo.toml']
    hashes = {}
    for name in files:
        hashes[name] = digest(name)
        shutil.copyfile(name, out/'sources'/name.replace('/', '__'))
    shutil.copyfile(config_path, out/'config.json')
    provenance = {'created_before_launch_utc': datetime.now(timezone.utc).isoformat(), 'binary_sha256': digest(immutable),
                  'config_sha256': digest(config_path), 'source_sha256': hashes, 'python': platform.python_version(),
                  'hardware': platform.uname()._asdict(), 'cpu': Path('/proc/cpuinfo').read_text(),
                  'rustc': subprocess.check_output(['rustc', '--version'], text=True).strip(),
                  'cargo': subprocess.check_output(['cargo', '--version'], text=True).strip(),
                  'git_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
                  'scheduler': 'virtual Instant + epoch*10ms; no sleep or packet timing',
                  'auxiliary': 'separate public semantic beacon of owner-conditioned function events',
                  'command_template': [str(immutable), 'SEED', str(config['epochs']), 'ONLINE_PERCENT', 'TRUTH_PATH', 'BEACON_PATH']}
    (out/'provenance.json').write_text(json.dumps(provenance, indent=2)+'\n')
    commands = []
    for percent in config['online_percent']:
        for seed in config['seeds']:
            stem = out/'raw'/f'p{percent}-s{seed}'
            # stdout is compressed incrementally; bounded private/auxiliary files are
            # immediately compressed after each 384-epoch export and removed.
            with tempfile.TemporaryDirectory() as directory:
                private = Path(directory)/'truth'; beacon = Path(directory)/'beacon'
                cmd = [str(immutable.resolve()), str(seed), str(config['epochs']), str(percent), str(private), str(beacon)]
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                with gzip.open(str(stem)+'.observer.jsonl.gz', 'wb') as stream:
                    shutil.copyfileobj(process.stdout, stream)
                stderr = process.stderr.read().decode(); status = process.wait()
                commands.append({'seed': seed, 'online_percent': percent, 'exit': status, 'stderr': stderr})
                if status:
                    raise RuntimeError(stderr)
                for source, suffix in ((private, 'truth'), (beacon, 'beacon')):
                    with source.open('rb') as inp, gzip.open(str(stem)+f'.{suffix}.jsonl.gz', 'wb') as dest:
                        shutil.copyfileobj(inp, dest)
    (out/'commands.json').write_text(json.dumps(commands, indent=2)+'\n')
    summarize(out, config)
    artifacts = {str(p.relative_to(out)): digest(p) for p in out.rglob('*')
                 if p.is_file() and 'bin' not in p.relative_to(out).parts}
    (out/'artifact-sha256.json').write_text(json.dumps(artifacts, indent=2)+'\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--binary', type=Path)
    parser.add_argument('--raw-source', type=Path, help='Analyze retained raw streams into a fresh output directory')
    parser.add_argument('--config', type=Path, default=Path('experiments/configs/presence-30.json'))
    parser.add_argument('--out', type=Path, required=True); args = parser.parse_args()
    if args.raw_source is not None:
        if args.binary is not None or args.out.exists():
            parser.error('raw analysis needs a fresh output and no --binary')
        source = args.raw_source.resolve()
        config = json.loads(args.config.read_text())
        verified_artifacts = verify_retained_artifacts(source, config)
        args.out.mkdir(parents=True)
        provenance = {'created_before_analysis_utc': datetime.now(timezone.utc).isoformat(),
                      'raw_source': str(source), 'raw_artifact_manifest_sha256': digest(source/'artifact-sha256.json'),
                      'raw_provenance_sha256': digest(source/'provenance.json'),
                      'verified_source_artifacts': verified_artifacts['verified_artifacts'],
                      'verified_data_artifacts': verified_artifacts['verified_data_artifacts'],
                      'measurement_executable': verified_artifacts['measurement_executable'],
                      'config_sha256': digest(args.config), 'tie_seed': 90000,
                      'tie_seed_semantics': 'public constant independent of workload seeds; no latent seed passed to attack',
                      'source_sha256': {p: digest(p) for p in ('research/analysis/presence.py', 'research/attacks/presence.py')}}
        (args.out/'provenance.json').write_text(json.dumps(provenance, indent=2)+'\n')
        shutil.copyfile(args.config, args.out/'config.json')
        shutil.copyfile(__file__, args.out/'analysis-source.py')
        shutil.copyfile('research/attacks/presence.py', args.out/'attack-source.py')
        summarize(args.out, config, raw_out=source)
    else:
        if args.binary is None:
            parser.error('--binary or --raw-source is required')
        run(args.binary, args.config, args.out)
