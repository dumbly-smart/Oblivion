"""Real licensed text postings; synthetic queries; passive local SSE evaluation."""
import argparse
from collections import Counter
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import random
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import scipy

from research.analysis.sse import cluster_interval, dump, metrics, read_observations, update_order
from research.attacks.inference import infer
from research.attacks.sse import CountVolumeAttack

ROOT = Path(__file__).resolve().parents[2]
MODES = ('exact_count_control', 'sse', 'padded_sse')
ATTACKS = ('count_volume', 'likelihood_assignment', 'iterative_hungarian_markov', 'exact_markov_bound')
SOURCES = ('crates/oblivion-sse/src/lib.rs', 'crates/oblivion-sse/examples/corpus.rs',
           'research/analysis/corpus.py', 'research/analysis/sse.py',
           'research/attacks/sse.py', 'research/attacks/inference.py', 'scripts/evaluate_corpus.py')


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            digest.update(block)
    return digest.hexdigest()


def snapshot_binary(source, destination):
    """Copy one executable inode into a private run path before any export."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open('rb') as executable, destination.open('xb') as frozen:
        before = os.fstat(executable.fileno())
        shutil.copyfileobj(executable, frozen, length=65536)
        after = os.fstat(executable.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise RuntimeError('source executable changed while snapshotting; preserve output and retry in a new directory')
    destination.chmod(0o555)
    return destination, sha(destination)


def load_records(archive, config):
    """Stream bounded archive member; retain tokens/digest/class, never SMS text."""
    if archive.stat().st_size > 300_000 or sha(archive) != config['source_sha256']:
        raise ValueError('source archive size/hash mismatch')
    records, seen, member_hash, lines = [], set(), hashlib.sha256(), 0
    with zipfile.ZipFile(archive) as source:
        member = source.getinfo('SMSSpamCollection')
        if member.file_size > 600_000:
            raise ValueError('source member size limit')
        with source.open(member) as stream:
            for raw in stream:
                member_hash.update(raw)
                lines += 1
                if len(raw) > 10000:
                    raise ValueError('source record size limit')
                label, text = raw.decode('utf-8').rstrip('\r\n').split('\t', 1)
                if label not in ('ham', 'spam'):
                    raise ValueError('unknown corpus class')
                normalized = ' '.join(text.lower().split())
                digest = hashlib.sha256(normalized.encode()).hexdigest()
                if digest in seen:
                    continue
                seen.add(digest)
                tokens = frozenset(word for word in re.findall('[a-z]+', normalized) if 3 <= len(word) <= 16)
                records.append({'digest': digest, 'spam': label == 'spam', 'tokens': tokens})
    if member_hash.hexdigest() != config['member_sha256']:
        raise ValueError('source member hash mismatch')
    return records, {'source_lines': lines, 'deduplicated_documents': len(records),
                     'duplicates_removed': lines-len(records), 'source_member_sha256': member_hash.hexdigest()}


def select_vocabulary(documents, keywords=8):
    """Auxiliary-only frequent vocabulary, with distinct auxiliary count bins."""
    counts = Counter(word for doc in documents for word in doc['tokens'])
    selected, used_counts = [], set()
    for word, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        if count not in used_counts:
            selected.append(word)
            used_counts.add(count)
        if len(selected) == keywords:
            return selected
    raise ValueError('insufficient distinct auxiliary count bins')


def postings(documents, vocabulary):
    return [[index for index, doc in enumerate(documents) if word in doc['tokens']] for word in vocabulary]


def make_trial(records, config, trial):
    rng = random.Random(config['seed'] + trial)
    shuffled = list(records)
    rng.shuffle(shuffled)
    pools = [shuffled[i::3] for i in range(3)]
    n = config['documents']
    base, target = rng.sample(pools[0], n), rng.sample(pools[1], n)
    vocabulary = select_vocabulary(base, config['keywords'])
    views = {'matched': base}
    for fraction in config['drift_spam_fractions']:
        spam = [doc for doc in pools[2] if doc['spam']]
        ham = [doc for doc in pools[2] if not doc['spam']]
        amount = round(n * fraction)
        chosen = rng.sample(spam, amount) + rng.sample(ham, n-amount)
        rng.shuffle(chosen)
        views[f'spam{round(100*fraction)}'] = chosen
    labels = list(range(config['keywords']))
    weights = list(range(1, len(labels)+1))
    rng.shuffle(weights)
    profile = rng.choices(labels, weights=weights, k=config['profile_queries'])
    queries = [rng.choices(labels, weights=weights, k=config['queries_per_session']) for _ in range(config['target_sessions'])]
    auxiliary = {}
    for name, documents in views.items():
        auxiliary[name] = {'counts': [len(p) for p in postings(documents, vocabulary)],
                           'public_postings': postings(documents, vocabulary),
                           'corpus_documents': n, 'vocabulary': vocabulary,
                           'query_counts': [profile.count(c) for c in labels], 'profile_labels': profile,
                           'profiling_session': f'independent-public-{trial}',
                           'document_digests': [d['digest'] for d in documents],
                           'spam_fraction': sum(d['spam'] for d in documents)/n}
    truth = {'postings': postings(target, vocabulary), 'target_sessions': queries,
             'document_digests': [d['digest'] for d in target],
             'spam_fraction': sum(d['spam'] for d in target)/n}
    # Drift views may overlap each other; none overlaps target or baseline auxiliary.
    target_ids = set(truth['document_digests'])
    if any(target_ids.intersection(a['document_digests']) for a in auxiliary.values()):
        raise RuntimeError('corpus partition crossed knowledge boundary')
    return auxiliary, truth


def export(binary, path, real_postings, queries, pad_to, seed):
    totals = [pad_to if pad_to is not None else len(p) for p in real_postings]
    workload = {'postings': real_postings, 'queries': queries, 'pad_to': pad_to,
                'update_order': update_order(totals, seed)}
    # The trusted input is never passed to an attack or included in wire output.
    payload = json.dumps(workload).encode()
    with gzip.open(path, 'wb', compresslevel=6) as wire:
        with subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as process:
            process.stdin.write(payload)
            process.stdin.close()
            for block in iter(lambda: process.stdout.read(65536), b''):
                wire.write(block)
            if process.wait() != 0:
                raise RuntimeError('real SSE corpus exporter failed')


def score(directory, mode, auxiliary, config, trial):
    sessions, updates = read_observations(directory/f'{mode}.jsonl.gz')
    results, predictions = [], []
    for view, knowledge in auxiliary.items():
        if mode == 'exact_count_control' and view != 'matched':
            continue
        for session, observations in sessions.items():
            started = time.perf_counter()
            padded = mode == 'padded_sse'
            rankings = CountVolumeAttack().run(observations, knowledge, seed=trial*100+session,
                                              pad_to=config['pad_to'] if padded else None)
            inferred = infer(observations, knowledge, padded=padded, seed=config['seed']+trial*100+session)
            predicted = {'count_volume': {'rankings': rankings}, **inferred}
            elapsed = time.perf_counter()-started
            # Read target labels only after every prediction for this session is fixed.
            truth = json.loads((directory/'ground-truth.json').read_text())
            labels = truth['target_sessions'][session]
            majority = int(np.argmax(knowledge['query_counts']))
            for name, prediction in predicted.items():
                value = metrics(prediction['rankings'], labels, config['keywords'], majority)
                value.update(trial=trial, session=session, mode=mode, view=view, attack=name,
                             updates=updates, mean_postings=float(np.mean([o['count'] for o in observations])),
                             mean_response_json_bytes=float(np.mean([o['response_json_bytes'] for o in observations])),
                             objective_gap=prediction.get('exact_objective', 0)-prediction.get('objective', 0),
                             all_attacks_seconds=elapsed,
                             auxiliary_spam_fraction=knowledge['spam_fraction'], target_spam_fraction=truth['spam_fraction'])
                results.append(value)
                predictions.append(dict(trial=trial, session=session, mode=mode, view=view, attack=name, **prediction))
    with gzip.open(directory/f'{mode}-predictions.json.gz', 'wt') as stream:
        json.dump(predictions, stream)
    return results


def require_controls(rows):
    for attack in ATTACKS:
        advantages = [r['advantage_over_profile_majority'] for r in rows if r['attack'] == attack]
        if not advantages or np.mean(advantages) < .2:
            raise RuntimeError(f'positive control failed: {attack}')


def summarize(rows, trials):
    summary = []
    keys = ('accuracy', 'balanced_accuracy', 'top3_accuracy', 'majority_accuracy', 'oracle_majority_accuracy',
            'chance_accuracy', 'advantage_over_profile_majority', 'mean_postings', 'mean_response_json_bytes', 'objective_gap')
    groups = sorted({(r['mode'], r['view'], r['attack']) for r in rows})
    for mode, view, attack in groups:
        group = [r for r in rows if (r['mode'], r['view'], r['attack']) == (mode, view, attack)]
        row = dict(mode=mode, view=view, attack=attack, split_resample_trials=trials, target_sessions=len(group))
        for key in keys:
            values = [float(np.mean([r[key] for r in group if r['trial'] == trial])) for trial in range(trials)]
            row[key] = float(np.mean(values))
            row[key+'_trial_bootstrap_95'] = cluster_interval(values)
        summary.append(row)
    paired = []
    for mode in ('sse', 'padded_sse'):
        for attack in sorted({r['attack'] for r in rows if r['mode'] == mode}):
            for view in sorted({r['view'] for r in rows if r['mode'] == mode} - {'matched'}):
                values = []
                for trial in range(trials):
                    take = lambda v: np.mean([r['accuracy'] for r in rows if (r['trial'], r['mode'], r['view'], r['attack']) == (trial, mode, v, attack)])
                    values.append(float(take(view)-take('matched')))
                paired.append(dict(mode=mode, view=view, attack=attack,
                                   accuracy_difference_vs_matched=float(np.mean(values)),
                                   paired_trial_bootstrap_95=cluster_interval(values)))
    return summary, paired


def plot(summary, path):
    fig, axes = plt.subplots(1, 2, figsize=(12, 4))
    for axis, mode in zip(axes, ('sse', 'padded_sse')):
        for attack in ATTACKS:
            group = [r for r in summary if r['mode'] == mode and r['attack'] == attack]
            means = np.asarray([r['accuracy'] for r in group])
            ci = np.asarray([r['accuracy_trial_bootstrap_95'] for r in group])
            axis.errorbar([r['view'] for r in group], means,
                          yerr=np.maximum(0, [means-ci[:, 0], ci[:, 1]-means]), marker='o', capsize=3, label=attack)
        axis.axhline(.125, color='gray', linestyle=':', label='uniform chance')
        axis.axhline(group[0]['majority_accuracy'], color='black', linestyle='--', label='profile majority')
        axis.set(title=mode, ylabel='Query recovery accuracy', ylim=(0, 1.02), xlabel='Auxiliary document view; fixed target')
    axes[0].legend(fontsize=7)
    fig.suptitle('Real SMS document incidences · synthetic IID queries · 30 conditional split resamples')
    fig.tight_layout()
    fig.savefig(path, dpi=170)
    plt.close(fig)


def run(config_path, output, binary):
    started = time.time()
    config = json.loads(config_path.read_text())
    if config['trials'] != 30 or config['keywords'] != 8 or config['pad_to'] != config['documents']:
        raise ValueError('recorded experiment requires 30 trials, 8 keywords and public document-bound padding')
    output.mkdir(parents=True, exist_ok=True)
    if any(p.name != 'bin' for p in output.iterdir()):
        raise ValueError('output must be new except ignored source cache')
    before = {p: sha(ROOT/p) for p in SOURCES}
    binary_source = binary
    binary, binary_before = snapshot_binary(binary_source, output/'bin'/'corpus')
    archive = output/'bin'/'sms.zip'
    archive.parent.mkdir(exist_ok=True)
    if not archive.exists():
        if config['source_url'] != 'https://archive.ics.uci.edu/static/public/228/sms%2Bspam%2Bcollection.zip':
            raise ValueError('only pinned official public dataset URL is accepted')
        with urllib.request.urlopen(config['source_url'], timeout=60) as response, archive.open('wb') as cache:
            size = 0
            for block in iter(lambda: response.read(65536), b''):
                size += len(block)
                if size > 300000:
                    raise ValueError('download size limit')
                cache.write(block)
    records, source_info = load_records(archive, config)
    dump(output/'config.json', config)
    # Execute and score every leaky control before building a defended index.
    rows, splits = [], []
    for trial in range(config['trials']):
        auxiliary, truth = make_trial(records, config, trial)
        directory = output/f'trial-{trial:02}'
        directory.mkdir()
        dump(directory/'auxiliary.json', auxiliary)
        dump(directory/'ground-truth.json', truth)
        # Retain actual derived public postings too; no message text is retained.
        control_postings = auxiliary['matched']['public_postings']
        dump(directory/'control-postings.json', control_postings)
        export(binary, directory/'exact_count_control.jsonl.gz', control_postings,
               truth['target_sessions'], None, config['seed']+trial)
        rows.extend(score(directory, 'exact_count_control', auxiliary, config, trial))
        splits.append((auxiliary, truth))
        print(f'Corpus control {trial+1}/30', flush=True)
    require_controls(rows)
    dump(output/'positive-controls.json', {'passed': True, 'threshold_advantage': .2,
                                         'executed_before_target_modes': True, 'session_metrics': rows})
    for trial, (auxiliary, truth) in enumerate(splits):
        directory = output/f'trial-{trial:02}'
        for mode in ('sse', 'padded_sse'):
            export(binary, directory/f'{mode}.jsonl.gz', truth['postings'], truth['target_sessions'],
                   config['pad_to'] if mode == 'padded_sse' else None, config['seed']+trial)
            rows.extend(score(directory, mode, auxiliary, config, trial))
        print(f'Corpus target {trial+1}/30', flush=True)
    summary, paired = summarize(rows, config['trials'])
    drift = []
    for trial, (auxiliary, truth) in enumerate(splits):
        base = np.asarray(auxiliary['matched']['counts'])/config['documents']
        for view, knowledge in auxiliary.items():
            drift.append(dict(trial=trial, view=view, auxiliary_spam_fraction=knowledge['spam_fraction'],
                              target_spam_fraction=truth['spam_fraction'],
                              mean_absolute_document_frequency_shift_vs_base=float(np.mean(abs(np.asarray(knowledge['counts'])/config['documents']-base)))))
    report = {'summary': summary, 'paired_auxiliary_differences': paired, 'session_metrics': rows,
              'document_shift': drift, 'source': source_info,
              'scope': 'Real licensed SMS document incidences; synthetic IID queries; actual bounded GGM SSE with fresh OsRng keys; local passive server observer.',
              'knowledge': 'Eight vocabulary words selected from matched auxiliary only, distinct auxiliary count bins; independent synthetic public profile; target text/doc incidence and query labels excluded from all attacker inputs.',
              'uncertainty': '5000 bootstrap resamples of 30 seeded split/workload trial means conditional on this single public corpus; both sessions clustered; drift differences paired. Source documents recur across trial resamples, so these are not 30 independent corpus collections.',
              'limits': 'Small known vocabulary and static corpus. Artificial auxiliary class-mixture drift, not chronological drift. IID synthetic queries. Optimistic distinct-count vocabulary selection disclosed. Likelihood models are not SAP/IHOP reproductions; iterative top3 uses exhaustive posterior. No security theorem or real-user query behavior claim.'}
    dump(output/'report.json', report)
    plot(summary, output/'corpus-drift.png')
    after = {p: sha(ROOT/p) for p in SOURCES}
    if before != after:
        raise RuntimeError('source changed during run; preserve artifacts and rerun stable source')
    binary_after = sha(binary)
    if binary_before != binary_after:
        raise RuntimeError('frozen executable changed during run; preserve artifacts and rerun')
    dump(output/'provenance.json', {'command': sys.argv, 'git_head': subprocess.check_output(['git','rev-parse','HEAD'], cwd=ROOT, text=True).strip(),
                                  'source_sha256_before': before, 'source_sha256_after': after,
                                  'config_sha256': sha(config_path), 'binary_sha256': binary_before,
                                  'binary_source_path': str(binary_source), 'binary_snapshot_path': str(binary.relative_to(output)),
                                  'binary_sha256_before': binary_before, 'binary_sha256_after': binary_after,
                                  'binary_execution': 'Private copied executable; SHA256 recorded before first export and verified after all exports. Every control and target subprocess launches this same copy.',
                                  'archive_sha256': sha(archive), 'source': source_info,
                                  'dataset': {k:config[k] for k in ('source_url','dataset_doi','license','attribution')},
                                  'python': sys.version, 'numpy': np.__version__, 'scipy': scipy.__version__,
                                  'platform': platform.platform(), 'elapsed_seconds': time.time()-started,
                                  'randomness': 'Seeded split/workload RNG; fresh Client::new OsRng cryptographic keys/index identities each mode/trial.',
                                  'artifacts_sha256': {str(p.relative_to(output)): sha(p) for p in sorted(output.rglob('*')) if p.is_file() and 'bin' not in p.relative_to(output).parts}})
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('config', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--binary', type=Path, default=Path('target/release/examples/corpus'))
    args = parser.parse_args()
    run(args.config.resolve(), args.output.resolve(), args.binary.resolve())
