"""Stronger leaf/tag and timing analysis of preserved genuine component traces."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import numpy as np
from sklearn.metrics import accuracy_score, balanced_accuracy_score, roc_auc_score
from research.attacks.leaf_timing import LeafTimingAttack
from research.analysis.leakage import load, bootstrap


def evaluate(source, output):
    config = json.loads((source/'config.json').read_text())
    if config['trials'] < 30 or config['sessions'] < 4 or config['sessions'] % 2:
        raise ValueError('need at least 30 trials and an even number of whole sessions')
    output.mkdir(exist_ok=False)
    hashes = {}
    results = []
    summary = []
    for mode in ('plaintext', 'encrypt_only', 'oram'):
        mode_rows = []
        for trial in range(config['trials']):
            profile, target, known, truth = [], [], [], []
            profile_ids, target_ids = [], []
            for session in range(config['sessions']):
                directory = source/'frequency'/mode/f'{trial}-{session}'
                rows, labels = load(directory)
                for filename in ('observer.jsonl', 'ground-truth.jsonl'):
                    path = directory/filename
                    hashes[str(path.relative_to(source))] = hashlib.sha256(path.read_bytes()).hexdigest()
                name = f'trial-{trial}-session-{session}'
                observations = [dict(session=name, tag=r['tag'], bytes=r['bytes'], latency_ns=r['latency_ns']) for r in rows]
                if session < config['sessions']//2:
                    profile.extend(observations); known.extend(map(int, labels)); profile_ids.append(name)
                else:
                    target.extend(observations); truth.extend(map(int, labels)); target_ids.append(name)
            attack = LeafTimingAttack().fit(profile, dict(profile_labels=known, profile_session_ids=profile_ids))
            prediction = attack.run(target, dict(target_session_ids=target_ids))
            scores = [r[1] for r in prediction.metadata['original_scores']]
            majority = int(sum(known) > len(known)/2)
            row = dict(mode=mode, trial=trial, accuracy=accuracy_score(truth, prediction.predictions),
                       balanced_accuracy=balanced_accuracy_score(truth, prediction.predictions),
                       auc=roc_auc_score(truth, scores), profile_majority_accuracy=float(np.mean(np.asarray(truth)==majority)),
                       observations=len(truth))
            mode_rows.append(row); results.append(row)
            with gzip.open(output/f'{mode}-{trial:02}.predictions.json.gz', 'wt') as stream:
                json.dump(dict(session_ids=target_ids, predictions=prediction.predictions, scores_uncalibrated=scores), stream)
        cell = dict(mode=mode, trials=len(mode_rows), **{
            key: dict(mean=float(np.mean([r[key] for r in mode_rows])), ci95_trials=bootstrap([r[key] for r in mode_rows]))
            for key in ('accuracy', 'balanced_accuracy', 'auc', 'profile_majority_accuracy')})
        if mode != 'oram' and cell['balanced_accuracy']['ci95_trials'][0] <= .5:
            raise RuntimeError('leaky positive control failed; defense not interpreted')
        summary.append(cell)
    report = dict(summary=summary, trials=results, configuration=config,
                  methodology='30 independent fitted-model trials; first half of whole sessions profile, remaining whole sessions target. Equal-weight trial-bootstrap means, 5000 resamples. Target within-session tag frequencies are unlabeled transductive observations. Two logical records have 75/25 popularity; balanced chance is 1/2 and raw accuracy must be compared with profiling-majority prediction.',
                  limitations='Reanalysis of historical genuine 16x64-byte component traces, not a new run of current process pipeline. ORAM tag is the physical accessed leaf; baseline tags are permuted visible logical addresses. Local API duration includes controller work and trace draining; not remote packet or isolated storage service time. Binary logical-record inference only. No proof from non-rejection and no exhaustive sequence/host attack.',
                  source_root=str(source), input_sha256=hashes,
                  analysis_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  attacker_sha256=hashlib.sha256(Path('research/attacks/leaf_timing.py').read_bytes()).hexdigest(),
                  sklearn_version=__import__('sklearn').__version__)
    (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(7, 4))
    means = np.asarray([r['balanced_accuracy']['mean'] for r in summary])
    bounds = np.asarray([r['balanced_accuracy']['ci95_trials'] for r in summary])
    ax.bar([r['mode'] for r in summary], means, yerr=np.maximum(0, np.array([means-bounds[:,0], bounds[:,1]-means])), capsize=4)
    ax.axhline(.5, color='gray', linestyle='--'); ax.set(ylabel='Balanced logical-record recovery', ylim=(0, 1.05))
    fig.tight_layout(); fig.savefig(output/'leaf-timing.png', dpi=150); plt.close(fig)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('source', type=Path); parser.add_argument('output', type=Path)
    args = parser.parse_args(); evaluate(args.source, args.output)
