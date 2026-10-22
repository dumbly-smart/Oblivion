#!/usr/bin/env python3
"""Numerical offline inference over existing local synthetic encrypted SSE traces."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import sys
import time
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import scipy
from research.attacks.inference import infer
from research.analysis.sse import read_observations, metrics, cluster_interval, MODES

ROOT = Path(__file__).resolve().parents[2]
ATTACKS = ('likelihood_assignment', 'iterative_hungarian_markov', 'exact_markov_bound')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dump(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def source_hashes():
    paths = ['research/attacks/inference.py','research/analysis/inference.py',
             'research/tests/test_inference.py','research/analysis/sse.py','research/attacks/sse.py']
    return {path:sha(ROOT/path) for path in paths}


def evaluate(source, output):
    """Read-only inputs. Target labels are read only after numerical inference."""
    before = source_hashes()
    started = time.time()
    config = json.loads((source/'config.json').read_text())
    if config['trials'] != 30:
        raise ValueError('this recorded evaluation requires 30 independent source trials')
    output.mkdir(parents=True, exist_ok=False)
    input_files = sorted(p for p in source.rglob('*') if p.is_file() and
                         (p.suffix == '.gz' or p.name in ('auxiliary.json','ground-truth.json','config.json','provenance.json')))
    inputs = {str(p.relative_to(source)):sha(p) for p in input_files}
    dump(output/'config.json', {'source_config':config,'source_directory':str(source),
                              'iterations':200,'free_size':3,'smoothing':'Jeffreys .5 document probabilities; Laplace 1 query and transition probabilities',
                              'max_keywords':8,'bootstrap_samples':5000})
    rows = []
    predictions = []
    for mode in MODES:  # exact-count positive control is processed first
        for trial in range(config['trials']):
            directory = source/f'trial-{trial:02}'
            auxiliary = json.loads((directory/'auxiliary.json').read_text())
            auxiliary['corpus_documents'] = config['public_corpus_documents']
            sessions, _ = read_observations(directory/f'{mode}.jsonl.gz')
            for session, observations in sessions.items():
                tick = time.perf_counter()
                result = infer(observations, auxiliary, padded=mode=='padded_sse', seed=config['seed']+trial*100+session)
                elapsed = time.perf_counter()-tick
                # Ground truth is loaded after all rankings/mappings are fixed.
                labels = json.loads((directory/'ground-truth.json').read_text())['target_sessions'][session]
                majority = int(np.argmax(auxiliary['query_counts']))
                for name in ATTACKS:
                    output_record = result[name]
                    score = metrics(output_record['rankings'], labels, config['keywords'], majority)
                    tag_label = {}
                    for observation,label in zip(observations,labels):
                        if observation['tag'] in tag_label and tag_label[observation['tag']] != label:
                            raise ValueError('source tags inconsistent with evaluator truth')
                        tag_label[observation['tag']] = label
                    score.update(attack=name, mode=mode, trial=trial, session=session,
                                 distinct_token_accuracy=float(np.mean([prediction == tag_label[tag] for tag,prediction in zip(output_record['observed_tags'],output_record['mapping'])])),
                                 objective=output_record['objective'], exact_objective=output_record['exact_objective'],
                                 objective_gap=output_record['exact_objective']-output_record['objective'],
                                 all_three_inference_methods_seconds=elapsed)
                    rows.append(score)
                    predictions.append(dict(attack=name,mode=mode,trial=trial,session=session,**output_record))
            print(f'{mode} trial {trial+1}/30', flush=True)
        if mode == 'exact_count_control':
            for name in ATTACKS:
                advantages = [r['advantage_over_profile_majority'] for r in rows if r['mode']==mode and r['attack']==name]
                if np.mean(advantages) < .2:
                    raise RuntimeError(f'positive control failed for {name}')
    summary = []
    keys = ['accuracy','balanced_accuracy','distinct_token_accuracy','top3_accuracy','majority_accuracy',
            'oracle_majority_accuracy','chance_accuracy','chance_top3_accuracy','advantage_over_profile_majority','objective_gap']
    for mode in MODES:
        for name in ATTACKS:
            group = [r for r in rows if r['mode']==mode and r['attack']==name]
            item = {'mode':mode,'attack':name,'independent_trials':config['trials'],'target_sessions':len(group)}
            for key in keys:
                estimates = [float(np.mean([r[key] for r in group if r['trial']==trial])) for trial in range(config['trials'])]
                item[key] = float(np.mean(estimates))
                item[key+'_cluster_bootstrap_95'] = cluster_interval(estimates)
            summary.append(item)
    report = {'configuration':config,'summary':summary,'session_metrics':rows,
              'scope':'read-only numerical inference over previously generated real SSE exports of synthetic local workloads; no protocol mutation or external target interaction',
              'methods':'Exact Hungarian optimization of separable count + IID-frequency plug-in log likelihood; approximate repeated subset Hungarian refinement of count + first-order Markov log likelihood; exhaustive eight-keyword Markov optimum comparator.',
              'top3':'Optimizer MAP label first; remaining candidates ranked by exact bounded-model posterior marginals. Thus top-three for iterative method uses extra exhaustive computation and is not a scalable IHOP claim.',
              'uncertainty':'5000 percentile bootstrap resamples of 30 whole independent source-trial means; both target sessions sharing one auxiliary corpus/profile remain together.',
              'knowledge_boundary':'Public auxiliary corpus counts and complete independent labeled profiling session only; target labels loaded after all predictions are fixed and used solely for scoring.',
              'limitations':'Not SAP or IHOP reproduction. Source query sessions are IID draws, so first-order transition modeling can overfit auxiliary noise and is not expected to improve recovery. Synthetic stable distributions, vocabulary eight, static corpus, known candidate universe and corpus size. No cross-keyword document co-occurrence feature: client-encrypted IDs and distinct GGM posting addresses do not expose those intersections. No active experiment. No cryptographic or full-system security conclusion. Multiclass ranking task; binary ROC/AUC does not apply.'}
    dump(output/'report.json',report)
    dump(output/'predictions.json',predictions)
    fig, axes = plt.subplots(1,2,figsize=(12,4))
    for axis,key,title in [(axes[0],'accuracy','Query recovery'),(axes[1],'balanced_accuracy','Balanced query recovery')]:
        x = np.arange(len(MODES)); width=.25
        for offset,name in enumerate(ATTACKS):
            group=[r for r in summary if r['attack']==name]
            mean=np.asarray([r[key] for r in group]);ci=np.asarray([r[key+'_cluster_bootstrap_95'] for r in group])
            axis.bar(x+(offset-1)*width,mean,width,label=name.replace('_',' '),yerr=np.maximum(0,[mean-ci[:,0],ci[:,1]-mean]),capsize=2)
        axis.axhline(1/config['keywords'],color='gray',linestyle=':',label='uniform chance')
        if key=='accuracy':
            axis.plot(x,[r['majority_accuracy'] for r in summary if r['attack']==ATTACKS[0]],'k--',label='profile majority')
        axis.set(xticks=x,xticklabels=['exact-count control','SSE','padded SSE'],ylim=(0,1.08),ylabel='Accuracy',title=title)
    axes[0].legend(fontsize=7)
    fig.suptitle('Numerical inference on actual synthetic SSE exports · 30 source trials · 95% trial bootstrap')
    fig.tight_layout();fig.savefig(output/'inference-attacks.png',dpi=170);plt.close(fig)
    after=source_hashes()
    if before != after:
        raise RuntimeError('analysis source changed during evaluation; rerun with stable sources')
    dump(output/'provenance.json',{'command':sys.argv,'python':sys.version,'python_executable_sha256':sha(Path(sys.executable)),
         'numpy':np.__version__,'scipy':scipy.__version__,'matplotlib':matplotlib.__version__,'platform':platform.platform(),
         'source_sha256_before':before,'source_sha256_after':after,'input_sha256':inputs,
         'source_generation_provenance':json.loads((source/'provenance.json').read_text()),
         'elapsed_seconds':time.time()-started,'execution':'Only local numerical Python analysis is executed. Rust trace-generation executable is not launched; its original provenance is preserved verbatim.',
         'output_sha256':{p.name:sha(p) for p in output.iterdir() if p.is_file()}})
    return report


if __name__ == '__main__':
    parser=argparse.ArgumentParser();parser.add_argument('source',type=Path);parser.add_argument('output',type=Path)
    args=parser.parse_args();evaluate(args.source.resolve(),args.output.resolve())
