#!/usr/bin/env python3
"""Generate actual timer/queue wire, then fit only independent profile processes."""
import argparse
from dataclasses import asdict
import gzip
import hashlib
import json
from pathlib import Path
import platform
import random
import shutil
import subprocess
import sys
import time

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import sklearn

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from research.attacks.batch_load import BatchLoadAttack, FEATURE_NAMES, features

SOURCES=('crates/oblivion-batcher/src/lib.rs','crates/oblivion-batcher/src/envelope.rs',
         'crates/oblivion-batcher/examples/load_trace.rs','research/attacks/batch_load.py',
         'research/attacks/registry.py','research/tests/test_batch_load.py','scripts/evaluate_batch_load.py')
MODES=('plaintext_control','protected')


def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def dump(path,value):path.write_text(json.dumps(value,indent=2)+'\n')


def interval(values):
    values=np.asarray(values,dtype=float);rng=np.random.default_rng(20261023)
    samples=rng.choice(values,(5000,len(values)),replace=True).mean(axis=1)
    return [float(v) for v in np.quantile(samples,[.025,.975])]


def read_trace(path):
    with gzip.open(path,'rt') as stream:return [json.loads(line) for line in stream]


def generate_process(binary,directory,identifier,percent,seed,mode,config):
    truth=directory/f'{identifier}-truth.json'
    wire=directory/f'{identifier}-observer.jsonl.gz'
    args=[str(binary),str(config['period_ms']),str(config['epochs']),str(config['participants']),
          str(percent),str(seed),'plaintext' if mode=='plaintext_control' else 'protected',str(truth),identifier]
    with gzip.open(wire,'wb',compresslevel=6) as observer:
        with subprocess.Popen(args,stdout=subprocess.PIPE) as process:
            for block in iter(lambda:process.stdout.read(65536),b''):observer.write(block)
            if process.wait()!=0:raise RuntimeError('actual batcher timer exporter failed')
    trace=read_trace(wire);features(trace)
    # This is workload validation only, separate from every attacker invocation.
    private=json.loads(truth.read_text())
    if private['real_percent']!=percent or sum(r['real'] for r in private['requests'])!=config['epochs']*config['participants']*percent//100:
        raise RuntimeError('trusted workload count mismatch')
    return trace


def run(config_path,output):
    started=time.time();before={p:sha(ROOT/p) for p in SOURCES};config_bytes=config_path.read_bytes();config=json.loads(config_bytes)
    if set(config)!={'seed','trials','period_ms','epochs','participants','profile_processes_per_class','target_processes_per_class'}:
        raise ValueError('configuration schema')
    if any(type(value) is not int or value < 0 for value in config.values()) or config['seed'] > 2**32-2000000:
        raise ValueError('bounded nonnegative integer configuration required')
    if config['trials']!=30 or config['participants']!=8 or config['epochs']!=32 or config['period_ms']!=10 or config['profile_processes_per_class']!=2 or config['target_processes_per_class']!=2:
        raise ValueError('recorded campaign requires 30 trials,32 actual10ms epochs,8 participants,2+2 whole processes per class')
    subprocess.run(['cargo','build','--release','-p','oblivion-batcher','--example','load_trace'],cwd=ROOT,check=True)
    if before!={p:sha(ROOT/p) for p in SOURCES}:raise RuntimeError('sources changed during build')
    output.mkdir(parents=True,exist_ok=False);(output/'config.json').write_bytes(config_bytes);(output/'bin').mkdir()
    binary=output/'bin'/'load_trace';shutil.copy2(ROOT/'target/release/examples/load_trace',binary);binary.chmod(0o555);binary_before=sha(binary)
    source_snapshots={}
    for path in SOURCES:
        snapshot=output/'source-snapshot'/path;snapshot.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(ROOT/path,snapshot);source_snapshots[path]=sha(snapshot)
    if before!=source_snapshots:raise RuntimeError('source snapshot differs from pre-build hashes')
    # Durable evidence is written before the first timed process, even on a failed gate.
    dump(output/'provenance-before.json',dict(command=sys.argv,
          git_head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
          source_sha256_before=before,source_snapshot_sha256=source_snapshots,
          binary_sha256_before=binary_before,binary_snapshot_path='bin/load_trace',
          config_sha256=sha(output/'config.json'),python=sys.version,numpy=np.__version__,sklearn=sklearn.__version__,
          rustc=subprocess.check_output(['rustc','--version'],text=True).strip(),platform=platform.platform(),
          processor=platform.processor(),cpu_model=next((line.split(':',1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')),'unknown'),
          before_first_measurement=True,metric='Squared Euclidean distance to authorized class means across all22fixed-unit features; no learned variance weights or confidence.'))
    trial_rows=[];predictions=[];shapes=set();importances=[]
    for mode_index,mode in enumerate(MODES):
        for trial in range(config['trials']):
            directory=output/mode/f'trial-{trial:02}';directory.mkdir(parents=True)
            jobs=[(role,label,sample) for role in ('profile','target') for label in range(3) for sample in range(2)]
            rng=random.Random(config['seed']+mode_index*1000000+trial*100);rng.shuffle(jobs)
            profiles=[];targets=[];plan=[]
            for serial,(role,label,sample) in enumerate(jobs):
                identifier=f'm{mode_index}-t{trial:02}-s{serial:02}'
                seed=config['seed']+mode_index*1000000+trial*100+serial+1
                observations=generate_process(binary,directory,identifier,label*50,seed,mode,config)
                plan.append(dict(process_id=identifier,role=role,private_label=label,workload_seed=seed))
                if role=='profile':profiles.append(dict(process_id=identifier,label=label,observations=observations))
                else:targets.append((identifier,observations))
                arrival=[r for r in observations if r['type']=='arrival'];emission=[r for r in observations if r['type']=='emission']
                shapes.add((len(arrival),len(emission),tuple(sorted({len(r['frame']) for r in arrival})),
                            tuple(sorted({len(r['frames']) for r in emission})),tuple(sorted({r['slot'] for r in arrival})),
                            tuple(sorted({r['destination'] for r in observations}))))
            dump(directory/'private-process-plan.json',plan)
            model=BatchLoadAttack().fit(profiles,seed=config['seed']+trial)
            importances.append(dict(mode=mode,trial=trial,class_centroids=model.centroids_.tolist()))
            scored=[]
            for identifier,observations in targets:
                # No target class, request marker truth, workload seed or plan enters the attack.
                result=model.run(observations,{'process_id':identifier})
                private=json.loads((directory/f'{identifier}-truth.json').read_text())
                label=private['real_percent']//50
                item=dict(mode=mode,trial=trial,process_id=identifier,prediction=int(result.predictions[0]),private_true_label=label,
                          result=asdict(result))
                predictions.append(item);scored.append(item)
            correct=[r['prediction']==r['private_true_label'] for r in scored]
            row=dict(mode=mode,trial=trial,accuracy=float(np.mean(correct)),
                     balanced_accuracy=float(np.mean([np.mean([r['prediction']==label for r in scored if r['private_true_label']==label]) for label in range(3)])),
                     profile_majority_accuracy=1/3,chance_accuracy=1/3,target_processes=len(scored))
            trial_rows.append(row)
            print(f'{mode} model trial {trial+1}/30 accuracy={row["accuracy"]:.3f}',flush=True)
        if mode=='plaintext_control':
            control_values=[r['accuracy'] for r in trial_rows]
            control=np.mean(control_values)
            control_interval=interval(control_values)
            if control<.8 or control_interval[0]<=1/3:raise RuntimeError('genuinely plaintext-wire positive control failed; protected generation not started')
            dump(output/'positive-control.json',dict(passed=True,accuracy=float(control),threshold=.8,
                 executed_before_protected=True,whole_trial_bootstrap_95=control_interval,scope='Actual unauthenticated plaintext request frames, not trusted target flags passed to attacker.'))
    summary=[]
    for mode in MODES:
        group=[r for r in trial_rows if r['mode']==mode]
        item=dict(mode=mode,independent_model_trials=30,held_out_processes=sum(r['target_processes'] for r in group))
        for key in ('accuracy','balanced_accuracy','profile_majority_accuracy','chance_accuracy'):
            values=[r[key] for r in group];item[key]=float(np.mean(values));item[key+'_whole_trial_bootstrap_95']=interval(values)
        summary.append(item)
    report={'summary':summary,'trial_metrics':trial_rows,'public_shapes':[
                dict(arrivals=s[0],emissions=s[1],frame_bytes=list(s[2]),batch_frame_counts=list(s[3]),public_slots=list(s[4]),public_destinations=list(s[5])) for s in sorted(shapes)],
            'feature_names':list(FEATURE_NAMES),'fitted_model_centroids':importances,
            'scope':'Actual EpochBatcher and monotonic OS timer with eight enrolled participants,32 epochs of10ms; protected Endpoint.send/receive genuine fresh OsRng-keyed AEAD; no network sockets, downstream compute, storage or scaling measured.',
            'control':'The control uses genuine shape-valid but deliberately unauthenticated plaintext request frames, body opcode public at byte20 and zero MAC. EpochBatcher only queues opaque envelopes. The trusted control oracle checks plaintext; it does not pretend these frames authenticate.',
            'knowledge':'Two complete independently generated labeled profile processes per class; two complete target processes per class held out. Observers receive actual full wire bytes and arrival/emission metadata; private workload flags/labels/seeds/plans are excluded from attack arguments. IDs are opaque and are not classifier features.',
            'features':'Fixed22-feature whitelist combines actual arrival/interarrival/emission/queue timing,frame and batch shape,logical destination/slot counts, and public body-byte20==1 fraction. Same extraction and classifier for control and protected; protected byte20 is ciphertext, with no separate real/dummy field.',
            'uncertainty':'5000 percentile bootstrap resamples of30 whole independently profiled model trials; all6 held-out process predictions per trial remain clustered. Interleaved shuffled launch order across profile/target roles and classes; modes execute control first, so host regime shifts across modes remain a limitation.',
            'limitations':'Small supervised Euclidean nearest class centroid over22features in fixed public units(timing/10ms and count/shape/publicbounds),six training processes per trial,synthetic labels/schedules,one local host/fixed enrollment and cadence. No calibrated confidence, cryptographic security proof, timing equivalence bound, actual packet trace or full-system result.'}
    dump(output/'report.json',report);dump(output/'predictions.json',predictions)
    mean=np.asarray([r['accuracy'] for r in summary]);ci=np.asarray([r['accuracy_whole_trial_bootstrap_95'] for r in summary])
    fig,axis=plt.subplots(figsize=(7,4));axis.bar(['plaintext control','AEAD fixed batching'],mean,color=['#b86644','#447799'])
    axis.errorbar(range(2),mean,yerr=np.maximum(0,[mean-ci[:,0],ci[:,1]-mean]),fmt='none',color='black',capsize=5)
    axis.axhline(1/3,color='gray',linestyle='--',label='balanced three-class chance / profile majority')
    axis.set(ylabel='Whole-process load classification accuracy',ylim=(0,1.05),title='Actual timer + wire:0%,50%,100% real load\n30 independently profiled model trials');axis.legend(fontsize=8)
    fig.tight_layout();fig.savefig(output/'batch-load.png',dpi=170);plt.close(fig)
    after={p:sha(ROOT/p) for p in SOURCES};binary_after=sha(binary)
    if before!=after or binary_before!=binary_after or config_bytes!=(output/'config.json').read_bytes():raise RuntimeError('sources, frozen executable or config changed during campaign')
    dump(output/'provenance.json',dict(command=sys.argv,git_head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
          source_sha256_before=before,source_sha256_after=after,binary_sha256_before=binary_before,binary_sha256_after=binary_after,
          binary_snapshot_path='bin/load_trace',config_sha256=sha(output/'config.json'),python=sys.version,numpy=np.__version__,sklearn=sklearn.__version__,
          rustc=subprocess.check_output(['rustc','--version'],text=True).strip(),platform=platform.platform(),elapsed_seconds=time.time()-started,
          randomness='Seeded launch order and per-process independent workload schedules; production Endpoint::provision generates fresh OsRng keys every process. Workload seeds are private harness inputs, not attacker auxiliary knowledge.',
          artifacts_sha256={str(p.relative_to(output)):sha(p) for p in sorted(output.rglob('*')) if p.is_file() and 'bin' not in p.relative_to(output).parts}))
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--config',type=Path,default=ROOT/'experiments/configs/batch-load-20261023.json')
    parser.add_argument('--output',type=Path,default=ROOT/'experiments/results/batch-load-20261023')
    args=parser.parse_args();run(args.config.resolve(),args.output.resolve())
