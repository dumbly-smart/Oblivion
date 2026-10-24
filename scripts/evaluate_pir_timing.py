#!/usr/bin/env python3
"""Fresh whole-session target classifiers for one noncolluding PIR server."""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import numpy as np

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from research.attacks.pir_timing import PirTimingAttack, FEATURE_MODES, vectors


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def command(*args):return subprocess.check_output(args,cwd=ROOT,text=True).strip()
def load(path):
    with gzip.open(path,'rt') as f:return [json.loads(line) for line in f]
def interval(values,seed=811):
    values=np.asarray(values,dtype=float)
    if values.ndim!=1 or len(values)<2 or not np.isfinite(values).all():raise ValueError('finite independent trial estimates required')
    rng=np.random.default_rng(seed);b=values[rng.integers(0,len(values),(5000,len(values)))].mean(axis=1)
    return dict(mean=float(values.mean()),ci95_trials=list(map(float,np.quantile(b,[.025,.975]))),trials=len(values))

def read_trial(root,mode,count,trial,config):
    observer=[];truth=[];profile=[];target=[];labels=[];target_labels=[]
    for session in range(config['sessions']):
        path=root/'raw'/f'{mode}-n{count}-t{trial}-s{session}'
        obs=load(path/'observer.jsonl.gz');private=load(path/'private.jsonl.gz');latent=load(path/'truth.jsonl.gz')
        if len(obs)!=config['queries_per_session'] or len(private)!=len(obs) or len(latent)!=len(obs):raise ValueError('incomplete session')
        vectors(obs,'joint')
        if [r['step'] for r in obs]!=list(range(len(obs))):raise ValueError('unaligned observer steps')
        if any(set(r)!={'session','step','label','index'} for r in latent):raise ValueError('invalid truth schema')
        if any(set(r)!={'session','step','generation_ns','recovery_ns','correct'} or r['correct'] is not True for r in private):raise ValueError('failed private oracle')
        for o,p,t in zip(obs,private,latent):
            if (o['session'],o['step'])!=(p['session'],p['step']) or (o['session'],o['step'])!=(t['session'],t['step']):raise ValueError('unaligned observer/truth/private')
            if t['label'] not in (0,1,2) or t['index']!=[0,count//2,count-1][t['label']]:raise ValueError('invalid requested target')
            expected_width=(count+7)//8 if mode=='pir' else 0
            if len(o['query_bytes'])!=expected_width:raise ValueError('invalid query payload length')
            if o['visible_index']!=(t['index'] if mode=='control' else None):raise ValueError('private target in PIR observer')
        if [sum(r['label']==label for r in latent) for label in range(3)]!=[len(obs)//3]*3:raise ValueError('unbalanced session labels')
        destination,lab=(profile,labels) if session<config['profile_sessions'] else (target,target_labels)
        destination.extend(obs);lab.extend(r['label'] for r in latent)
        observer.extend(obs);truth.extend(latent)
    return profile,labels,target,target_labels,observer,truth

def fit_trial(profile,labels,target,truth,mode,seed):
    attack=PirTimingAttack(feature_mode=mode,seed=seed).fit(profile,dict(profile_labels=labels,profile_session_ids=sorted({r['session'] for r in profile})))
    result=attack.run(target,dict(target_session_ids=sorted({r['session'] for r in target})))
    y=np.asarray(truth);pred=np.asarray(result.predictions)
    return dict(balanced_accuracy=float(np.mean([np.mean(pred[y==c]==c) for c in range(3)])),accuracy=float(np.mean(pred==y)),predictions=result.predictions,
                truth=truth,metadata=result.metadata,confidence=result.confidence)

def positive_control(root,config):
    rows=[]
    for count in config['counts']:
        values=[]
        for trial in range(config['trials']):
            profile,labels,target,truth,_,_=read_trial(root,'control',count,trial,config)
            result=fit_trial(profile,labels,target,truth,'joint',config['model_seed']+trial)
            result.update(count=count,trial=trial);rows.append(result);values.append(result['balanced_accuracy'])
        if interval(values)['ci95_trials'][0]<=1/3+.1:raise RuntimeError('plaintext visible-index positive control failed')
    report=dict(passed=True,chance=1/3,cells=[dict(count=count,balanced_accuracy=interval([r['balanced_accuracy'] for r in rows if r['count']==count])) for count in config['counts']],trial_results=rows)
    (root/'positive-control-first.json').write_text(json.dumps(report,indent=2)+'\n')
    return report

def analyze(root,config):
    # This check is also repeated before interpreting protected runs.
    control=positive_control(root,config);trials=[];cells=[]
    for count in config['counts']:
        timing={label:{q:[] for q in [50,95,99]} for label in range(3)};bits={label:[] for label in range(3)}
        for trial in range(config['trials']):
            profile,labels,target,truth,observer,latent=read_trial(root,'pir',count,trial,config)
            for feature_mode in FEATURE_MODES:
                row=fit_trial(profile,labels,target,truth,feature_mode,config['model_seed']+trial)
                row.update(count=count,trial=trial,feature_mode=feature_mode);trials.append(row)
            for label in range(3):
                selected=[r for r,t in zip(observer,latent) if t['label']==label]
                for q in [50,95,99]:timing[label][q].append(float(np.quantile([r['server_ns'] for r in selected],q/100)))
                bits[label].extend(r['query_bytes'] for r in selected)
        diagnostics=[]
        for label in range(3):
            array=np.asarray(bits[label],dtype=np.uint8);unpacked=np.unpackbits(array,axis=1,bitorder='little')[:,:count];rates=unpacked.mean(axis=0)
            diagnostics.append(dict(label=label,requested_index=[0,count//2,count-1][label],samples=len(array),mean_one_rate=float(rates.mean()),min_bit_one_rate=float(rates.min()),max_bit_one_rate=float(rates.max()),requested_position_one_rates=[float(rates[i]) for i in [0,count//2,count-1]],all_bit_one_rates=rates.tolist()))
        cells.append(dict(count=count,record_bytes=config['record_bytes'],chance=1/3,classes=[0,count//2,count-1],
            classification={mode:interval([r['balanced_accuracy'] for r in trials if r['count']==count and r['feature_mode']==mode]) for mode in FEATURE_MODES},
            server_timing_by_label={str(label):{f'mean_trial_p{q}_ns':interval(values) for q,values in quantiles.items()} for label,quantiles in timing.items()},query_bit_diagnostics=diagnostics))
    (root/'trial-results.json').write_text(json.dumps(trials,indent=2)+'\n')
    report=dict(schema_version=1,positive_control_passed=control['passed'],cells=cells,analysis_sha256=sha(__file__),attacker_sha256=sha(ROOT/'research/attacks/pir_timing.py'),
                methodology='30 independently fitted models per feature mode/cell; two complete profiling sessions and two disjoint target sessions per trial; 96 balanced observations per session; bootstrap means of trial balanced accuracies (5000 resamples); no query-level pseudo-replication',
                observer='single server0 own query bytes and answer wall duration; plaintext control additionally exposes direct index; no second share/client generation/recovery/target labels in attacker input',
                distribution_argument='QueryPair.first is fresh OS-random bytes regardless of index; second is that vector XOR the requested point, also uniform for any fixed target under uniform first vector. Noncollusion required. Per-bit diagnostics are finite marginal checks, not a proof of full joint distribution or cryptographic privacy.')
    (root/'summary.json').write_text(json.dumps(report,indent=2)+'\n');plot(root,report)
    return report

def plot(root,report):
    import matplotlib;matplotlib.use('Agg');import matplotlib.pyplot as plt
    fig,axes=plt.subplots(1,2,figsize=(11,4));modes=list(FEATURE_MODES)
    for offset,cell in enumerate(report['cells']):
        x=np.arange(len(modes))+offset*.3;y=np.array([cell['classification'][m]['mean'] for m in modes]);ci=np.array([cell['classification'][m]['ci95_trials'] for m in modes])
        axes[0].bar(x,y,width=.28,yerr=np.maximum(0,np.stack([y-ci[:,0],ci[:,1]-y])),label=f'N={cell["count"]}')
        axes[1].plot([0,1,2],[cell['server_timing_by_label'][str(label)]['mean_trial_p95_ns']['mean']/1000 for label in range(3)],marker='o',label=f'N={cell["count"]}')
    axes[0].axhline(1/3,color='gray',linestyle='--');axes[0].set(xticks=np.arange(len(modes))+.15,xticklabels=['Joint','Timing','Share','Index constant'],ylabel='Held-out balanced accuracy',ylim=(0,1));axes[0].legend()
    axes[1].set(xticks=[0,1,2],xticklabels=['0','N/2','N-1'],xlabel='Requested index',ylabel='Mean trial server0 p95 (µs)');axes[1].legend()
    fig.tight_layout();fig.savefig(root/'pir-target-timing.png',dpi=150);plt.close(fig)

def run(config_path,root):
    config=json.loads(config_path.read_text())
    if config['trials']!=30 or config['sessions']!=4 or config['profile_sessions']!=2 or config['queries_per_session']!=96 or config['counts']!=[128,1024] or config['record_bytes']!=64:raise ValueError('requires bounded declared 30-trial grid')
    root.mkdir(parents=True,exist_ok=False);(root/'bin').mkdir();(root/'raw').mkdir();(root/'sources').mkdir()
    sources=[ROOT/'crates/oblivion-pir/examples/target_timing.rs',ROOT/'scripts/evaluate_pir_timing.py',ROOT/'research/attacks/pir_timing.py',ROOT/'research/attacks/registry.py',ROOT/'research/tests/test_pir_timing.py',ROOT/'Cargo.toml',ROOT/'Cargo.lock',ROOT/'crates/oblivion-pir/Cargo.toml']+sorted((ROOT/'crates/oblivion-pir/src').glob('*.rs'))
    hashes={str(p.relative_to(ROOT)):sha(p) for p in sources}
    subprocess.run(['cargo','build','--locked','--release','-p','oblivion-pir','--example','target_timing'],cwd=ROOT,check=True)
    if hashes!={str(p.relative_to(ROOT)):sha(p) for p in sources}:raise RuntimeError('source changed during build')
    binary=root/'bin/target_timing';shutil.copy2(ROOT/'target/release/examples/target_timing',binary);binary.chmod(0o555)
    for path in sources:shutil.copyfile(path,root/'sources'/str(path.relative_to(ROOT)).replace('/','__'))
    shutil.copyfile(config_path,root/'config.json')
    import sklearn
    before=dict(started_utc=datetime.now(timezone.utc).isoformat(),source_sha256=hashes,binary_sha256=sha(binary),configuration=config,git_head=command('git','rev-parse','HEAD'),git_status=command('git','status','--porcelain'),platform=platform.platform(),cpu=Path('/proc/cpuinfo').read_text(),rustc=command('rustc','--version','--verbose'),numpy=np.__version__,sklearn=sklearn.__version__,model_seed_scope='fixed public classifier seed + trial, independent of workload seed; no seed/step/session-id model features',workload_seed_scope='reproduction/private label scheduling only; not supplied to attacker model or protocol observer')
    (root/'provenance-before.json').write_text(json.dumps(before,indent=2)+'\n')
    commands=[]
    # Collect and validate every actual plaintext control before protected data.
    for mode in ['control','pir']:
        for count in config['counts']:
            for trial in range(config['trials']):
                for session in range(config['sessions']):
                    sid=f'{mode}-n{count}-t{trial}-s{session}';seed=config['seed']+count*100000+trial*4+session
                    out=root/'raw'/sid
                    if sha(binary)!=before['binary_sha256']:raise RuntimeError('frozen binary changed')
                    cmd=[str(binary),mode,str(count),str(config['record_bytes']),str(config['queries_per_session']),str(seed),sid,str(out)]
                    subprocess.run(cmd,cwd=ROOT,check=True);commands.append(cmd)
                    for path in out.glob('*.jsonl'):
                        with path.open('rb') as inp,gzip.GzipFile(filename=str(path)+'.gz',mode='wb',mtime=0) as dest:shutil.copyfileobj(inp,dest)
                        path.unlink()
        if mode=='control':positive_control(root,config);print('plaintext positive control passed before PIR collection',flush=True)
    analyze(root,config)
    after=dict(finished_utc=datetime.now(timezone.utc).isoformat(),binary_after_sha256=sha(binary),source_after_sha256={str(p.relative_to(ROOT)):sha(p) for p in sources},commands=commands)
    if after['binary_after_sha256']!=before['binary_sha256']:raise RuntimeError('frozen binary changed')
    (root/'provenance-after.json').write_text(json.dumps(after,indent=2)+'\n')
    manifest={str(p.relative_to(root)):sha(p) for p in sorted(root.rglob('*')) if p.is_file() and 'bin' not in p.relative_to(root).parts}
    (root/'artifact-sha256.json').write_text(json.dumps(manifest,indent=2)+'\n')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--config',type=Path,default=ROOT/'experiments/configs/pir-target-timing-30.json');parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();run(args.config.resolve(),args.output.resolve())
