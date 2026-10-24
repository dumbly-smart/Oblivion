#!/usr/bin/env python3
"""Matched heap-backed vendor Path/Circuit ORAM benchmark, separate GPL program."""
import argparse
from collections import Counter
from datetime import datetime,timezone
import gzip
import hashlib
import json
from pathlib import Path
import platform
import random
import shutil
import subprocess
import sys
import numpy as np
ROOT=Path(__file__).resolve().parents[1]
REFERENCE=ROOT/'research/oram_reference'


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def command(*args):return subprocess.check_output(args,cwd=ROOT,text=True).strip()
def interval(values):
    a=np.asarray(values,dtype=float)
    if a.ndim!=1 or len(a)<2 or not np.isfinite(a).all():raise ValueError('finite independent trials required')
    rng=np.random.default_rng(62311);boot=a[rng.integers(0,len(a),(5000,len(a)))].mean(axis=1)
    return dict(mean=float(a.mean()),ci95_trials=list(map(float,np.quantile(boot,[.025,.975]))),trials=len(a))
def summarize_trial(rows,config,algorithm):
    setup=[r for r in rows if r['kind']=='setup'];access=[r for r in rows if r['kind']=='access'];summary=[r for r in rows if r['kind']=='summary']
    if len(setup)!=1 or len(summary)!=1 or len(access)!=config['operations'] or len(rows)!=len(access)+2 or [r['step'] for r in access]!=list(range(config['operations'])):raise ValueError('incomplete/duplicate raw trial rows')
    if setup[0]['algorithm']!=algorithm or setup[0]['blocks']!=config['blocks']:raise ValueError('incorrect measured geometry')
    if any(r['correct'] is not True for r in access):raise ValueError('full-record oracle failure')
    expected=dict(measured_checks=config['operations'],initialization_checks=config['blocks'],warmup_checks=config['warmup'],final_audit_checks=config['blocks'])
    if any(summary[0][k]!=v for k,v in expected.items()):raise ValueError('incomplete oracle checks')
    histogram=Counter(r['stash'] for r in access)
    result=dict(**expected,oracle_checks=sum(expected.values()),setup_ns=setup[0]['setup_ns'],stash_histogram=dict(histogram),max_measured_stash=max(histogram),latency={})
    for kind,predicate in [('all',lambda r:True),('read',lambda r:not r['write']),('write',lambda r:r['write'])]:
        values=[r['latency_ns'] for r in access if predicate(r)]
        if not values:raise ValueError('read/write samples absent')
        result['latency'][kind]={f'p{q}_ns':float(np.quantile(values,q/100)) for q in [50,95,99]}
        result['latency'][kind]['count']=len(values)
    return result

def analyze(root,config):
    trials=[];cells=[]
    for blocks in config['blocks']:
        for algorithm in config['algorithms']:
            selected=[];histogram=Counter()
            for trial in range(config['trials']):
                with gzip.open(root/'raw'/f'{algorithm}-n{blocks}-t{trial}.jsonl.gz','rt') as stream:rows=[json.loads(line) for line in stream]
                result=summarize_trial(rows,dict(blocks=blocks,operations=config['operations'],warmup=config['warmup']),algorithm)
                result.update(blocks=blocks,algorithm=algorithm,trial=trial);trials.append(result);selected.append(result);histogram.update(result['stash_histogram'])
            cells.append(dict(blocks=blocks,algorithm=algorithm,trials=len(selected),max_measured_stash=max(r['max_measured_stash'] for r in selected),stash_histogram=dict(sorted(histogram.items())),
                latency={kind:{f'mean_trial_p{q}_ns':interval([r['latency'][kind][f'p{q}_ns'] for r in selected]) for q in [50,95,99]} for kind in ['all','read','write']},
                mean_trial_setup_ns=interval([r['setup_ns'] for r in selected]),oracle_checks=sum(r['oracle_checks'] for r in selected)))
    (root/'trial-results.json').write_text(json.dumps(trials,indent=2)+'\n')
    report=dict(schema_version=1,cells=cells,reference_version='mc-oblivious-ram=2.3.0; mc-oblivious-traits=2.3.0',analysis_sha256=sha(__file__),
        methodology='30 fresh processes/controllers per cell; seeded uniform read/write workload only, every creator RNG freshly OS-seeded ChaCha20Rng; setup creation separate, initialization/warmup/final audit excluded from operation timings; means of trial p50/p95/p99, 5000 percentile bootstrap resamples at trial level',
        backend='Vendor HeapORAMStorage, unencrypted trusted heap, same for both reference algorithms; not the encrypted Oblivion backend and not an untrusted-storage security benchmark',
        bandwidth='Not instrumented. No backend bytes or network bandwidth inferred from formulas.',license='Separate GPL-3.0 benchmark program; Oblivion workspace has no dependency on it')
    (root/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
    import matplotlib;matplotlib.use('Agg');import matplotlib.pyplot as plt
    fig,axes=plt.subplots(1,2,figsize=(10,4))
    for algorithm in config['algorithms']:
        values=[r for r in cells if r['algorithm']==algorithm];x=[r['blocks'] for r in values];y=np.array([r['latency']['all']['mean_trial_p95_ns']['mean']/1000 for r in values]);ci=np.array([r['latency']['all']['mean_trial_p95_ns']['ci95_trials'] for r in values])/1000
        axes[0].errorbar(x,y,yerr=np.maximum(0,np.stack([y-ci[:,0],ci[:,1]-y])),marker='o',label=algorithm)
        axes[1].plot(x,[r['max_measured_stash'] for r in values],marker='o',label=algorithm)
    for ax in axes:ax.set_xscale('log');ax.legend();ax.set_xlabel('Logical 1024-byte records (Z=4)')
    axes[0].set_ylabel('Mean trial p95 (µs), trusted heap reference');axes[1].set_ylabel('Maximum measured post-access stash blocks')
    fig.tight_layout();fig.savefig(root/'circuit-reference.png',dpi=150);plt.close(fig)
    return report

def run(config_path,root):
    config=json.loads(config_path.read_text())
    if config['blocks']!=[64,1024] or config['algorithms']!=['path','circuit'] or config['trials']!=30 or config['operations']!=512 or config['warmup']!=16 or config['logical_block_bytes']!=1024 or config['bucket_capacity']!=4 or config['stash_capacity']!=128:raise ValueError('expected bounded matched 30-trial reference configuration')
    root.mkdir(parents=True,exist_ok=False);(root/'bin').mkdir();(root/'raw').mkdir();(root/'logs').mkdir();(root/'sources').mkdir()
    files=[REFERENCE/'Cargo.toml',REFERENCE/'Cargo.lock',REFERENCE/'src/main.rs',REFERENCE/'LICENSE',Path(__file__).resolve()]
    sources={str(p.relative_to(ROOT)):sha(p) for p in files}
    # Build only this independent GPL workspace; no Oblivion library is linked.
    subprocess.run(['cargo','build','--locked','--release','--manifest-path',str(REFERENCE/'Cargo.toml')],cwd=ROOT,check=True)
    if sources!={str(p.relative_to(ROOT)):sha(p) for p in files}:raise RuntimeError('adapter source changed during build')
    binary=root/'bin/oblivion-oram-reference';shutil.copy2(REFERENCE/'target/release/oblivion-oram-reference',binary);binary.chmod(0o555)
    for path in files:shutil.copyfile(path,root/'sources'/str(path.relative_to(ROOT)).replace('/','__'))
    # Registry source files/checksums expose which genuine dependency was built.
    metadata_deps=json.loads(command('cargo','metadata','--locked','--format-version','1','--manifest-path',str(REFERENCE/'Cargo.toml')))
    packages=[]
    for package in metadata_deps['packages']:
        if package['name'] in ['mc-oblivious-ram','mc-oblivious-traits','aligned-cmov','balanced-tree-index']:
            directory=Path(package['manifest_path']).parent
            packages.append(dict(name=package['name'],version=package['version'],license=package['license'],registry_source=package['source'],manifest_sha256=sha(directory/'Cargo.toml'),source_sha256={str(p.relative_to(directory)):sha(p) for p in directory.rglob('*') if p.is_file() and p.suffix=='.rs'}))
    shutil.copyfile(config_path,root/'config.json')
    before=dict(started_utc=datetime.now(timezone.utc).isoformat(),binary_sha256=sha(binary),adapter_source_sha256=sources,reference_packages=packages,configuration=config,
        compiler=command('rustc','--version','--verbose'),cargo=command('cargo','--version'),git_head=command('git','rev-parse','HEAD'),git_status=command('git','status','--porcelain'),platform=platform.platform(),cpu=Path('/proc/cpuinfo').read_text(),license='GPL-3.0 isolated reference executable; upstream copyright MobileCoin Foundation 2018-2023',features='default assembly; no no_asm_insecure flag',backend='unencrypted HeapORAMStorage, trusted heap algorithm benchmark; no network or TEE')
    (root/'provenance-before.json').write_text(json.dumps(before,indent=2)+'\n')
    commands=[];order=random.Random(config['order_seed'])
    for blocks in config['blocks']:
        for trial in range(config['trials']):
            algorithms=list(config['algorithms']);order.shuffle(algorithms)
            for algorithm in algorithms:
                if sha(binary)!=before['binary_sha256']:raise RuntimeError('frozen binary changed')
                path=root/'raw'/f'{algorithm}-n{blocks}-t{trial}.jsonl';cmd=[str(binary),algorithm,str(blocks),str(config['operations']),str(config['warmup']),str(config['seed']+trial),str(path)]
                result=subprocess.run(cmd,cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                (root/'logs'/f'{algorithm}-n{blocks}-t{trial}.log').write_text(result.stdout);commands.append(dict(command=cmd,exit=result.returncode))
                if result.returncode:raise RuntimeError(f'reference failed; preserved log/raw: {path}')
                with path.open('rb') as src,gzip.GzipFile(filename=str(path)+'.gz',mode='wb',mtime=0) as dst:shutil.copyfileobj(src,dst)
                path.unlink()
            print(f'N={blocks} trial {trial+1}/{config["trials"]}',flush=True)
    analyze(root,config)
    after=dict(finished_utc=datetime.now(timezone.utc).isoformat(),binary_sha256=sha(binary),adapter_source_after_sha256={str(p.relative_to(ROOT)):sha(p) for p in files},commands=commands)
    if after['binary_sha256']!=before['binary_sha256']:raise RuntimeError('frozen binary changed')
    (root/'provenance-after.json').write_text(json.dumps(after,indent=2)+'\n')
    manifest={str(p.relative_to(root)):sha(p) for p in sorted(root.rglob('*')) if p.is_file() and 'bin' not in p.relative_to(root).parts}
    (root/'artifact-sha256.json').write_text(json.dumps(manifest,indent=2)+'\n')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--config',type=Path,default=ROOT/'experiments/configs/circuit-reference-30.json');parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();run(args.config.resolve(),args.output.resolve())
