#!/usr/bin/env python3
"""Bounded independent-trial ORAM/PIR geometry campaign and raw-data regeneration."""
import argparse
from collections import Counter
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import numpy as np

ROOT = Path(__file__).resolve().parents[1]

def configurations():
    for n in [64, 256]:
        for width in [64, 256, 1024]:
            for z in [3, 4, 5]:
                for workload in ['same', 'uniform']:
                    yield 'oram', f'oram-n{n}-b{width}-z{z}-{workload}', dict(version=1, blocks=n, block_bytes=width, bucket_capacity=z, operations=128, warmup=16, trials=30, seed=20261022, workload=workload)
    for n in [64, 1024, 10000]:
        for width in [64, 1024]:
            yield 'pir', f'pir-n{n}-b{width}', dict(version=1, count=n, record_bytes=width, trials=30, queries_per_trial=16, seed=20261022)

def estimate(values):
    a = np.asarray(values, dtype=float)
    if a.ndim != 1 or len(a) < 2 or not np.isfinite(a).all():
        raise ValueError('need multiple finite independent trial estimates')
    rng = np.random.default_rng(20261022)
    ci = np.quantile(a[rng.integers(0, len(a), (5000, len(a)))].mean(axis=1), [.025, .975])
    return dict(mean=float(a.mean()), ci95_trials=list(map(float, ci)), trials=len(a))

def pir_trials(rows, trials, queries):
    if len(rows) != trials * queries or {(r['trial'], r['query']) for r in rows} != {(t, q) for t in range(trials) for q in range(queries)}:
        raise ValueError('incomplete or duplicate PIR trial samples')
    metrics = {k: [] for k in ['generation_ns', 'server1_ns', 'server2_ns', 'recovery_ns', 'serial_total_ns', 'two_server_scan_GB_s']}
    for t in range(trials):
        selected = [r for r in rows if r['trial'] == t]
        for k in ['generation_ns', 'server1_ns', 'server2_ns', 'recovery_ns']:
            metrics[k].append(float(np.mean([r[k] for r in selected])))
        total_server = sum(r['server1_ns'] + r['server2_ns'] for r in selected)
        metrics['serial_total_ns'].append(sum(metrics[k][-1] for k in ['generation_ns', 'server1_ns', 'server2_ns', 'recovery_ns']))
        metrics['two_server_scan_GB_s'].append(sum(2 * r['database_payload_bytes_per_server'] for r in selected) / total_server)
    return metrics

def load(path):
    opener = gzip.open if str(path).endswith('.gz') else open
    with opener(path, 'rt') as f:
        return [json.loads(line) for line in f if line.strip()]

def analyze(root):
    previous = json.loads((root/'summary.json').read_text()) if (root/'summary.json').exists() else {}
    revisions = list(previous.get('analysis_revisions_sha256', []))
    for revision in [previous.get('analysis_sha256'), sha(ROOT/'scripts/sweep_geometry.py')]:
        if revision and (not revisions or revisions[-1] != revision):
            revisions.append(revision)
    cells = []
    for kind, name, _ in configurations():
        out = root / name
        config = json.loads((out / 'config.json').read_text())
        if kind == 'oram':
            rows = load(out / 'summary.jsonl')
            if len(rows) != config['trials'] or {r['trial'] for r in rows} != set(range(config['trials'])):
                raise ValueError('incomplete ORAM trials')
            histogram = Counter()
            latencies = {q: [] for q in [50, 95, 99]}
            maximum = 0
            for row in rows:
                private = load(out / f"private-{row['trial']}.jsonl.gz")
                if len(private) != config['operations'] or [r['step'] for r in private] != list(range(config['operations'])):
                    raise ValueError('incomplete private ORAM samples')
                hist = Counter(r['stash'] for r in private)
                if {str(k): v for k, v in hist.items()} != row['stash_histogram']:
                    raise ValueError('stash histogram differs from genuine private trace')
                histogram.update(hist)
                maximum = max(maximum, max(hist))
                for q in latencies:
                    latencies[q].append(float(np.quantile([r['latency_ns'] for r in private], q/100)))
                observer_path = out / f"observer-{row['trial']}.jsonl.gz"
                with gzip.open(observer_path, 'rt') as stream:
                    count, total_bytes, byte_sizes = 0, 0, set()
                    for line in stream:
                        event = json.loads(line); count += 1; total_bytes += event['bytes']; byte_sizes.add(event['bytes'])
                path_buckets = (config['blocks']-1).bit_length()+1
                if count != config['operations']*2*path_buckets or total_bytes != config['operations']*row['bytes_per_access'] or len(byte_sizes)!=1:
                    raise ValueError('observer count/bytes differ from public geometry')
            metrics = dict(**{f'mean_trial_p{q}_ns': estimate(v) for q,v in latencies.items()}, stash_histogram=dict(sorted(histogram.items())), max_measured_stash=maximum,
                           bytes_per_access=rows[0]['bytes_per_access'], encrypted_storage_bytes=rows[0]['encrypted_storage_bytes'],
                           storage_expansion=rows[0]['encrypted_storage_bytes']/rows[0]['logical_storage_bytes'], private_state=rows[0]['private_state'])
        else:
            rows = load(out / 'private-samples.jsonl.gz')
            metrics = {k: estimate(v) for k, v in pir_trials(rows, config['trials'], config['queries_per_trial']).items()}
            metrics.update({k: rows[0][k] for k in ['query_payload_bytes', 'response_payload_bytes', 'database_payload_bytes_per_server']})
            metrics['two_server_database_payload_bytes'] = 2 * rows[0]['database_payload_bytes_per_server']
        cells.append(dict(kind=kind, name=name, config=config, metrics=metrics))
    report = dict(schema_version=1, cells=cells, analysis_sha256=sha(ROOT/'scripts/sweep_geometry.py'),
                  analysis_revisions_sha256=revisions, measurement_provenance_sha256=sha(root/'provenance.json'),
                  methodology='30 independent fresh controllers/server states per cell; bootstrap means of trial estimates, 5000 resamples; ORAM p95 uses linear sample quantile; OS crypto randomness, seeded workload only. PIR throughput is sum of both database payloads divided by serial server answer time, decimal GB/s, in-process and warm-up excluded. Payload memory excludes allocator overhead. Shared host; timing instrumentation and scheduling affect results.')
    (root/'summary.json').write_text(json.dumps(report, indent=2)+'\n')
    plot(root, cells)
    return report

def plot(root, cells):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(11, 4))
    for n in [64, 256]:
        for workload in ['same', 'uniform']:
            chosen = [c for c in cells if c['kind']=='oram' and c['config']['blocks']==n and c['config']['block_bytes']==256 and c['config']['workload']==workload]
            x=[c['config']['bucket_capacity'] for c in chosen]
            y=np.array([c['metrics']['mean_trial_p95_ns']['mean']/1000 for c in chosen])
            ci=np.array([c['metrics']['mean_trial_p95_ns']['ci95_trials'] for c in chosen])/1000
            axes[0].errorbar(x,y,yerr=np.maximum(0,np.array([y-ci[:,0],ci[:,1]-y])),marker='o',label=f'N={n}, {workload}')
            axes[1].plot(x,[c['metrics']['max_measured_stash'] for c in chosen],marker='o',label=f'N={n}, {workload}')
    axes[0].set(xlabel='Bucket capacity Z (256-byte blocks)',ylabel='Mean trial p95 latency (µs)')
    axes[1].set(xlabel='Bucket capacity Z (256-byte blocks)',ylabel='Maximum measured post-eviction stash blocks')
    for ax in axes: ax.legend(fontsize=8)
    fig.tight_layout();fig.savefig(root/'oram-geometry.png',dpi=150);plt.close(fig)
    fig, axes = plt.subplots(1, 2, figsize=(11,4))
    for z in [3,4,5]:
        chosen=[c for c in cells if c['kind']=='oram' and c['config']['blocks']==256 and c['config']['workload']=='uniform' and c['config']['bucket_capacity']==z]
        x=[c['config']['block_bytes'] for c in chosen]
        axes[0].plot(x,[c['metrics']['bytes_per_access']/c['config']['block_bytes'] for c in chosen],marker='o',label=f'Z={z}')
        axes[1].plot(x,[c['metrics']['mean_trial_p95_ns']['mean']/1000 for c in chosen],marker='o',label=f'Z={z}')
    axes[0].set(xlabel='Block bytes (N=256, uniform)',ylabel='Encrypted payload bytes / logical block bytes',xscale='log')
    axes[1].set(xlabel='Block bytes (N=256, uniform)',ylabel='Mean trial p95 (µs)',xscale='log')
    for ax in axes: ax.legend()
    fig.tight_layout();fig.savefig(root/'oram-width.png',dpi=150);plt.close(fig)
    fig,axes=plt.subplots(1,2,figsize=(11,4))
    for width in [64,1024]:
        chosen=[c for c in cells if c['kind']=='pir' and c['config']['record_bytes']==width]
        for ax,key,scale in [(axes[0],'serial_total_ns',1000),(axes[1],'two_server_scan_GB_s',1)]:
            x=[c['config']['count'] for c in chosen];y=np.array([c['metrics'][key]['mean']/scale for c in chosen]);ci=np.array([c['metrics'][key]['ci95_trials'] for c in chosen])/scale
            ax.errorbar(x,y,yerr=np.maximum(0,np.array([y-ci[:,0],ci[:,1]-y])),marker='o',label=f'{width}-byte records');ax.set_xscale('log');ax.legend()
    axes[0].set(xlabel='Records per server',ylabel='Mean trial serial total (µs)')
    axes[1].set(xlabel='Records per server',ylabel='In-process two-server scan (decimal GB/s)')
    fig.tight_layout();fig.savefig(root/'pir-geometry.png',dpi=150);plt.close(fig)

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def command(*args): return subprocess.check_output(args, cwd=ROOT, text=True).strip()
def compress(out):
    for path in list(out.glob('observer-*.jsonl')) + list(out.glob('private*.jsonl')):
        with path.open('rb') as src, gzip.GzipFile(filename=str(path)+'.gz', mode='wb', mtime=0) as dst: shutil.copyfileobj(src,dst)
        path.unlink()

def main():
    parser=argparse.ArgumentParser();parser.add_argument('output',type=Path);parser.add_argument('--plot-only',action='store_true');args=parser.parse_args();root=args.output.resolve()
    if args.plot_only:
        reanalyze(root)
        return
    root.mkdir(parents=True,exist_ok=False)
    binaries=root/'bin';binaries.mkdir(parents=True,exist_ok=True)
    subprocess.run(['cargo','build','--locked','--release','-p','oblivion-store','--example','oram-measure','-p','oblivion-pir','--example','pir-measure'],cwd=ROOT,check=True)
    for name in ['oram-measure','pir-measure']: shutil.copy2(ROOT/'target/release/examples'/name,binaries/name)
    files=sorted(p for p in ROOT.glob('crates/**/*') if p.is_file())+[ROOT/'Cargo.toml',ROOT/'Cargo.lock',Path(__file__).resolve()]
    source={str(p.relative_to(ROOT)):sha(p) for p in files}
    metadata=dict(schema_version=1,started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),git_head=command('git','rev-parse','HEAD'),git_status=command('git','status','--porcelain'),source_sha256=source,
                  executable_sha256={name:sha(binaries/name) for name in ['oram-measure','pir-measure']},rustc=command('rustc','--version','--verbose'),platform=platform.platform(),cpu=Path('/proc/cpuinfo').read_text(),configurations=[dict(kind=k,name=n,config=c) for k,n,c in configurations()],crypto_randomness='OS sourced, never seeded; seeds control logical workload only',measurement_scope='in-process memory-backed, no network or TEE')
    # Provenance is durable before any measurement starts.
    (root/'provenance.json').write_text(json.dumps(metadata,indent=2)+'\n')
    for kind,name,config in configurations():
        cfg=root/f'{name}.json';cfg.write_text(json.dumps(config,indent=2)+'\n')
        print(name,flush=True)
        subprocess.run([str(binaries/('oram-measure' if kind=='oram' else 'pir-measure')),str(cfg),str(root/name)],cwd=ROOT,check=True)
        compress(root/name)
    analyze(root)
    write_manifest(root)

DERIVED_FILES = {'summary.json', 'oram-geometry.png', 'oram-width.png', 'pir-geometry.png'}

def artifact_paths(root):
    return {str(p.relative_to(root)): p for p in root.rglob('*')
            if p.is_file() and p.name != 'sha256.json' and 'bin' not in p.relative_to(root).parts}

def verify_manifest(root):
    """Check the accepted baseline before permitting any derived-file overwrite."""
    manifest = json.loads((root/'sha256.json').read_text())
    if not isinstance(manifest, dict) or not manifest:
        raise ValueError('artifact manifest must be a nonempty object')
    paths = artifact_paths(root)
    if paths.keys() != manifest.keys():
        raise ValueError(f'artifact set differs from manifest: {sorted(paths.keys() ^ manifest.keys())}')
    for name, digest in manifest.items():
        if sha(paths[name]) != digest:
            raise ValueError(f'artifact hash differs from manifest: {name}')
    return manifest

def write_manifest(root, previous=None):
    path = root/'sha256.json'
    paths = artifact_paths(root)
    if previous is None:
        if path.exists():
            raise FileExistsError('refusing to replace an existing artifact baseline')
        manifest = {name: sha(file) for name, file in sorted(paths.items())}
    else:
        # Preserve accepted raw/provenance hashes verbatim. Recheck immutable files
        # after analysis too, so no concurrent raw change can enter the new baseline.
        if json.loads(path.read_text()) != previous:
            raise ValueError('manifest changed during reanalysis')
        immutable = {name: digest for name, digest in previous.items() if name not in DERIVED_FILES}
        if set(paths) - set(previous) - DERIVED_FILES:
            raise ValueError('unexpected new artifacts during reanalysis')
        for name, digest in immutable.items():
            if name not in paths or sha(paths[name]) != digest:
                raise ValueError(f'immutable artifact changed during reanalysis: {name}')
        manifest = {**immutable, **{name: sha(paths[name]) for name in sorted(DERIVED_FILES) if name in paths}}
    path.write_text(json.dumps(manifest, indent=2)+'\n')

def reanalyze(root):
    previous = verify_manifest(root)
    report = analyze(root)
    write_manifest(root, previous)
    return report

if __name__=='__main__': main()
