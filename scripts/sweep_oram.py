#!/usr/bin/env python3
"""Execute 30 fresh controllers per size and regenerate measured ORAM figure."""
import argparse,gzip,json,pathlib,subprocess,sys
import numpy as np
from research.analysis.system import trial_interval
ROOT=pathlib.Path(__file__).resolve().parents[1]
def plot(root):
    import matplotlib;matplotlib.use('Agg');import matplotlib.pyplot as plt
    cells=[]
    for path in sorted(root.glob('blocks-*'),key=lambda p:int(p.name.split('-')[1])):
        config=json.loads((path/'config.json').read_text());rows=[json.loads(s) for s in (path/'summary.jsonl').read_text().splitlines()]
        values=[np.mean([r['read']['p95_ns'],r['write']['p95_ns']])/1000 for r in rows]
        cells.append({'blocks':config['blocks'],'block_bytes':config['block_bytes'],'trials':len(rows),'mean_trial_rw_p95_us':float(np.mean(values)),'ci95':trial_interval(values),
                      'bytes_per_access':rows[0]['bytes_per_access'],'storage_expansion':rows[0]['encrypted_storage_bytes']/rows[0]['logical_storage_bytes'],
                      'max_stash':max(r['max_measured_stash'] for r in rows),'trusted_metadata_bytes':rows[0]['private_state']['trusted_metadata_bytes']})
    (root/'summary.json').write_text(json.dumps({'cells':cells,'methodology':'mean of per-trial read/write p95, 30 independent trials; trial-bootstrap interval; not pooled p95 or network measurement'},indent=2)+'\n')
    fig,axes=plt.subplots(1,2,figsize=(10,4));x=[r['blocks'] for r in cells];y=np.array([r['mean_trial_rw_p95_us'] for r in cells]);ci=np.array([r['ci95'] for r in cells]);axes[0].errorbar(x,y,yerr=np.maximum(0,np.stack([y-ci[:,0],ci[:,1]-y])),marker='o');axes[0].set(xlabel='Logical blocks (256 bytes)',ylabel='Mean trial read/write p95 (µs)',xscale='log',title='Actual memory-backed Path ORAM')
    axes[1].plot(x,[r['bytes_per_access']/256 for r in cells],marker='o');axes[1].set(xlabel='Logical blocks',ylabel='Payload bandwidth amplification',xscale='log');fig.tight_layout();fig.savefig(root/'oram-size.png',dpi=150);plt.close(fig)
def main():
    p=argparse.ArgumentParser();p.add_argument('output',type=pathlib.Path);p.add_argument('--plot-only',action='store_true');args=p.parse_args();root=args.output
    if args.plot_only:plot(root);return
    root.mkdir(exist_ok=False)
    for blocks in [16,64,256,1024]:
        config={'version':1,'blocks':blocks,'block_bytes':256,'operations':128,'warmup':16,'trials':30,'seed':20261021,'workload':'uniform'}
        cfg=root/f'config-{blocks}.json';cfg.write_text(json.dumps(config)+'\n');out=root/f'blocks-{blocks}'
        subprocess.run([sys.executable,'scripts/measure_oram.py',str(cfg),str(out)],cwd=ROOT,check=True)
        for raw in list(out.glob('observer-*.jsonl'))+list(out.glob('private-*.jsonl')):
            with raw.open('rb') as src,gzip.open(str(raw)+'.gz','wb') as dst:
                while chunk:=src.read(1<<20):dst.write(chunk)
            raw.unlink()
    plot(root)
if __name__=='__main__':main()
