"""Run genuine local encrypted-index chosen-update association experiments."""
import argparse,gzip,hashlib,json,pathlib,platform,shutil,subprocess,tempfile,time
import numpy as np
from research.attacks.linkability import recover_links
from research.analysis.system import trial_interval
ROOT=pathlib.Path(__file__).resolve().parents[2]
def digest_files():
    h=hashlib.sha256()
    for path in sorted(list((ROOT/'crates/oblivion-sse').rglob('*.rs'))+[ROOT/'research/attacks/linkability.py',ROOT/'research/analysis/linkability.py']):h.update(str(path.relative_to(ROOT)).encode()+b'\0'+path.read_bytes()+b'\0')
    return h.hexdigest()
def main():
    parser=argparse.ArgumentParser();parser.add_argument('output',type=pathlib.Path);parser.add_argument('--trials',type=int,default=30);args=parser.parse_args()
    if not 2<=args.trials<=1000:raise SystemExit('trials must be 2..1000')
    args.output.mkdir(exist_ok=False);subprocess.run(['cargo','build','--locked','--release','-p','oblivion-sse','--example','injection'],cwd=ROOT,check=True)
    binary=ROOT/'target/release/examples/injection';binary_sha=hashlib.sha256(binary.read_bytes()).hexdigest();source_sha=digest_files();started=time.time();scores=[]
    with tempfile.TemporaryDirectory(prefix='oblivion-linkability-') as temporary:
        executable=pathlib.Path(temporary)/'local-example';shutil.copy2(binary,executable)
        for trial in range(args.trials):
            seed=20261021+trial;truth_path=args.output/f'truth-{trial}.json'
            proc=subprocess.run([str(executable),str(seed),str(truth_path.resolve())],cwd=ROOT,capture_output=True,check=True)
            wire=[json.loads(line) for line in proc.stdout.splitlines()];truth=json.loads(truth_path.read_text())['slots']
            with gzip.open(args.output/f'observer-{trial}.jsonl.gz','wb') as stream:stream.write(proc.stdout)
            for mode in ['stable_tag_control','ggm']:
                result=recover_links(wire,mode,seed)
                scores.append({'trial':trial,'seed':seed,'mode':mode,'before_accuracy':float(np.mean(np.array(result['before_predictions'])==truth)),
                               'after_accuracy':float(np.mean(np.array(result['after_predictions'])==truth)),'before_matches':result['before_matches'],'after_matches':result['after_matches'],'classes':len(truth)})
    summaries={}
    for mode in ['stable_tag_control','ggm']:
        rows=[r for r in scores if r['mode']==mode];summaries[mode]={key:{'mean':float(np.mean([r[key] for r in rows])),'ci95_trials':trial_interval([r[key] for r in rows])} for key in ['before_accuracy','after_accuracy']};summaries[mode]['before_matches']=sum(r['before_matches'] for r in rows);summaries[mode]['after_matches']=sum(r['after_matches'] for r in rows)
    if summaries['stable_tag_control']['before_accuracy']['mean']<=1/8+.1:raise RuntimeError('positive control failed')
    report={'configuration':{'seed':20261021,'trials':args.trials,'keywords':8,'initial_postings_per_keyword':4,'chosen_additions_per_keyword':1},'summaries':summaries,'trials':scores,
            'baseline':{'chance':1/8,'balanced_keyword_classes':True},'binary_sha256_before_launch':binary_sha,'source_sha256':source_sha,'platform':platform.platform(),
            'rustc':subprocess.check_output(['rustc','--version'],text=True).strip(),'elapsed_seconds':time.time()-started,'output':str(args.output.resolve()),
            'methodology':'30 independent ephemeral cryptographic setups; bootstrap whole trial means; all observed updates and searches are real crate/baseline requests',
            'claim':'forward privacy delays association until a future search; it does not conceal chosen posting membership after that search',
            'scope':'local synthetic in-memory indices; no external target or service; association to past opaque query identity rather than plaintext keyword recovery'}
    (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    import matplotlib;matplotlib.use('Agg');import matplotlib.pyplot as plt
    fig,ax=plt.subplots(figsize=(7,4));x=np.arange(2);width=.35
    for i,stage in enumerate(['before_accuracy','after_accuracy']):ax.bar(x+(i-.5)*width,[summaries[m][stage]['mean'] for m in ['stable_tag_control','ggm']],width,label='Before next search' if i==0 else 'After next search')
    ax.axhline(1/8,color='gray',linestyle='--',label='uniform chance');ax.set(xticks=x,xticklabels=['Stable-tag encrypted control','Bounded GGM SSE'],ylabel='Opaque prior-query association accuracy',ylim=(0,1.08));ax.legend();fig.tight_layout();fig.savefig(args.output/'update-linkability.png',dpi=150);plt.close(fig)
    print(json.dumps(summaries,indent=2))
if __name__=='__main__':main()
