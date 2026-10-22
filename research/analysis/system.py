"""Independent-session joint A-G attacks and measured cost/privacy figures."""
import argparse,json,pathlib
from collections import defaultdict
import numpy as np
from scipy.stats import rankdata
from research.attacks.joint import JointAttack,FEATURES

NAMES={'A':'Plaintext','B':'Encrypt only','C':'+ ORAM','D':'+ PIR','E':'+ batching','F':'+ padded executor','G':'Combined'}
def load(path):return [json.loads(line) for line in pathlib.Path(path).read_text().splitlines() if line]
def trial_interval(values,seed=1):
    values=np.asarray(values,dtype=float)
    if values.ndim!=1 or len(values)<2 or not np.isfinite(values).all():raise ValueError('need at least two finite independent trial estimates')
    rng=np.random.default_rng(seed);boot=values[rng.integers(0,len(values),(5000,len(values)))].mean(axis=1)
    return list(map(float,np.quantile(boot,[.025,.975])))
def nondominated(points):
    return [i for i,p in enumerate(points) if not any(all(a<=b for a,b in zip(q,p)) and any(a<b for a,b in zip(q,p)) for j,q in enumerate(points) if i!=j)]
def balanced(y,pred,classes):return float(np.mean([np.mean(pred[y==c]==c) for c in classes]))
def auc(y,score):
    positives=int(np.sum(y==1));negatives=int(np.sum(y==0))
    if positives==0 or negatives==0:return None
    ranks=rankdata(score);return float((ranks[y==1].sum()-positives*(positives+1)/2)/(positives*negatives))
def analyze(root):
    root=pathlib.Path(root);config=json.loads((root/'config.json').read_text());trials=[];models=[]
    for mode in NAMES:
        for trial in range(config['trials']):
            profile=[];profile_labels=[];target=[];labels=[]
            for session in range(config['sessions']):
                path=root/mode/f'{trial}-{session}';obs=load(path/'observer.jsonl');truth=load(path/'ground-truth.jsonl')
                if [r['step'] for r in obs]!=[r['step'] for r in truth]:raise ValueError('unaligned observer/truth')
                destination,label_destination=(profile,profile_labels) if session<config['sessions']//2 else (target,labels)
                destination.extend(obs);label_destination.extend(r['label'] for r in truth)
            attack=JointAttack(seed=config['seed']+trial).fit(profile,profile_labels);result=attack.run(target,{})
            y=np.array(labels);pred=np.array(result.predictions);scores=np.asarray(result.scores)
            real=y!=0;binary_pred=(scores[:,1:].sum(axis=1)>.5).astype(int)
            function_pred=np.argmax(scores[real,1:],axis=1)+1
            p=np.bincount(profile_labels,minlength=3);majority=int(p.argmax())
            row={'mode':mode,'trial':trial,'accuracy':float(np.mean(y==pred)),'balanced_accuracy':balanced(y,pred,[0,1,2]),
                 'majority_accuracy':float(np.mean(y==majority)),'majority_balanced_accuracy':1/3,
                 'real_dummy_accuracy':float(np.mean(binary_pred==real)),'real_dummy_auc':auc(real.astype(int),scores[:,1:].sum(axis=1)),
                 'conditional_real_function_accuracy':float(np.mean(function_pred==y[real])),
                 'top2_accuracy':float(np.mean([a in np.argsort(s)[-2:] for a,s in zip(y,scores)])),
                 'profile_observations':len(profile),'target_observations':len(target),'independent_profile_sessions':config['sessions']//2,
                 'independent_target_sessions':config['sessions']//2}
            trials.append(row);models.append({'mode':mode,'trial':trial,'metadata':result.metadata})
    data=load(root/'metrics.jsonl');summaries={}
    for mode in NAMES:
        rows=[r for r in trials if r['mode']==mode];metrics=[r for r in data if r['mode']==mode];summary={}
        for key in ['accuracy','balanced_accuracy','majority_accuracy','real_dummy_accuracy','real_dummy_auc','conditional_real_function_accuracy','top2_accuracy']:
            values=[r[key] for r in rows];summary[key]={'mean':float(np.mean(values)),'ci95_trials':trial_interval(values,config['seed'])}
        latency=np.array([r['latency_ns'] for r in metrics])/1e6
        if any('opportunity_wall_ns' not in r for r in metrics):raise ValueError('legacy records lack measured wall occupation; retain their original analysis rather than substitute response latency')
        occupation=np.array([r['opportunity_wall_ns'] for r in metrics])/1e6
        real_latencies=[]
        for trial in range(config['trials']):
            for session in range(config['sessions']):
                labels={r['step']:r['label'] for r in load(root/mode/f'{trial}-{session}'/'ground-truth.jsonl')}
                real_latencies.extend(r['latency_ns']/1e6 for r in metrics if r['trial']==trial and r['session']==session and labels[r['step']]!=0)
        wire=np.array([r['request_bytes']+r['response_bytes']+r['registry_bytes']+r['storage_bytes'] for r in metrics])
        summary['benchmark']={'observations':len(metrics),'p50_ms':float(np.quantile(latency,.5)),'p95_ms':float(np.quantile(latency,.95)),'p99_ms':float(np.quantile(latency,.99)),
            'mean_ms':float(latency.mean()),'mean_opportunity_wall_ms':float(occupation.mean()),'real_p50_ms':float(np.quantile(real_latencies,.5)),'real_p95_ms':float(np.quantile(real_latencies,.95)),'real_p99_ms':float(np.quantile(real_latencies,.99)),'bytes_per_public_opportunity':float(wire.mean()),'bytes_per_real_invocation':float(wire.mean()*2),
            'mean_registry_us':float(np.mean([r['registry_ns'] for r in metrics])/1000),'mean_execution_ms':float(np.mean([r['execution_ns'] for r in metrics])/1e6),
            'mean_padding_ms':float(np.mean([r['padding_ns'] for r in metrics])/1e6),'process_cpu_ticks':sum(r['cpu_ticks'] for r in metrics),
            'max_process_rss_pages':max(r['rss_pages'] for r in metrics),'deadline_misses':sum(r['deadline_missed'] for r in metrics),
            'late_epochs':sum(r['late_by_ns']>0 for r in metrics),'max_late_ms':max(r['late_by_ns'] for r in metrics)/1e6,
            'useful_real_throughput_per_s':float(len(real_latencies)/(occupation.sum()/1000)),
            'hypothetical_compute_cost_per_million_real':float(occupation.sum()/1000/len(real_latencies)*1e6*.00001),
            'hypothetical_client_response_egress_cost_per_million_real':float(sum(r['response_bytes'] for r in metrics)/len(real_latencies)*1e6/(1<<30)*.1)}
        per_trial_real_p95=[]
        for trial in range(config['trials']):
            values=[]
            for session in range(config['sessions']):
                truth={r['step']:r['label'] for r in load(root/mode/f'{trial}-{session}'/'ground-truth.jsonl')}
                values.extend(r['latency_ns']/1e6 for r in metrics if r['trial']==trial and r['session']==session and truth[r['step']]!=0)
            per_trial_real_p95.append(float(np.quantile(values,.95)))
        summary['benchmark']['mean_trial_real_p95_ms']=float(np.mean(per_trial_real_p95))
        summary['benchmark']['mean_trial_real_p95_ms_ci95']=trial_interval(per_trial_real_p95,config['seed'])
        driver_observed=mode in ['F','G'] and all('driver_work_overrun_ns' in r and 'publication_lateness_ns' in r for r in metrics)
        summary['benchmark']['driver_work_overruns']=sum(r['driver_work_overrun_ns']>0 for r in metrics) if driver_observed else None
        summary['benchmark']['publication_lateness_p95_ms']=float(np.quantile([r['publication_lateness_ns']/1e6 for r in metrics if r['execution_ns']>0],.95)) if driver_observed else None
        summaries[mode]=summary
    if summaries['A']['balanced_accuracy']['mean']<=1/3+.1:raise RuntimeError('joint attack positive control failed')
    keys=list(NAMES);points=[(summaries[k]['benchmark']['bytes_per_public_opportunity'],summaries[k]['balanced_accuracy']['mean']) for k in keys]
    report={'schema_version':1,'analysis_source_sha256':__import__('hashlib').sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'attacker_source_sha256':__import__('hashlib').sha256(pathlib.Path(__file__).parents[1].joinpath('attacks/joint.py').read_bytes()).hexdigest(),'configuration':config,'mode_names':NAMES,'summaries':summaries,
            'pareto_bandwidth_attack_point_estimates':[keys[i] for i in nondominated(points)],
            'pareto_latency_bandwidth_attack_point_estimates':[keys[i] for i in nondominated([(summaries[k]['benchmark']['real_p95_ms'],summaries[k]['benchmark']['bytes_per_real_invocation'],summaries[k]['balanced_accuracy']['mean']) for k in keys])],
            'features':list(FEATURES),'attacker_knowledge':'mechanisms/config and whole independent labeled profiling sessions; no target labels supplied to model',
            'statistical_methodology':'per-trial new fitted forest, mean target metrics, percentile bootstrap of 30 independent trial clusters (or recorded smaller configured count)',
            'scope':'actual API-boundary A-G integration, encrypted full PIR query frames and actual guest storage calls; not packet capture, TEE, formal proof or open-loop load test',
            'cost_model':{'wall_occupation_source':'measured opportunity_wall_ns including scheduled idle/validation/serialization; latency_ns is separately measured response latency','hypothetical_executor_second_price':.00001,'hypothetical_response_GiB_price':.1,'currency':'illustrative cost units, not provider prices','egress_scope':'client response payload only; no actual bill, TLS/TCP overhead or internal storage egress inferred'},
            'timing_caveat':'shared host, serialization/instrumentation overhead and scheduler jitter; CPU ticks and RSS include common process/engine/library state'}
    (root/'joint-report.json').write_text(json.dumps(report,indent=2)+'\n');(root/'joint-trials.json').write_text(json.dumps(trials,indent=2)+'\n');(root/'attack-models.json').write_text(json.dumps(models,indent=2)+'\n')
    plot(root,report);return report

def plot(root,report):
    import matplotlib;matplotlib.use('Agg');import matplotlib.pyplot as plt
    keys=list(NAMES);s=report['summaries'];acc=np.array([s[k]['balanced_accuracy']['mean'] for k in keys]);chance=1/3
    for name,x,label in [('latency-privacy',[s[k]['benchmark']['p95_ms'] for k in keys],'p95 opportunity latency (ms)'),('bandwidth-privacy',[s[k]['benchmark']['bytes_per_public_opportunity'] for k in keys],'API payload bytes per public opportunity'),('cost-attack',[s[k]['benchmark']['mean_opportunity_wall_ms'] for k in keys],'Serial wall occupation per opportunity (ms; cost proxy)')]:
        fig,ax=plt.subplots(figsize=(7,4));ax.scatter(x,acc);ax.axhline(chance,color='gray',linestyle='--',label='balanced chance')
        for key,a,b in zip(keys,x,acc):ax.annotate(key,(a,b),xytext=(4,4),textcoords='offset points')
        frontier=nondominated(list(zip(x,acc)));frontier=sorted(frontier,key=lambda i:x[i]);ax.plot(np.array(x)[frontier],acc[frontier],':',label='point-estimate Pareto frontier')
        ax.set(xlabel=label,ylabel='Joint attack balanced accuracy',ylim=(0,1.08));ax.legend();fig.tight_layout();fig.savefig(root/f'{name}.png',dpi=150);plt.close(fig)
    fig=plt.figure(figsize=(11,4));ax=fig.add_subplot(121,projection='3d')
    bw=np.array([s[k]['benchmark']['bytes_per_real_invocation']/1024 for k in keys]);lat=np.array([s[k]['benchmark']['real_p95_ms'] for k in keys])
    ax.scatter(bw,lat,acc)
    for k,a,b,c in zip(keys,bw,lat,acc):ax.text(a,b,c,k)
    ax.set(xlabel='Payload KiB / real',ylabel='Real p95 ms',zlabel='Balanced attack accuracy',title='Latency / bandwidth / inference')
    panel=fig.add_subplot(122)
    for limit,marker in [(100,'x'),(110,'o')]:
        allowed=[i for i,k in enumerate(keys) if lat[i]<=limit]
        front=nondominated([(bw[i],acc[i]) for i in allowed]);front=sorted([allowed[i] for i in front],key=lambda i:bw[i])
        if front:panel.plot(bw[front],acc[front],marker=marker,label=f'p95 <= {limit} ms frontier')
    panel.scatter(bw,acc,color='gray',alpha=.4)
    for k,a,b in zip(keys,bw,acc):panel.annotate(k,(a,b),xytext=(3,3),textcoords='offset points')
    panel.set(xlabel='Payload KiB / real',ylabel='Balanced attack accuracy',title='Explicit operational SLO filters',ylim=(0,1.08));panel.legend(fontsize=8);fig.tight_layout();fig.savefig(root/'pareto-three-axis-slo.png',dpi=150);plt.close(fig)
    fig,axes=plt.subplots(1,2,figsize=(10,4));ci=np.array([s[k]['balanced_accuracy']['ci95_trials'] for k in keys]);axes[0].bar(keys,acc,yerr=np.maximum(0,np.stack([acc-ci[:,0],ci[:,1]-acc])));axes[0].axhline(chance,color='gray',linestyle='--');axes[0].set(ylabel='Joint balanced accuracy',ylim=(0,1.08),title='A–G ablation (trial CI)')
    width=.38;positions=np.arange(len(keys));axes[1].bar(positions-width/2,[s[k]['real_dummy_accuracy']['mean'] for k in keys],width,label='Real/dummy');axes[1].bar(positions+width/2,[s[k]['conditional_real_function_accuracy']['mean'] for k in keys],width,label='Function given real');axes[1].set(xticks=positions,xticklabels=keys,ylabel='Accuracy',ylim=(0,1.08));axes[1].axhline(.5,color='gray',linestyle='--');axes[1].legend();fig.tight_layout();fig.savefig(root/'ablation-attacks.png',dpi=150);plt.close(fig)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('results');args=parser.parse_args();report=analyze(args.results)
    for mode,row in report['summaries'].items():print(mode,row['balanced_accuracy'],row['benchmark']['p95_ms'])
if __name__=='__main__':main()
