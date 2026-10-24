#!/usr/bin/env python3
"""100k actual Path ORAM leaf diagnostics, with compressed raw evidence."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import numpy as np
from scipy import stats
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
ROOT=Path(__file__).resolve().parents[1]

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as file:
        for block in iter(lambda:file.read(1024*1024),b''):h.update(block)
    return h.hexdigest()

def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def read(path):
    with gzip.open(path,'rt') as file:
        for line in file:yield json.loads(line)

def mi(x,y,n,m):
    table=np.bincount(x*m+y,minlength=n*m).reshape(n,m).astype(float)
    probability=table/table.sum(); expected=probability.sum(axis=1)[:,None]*probability.sum(axis=0)[None,:]
    valid=probability>0
    return float(np.sum(probability[valid]*np.log2(probability[valid]/expected[valid])))

def permutation_mi(x,y,n,m,rng,repeats=499):
    observed=mi(x,y,n,m)
    null=np.array([mi(x,rng.permutation(y),n,m) for _ in range(repeats)])
    return {'plugin_bits':observed,'null_mean_bits':float(null.mean()),'null_95_range_bits':list(map(float,np.quantile(null,[.025,.975]))),'permutation_p':float((1+np.count_nonzero(null>=observed))/(repeats+1)),'permutations':repeats}

def analyze(output):
    rng=np.random.default_rng(20261021);reports={};data={};tests=[]
    for workload in ('same','uniform'):
        path=output/workload;config=json.loads((path/'config.json').read_text());n=config['blocks'];ops=config['operations']
        leaves=[];frames=set();events=0
        for event in read(path/'observer-0.jsonl.gz'):
            events+=1;frames.add(event['bytes'])
            if event['direction']=='read' and event['bucket']>=n-1:leaves.append(event['bucket']-(n-1))
        assert len(leaves)==ops and events==ops*2*(int(np.log2(n))+1) and len(frames)==1
        private=list(read(path/'private-0.jsonl.gz'));assert len(private)==ops and all(row['step']==step for step,row in enumerate(private))
        values=np.array(leaves,dtype=np.int64);addresses=np.array([row['logical_address'] for row in private],dtype=np.int64);write=np.array([row['write'] for row in private],dtype=np.int64)
        if workload=='same':assert np.all(addresses==0)
        counts=np.bincount(values,minlength=n);cdf=np.cumsum(counts)/ops;ks=float(np.max(np.abs(cdf-np.arange(1,n+1)/n)))
        null=np.random.default_rng(20261022).multinomial(ops,np.ones(n)/n,size=5000)
        null_d=np.max(np.abs(np.cumsum(null,axis=1)/ops-np.arange(1,n+1)/n),axis=1)
        chi=stats.chisquare(counts);ks_p=float((1+np.count_nonzero(null_d>=ks))/(len(null_d)+1))
        report={'accesses':ops,'visible_leaf_count':n,'physical_events':events,'bucket_bytes':list(frames),'chi2_uniform_statistic':float(chi.statistic),'chi2_uniform_p':float(chi.pvalue),'discrete_ks_vs_uniform_D':ks,'discrete_ks_multinomial_p':ks_p,'ks_null_simulations':5000,'leaf_counts':counts.tolist(),'numeric_leaf_autocorrelation':{str(lag):float(np.corrcoef(values[:-lag],values[lag:])[0,1]) for lag in (1,2,4,8,16)},'consecutive_equal_fraction':float(np.mean(values[:-1]==values[1:])),'consecutive_equal_uniform_expectation':1/n,'leaf_write_dependence':permutation_mi(values,write,n,2,rng),'adjacent_leaf_dependence':permutation_mi(values[:-1],values[1:],n,n,rng),'leaf_logical_address_dependence':permutation_mi(values,addresses,n,n,rng) if workload=='uniform' else {'not_identifiable':'logical address is constant; zero entropy makes an independence test vacuous'}}
        reports[workload]=report;data[workload]=values
        tests.extend([(workload+'.chi2_uniform',float(chi.pvalue)),(workload+'.ks_uniform',ks_p),(workload+'.leaf_write_MI',report['leaf_write_dependence']['permutation_p']),(workload+'.adjacent_leaf_MI',report['adjacent_leaf_dependence']['permutation_p'])])
        if workload=='uniform':tests.append((workload+'.leaf_logical_MI',report['leaf_logical_address_dependence']['permutation_p']))
    n=reports['same']['visible_leaf_count'];a=data['same'];b=data['uniform'];counts=np.array([np.bincount(a,minlength=n),np.bincount(b,minlength=n)])
    homogeneity=stats.chi2_contingency(counts,correction=False);observed=float(np.max(np.abs(np.cumsum(counts[0])/len(a)-np.cumsum(counts[1])/len(b))))
    joined=np.concatenate([a,b]);null=[]
    for _ in range(499):
        shuffled=rng.permutation(joined);x=np.bincount(shuffled[:len(a)],minlength=n)/len(a);y=np.bincount(shuffled[len(a):],minlength=n)/len(b)
        null.append(np.max(np.abs(np.cumsum(x)-np.cumsum(y))))
    ks_p=float((1+np.count_nonzero(np.array(null)>=observed))/500)
    tests.extend([('same_vs_uniform.homogeneity',float(homogeneity.pvalue)),('same_vs_uniform.discrete_KS',ks_p)])
    adjusted={};running=0
    for rank,(name,pvalue) in enumerate(sorted(tests,key=lambda row:row[1])):
        running=max(running,min(1,(len(tests)-rank)*pvalue));adjusted[name]={'raw_p':pvalue,'holm_adjusted_p':running}
    result={'workloads':reports,'same_vs_uniform':{'homogeneity_chi2':float(homogeneity.statistic),'homogeneity_p':float(homogeneity.pvalue),'discrete_KS_D':observed,'discrete_KS_permutation_p':ks_p,'permutations':499},'predefined_diagnostic_family_holm':adjusted,'minimum_adjusted_p':min(row['holm_adjusted_p'] for row in adjusted.values()),'methodology':'One fresh OS-crypto session per workload; exactly100000 measured actualORAM accesses each, materialization+1000warmup excluded. Discrete KS uniform null calibrated by5000multinomial draws; two-workload KS and MI by499permutations. Holm correction across11 predefined diagnosticpvalues. MI is biased plugin estimate with reported permutationnull baseline. Numeric leaf autocorrelations at stated lags are exploratory features.','limitations':'One trial per workload cannot establish cross-session robustness, statistical independence or indistinguishability. Permutation/multinomial references model exchangeable IID nulls; failure to reject does not prove them. Correlation depends on arbitrary numeric leaf labels. Same-address logical dependence is unidentifiable because the logical variable is constant. No timing classifier, cache, network, composition or active-attack claim. Workloadseed reproducible; cryptographic leaves/keys/nonces intentionally OS-random.'}
    save(output/'diagnostics.json',result)
    fig,axes=plt.subplots(1,2,figsize=(10,4))
    for workload,values in data.items():
        axes[0].plot(np.arange(n),np.bincount(values,minlength=n),label=workload,alpha=.7)
        axes[1].plot([1,2,4,8,16],[reports[workload]['numeric_leaf_autocorrelation'][str(lag)] for lag in (1,2,4,8,16)],marker='o',label=workload)
    axes[0].axhline(len(a)/n,linestyle='--',color='black',label='uniform expectation');axes[0].set(xlabel='Visible leaf',ylabel='Count in100000accesses')
    axes[1].axhline(0,color='black',linestyle='--');axes[1].set(xlabel='Lag',ylabel='Numeric leaf autocorrelation')
    for axis in axes:axis.legend();axis.grid(alpha=.2)
    fig.tight_layout();fig.savefig(output/'leaf-diagnostics.png',dpi=180);plt.close(fig)
    save(output/'analysis-provenance.json',{'script_sha256':digest(Path(__file__)),'numpy':np.__version__,'scipy':__import__('scipy').__version__,'matplotlib':matplotlib.__version__,'analysis_seed':20261021})
    print(json.dumps({'minimum_holm_p':result['minimum_adjusted_p'],'same_vs_uniform':result['same_vs_uniform']},indent=2),flush=True)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('output',type=Path);parser.add_argument('--analyze-only',action='store_true');args=parser.parse_args()
    output=args.output.resolve()
    if args.analyze_only:analyze(output);return
    if shutil.disk_usage(output.parent).free<2*1024**3:raise SystemExit('need2GiBfree temporary raw trace budget')
    output.mkdir();(output/'bin').mkdir()
    subprocess.run(['cargo','build','--locked','--release','-p','oblivion-store','--example','oram-measure'],cwd=ROOT,check=True)
    binary=output/'bin/oram-measure';shutil.copy2(ROOT/'target/release/examples/oram-measure',binary)
    metadata={'binary_sha256_before_launch':digest(binary),'generator_source_sha256':digest(ROOT/'crates/oblivion-store/examples/measure.rs'),'script_sha256':digest(Path(__file__)),'platform':platform.platform(),'rustc':subprocess.check_output(['rustc','--version','--verbose'],text=True),'operations_per_workload':100000,'trials_per_workload':1,'seed':4242,'geometry':{'blocks':64,'block_bytes':64},'crypto_randomness':'OS generated, freshsession perworkload','started_unix_ns':time.time_ns(),'disk_free_before_bytes':shutil.disk_usage(output.parent).free}
    save(output/'metadata.json',metadata)
    for workload in ('same','uniform'):
        config={'version':1,'blocks':64,'block_bytes':64,'operations':100000,'warmup':1000,'trials':1,'seed':4242,'workload':workload};config_path=output/f'{workload}-config.json';save(config_path,config)
        command=[str(binary),str(config_path),str(output/workload)];before=time.monotonic_ns();result=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=300)
        save(output/f'{workload}-launch.json',{'command':command,'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr,'process_wall_ns':time.monotonic_ns()-before})
        result.check_returncode()
        for path in (output/workload).glob('*-0.jsonl'):
            before_hash=digest(path)
            with path.open('rb') as source,gzip.open(str(path)+'.gz','wb',compresslevel=6) as target:shutil.copyfileobj(source,target,1024*1024)
            with gzip.open(str(path)+'.gz','rb') as source:
                check=hashlib.sha256()
                for block in iter(lambda:source.read(1024*1024),b''):check.update(block)
            assert check.hexdigest()==before_hash
            save(Path(str(path)+'.compression.json'),{'uncompressed_sha256':before_hash,'uncompressed_bytes':path.stat().st_size,'gzip_sha256':digest(Path(str(path)+'.gz')),'verified_decompression_sha256':check.hexdigest()})
            path.unlink()
        print(f'Completed+compressed {workload}:100000actualaccesses',flush=True)
    metadata.update(binary_sha256_after_run=digest(binary),completed_unix_ns=time.time_ns());save(output/'metadata.json',metadata);analyze(output)
if __name__=='__main__':main()
