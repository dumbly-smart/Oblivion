"""Measured Wasmtime setup/first/warm class sweep; independent child-process trials."""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shutil
import subprocess
import statistics


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validate_trial(trial):
    if not isinstance(trial, dict) or trial.get('schema') != 1 or trial.get('class') not in ('small','medium','small_lowfuel') or trial.get('mode') not in ('control','protected'):
        raise ValueError('trial schema')
    calls=trial.get('calls')
    if not isinstance(calls,list) or len(calls)!=12 or len(trial.get('compile_ns',[]))!=6:
        raise ValueError('trial cardinality')
    seen=set()
    for call in calls:
        if call.get('oracle_passed') is not True or type(call.get('function')) is not int or not 0<=call['function']<=5 or call.get('phase') not in ('first','warm'):
            raise ValueError('call oracle/schema')
        key=(call['function'],call['phase'])
        if key in seen: raise ValueError('duplicate call')
        seen.add(key)
        expected='OutOfFuel' if call['function']==5 or trial['class']=='small_lowfuel' and call['function']!=0 else 'Success'
        if call.get('status')!=expected: raise ValueError('unexpected guest status')
        for field in ('wall_ns','work_ns','total_ns','body_bytes','storage_events'):
            if type(call.get(field)) is not int or not 0<=call[field]<=10**15: raise ValueError('metric bound')
        if trial['mode']=='protected' and (call['body_bytes']!=trial['output_bytes'] or call['storage_events']!=128):
            raise ValueError('protected shape')
    return trial


def estimate(values):
    rng=random.Random(801); n=len(values); samples=sorted(statistics.mean(rng.choices(values,k=n)) for _ in range(1000))
    return {'mean':statistics.mean(values),'ci95':[samples[24],samples[974]],'trials':n,'unit':'independent child process'}


def summarize_trials(trials):
    if not trials: raise ValueError('no trials')
    cells={}
    for trial in trials:
        validate_trial(trial);cells.setdefault((trial['class'],trial['mode']),[]).append(trial)
    result=[]
    for (name,mode),rows in cells.items():
        summary={'class':name,'mode':mode,'trials':len(rows),'engine_ns':estimate([r['engine_ns'] for r in rows]),
                 'compile_ns':estimate([sum(r['compile_ns']) for r in rows]),'cpu_seconds':estimate([r['cpu_user_seconds']+r['cpu_system_seconds'] for r in rows]),
                 'max_rss_kib':estimate([r['max_rss_kib'] for r in rows]),'deadline_misses':sum(c['deadline_missed'] for r in rows for c in r['calls']),'calls':[]}
        for function in range(6):
            for phase in ('first','warm'):
                calls=[next(c for c in r['calls'] if (c['function'],c['phase'])==(function,phase)) for r in rows]
                summary['calls'].append({'function':function,'phase':phase,**{field:estimate([c[field] for c in calls]) for field in ('wall_ns','work_ns','body_bytes','storage_events')},'padding_tail_ns':estimate([max(0,c['total_ns']-c['work_ns']) for c in calls])})
        result.append(summary)
    return result


def plot(result,out):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig,axes=plt.subplots(2,2,figsize=(12,8)); labels=[r['class']+'\n'+r['mode'] for r in result];x=list(range(len(result)))
    for axis,field,title,scale in ((axes[0,0],'engine_ns','New engine creation (ms)',1e6),(axes[0,1],'compile_ns','Six module registrations (ms)',1e6),(axes[1,0],'cpu_seconds','Whole child CPU seconds',1),(axes[1,1],'max_rss_kib','Peak child RSS (MiB)',1024)):
        means=[r[field]['mean']/scale for r in result];errors=[[r[field]['mean']/scale-r[field]['ci95'][0]/scale for r in result],[r[field]['ci95'][1]/scale-r[field]['mean']/scale for r in result]]
        axis.bar(x,means,yerr=errors,capsize=3);axis.set_xticks(x,labels,fontsize=7);axis.set_title(title)
    fig.suptitle('Actual Wasmtime resource classes: 30 fresh processes/cell; bootstrap 95% CI');fig.tight_layout();fig.savefig(out/'resource-classes.png',dpi=140);plt.close(fig)
    fig,axis=plt.subplots(figsize=(11,5))
    for phase in ('first','warm'):
        means=[statistics.mean(c['wall_ns']['mean'] for c in r['calls'] if c['phase']==phase)/1e6 for r in result]
        axis.plot(x,means,marker='o',label=phase+' invocation of each compiled module')
    axis.set_xticks(x,labels);axis.set_yscale('log');axis.set_ylabel('Mean invocation wall time (ms, log)');axis.legend();fig.tight_layout();fig.savefig(out/'first-warm.png',dpi=140);plt.close(fig)


def run(binary,config_path,out):
    if out.exists(): raise ValueError('output exists; preserve historical evidence')
    config=json.loads(config_path.read_text());out.mkdir(parents=True);(out/'bin').mkdir();(out/'sources').mkdir()
    immutable=out/'bin'/'resource_measure';shutil.copyfile(binary,immutable);immutable.chmod(0o555)
    sources=['crates/oblivion-exec/examples/resource_measure.rs','crates/oblivion-exec/src/lib.rs','crates/oblivion-exec/src/host.rs','crates/oblivion-exec/src/staging.rs','crates/oblivion-store/src/lib.rs','crates/oblivion-store/src/backend.rs','scripts/measure_executor_resources.py','research/tests/test_executor_resources.py','Cargo.lock','crates/oblivion-exec/Cargo.toml']+[f'examples/wasm-functions/{name}.wat' for name in ('echo','sum','fibonacci','hash','stateful')]
    hashes={p:sha(p) for p in sources}
    for path in sources:shutil.copyfile(path,out/'sources'/path.replace('/','__'))
    shutil.copyfile(config_path,out/'config.json')
    provenance={'created_before_launch_utc':datetime.now(timezone.utc).isoformat(),'binary_sha256':sha(immutable),'source_sha256':hashes,'config_sha256':sha(config_path),'python':platform.python_version(),'host':platform.uname()._asdict(),'cpu':Path('/proc/cpuinfo').read_text(),'rustc':subprocess.check_output(['rustc','--version'],text=True).strip(),'cargo':subprocess.check_output(['cargo','--version'],text=True).strip(),'git_head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'rss_scope':'Linux wait4 ru_maxrss KiB, each complete child process','cpu_scope':'wait4 floating-second user+system per complete child; engine/compilation/ORAM oracle/serialization included','cold_definition':'new Engine + separately timed module register; page cache not flushed; warm means existing compiled module, fresh instance'}
    (out/'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
    trials=[]; commands=[]
    with gzip.open(out/'raw.jsonl.gz','wt') as raw:
        for name in config['classes']:
            for mode in config['modes']:
                for seed in config['seeds']:
                    command=[str(immutable.resolve()),name,mode,str(seed)]
                    process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                    stdout=process.stdout.read();stderr=process.stderr.read();_,status,usage=os.wait4(process.pid,0);process.returncode=os.waitstatus_to_exitcode(status)
                    commands.append({'class':name,'mode':mode,'seed':seed,'exit':process.returncode,'stderr':stderr.decode()})
                    (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
                    if process.returncode:raise RuntimeError(stderr.decode())
                    trial=json.loads(stdout);trial.update(cpu_user_seconds=usage.ru_utime,cpu_system_seconds=usage.ru_stime,max_rss_kib=usage.ru_maxrss)
                    validate_trial(trial);raw.write(json.dumps(trial)+'\n');raw.flush();trials.append(trial)
    if sha(immutable)!=provenance['binary_sha256']:raise RuntimeError('binary changed')
    result=summarize_trials(trials);(out/'summary.json').write_text(json.dumps(result,indent=2)+'\n');plot(result,out)
    (out/'verification.json').write_text(json.dumps({'binary_hash_matches_after_launch':True,'trials':len(trials),'calls':sum(len(r['calls']) for r in trials),'oracles_passed':True},indent=2)+'\n')
    (out/'artifact-sha256.json').write_text(json.dumps({str(p.relative_to(out)):sha(p) for p in out.rglob('*') if p.is_file()},indent=2)+'\n')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--binary',type=Path,required=True);parser.add_argument('--config',type=Path,default=Path('experiments/configs/executor-resources-30.json'));parser.add_argument('--out',type=Path,required=True);args=parser.parse_args();run(args.binary,args.config,args.out)
