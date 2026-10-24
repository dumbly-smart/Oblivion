"""Bounded real-process epoch/participant/real-load evaluation; no overload model."""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import platform
import random
import shutil
import statistics
import subprocess
import tempfile
import time


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def jsonl(path):return [json.loads(line) for line in path.read_text().splitlines()]

def require(condition,message):
    if not condition:raise ValueError(message)

def validate_observer_row(row):
    allowed={'version','epoch','slot','observer','request_bytes','response_bytes','batch_count','latency_ns','epoch_due_ns','batch_sent_ns','late_by_ns'}
    require(isinstance(row,dict) and set(row)==allowed,'observer schema contains private or unknown fields')

def analyze_trial(path,cell,wall_seconds):
    p=cell['participants'];epochs=cell['epochs'];n=p*epochs;percent=cell['real_percent']
    require(type(wall_seconds) in (int,float) and 0<wall_seconds<3600,'wall bound')
    config=json.loads((path/'metadata.json').read_text())['configuration'];summary=json.loads((path/'client-summary.json').read_text())
    for key in ('participants','epoch_ms','epochs','real_percent'):require(config[key]==cell[key],'metadata mismatch')
    require(config['mixed_functions'] is True and config['class_ms']==100,'class/mixed configuration')
    public=jsonl(path/'envelope-observer.jsonl');truth=jsonl(path/'client-ground-truth.jsonl');private=jsonl(path/'executor-private.jsonl');publication=jsonl(path/'publication-private.jsonl');client_latency=jsonl(path/'client-private-latency.jsonl');storage=jsonl(path/'storage-observer.jsonl')
    require(all(len(rows)==n for rows in (public,truth,private,publication,client_latency)),'trial cardinality')
    expected={(epoch,slot) for epoch in range(epochs) for slot in range(p)}
    def index(rows):
        keyed={(row['epoch'],row['slot']):row for row in rows};require(len(keyed)==len(rows) and set(keyed)==expected,'epoch/slot coverage');return keyed
    public,truth,private,publication,client_latency=map(index,(public,truth,private,publication,client_latency))
    real=dummy=real_cpu=dummy_cpu=0;functions=set();counters=[0]*p
    for epoch,slot in sorted(expected):
        key=(epoch,slot);o=public[key];t=truth[key];e=private[key];pub=publication[key];client=client_latency[key]
        validate_observer_row(o)
        require(set(client)=={'version','epoch','slot','client_ready_ns','queue_wait_ns','arrival_to_response_ns'},'private client latency schema')
        is_real=percent==100 or percent==50 and (epoch+slot)%2==0;function=(epoch*p+slot)%5
        require(t['real'] is is_real and e['real'] is is_real and t['function']==e['function']==function,'truth schedule mismatch')
        require(e['status']=='Success' and e['pir_queries_completed']==2 and e['pir_application_frame_bytes']==466,'executor/PIR completion oracle')
        require(o['request_bytes']==o['response_bytes']==164 and o['batch_count']==p,'envelope shape')
        for field in ('latency_ns','epoch_due_ns','batch_sent_ns','late_by_ns'):
            require(type(o[field]) is int and 0<=o[field]<=10**15,'latency bound')
        for field in ('queue_wait_ns','arrival_to_response_ns','client_ready_ns'):
            require(type(client[field]) is int and 0<=client[field]<=10**15,'private client latency bound')
        require(client['arrival_to_response_ns']==client['queue_wait_ns']+o['latency_ns'],'latency stage identity')
        require(o['epoch_due_ns']==(epoch+1)*cell['epoch_ms']*1_000_000,'epoch cadence metadata')
        cpu=pub['executor_process_cpu_ns'];require(type(cpu) is int and 0<cpu<10**15,'CPU bound')
        if is_real:
            real+=1;real_cpu+=cpu;functions.add(function)
            if function==4:counters[slot]+=1
        else:dummy+=1;dummy_cpu+=cpu
    require(summary['real_invocations']==real and summary['dummy_invocations']==dummy,'client count oracle')
    require(summary['functions_verified']==len(functions) and summary['client_state_counters']==counters,'client function/state oracle')
    require(summary['epoch_ms']==cell['epoch_ms'] and summary['epochs']==epochs and summary['participants']==p,'summary schedule')
    require(summary['encrypted_pir_links'] is True and summary['processes']==4,'process topology')
    require(len(storage)==n*128 and all(row['bytes']==316 and row['direction'] in ('read','write') for row in storage),'ORAM trace shape')
    storage_bytes=sum(row['bytes'] for row in storage);pir_bytes=sum(row['pir_application_frame_bytes'] for row in private.values());envelope_bytes=sum(row['request_bytes']+row['response_bytes'] for row in public.values());total=storage_bytes+pir_bytes+envelope_bytes
    return {**cell,'wall_seconds':wall_seconds,'server_measurement_wall_ns':summary['measurement_wall_ns'],'real_successes':real,'dummy_successes':dummy,'functions_verified':sorted(functions),'real_goodput_per_second':real/wall_seconds,'all_goodput_per_second':n/wall_seconds,'storage_events':len(storage),'storage_bytes':storage_bytes,'pir_application_frame_bytes':pir_bytes,'envelope_bytes':envelope_bytes,'total_application_bytes':total,'dummy_application_bytes':total*dummy//n,'application_bytes_per_real_success':total/real if real else None,'executor_process_cpu_ns':real_cpu+dummy_cpu,'real_executor_cpu_ns':real_cpu,'dummy_executor_cpu_ns':dummy_cpu,'executor_cpu_ns_per_real_success':(real_cpu+dummy_cpu)/real if real else None,'arrival_p50_ns':statistics.median(row['arrival_to_response_ns'] for row in client_latency.values()),'arrival_max_ns':max(row['arrival_to_response_ns'] for row in client_latency.values()),'queue_mean_ns':statistics.mean(row['queue_wait_ns'] for row in client_latency.values()),'forward_mean_ns':statistics.mean(row['latency_ns'] for row in public.values()),'batch_late_max_ns':max(row['late_by_ns'] for row in public.values()),'publication_late_max_ns':max(row['publication_lateness_ns'] for row in publication.values()),'driver_work_overruns':sum(row['driver_work_overrun_ns']>0 for row in publication.values()),'oracle_passed':True}

def estimate(values):
    n=len(values);rng=random.Random(9001);boot=sorted(statistics.mean(rng.choices(values,k=n)) for _ in range(1000));return {'mean':statistics.mean(values),'ci95':[boot[24],boot[974]],'trials':n,'unit':'whole fresh demo process tree'}

def summarize(trials):
    require(bool(trials),'no trials');cells={}
    for row in trials:cells.setdefault((row['participants'],row['epoch_ms'],row['real_percent'],row['epochs']),[]).append(row)
    fields=('wall_seconds','real_goodput_per_second','all_goodput_per_second','total_application_bytes','dummy_application_bytes','application_bytes_per_real_success','real_executor_cpu_ns','dummy_executor_cpu_ns','executor_cpu_ns_per_real_success','arrival_p50_ns','arrival_max_ns','queue_mean_ns','forward_mean_ns','batch_late_max_ns','publication_late_max_ns','driver_work_overruns')
    return [{'participants':key[0],'epoch_ms':key[1],'real_percent':key[2],'epochs':key[3],'trials':len(rows),**{field:None if rows[0][field] is None else estimate([row[field] for row in rows]) for field in fields}} for key,rows in cells.items()]

def plot(rows,out):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig,axes=plt.subplots(1,2,figsize=(12,5))
    for p in (1,2):
        for period in (200,400):
            subset=[r for r in rows if r['participants']==p and r['epoch_ms']==period];x=[r['real_percent'] for r in subset]
            for axis,field,scale in ((axes[0],'arrival_p50_ns',1e6),(axes[1],'real_goodput_per_second',1)):
                y=[r[field]['mean']/scale for r in subset];err=[[r[field]['mean']/scale-r[field]['ci95'][0]/scale for r in subset],[r[field]['ci95'][1]/scale-r[field]['mean']/scale for r in subset]];axis.errorbar(x,y,yerr=err,marker='o',capsize=3,label=f'P={p}, E={period}ms')
    axes[0].set_ylabel('Trial median ready→authenticated response (ms)');axes[1].set_ylabel('Real successes / full process-tree wall second')
    for axis in axes:axis.set_xlabel('Real load (%)');axis.legend(fontsize=8)
    fig.tight_layout();fig.savefig(out/'epoch-system.png',dpi=140);plt.close(fig)

def run(binary,config_path,out):
    require(not out.exists(),'preserve existing output');config=json.loads(config_path.read_text());
    require(config.get('participants')==[1,2] and config.get('epoch_ms')==[200,400] and config.get('real_percent')==[0,50,100] and type(config.get('epochs')) is int and 1<=config['epochs']<=128 and type(config.get('trials')) is int and 1<=config['trials']<=1000,'bounded sweep configuration');out.mkdir(parents=True);(out/'raw').mkdir();(out/'bin').mkdir();(out/'sources').mkdir()
    immutable=out/'bin'/'oblivion-server';shutil.copyfile(binary,immutable);immutable.chmod(0o555)
    files=sorted(p for p in Path('crates').rglob('*') if p.is_file())+[Path('Cargo.lock'),Path('Cargo.toml'),Path('scripts/evaluate_epoch_system.py'),Path('research/tests/test_epoch_system.py')]
    hashes={str(path):sha(path) for path in files}
    for path in files:shutil.copyfile(path,out/'sources'/str(path).replace('/','__'))
    shutil.copyfile(config_path,out/'config.json')
    provenance={'created_before_launch_utc':datetime.now(timezone.utc).isoformat(),'binary_sha256':sha(immutable),'source_sha256':hashes,'config_sha256':sha(config_path),'host':platform.uname()._asdict(),'cpu':Path('/proc/cpuinfo').read_text(),'python':platform.python_version(),'rustc':subprocess.check_output(['rustc','--version'],text=True).strip(),'git_head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'observer_contract':'strict public envelope schema; response Instant captured immediately after pipe read_exact in reader thread, before channel send; client readiness/queue/arrival timing exists only in client-private-latency.jsonl and is joined for performance scoring', 'scheduler':'real monotonic wall schedule, serial closed-loop epoch clients; no independent offered-arrival process','CPU_scope':'executor ProcessTime from incoming frame until publication; excludes two PIR child CPUs, client process, independent client oracle; includes executor instrumentation and waits/ticker','traffic_scope':'actual envelope/storage event bytes and completed protocol-geometry-derived PIR application frame bytes; excludes TCP/IP/setup'}
    (out/'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n');trials=[];commands=[];failures=[]
    for p in config['participants']:
        for period in config['epoch_ms']:
            for real in config['real_percent']:
                cell={'participants':p,'epoch_ms':period,'real_percent':real,'epochs':config['epochs']}
                for trial in range(config['trials']):
                    name=f'p{p}-e{period}-r{real}-t{trial:02}';destination=out/'raw'/name;destination.mkdir()
                    with tempfile.TemporaryDirectory() as directory:
                        path=Path(directory)/'trial';command=[str(immutable.resolve()),'demo-sweep',str(path),str(real),str(p),str(period),str(config['epochs']),'mixed'];started=time.monotonic();completed=subprocess.run(command,capture_output=True,text=True);wall=time.monotonic()-started
                        command_result={'cell':cell,'trial':trial,'exit':completed.returncode,'stdout':completed.stdout,'stderr':completed.stderr,'wall_seconds':wall};commands.append(command_result);(out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
                        # Preserve even failed/partial output before reporting an error.
                        if path.exists():
                            for source in path.iterdir():
                                if source.is_file():
                                    with source.open('rb') as inp,gzip.open(destination/(source.name+'.gz'),'wb') as dest:shutil.copyfileobj(inp,dest)
                        try:
                            require(completed.returncode==0,f'failed trial {name}: {completed.stderr}')
                            row=analyze_trial(path,cell,wall)
                        except (ValueError,KeyError,TypeError,FileNotFoundError) as error:
                            failures.append({'cell':cell,'trial':trial,'error':str(error)})
                            (out/'failed-trials.json').write_text(json.dumps(failures,indent=2)+'\n')
                            continue
                        row['trial']=trial;trials.append(row)
                        (out/'trial-metrics.json').write_text(json.dumps(trials,indent=2)+'\n')
    require(sha(immutable)==provenance['binary_sha256'],'binary changed');require(len(commands)==12*config['trials'] and len(trials)+len(failures)==len(commands),'expected trial set');rows=summarize(trials);
    for row in rows:
        row['attempted_trials']=config['trials'];row['failed_trials']=sum(item['cell']['participants']==row['participants'] and item['cell']['epoch_ms']==row['epoch_ms'] and item['cell']['real_percent']==row['real_percent'] for item in failures)
    (out/'summary.json').write_text(json.dumps(rows,indent=2)+'\n');plot(rows,out)
    (out/'verification.json').write_text(json.dumps({'binary_hash_matches_after_launch':True,'observer_private_timing_separated':True,'response_timestamp_scope':'reader thread immediately after read_exact, before channel handoff','attempted_trials':len(commands),'failed_trials':len(failures),'successful_trials':len(trials),'oracle_passed':not failures and all(row['oracle_passed'] for row in trials),'invocations':sum(row['real_successes']+row['dummy_successes'] for row in trials)},indent=2)+'\n')
    (out/'artifact-sha256.json').write_text(json.dumps({str(path.relative_to(out)):sha(path) for path in out.rglob('*') if path.is_file()},indent=2)+'\n')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--binary',type=Path,required=True);parser.add_argument('--config',type=Path,default=Path('experiments/configs/epoch-system-30.json'));parser.add_argument('--out',type=Path,required=True);args=parser.parse_args();run(args.binary,args.config,args.out)
