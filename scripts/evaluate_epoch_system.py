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

PIR_FRAME_HEADER_BYTES=36
PIR_AEAD_TAG_BYTES=16
DEMO_PIR_RECORD_COUNT=5
DEMO_PIR_RECORD_BYTES=160
EXPECTED_DEMO_PIR_APPLICATION_FRAME_BYTES=2*(
    PIR_FRAME_HEADER_BYTES+PIR_AEAD_TAG_BYTES+(DEMO_PIR_RECORD_COUNT+7)//8
    +PIR_FRAME_HEADER_BYTES+PIR_AEAD_TAG_BYTES+DEMO_PIR_RECORD_BYTES
)


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
    real=dummy=real_success=dummy_success=real_cpu=dummy_cpu=failed_cpu=success_cpu=0
    real_success_cpu=real_failed_cpu=dummy_success_cpu=dummy_failed_cpu=0
    functions=set();counters=[0]*p;causes={};per_call_bytes=[];dummy_bytes=[];pir_bytes=[];recorded_storage_events=recorded_storage_bytes=0
    known_statuses={'Success','InvalidInput','OutOfFuel','Trap','Timeout','Resource','Storage'}
    for epoch,slot in sorted(expected):
        key=(epoch,slot);o=public[key];t=truth[key];e=private[key];pub=publication[key];client=client_latency[key]
        validate_observer_row(o)
        require(set(client)=={'version','epoch','slot','client_ready_ns','queue_wait_ns','arrival_to_response_ns'},'private client latency schema')
        is_real=percent==100 or percent==50 and (epoch+slot)%2==0;function=(epoch*p+slot)%5
        require(t['real'] is is_real and t['function']==function,'client truth schedule mismatch')
        require(e['status'] in known_statuses,'unknown engine status')
        flags=[e.get(name,True) for name in ('registry_authenticated','request_authenticated','request_valid')]
        require(all(type(flag) is bool for flag in flags),'private protocol flags')
        if flags[1] and flags[2]:require(e['real'] is is_real and e['function']==function,'valid executor request identity mismatch')
        else:require(e['real'] is False and e['function']==4,'invalid request must use sanitized worker fallback')
        succeeded=e['status']=='Success' and all(flags)
        if 'success' in t:
            require(type(t['success']) is bool and t['success']==succeeded,'client/engine outcome mismatch')
        else:
            require(succeeded,'historical client log cannot certify a retained error')
        require(type(e['pir_queries_completed']) is int and 0<=e['pir_queries_completed']<=2,'PIR completion count')
        framed=e['pir_application_frame_bytes']
        require(framed==EXPECTED_DEMO_PIR_APPLICATION_FRAME_BYTES if e['pir_queries_completed']==2 else framed is None,'PIR accounting oracle')
        if succeeded:require(e['pir_queries_completed']==2,'success without completed PIR')
        count=e.get('storage_events');byte_count=e.get('storage_bytes')
        if count is None or byte_count is None:
            require(succeeded,'retained failure missing per-invocation storage accounting');count=128;byte_count=128*316
        require(type(count) is int and 0<=count<=128 and type(byte_count) is int and byte_count==count*316,'per-invocation storage accounting')
        if succeeded:require(count==128,'successful invocation has incomplete ORAM shape')
        recorded_storage_events+=count;recorded_storage_bytes+=byte_count;pir_bytes.append(framed)
        require(o['request_bytes']==o['response_bytes']==164 and o['batch_count']==p,'envelope shape')
        call_bytes=None if framed is None else 328+framed+byte_count;per_call_bytes.append(call_bytes)
        if not is_real:dummy_bytes.append(call_bytes)
        for field in ('latency_ns','epoch_due_ns','batch_sent_ns','late_by_ns'):
            require(type(o[field]) is int and 0<=o[field]<=10**15,'latency bound')
        for field in ('queue_wait_ns','arrival_to_response_ns','client_ready_ns'):
            require(type(client[field]) is int and 0<=client[field]<=10**15,'private client latency bound')
        require(client['arrival_to_response_ns']==client['queue_wait_ns']+o['latency_ns'],'latency stage identity')
        require(o['epoch_due_ns']==(epoch+1)*cell['epoch_ms']*1_000_000,'epoch cadence metadata')
        cpu=pub['executor_process_cpu_ns'];require(type(cpu) is int and 0<cpu<10**15,'CPU bound')
        if succeeded:success_cpu+=cpu
        else:
            failed_cpu+=cpu;cause=e['status'] if e['status']!='Success' else ('RequestAuthentication' if not flags[1] else ('InvalidRequest' if not flags[2] else 'RegistryAuthentication'))
            causes[cause]=causes.get(cause,0)+1
        if is_real:
            real+=1;real_cpu+=cpu
            if succeeded:
                real_success+=1;real_success_cpu+=cpu;functions.add(function)
                if function==4:counters[slot]+=1
            else:real_failed_cpu+=cpu
        else:
            dummy+=1;dummy_cpu+=cpu
            if succeeded:dummy_success+=1;dummy_success_cpu+=cpu
            else:dummy_failed_cpu+=cpu
    real_failed=real-real_success;dummy_failed=dummy-dummy_success
    if real_failed+dummy_failed:require(summary.get('retains_runtime_errors') is True,'error retention policy missing')
    require(summary['real_invocations']==real and summary['dummy_invocations']==dummy,'client count oracle')
    for name,value in {'successful_real_invocations':real_success,'failed_real_invocations':real_failed,'successful_dummy_invocations':dummy_success,'failed_dummy_invocations':dummy_failed,'offered_invocations':n,'completed_invocations':n}.items():
        if name in summary:require(summary[name]==value,'client outcome accounting')
        else:require(real_failed+dummy_failed==0,'retained failure missing summary outcomes')
    require(summary['functions_verified']==len(functions) and summary['client_state_counters']==counters,'client function/state oracle')
    require(summary['epoch_ms']==cell['epoch_ms'] and summary['epochs']==epochs and summary['participants']==p,'summary schedule')
    require(summary['encrypted_pir_links'] is True and summary['processes']==4,'process topology')
    require(all(row['bytes']==316 and row['direction'] in ('read','write') for row in storage),'ORAM trace entries')
    storage_bytes=sum(row['bytes'] for row in storage)
    require(len(storage)==recorded_storage_events and storage_bytes==recorded_storage_bytes,'ORAM trace/private accounting mismatch')
    def total(values):return None if any(value is None for value in values) else sum(values)
    aggregate=total(per_call_bytes);cpu=real_cpu+dummy_cpu
    return {**cell,'wall_seconds':wall_seconds,'server_measurement_wall_ns':summary['measurement_wall_ns'],'offered_invocations':n,'completed_invocations':n,'real_invocations_offered':real,'dummy_invocations_offered':dummy,'real_successes':real_success,'dummy_successes':dummy_success,'failed_real_invocations':real_failed,'failed_dummy_invocations':dummy_failed,'failure_causes':causes,'functions_verified':sorted(functions),'real_goodput_per_second':real_success/wall_seconds,'all_goodput_per_second':(real_success+dummy_success)/wall_seconds,'completion_rate_per_second':n/wall_seconds,'storage_events':len(storage),'storage_bytes':storage_bytes,'storage_full_shape':len(storage)==n*128,'pir_application_frame_bytes':total(pir_bytes),'envelope_bytes':n*328,'total_application_bytes':aggregate,'dummy_application_bytes':total(dummy_bytes),'application_bytes_per_real_success':aggregate/real_success if aggregate is not None and real_success else None,'executor_process_cpu_ns':cpu,'real_executor_cpu_ns':real_cpu,'dummy_executor_cpu_ns':dummy_cpu,'successful_executor_cpu_ns':success_cpu,'failed_executor_cpu_ns':failed_cpu,'real_success_executor_cpu_ns':real_success_cpu,'real_failed_executor_cpu_ns':real_failed_cpu,'dummy_success_executor_cpu_ns':dummy_success_cpu,'dummy_failed_executor_cpu_ns':dummy_failed_cpu,'executor_cpu_ns_per_real_success':cpu/real_success if real_success else None,'arrival_p50_ns':statistics.median(row['arrival_to_response_ns'] for row in client_latency.values()),'arrival_max_ns':max(row['arrival_to_response_ns'] for row in client_latency.values()),'queue_mean_ns':statistics.mean(row['queue_wait_ns'] for row in client_latency.values()),'forward_mean_ns':statistics.mean(row['latency_ns'] for row in public.values()),'batch_late_max_ns':max(row['late_by_ns'] for row in public.values()),'publication_late_max_ns':max(row['publication_lateness_ns'] for row in publication.values()),'driver_work_overruns':sum(row['driver_work_overrun_ns']>0 for row in publication.values()),'oracle_passed':True}

def estimate(values):
    n=len(values);rng=random.Random(9001);boot=sorted(statistics.mean(rng.choices(values,k=n)) for _ in range(1000));return {'mean':statistics.mean(values),'ci95':[boot[24],boot[974]],'trials':n,'unit':'whole fresh demo process tree'}

def aggregate_cost_ratio(rows,numerator):
    """Ratio of all attempts' cost to all real successes; resample whole trials."""
    n=len(rows);successes=sum(row['real_successes'] for row in rows)
    unknown=sum(row[numerator] is None for row in rows)
    cost=None if unknown else sum(row[numerator] for row in rows)
    point=cost/successes if cost is not None and successes else None
    rng=random.Random(9001);defined=[];zero_denominator=unknown_numerator=0
    for _ in range(1000):
        sample=rng.choices(rows,k=n);denominator=sum(row['real_successes'] for row in sample)
        missing=any(row[numerator] is None for row in sample)
        if denominator==0:zero_denominator+=1
        if missing:unknown_numerator+=1
        if denominator and not missing:defined.append(sum(row[numerator] for row in sample)/denominator)
    defined.sort()
    conditional_ci=[defined[int(.025*(len(defined)-1))],defined[int(.975*(len(defined)-1))]] if defined else None
    return {'estimate':point,'mean':point,'estimand':f'sum({numerator}) / sum(real_successes), including zero-success trials cost',
            'numerator_total':cost,'real_successes_total':successes,'trials':n,'numerator_unknown_trials':unknown,
            'ci95':conditional_ci if len(defined)==1000 else None,'ci95_defined_resamples_only':conditional_ci,
            'bootstrap_resamples':1000,'defined_bootstrap_resamples':len(defined),
            'undefined_denominator_bootstrap_resamples':zero_denominator,'unknown_numerator_bootstrap_resamples':unknown_numerator,
            'ci_scope':'No finite unconditional interval when any resample is undefined; defined-only interval explicitly conditional',
            'unit':'whole fresh demo process tree','mean_alias':'mean aliases ratio-of-sums point estimate, not trial-ratio arithmetic mean'}


def summarize(trials):
    require(bool(trials),'no trials');cells={}
    for row in trials:cells.setdefault((row['participants'],row['epoch_ms'],row['real_percent'],row['epochs']),[]).append(row)
    fields=('wall_seconds','real_goodput_per_second','all_goodput_per_second','total_application_bytes','dummy_application_bytes','application_bytes_per_real_success','real_executor_cpu_ns','dummy_executor_cpu_ns','executor_cpu_ns_per_real_success','arrival_p50_ns','arrival_max_ns','queue_mean_ns','forward_mean_ns','batch_late_max_ns','publication_late_max_ns','driver_work_overruns','offered_invocations','completed_invocations','real_successes','dummy_successes','failed_real_invocations','failed_dummy_invocations','successful_executor_cpu_ns','failed_executor_cpu_ns','real_success_executor_cpu_ns','real_failed_executor_cpu_ns','dummy_success_executor_cpu_ns','dummy_failed_executor_cpu_ns')
    output=[]
    for key,rows in cells.items():
        result={'participants':key[0],'epoch_ms':key[1],'real_percent':key[2],'epochs':key[3],'trials':len(rows),
                'metric_missing_trials':{field:sum(row[field] is None for row in rows) for field in fields},
                **{field:None if any(row[field] is None for row in rows) else estimate([row[field] for row in rows]) for field in fields}}
        result['aggregate_ratio_statistics']={}
        for field,numerator in (('application_bytes_per_real_success','total_application_bytes'),('executor_cpu_ns_per_real_success','executor_process_cpu_ns')):
            stats=aggregate_cost_ratio(rows,numerator);result['aggregate_ratio_statistics'][field]=stats
            result[field]=stats if stats['estimate'] is not None else None
            finite=[row[field] for row in rows if row[field] is not None]
            conditional=estimate(finite) if finite else None
            if conditional is not None:
                conditional.update(estimand='CONDITIONAL mean trial ratio among defined trials; not overall cost',defined_trials=len(finite),undefined_trials=len(rows)-len(finite))
            result['conditional_mean_trial_'+field]=conditional
        output.append(result)
    return output


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
    provenance={'created_before_launch_utc':datetime.now(timezone.utc).isoformat(),'binary_sha256':sha(immutable),'source_sha256':hashes,'config_sha256':sha(config_path),'host':platform.uname()._asdict(),'cpu':Path('/proc/cpuinfo').read_text(),'python':platform.python_version(),'rustc':subprocess.check_output(['rustc','--version'],text=True).strip(),'git_head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'observer_contract':'strict public envelope schema; response Instant captured immediately after pipe read_exact in reader thread, before channel send; client readiness/queue/arrival timing exists only in client-private-latency.jsonl and is joined for performance scoring', 'scheduler':'real monotonic wall schedule, serial closed-loop epoch clients; no independent offered-arrival process','trial_success_semantics':'valid protocol/oracle accounting; masked runtime failures retained separately and never counted as successful guests', 'CPU_scope':'executor ProcessTime from incoming frame until publication; excludes two PIR child CPUs, client process, independent client oracle; includes executor instrumentation and waits/ticker','traffic_scope':'actual envelope/storage event bytes and completed protocol-geometry-derived PIR application frame bytes; excludes TCP/IP/setup'}
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
    (out/'verification.json').write_text(json.dumps({'binary_hash_matches_after_launch':True,'observer_private_timing_separated':True,'response_timestamp_scope':'reader thread immediately after read_exact, before channel handoff','attempted_trials':len(commands),'failed_trials':len(failures),'successful_trials':len(trials),'oracle_passed':not failures and all(row['oracle_passed'] for row in trials),'runtime_failed_invocations':sum(row['failed_real_invocations']+row['failed_dummy_invocations'] for row in trials),'oracle_valid_trials':len(trials),'invocations':sum(row['real_successes']+row['dummy_successes'] for row in trials)},indent=2)+'\n')
    (out/'artifact-sha256.json').write_text(json.dumps({str(path.relative_to(out)):sha(path) for path in out.rglob('*') if path.is_file()},indent=2)+'\n')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--binary',type=Path,required=True);parser.add_argument('--config',type=Path,default=Path('experiments/configs/epoch-system-30.json'));parser.add_argument('--out',type=Path,required=True);args=parser.parse_args();run(args.binary,args.config,args.out)
