#!/usr/bin/env python3
"""Refit autoscaler attacks and rebuild reports/plots from retained raw streams."""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import math
from pathlib import Path
import sys
import numpy as np
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from research.simulation.run import evaluate, nondominated, plot, privacy_claims
from research.simulation.scaler import Config, DEFAULT_POLICIES, POLICIES, features, trial_interval

RAW_FILES=('config.json','observer.jsonl.gz','private.jsonl.gz','workloads-private.jsonl.gz')
METRICS={'arrivals','completed','dropped','unfinished','instance_seconds','cost','p95','p99','queue_max','queue_mean','slo_violation_rate','cold_starts'}

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def fail(condition,message):
    if not condition:raise ValueError(message)
def rows(path):
    with gzip.open(path,'rt') as source:return [json.loads(line) for line in source]
def number(value,minimum=0,maximum=1e15):return type(value) in (int,float) and math.isfinite(value) and minimum<=value<=maximum

def load_inputs(source):
    raw=json.loads((source/'config.json').read_text())
    fail(isinstance(raw,dict) and set(raw)<={'version','seed','trials','sessions','workloads','simulation','imports','policies','dp_noise_source'},'unsupported config schema')
    fail(raw.get('version')==1 and type(raw.get('trials')) is int and 2<=raw['trials']<=100,'invalid trials/version')
    fail(type(raw.get('sessions')) is int and 8<=raw['sessions']<=64 and raw['sessions']%8==0,'invalid whole-session split')
    fail(type(raw.get('seed')) is int and raw['seed']>=0,'invalid experiment seed')
    fail(isinstance(raw.get('workloads'),list) and raw['workloads'] and all(type(k) is str for k in raw['workloads']) and len(set(raw['workloads']))==len(raw['workloads']) and set(raw['workloads'])<={'uniform','zipf','diurnal','burst'},'invalid workloads')
    fail(not raw.get('imports',[]),'this retained-raw route supports synthetic sessions without imports')
    policies=raw.get('policies',list(DEFAULT_POLICIES))
    fail(isinstance(policies,list) and policies and all(type(p) is str for p in policies) and len(set(policies))==len(policies) and not set(policies)-set(POLICIES) and 'naive' in policies,'invalid policy selection or missing naive positive control')
    fail(raw.get('dp_noise_source','seeded_experiment') in ('seeded_experiment','os_csprng'),'invalid DP noise source')
    cfg=Config(**raw['simulation']);cfg.validate();fail(cfg.functions==2,'binary function-pool experiment required')
    expected={(t,s,w,p) for t in range(raw['trials']) for s in range(raw['sessions']) for w in raw['workloads'] for p in policies}
    expected_truth={key[:3] for key in expected};epochs=math.ceil(cfg.duration/cfg.epoch)
    public={};private={};truth={}
    for row in rows(source/'observer.jsonl.gz'):
        fail(isinstance(row,dict) and set(row)=={'trial','session','workload','policy','rows'},'strict public session schema required')
        key=(row['trial'],row['session'],row['workload'],row['policy'])
        fail(key in expected and key not in public,'duplicate or out-of-range observer session')
        fail(isinstance(row['rows'],list) and len(row['rows'])==epochs,'incomplete observer epochs')
        for epoch,event in enumerate(row['rows']):
            features(event)  # Existing whitelist rejects private/truth fields.
            fail(type(event['epoch']) is int and event['epoch']==epoch,'observer epoch order')
            for field in ['instances','scale_up','scale_down','cold_starts']:
                fail(isinstance(event[field],list) and len(event[field])==cfg.functions and all(type(n) is int and 0<=n<=1000000 for n in event[field]),'invalid observable pool counts')
            fail(all(n<=cfg.maximum for n in event['instances']),'capacity exceeded')
        public[key]=row['rows']
    fail(set(public)==expected,'missing observer trial/session/policy')
    for row in rows(source/'workloads-private.jsonl.gz'):
        fail(isinstance(row,dict) and set(row)=={'trial','session','workload','seed','labels','requests'},'strict workload truth schema required')
        key=(row['trial'],row['session'],row['workload']);fail(key in expected_truth and key not in truth,'duplicate or out-of-range truth session')
        fail(type(row['seed']) is int and row['seed']>=0,'invalid workload seed')
        fail(isinstance(row['labels'],list) and len(row['labels'])==epochs,'incomplete truth epochs')
        for epoch,label in enumerate(row['labels']):
            fail(isinstance(label,dict) and set(label)=={'epoch','intensity','hot','arrivals','rate'},'strict label schema required')
            fail(type(label['epoch']) is int and label['epoch']==epoch,'truth epoch order')
            fail(all(type(label[k]) is int and label[k] in (0,1) for k in ['intensity','hot']),'binary class labels required')
            fail(label['intensity']==(row['session']%4)//2 and label['hot']==row['session']%2,'session class protocol differs')
            fail(type(label['arrivals']) is int and label['arrivals']>=0 and number(label['rate']),'invalid label diagnostics')
        fail(isinstance(row['requests'],list) and len(row['requests'])==sum(x['arrivals'] for x in row['labels']),'workload arrival totals differ')
        for request in row['requests']:
            fail(isinstance(request,dict) and set(request)=={'time','function'} and number(request['time'],0,cfg.duration) and request['time']<cfg.duration and type(request['function']) is int and 0<=request['function']<cfg.functions,'invalid retained workload request')
        fail([r['time'] for r in row['requests']]==sorted(r['time'] for r in row['requests']),'unsorted workload requests')
        truth[key]=row
    fail(set(truth)==expected_truth,'missing workload truth trial/session')
    for row in rows(source/'private.jsonl.gz'):
        fail(isinstance(row,dict) and set(row)=={'trial','session','workload','policy','metrics','requests'},'strict private session schema required')
        key=(row['trial'],row['session'],row['workload'],row['policy']);fail(key in expected and key not in private,'duplicate or out-of-range private session')
        validate_metrics(row,truth[key[:3]],public[key],cfg)
        private[key]=row['metrics']
    fail(set(private)==expected,'missing private trial/session/policy')
    return raw,cfg,public,private,truth

def validate_metrics(row,truth,observer,cfg):
    records=row['requests'];metrics=row['metrics']
    fail(isinstance(metrics,dict) and set(metrics)==METRICS and isinstance(records,list),'invalid private metrics/requests')
    fail(len(records)==len(truth['requests']),'private/workload arrival count differs')
    for request,submitted in zip(records,truth['requests']):
        fail(isinstance(request,dict) and set(request)=={'arrived','function','dropped','started','finished'},'invalid lifecycle schema')
        fail(request['arrived']==submitted['time'] and request['function']==submitted['function'] and type(request['dropped']) is bool,'private/workload identity mismatch')
        for key in ['started','finished']:
            fail(request[key] is None or number(request[key],request['arrived'],cfg.duration),'invalid lifecycle timestamp')
        fail(not request['dropped'] or request['started'] is None and request['finished'] is None,'dropped request executed')
        fail(request['finished'] is None or request['started'] is not None and math.isclose(request['finished']-request['started'],cfg.service,rel_tol=1e-10,abs_tol=1e-10),'invalid service duration')
    latencies=[r['finished']-r['arrived'] for r in records if r['finished'] is not None]
    dropped=sum(r['dropped'] for r in records);unfinished=sum(not r['dropped'] and r['finished'] is None for r in records)
    waiting=sum((cfg.duration if r['started'] is None else r['started'])-r['arrived'] for r in records if not r['dropped'])/cfg.duration
    recomputed=dict(arrivals=len(records),completed=len(latencies),dropped=dropped,unfinished=unfinished,
        p95=float(np.percentile(latencies,95)) if latencies else None,p99=float(np.percentile(latencies,99)) if latencies else None,
        slo_violation_rate=(dropped+unfinished+sum(t>cfg.slo for t in latencies))/len(records) if records else 0.,
        cold_starts=sum(sum(o['cold_starts']) for o in observer),queue_mean=waiting)
    for name,expected in recomputed.items():
        actual=metrics[name]
        fail(actual is None if expected is None else number(actual) and math.isclose(actual,expected,rel_tol=1e-9,abs_tol=1e-9),f'raw metric disagrees with lifecycle/observer: {name}')
    for name in ['arrivals','completed','dropped','unfinished','queue_max','cold_starts']:
        fail(type(metrics[name]) is int and metrics[name]>=0,'invalid raw count')
    fail(number(metrics['instance_seconds'],0,cfg.duration*cfg.functions*cfg.maximum),'invalid instance-seconds counter')
    fail(number(metrics['cost']) and math.isclose(metrics['cost'],metrics['instance_seconds']*cfg.price_per_instance_second,rel_tol=1e-12,abs_tol=1e-12),'raw cost differs from stated price')
    fail(number(metrics['queue_mean'],0,metrics['queue_max']+1e-9),'queue mean exceeds maximum')
    # Preserve original raw counter precision after independent lifecycle checks.
    # Exact instance-seconds/queue-max require worker identities/event accounting,
    # which are recorded as per-session counters, not fully recoverable publicly.

def rebuild(raw,public,private,truth):
    trial_results=[]
    for trial in range(raw['trials']):
        for workload in raw['workloads']:
            for policy in raw.get('policies',DEFAULT_POLICIES):
                samples=[dict(observer=public[trial,session,workload,policy],labels=truth[trial,session,workload]['labels'],metrics=private[trial,session,workload,policy]) for session in range(raw['sessions'])]
                split=raw['sessions']//2
                for task in ['intensity']+([] if workload=='uniform' else ['hot']):
                    metrics=evaluate(samples[:split],samples[split:],task)
                    targets=[s['metrics'] for s in samples[split:]]
                    for key in targets[0]:
                        values=[m[key] for m in targets if m[key] is not None];metrics[key]=float(np.mean(values)) if values else None
                    trial_results.append(dict(trial=trial,workload=workload,policy=policy,task=task,**metrics))
    summary=[]
    for workload in raw['workloads']:
        for task in ['intensity']+([] if workload=='uniform' else ['hot']):
            points=[]
            for policy in raw.get('policies',DEFAULT_POLICIES):
                group=[r for r in trial_results if (r['workload'],r['task'],r['policy'])==(workload,task,policy)]
                point=dict(workload=workload,task=task,policy=policy,independent_trials=len(group))
                for key in group[0]:
                    if key not in ('trial','workload','task','policy'):
                        values=[r[key] for r in group if r[key] is not None];point[key]=float(np.mean(values)) if values else None
                for key in ('balanced_accuracy','accuracy','instance_seconds','p99','slo_violation_rate'):
                    point[key+'_ci95']=trial_interval([[r[key]] for r in group]) if all(r[key] is not None for r in group) else None
                points.append(point)
            for point,member in zip(points,nondominated(points,('instance_seconds','p99','balanced_accuracy'))):
                point['pareto_three_axes']=member;point['meets_slo_violation_1percent']=point['slo_violation_rate']<=.01
            eligible=[p for p in points if p['meets_slo_violation_1percent']];front=nondominated(eligible,('instance_seconds','balanced_accuracy'))
            for point in points:point['pareto_cost_leakage_slo']=next((member for p,member in zip(eligible,front) if p is point),False)
            summary.extend(points)
    positive=[dict(workload=p['workload'],task=p['task'],balanced_accuracy=p['balanced_accuracy'],passed=p['balanced_accuracy']>.6) for p in summary if p['policy']=='naive']
    cfg=Config(**raw['simulation'])
    policies=raw.get('policies',DEFAULT_POLICIES)
    return dict(config=raw,summary=summary,trial_metrics=trial_results,positive_controls=positive,
        imported_runs=[],privacy_claims=privacy_claims(cfg,policies,raw.get('dp_noise_source','seeded_experiment')),
        methodology='Known-policy diagonal nearest-centroid profiler fitted on first-half whole sessions and tested on disjoint second-half sessions. Equal-weight independent-trial bootstrap with 5,000 resamples. Public function-pool identities are visible; target labels are used only for scoring.',
        limitations=(
            'Synthetic function-affine simulator, not a deployed scheduler. The optional dp_laplace sampler has a conditional approximate-DP bound only under independent hidden uniform bits for its fixed-horizon observer; the recorded deterministic-seed experiment itself has no DP guarantee. No user-level or complete-runtime privacy guarantee. Exact cost/queue counters use retained private session metrics; public observer excludes those fields.'
            if raw.get('dp_noise_source','seeded_experiment') == 'seeded_experiment' else
            'Synthetic function-affine simulator, not a deployed scheduler. The optional dp_laplace sampler has a conditional approximate-DP bound under independent OS-CSPRNG bits for its fixed-horizon observer; the mechanism has not received an independent code audit. No user-level or complete-runtime privacy guarantee. Exact cost/queue counters use retained private session metrics; public observer excludes those fields. CSPRNG outputs are not reproducible from the public experiment seed.'))

def regenerate(source,output):
    source=Path(source).resolve();output=Path(output).resolve()
    if output.exists():raise FileExistsError('choose a fresh analysis output directory')
    inputs={name:sha(source/name) for name in RAW_FILES}
    raw,cfg,public,private,truth=load_inputs(source)
    report=rebuild(raw,public,private,truth)
    if inputs!={name:sha(source/name) for name in RAW_FILES}:raise ValueError('retained raw inputs changed during analysis')
    report['provenance']=dict(created_before_output_utc=datetime.now(timezone.utc).isoformat(),raw_source=str(source),raw_sha256=inputs,
        analysis_source_sha256={name:sha(ROOT/name) for name in ['scripts/regenerate_scaler.py','research/simulation/run.py','research/simulation/scaler.py']},
        public_sessions=len(public),private_sessions=len(private),workload_sessions=len(truth),read_cached_report=False,ran_simulator=False)
    report['methodology']='Existing known-policy diagonal nearest-centroid fit on first-half whole profiling sessions; second-half target predictions scored afterward. Refit every independent trial from retained public rows/private labels. Equal-weight trial bootstrap,5000resamples. Per-session raw performance counters aggregate only held-out sessions, with lifecycle/price consistency checks; no new workload generation or simulation.'
    report['limitations']=(
        'Synthetic function-affine model, not a deployment. Exact instance-seconds and queue maximum use recorded private session counters; incomplete worker identities prevent reconstructing those counters from public snapshots alone. Horizon-censored/dropped requests count as SLO failures. Point-estimate Pareto/SLO flags; hypothetical configured instance-second price. The deterministic seeded artifact has no DP guarantee; the optional dp_laplace sampler has a conditional approximate-DP bound for its fixed-horizon observer under independent hidden uniform bits. No user-level or full-runtime guarantee. Supports recorded synthetic-session campaigns without imported traces.'
        if raw.get('dp_noise_source','seeded_experiment') == 'seeded_experiment' else
        'Synthetic function-affine model, not a deployment. Exact instance-seconds and queue maximum use recorded private session counters; incomplete worker identities prevent reconstructing those counters from public snapshots alone. Horizon-censored/dropped requests count as SLO failures. Point-estimate Pareto/SLO flags; hypothetical configured instance-second price. The optional dp_laplace sampler has a conditional approximate-DP bound under independent OS-CSPRNG bits for its fixed-horizon observer; it has no independent code audit. No user-level or full-runtime guarantee. Supports recorded synthetic-session campaigns without imported traces; CSPRNG outputs are not reproducible from the public experiment seed.')
    output.mkdir(parents=True)
    (output/'config.json').write_text(json.dumps(raw,indent=2)+'\n');(output/'report.json').write_text(json.dumps(report,indent=2)+'\n');plot(output)
    manifest={p.name:sha(p) for p in output.iterdir() if p.is_file()};(output/'artifact-sha256.json').write_text(json.dumps(manifest,indent=2)+'\n')
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('raw_source',type=Path);parser.add_argument('new_output',type=Path);args=parser.parse_args();report=regenerate(args.raw_source,args.new_output);print(f'Rebuilt {len(report["trial_metrics"])} trial/task/policy results and {len(report["summary"])} summaries from raw sessions')
