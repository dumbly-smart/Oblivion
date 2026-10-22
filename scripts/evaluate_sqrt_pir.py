#!/usr/bin/env python3
"""Freeze and measure actual basic/matrix PIR; raw payloads and local scan costs."""
import argparse
from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ('crates/oblivion-pir/src/lib.rs', 'crates/oblivion-pir/src/sqrt.rs',
           'crates/oblivion-pir/examples/sqrt_measure.rs', 'crates/oblivion-pir/tests/sqrt.rs',
           'scripts/evaluate_sqrt_pir.py', 'research/tests/test_sqrt_pir.py')


def sha(path):
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256')
    return digest.hexdigest()


def dump(path, value):
    path.write_text(json.dumps(value, indent=2)+'\n')


def freeze_binary(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open('rb') as stream, destination.open('xb') as output:
        before = os.fstat(stream.fileno())
        shutil.copyfileobj(stream, output)
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise RuntimeError('binary changed during copy')
    destination.chmod(0o555)
    return destination, sha(destination)


def interval(values):
    values = np.asarray(values, dtype=float)
    rng = np.random.default_rng(20261023)
    sampled = rng.choice(values, (5000, len(values)), replace=True).mean(axis=1)
    return [float(v) for v in np.quantile(sampled, [.025, .975])]


def summarize(rows, trials, queries):
    groups = defaultdict(list)
    for row in rows:
        groups[row['count'], row['record_bytes'], row['mode']].append(row)
    summary, paired, trial_values = [], [], {}
    for (count, width, mode), group in sorted(groups.items()):
        expected = {(trial, step) for trial in range(trials) for step in range(queries)}
        found = [(r['trial'], r['step']) for r in group]
        if len(found) != len(expected) or set(found) != expected:
            raise ValueError('missing or duplicate trial samples')
        item = dict(count=count, record_bytes=width, mode=mode, fresh_state_trials=trials, samples=len(group))
        for key in ('query_payload_bytes', 'response_payload_bytes', 'scan_payload_bytes_per_server'):
            values = {r[key] for r in group}
            if len(values) != 1:
                raise ValueError('nonuniform public shape')
            item[key] = values.pop()
        item['total_payload_bytes'] = item['query_payload_bytes']+item['response_payload_bytes']
        derived = [dict(r, protocol_ns=sum(r[k] for k in ('generation_ns','server1_ns','server2_ns','recovery_ns'))) for r in group]
        for key in ('generation_ns', 'server1_ns', 'server2_ns', 'recovery_ns', 'protocol_ns'):
            values = [float(np.mean([r[key] for r in derived if r['trial'] == trial])) for trial in range(trials)]
            item[key] = float(np.mean(values))
            item[key+'_trial_bootstrap_95'] = interval(values)
            if key == 'protocol_ns':
                trial_values[count, width, mode] = values
        item['protocol_ns_p50'] = float(np.median([r['protocol_ns'] for r in derived]))
        item['protocol_ns_p95'] = float(np.quantile([r['protocol_ns'] for r in derived], .95))
        summary.append(item)
    for count, width in sorted({(r['count'],r['record_bytes']) for r in rows}):
        if (count,width,'xor') not in trial_values or (count,width,'sqrt') not in trial_values:
            raise ValueError('both paired modes required')
        differences = np.asarray(trial_values[count,width,'sqrt'])-trial_values[count,width,'xor']
        paired.append(dict(count=count,record_bytes=width,sqrt_minus_xor_protocol_ns=float(differences.mean()),
                           paired_trial_bootstrap_95=interval(differences)))
    return summary, paired


def plot(summary, output):
    fig, axes = plt.subplots(2, 2, figsize=(11, 7))
    for col, width in enumerate(sorted({r['record_bytes'] for r in summary})):
        for mode in ('xor','sqrt'):
            group = sorted([r for r in summary if r['record_bytes']==width and r['mode']==mode],key=lambda r:r['count'])
            x = [r['count'] for r in group]
            axes[0,col].plot(x,[r['total_payload_bytes'] for r in group],marker='o',label=mode)
            mean = np.asarray([r['protocol_ns']/1e6 for r in group])
            ci = np.asarray([r['protocol_ns_trial_bootstrap_95'] for r in group])/1e6
            axes[1,col].errorbar(x,mean,yerr=np.maximum(0,[mean-ci[:,0],ci[:,1]-mean]),marker='o',capsize=3,label=mode)
        axes[0,col].set(title=f'{width}-byte records',ylabel='Query + answer payload bytes',xscale='log',yscale='log')
        axes[1,col].set(xlabel='Public record count',ylabel='Sequential local protocol time (ms)',xscale='log',yscale='log')
        axes[0,col].legend();axes[1,col].legend()
    fig.suptitle('Actual two-server XOR vs square matrix packing · 30 fresh-state paired trials')
    fig.tight_layout();fig.savefig(output,dpi=170);plt.close(fig)


def run(config_path, output):
    started = time.time()
    before = {p:sha(ROOT/p) for p in SOURCES}
    config_bytes = config_path.read_bytes()
    config = json.loads(config_bytes)
    if config['trials'] != 30 or config['counts'] != [64,1024,10000] or config['record_bytes'] != [8,1024]:
        raise ValueError('recorded sweep requires the six declared geometries and 30 trials')
    subprocess.run(['cargo','build','--release','-p','oblivion-pir','--example','sqrt_measure'],cwd=ROOT,check=True)
    if before != {p:sha(ROOT/p) for p in SOURCES}:
        raise RuntimeError('sources changed during build')
    output.mkdir(parents=True,exist_ok=False)
    (output/'config.json').write_bytes(config_bytes)
    binary, binary_before = freeze_binary(ROOT/'target/release/examples/sqrt_measure',output/'bin'/'sqrt_measure')
    subprocess.run([str(binary),str(output/'config.json'),str(output/'measurement')],cwd=ROOT,check=True)
    rows = [json.loads(line) for line in (output/'measurement'/'private-samples.jsonl').read_text().splitlines()]
    summary, paired = summarize(rows,config['trials'],config['queries_per_trial'])
    diagnostics = [json.loads(line) for line in (output/'measurement'/'query-bit-diagnostics.jsonl').read_text().splitlines()]
    bit_summary = []
    for count in config['counts']:
        for width in config['record_bytes']:
            for mode in ('xor','sqrt'):
                group = [r for r in diagnostics if (r['count'],r['record_bytes'],r['mode'])==(count,width,mode)]
                for target in sorted({r['private_target_index'] for r in group}):
                    target_rows = [r for r in group if r['private_target_index']==target]
                    for server in range(2):
                        for bit in ('ones_first_bit','ones_tail_bit'):
                            rates = [r[bit][server]/r['samples'] for r in target_rows]
                            bit_summary.append(dict(count=count,record_bytes=width,mode=mode,private_target_index=target,server=server,bit=bit,
                                                    one_fraction=float(np.mean(rates)),trial_bootstrap_95=interval(rates)))
    report = {'summary':summary,'paired_latency':paired,'single_server_bit_diagnostics':bit_summary,
              'scope':'Sequential in-process calls to actual two independently owned XOR-PIR server states, fresh each mode/trial; full-record oracle verified for every query. No network framing, transport, authentication, hardware side-channel mitigation or sublinear server-work claim.',
              'privacy':'Each single query is uniform by construction from OsRng shares; column remains client-only. Bit-rate diagnostics are limited empirical sanity checks, not independence tests or security proofs. Joint shares expose the row; with matching data, colluding servers can identify it.',
              'uncertainty':'5000 percentile bootstrap samples of 30 whole fresh-state trial means per geometry/mode; same seeded workload indices paired across modes, randomized mode order; initialization excluded, one warm query per state. The same host and fixed deterministic record contents are reused.',
              'geometry':'r=c=ceil(sqrt(N)); matrix padding zeros. Two query payloads total 2ceil(r/8) bytes, responses 2cB bytes. Full masked scan r*c*B bytes per server. Square layout is not optimized for total bytes when B>1.'}
    dump(output/'report.json',report)
    plot(summary,output/'sqrt-pir.png')
    after = {p:sha(ROOT/p) for p in SOURCES}
    binary_after = sha(binary)
    if before != after or binary_before != binary_after or (output/'config.json').read_bytes()!=config_bytes:
        raise RuntimeError('source, frozen binary or configuration changed during campaign')
    dump(output/'provenance.json',{'command':sys.argv,'git_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                                  'source_sha256_before':before,'source_sha256_after':after,
                                  'binary_sha256_before':binary_before,'binary_sha256_after':binary_after,'binary_snapshot_path':'bin/sqrt_measure',
                                  'config_sha256':sha(output/'config.json'),'python':sys.version,'numpy':np.__version__,'platform':platform.platform(),
                                  'rustc':subprocess.check_output(['rustc','--version'],text=True).strip(),'elapsed_seconds':time.time()-started,
                                  'randomness':'Seeded ChaCha20 workload indices/mode order only; production QueryPair::generate uses OsRng fresh random shares.',
                                  'artifacts_sha256':{str(p.relative_to(output)):sha(p) for p in sorted(output.rglob('*')) if p.is_file() and 'bin' not in p.relative_to(output).parts}})
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--config',type=Path,default=ROOT/'experiments/configs/sqrt-pir-20261023.json')
    parser.add_argument('--output',type=Path,default=ROOT/'experiments/results/sqrt-pir-20261023')
    args=parser.parse_args();run(args.config.resolve(),args.output.resolve())
