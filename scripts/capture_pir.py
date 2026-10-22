#!/usr/bin/env python3
"""Capture only two dynamically owned loopback PIR ports, with honest fallback."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import queue
import re
import selectors
import shutil
import signal
import subprocess
import sys
import threading
import time
ROOT=Path(__file__).resolve().parents[1]
FIELDS=['frame.time_epoch','frame.len','ip.src','ip.dst','tcp.srcport','tcp.dstport','tcp.stream','tcp.len','tcp.flags','tcp.analysis.retransmission']

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def lines(path):return [json.loads(line) for line in path.read_text().splitlines()]
def next_line(stream,timeout=5):
    selector=selectors.DefaultSelector();selector.register(stream,selectors.EVENT_READ)
    ready=selector.select(timeout);selector.close()
    if not ready:raise TimeoutError('driver readiness timeout')
    line=stream.readline()
    if not line:raise RuntimeError('driver exited before readiness')
    return line

def decode_capture(path):
    command=['tshark','-r',str(path),'-T','fields','-E','separator=\t','-E','occurrence=f']
    for field in FIELDS:command+=['-e',field]
    result=subprocess.run(command,capture_output=True,text=True,check=True)
    packets=[]
    for line in result.stdout.splitlines():
        values=line.split('\t');values+=['']*(len(FIELDS)-len(values));row=dict(zip(FIELDS,values))
        row.update(time_unix_ns=int(round(float(row['frame.time_epoch'])*1e9)),frame_bytes=int(row['frame.len']),payload_bytes=int(row['tcp.len'] or 0),source_port=int(row['tcp.srcport']),destination_port=int(row['tcp.dstport']),stream=int(row['tcp.stream']),retransmission=bool(row['tcp.analysis.retransmission']))
        packets.append(row)
    return packets,{'command':command,'stderr':result.stderr}

def capture_statistics(log):
    """Require explicit zero drops, including every dumpcap component counter."""
    summaries=[line for line in log if 'Packets received/dropped on interface' in line]
    if len(summaries)!=1:raise ValueError('capture must report exactly one interface drop summary')
    match=re.search(r": (\d+)/(\d+) \(pcap:(\d+)/dumpcap:(\d+)/flushed:(\d+)/ps_ifdrop:(\d+)\)",summaries[0])
    if match is None:raise ValueError('unrecognized capture drop summary')
    received,dropped,pcap,dumpcap,flushed,ps_ifdrop=map(int,match.groups())
    if any((dropped,pcap,dumpcap,flushed,ps_ifdrop)):raise ValueError('capture reports dropped packets')
    return dict(received=received,dropped=dropped,pcap=pcap,dumpcap=dumpcap,flushed=flushed,ps_ifdrop=ps_ifdrop)

def validate_owned_packets(packets,ports):
    if len(set(ports))!=2 or any(type(port) is not int or not 0<port<65536 for port in ports):
        raise ValueError('expected exactly two distinct owned TCP ports')
    for row in packets:
        if row['ip.src']!='127.0.0.1' or row['ip.dst']!='127.0.0.1' or not (row['source_port'] in ports or row['destination_port'] in ports):
            raise ValueError('packet outside exact owned loopback ports')

def aggregate(output):
    launches=json.loads((output/'launches.json').read_text());sessions=[];stream_rows=[]
    for launch in launches:
        path=output/f"trial-{launch['trial']:03}";truth=lines(path/'client-ground-truth.jsonl');frames=lines(path/'application-frames.jsonl')
        assert len(truth)==len(frames)==launch['queries'] and all(row['verified'] and row['query_frame_bytes']==53 and row['answer_frame_bytes']==180 for row in frames)
        stats=capture_statistics(launch['capture_log']) if launch['capture_ok'] else None
        session={'trial':launch['trial'],'verified_queries':len(truth),'captured':launch['capture_ok'],'packets':0,'capture_interface_stats':stats}
        if launch['capture_ok']:
            packets=lines(path/'packet-observer.jsonl');ports=launch['ready']['ports'];validate_owned_packets(packets,ports)
            session.update(packets=len(packets),packet_lengths=sorted({row['frame_bytes'] for row in packets}),payload_lengths=sorted({row['payload_bytes'] for row in packets}),retransmissions=sum(row['retransmission'] for row in packets))
            streams={}
            for row in packets:streams.setdefault(row['stream'],[]).append(row)
            checked=0
            for server,port in enumerate(ports):
                for stream,group in streams.items():
                    if not any(row['source_port']==port or row['destination_port']==port for row in group):continue
                    queries=[row for row in group if row['destination_port']==port and row['payload_bytes']>0 and not row['retransmission']]
                    answers=[row for row in group if row['source_port']==port and row['payload_bytes']>0 and not row['retransmission']]
                    if not queries or not answers:raise ValueError('capture has incomplete application stream')
                    assert sum(row['payload_bytes'] for row in queries)==53 and sum(row['payload_bytes'] for row in answers)==180
                    first=min(row['time_unix_ns'] for row in queries)
                    matches=[row for row in truth if row['started_unix_ns']<=first<=row['finished_unix_ns']]
                    if len(matches)!=1:raise ValueError('packet first-data timestamp must belong to one exact private query interval')
                    ground=matches[0];checked+=1
                    stream_rows.append({'trial':launch['trial'],'server':server,'step':ground['step'],'packet_count':len(group),'wire_bytes':sum(row['frame_bytes'] for row in group),'query_payload_packets':len(queries),'answer_payload_packets':len(answers),'query_to_answer_ms':(max(row['time_unix_ns'] for row in answers)-first)/1e6})
            assert checked==len(truth)*2
            for server in (0,1):
                assigned=[row['step'] for row in stream_rows if row['trial']==launch['trial'] and row['server']==server]
                assert sorted(assigned)==list(range(len(truth))), 'each per-server query needs exactly one packet stream'

            session['verified_streams']=checked
            if stats['received']!=len(packets):raise ValueError('capture received count differs from decoded packet count')
        sessions.append(session)
    capture_count=sum(row['captured'] for row in sessions)
    report={'analysis_script_sha256':sha(Path(__file__)),'sessions':sessions,'trials':len(sessions),'captured_trials':capture_count,'verified_queries':sum(row['verified_queries'] for row in sessions),'scope':'only exact two owned dynamic loopback TCP ports per trial; key provisioning over private inherited pipes never captured','application_frames':{'query_bytes':53,'answer_bytes':180},'limitations':'Loopback capture includes TCP handshake/ACK/FIN, segmentation, kernel timing, offload and capture effects. Frame sizes are not application payload sizes. No external-network measurement, TEE, independent operators, cryptographic proof or active-attack availability claim. Application frame logs remain separate from genuine packet evidence. Packet-to-ground-truth matching uses same-host wall clocks only for evaluator labeling, not attack features.'}
    report['analysis_kind']='structural packet diagnostics; no inference attack or privacy acceptance test'
    report['total_packets']=sum(row['packets'] for row in sessions)
    report['verified_streams']=sum(row.get('verified_streams',0) for row in sessions)
    report['inference_attack_acceptance']='excluded: former packet centroid classifier lacked a validated positive control and has been removed; historical exploratory output is preserved separately'
    if stream_rows:
        with (output/'structural-streams.jsonl').open('w') as file:
            for row in stream_rows:file.write(json.dumps(row)+'\n')
    else:report['capture_limitation']='No actual packets captured; capture permission/tool failures recorded verbatim. Application frames are not packet evidence.'
    save(output/'structural-diagnostics.json',report)
    print(json.dumps({'trials':len(sessions),'captured_trials':capture_count,'verified_queries':report['verified_queries'],'packets':report['total_packets'],'verified_streams':report['verified_streams']},indent=2),flush=True)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('output',type=Path);parser.add_argument('--trials',type=int,default=30);parser.add_argument('--queries',type=int,default=100);parser.add_argument('--analyze-only',action='store_true');args=parser.parse_args();output=args.output.resolve()
    if args.analyze_only:aggregate(output);return
    if not 1<=args.trials<=30 or not 10<=args.queries<=10000 or args.queries%5:raise SystemExit('trials1..30;queries10..10000divisibleby5')
    output.mkdir();(output/'bin').mkdir();subprocess.run(['cargo','build','--locked','--release','-p','oblivion-pir','--example','capture_driver'],cwd=ROOT,check=True)
    binary=output/'bin/capture_driver';shutil.copy2(ROOT/'target/release/examples/capture_driver',binary)
    metadata={'binary_sha256_before_launch':sha(binary),'driver_source_sha256':sha(ROOT/'crates/oblivion-pir/examples/capture_driver.rs'),'script_sha256':sha(Path(__file__)),'platform':platform.platform(),'trials':args.trials,'queries_per_trial':args.queries,'workload_seed':20261021,'crypto_randomness':'freshOSrootperworkerpertrial; sharesOSrandom','capture_tool':shutil.which('dumpcap'),'decode_tool':shutil.which('tshark'),'started_unix_ns':time.time_ns(),'capture_policy':'exactdynamicowned127.0.0.1ports only; no privilege change or unrelated traffic','invocation':sys.argv,'source_hash_recording':'after build, before any workload launch; not a hermetic build snapshot','source_files_sha256_before_launch':{str(path.relative_to(ROOT)):sha(path) for path in [ROOT/'Cargo.toml',ROOT/'Cargo.lock',ROOT/'crates/oblivion-pir/Cargo.toml',*sorted((ROOT/'crates/oblivion-pir/src').rglob('*.rs')),ROOT/'crates/oblivion-pir/examples/capture_driver.rs']},'capture_tool_version':subprocess.run(['dumpcap','--version'],capture_output=True,text=True).stdout if shutil.which('dumpcap') else None,'decode_tool_version':subprocess.run(['tshark','--version'],capture_output=True,text=True).stdout if shutil.which('tshark') else None};save(output/'metadata.json',metadata);launches=[];capture_unavailable=False
    for trial in range(args.trials):
        path=output/f'trial-{trial:03}';command=[str(binary),str(path),str(args.queries),str(20261021+trial)]
        driver=subprocess.Popen(command,cwd=ROOT,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        capture=None;capture_log=[];ready=json.loads(next_line(driver.stdout));ports=ready['ports'];assert len(set(ports))==2 and all(isinstance(port,int) and 0<port<65536 for port in ports)
        capture_command=['dumpcap','-i','lo','-f',f'tcp and host 127.0.0.1 and (port {ports[0]} or port {ports[1]})','-w',str(path/'capture.pcapng'),'-a','duration:15']
        capture_ok=False
        if not capture_unavailable and shutil.which('dumpcap') and shutil.which('tshark'):
            capture=subprocess.Popen(capture_command,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True);events=queue.Queue()
            def read_log(stream):
                for line in stream:capture_log.append(line.rstrip());events.put(line)
            reader=threading.Thread(target=read_log,args=(capture.stderr,),daemon=True);reader.start();deadline=time.monotonic()+2
            while time.monotonic()<deadline and capture.poll() is None:
                try:line=events.get(timeout=.1)
                except queue.Empty:continue
                if 'File:' in line:capture_ok=True;break
            if not capture_ok:
                capture_unavailable=True
                if capture.poll() is None:capture.terminate()
                capture.wait(timeout=3);reader.join(timeout=1)
        else:capture_log.append('Capture unavailable: tool missing or prior concrete permission failure; no capture attempted for this trial.')
        driver.stdin.write('continue\n');driver.stdin.flush();driver.stdin.close();driver.wait(timeout=20);stdout=driver.stdout.read();stderr=driver.stderr.read()
        if capture is not None and capture.poll() is None:
            time.sleep(.15);capture.send_signal(signal.SIGINT);capture.wait(timeout=3);reader.join(timeout=1)
        if capture_ok:
            packets,decoder=decode_capture(path/'capture.pcapng')
            with (path/'packet-observer.jsonl').open('w') as file:
                for row in packets:file.write(json.dumps(row)+'\n')
            save(path/'decode-command.json',decoder)
            capture_ok=bool(packets)
        record={'trial':trial,'queries':args.queries,'command':command,'ready':ready,'driver_returncode':driver.returncode,'stdout':stdout,'stderr':stderr,'capture_command':capture_command,'capture_ok':capture_ok,'capture_log':capture_log,'capture_returncode':capture.returncode if capture is not None else None}
        launches.append(record);save(path/'capture-launch.json',record);save(output/'launches.json',launches)
        if driver.returncode:raise RuntimeError(f'driverfailed: {stderr}')
        print(f'Trial{trial+1}/{args.trials}:verified{args.queries};actualcapture={capture_ok}',flush=True)
    metadata.update(binary_sha256_after_run=sha(binary),completed_unix_ns=time.time_ns());save(output/'metadata.json',metadata);aggregate(output)
if __name__=='__main__':main()
