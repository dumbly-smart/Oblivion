#!/usr/bin/env python3
"""Summarize saved in-process PIR timing samples without regenerating data."""
import argparse
import json
from pathlib import Path
import numpy as np


def main():
    parser=argparse.ArgumentParser();parser.add_argument("directory",type=Path);parser.add_argument("output",type=Path)
    args=parser.parse_args()
    if args.output.exists():parser.error("output exists")
    rows=[json.loads(line) for line in (args.directory/"private-samples.jsonl").open()]
    config=json.loads((args.directory/"config.json").read_text())
    if len(rows)!=config["trials"]*config["queries_per_trial"]:raise ValueError("incomplete samples")
    result={"trials":config["trials"],"queries":len(rows),"scope":"in-process cached scans on a shared host; wall-clock ns; not network latency, cold DRAM bandwidth, or general server throughput", "phases":{}}
    for phase in ["generation_ns","server1_ns","server2_ns","recovery_ns"]:
        result["phases"][phase]=dict(zip(["p50","p95","p99"],map(float,np.percentile([r[phase] for r in rows],[50,95,99]))))
    throughput=[]
    for trial in range(config["trials"]):
        group=[r for r in rows if r["trial"]==trial]
        if len(group)!=config["queries_per_trial"]:raise ValueError("incomplete trial")
        throughput.append(sum(2*r["database_payload_bytes_per_server"] for r in group)/sum(r["server1_ns"]+r["server2_ns"] for r in group))
    rng=np.random.default_rng(519)
    ci=np.quantile(np.mean(rng.choice(throughput,size=(5000,len(throughput))),axis=1),[.025,.975])
    result.update(server_scan_GBps_mean=float(np.mean(throughput)),server_scan_GBps_trial_bootstrap_95=ci.tolist(),query_payload_bytes=rows[0]["query_payload_bytes"],response_payload_bytes=rows[0]["response_payload_bytes"],methodology="NumPy linear interpolated quantiles; 5000-resample trial bootstrap of cached scan throughput; decimal GB/s; seed519")
    args.output.write_text(json.dumps(result,indent=2)+"\n")


if __name__=="__main__":main()
