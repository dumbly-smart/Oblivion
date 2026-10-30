#!/usr/bin/env python3
"""Offline component evaluation with ground truth confined to the evaluator."""
import argparse
import json
from pathlib import Path
import numpy as np
from scipy.stats import rankdata
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from research.attacks.simple import FrequencyAttack, TrafficAttack, split_sessions


def rows(path):
    return [json.loads(line) for line in path.open()]


def load(path):
    observable = rows(path/"observer.jsonl")
    truth = rows(path/"ground-truth.jsonl")
    if len(observable) != len(truth) or any(a["step"] != b["step"] for a,b in zip(observable,truth)):
        raise ValueError("misaligned trace/labels")
    if any(set(row) != {"version","step","tag","bytes","latency_ns"} for row in observable):
        raise ValueError("unexpected observer field: review leakage schema")
    return observable, np.array([row["label"] for row in truth])


def metrics(result, labels):
    prediction = np.array(result.predictions)
    score = np.array(result.scores)
    accuracy = float(np.mean(prediction == labels))
    recalls = [float(np.mean(prediction[labels == c] == c)) for c in [0,1] if np.any(labels == c)]
    n1, n0 = int(np.sum(labels == 1)), int(np.sum(labels == 0))
    auc = float((rankdata(score)[labels == 1].sum()-n1*(n1+1)/2)/(n1*n0)) if n0 and n1 else None
    return {"accuracy":accuracy,"balanced_accuracy":float(np.mean(recalls)),"auc":auc,"majority_accuracy":float(max(n0,n1)/len(labels)),"samples":len(labels),"attack_metadata":result.metadata}


def bootstrap(values, seed=994, clusters=None):
    values = np.array(values)
    if clusters is not None:
        if len(clusters) != len(values):
            raise ValueError("mismatched trial clusters")
        keys = sorted(set(clusters))
        values = np.array([np.mean(values[np.array(clusters) == key]) for key in keys])
    rng = np.random.default_rng(seed)
    estimates = np.mean(rng.choice(values,size=(5000,len(values)),replace=True),axis=1)
    return [float(x) for x in np.quantile(estimates,[.025,.975])]


def evaluate(directory, output):
    config = json.loads((directory/"config.json").read_text())
    output.mkdir(exist_ok=False)
    records = []
    for attack, modes in [("frequency",["plaintext","encrypt_only","oram"]),("traffic",["unpadded","padded"])]:
        for mode in modes: # positive controls evaluated before defenses
            current = []
            for trial in range(config["trials"]):
                sessions = {f"{session:04}":load(directory/attack/mode/f"{trial}-{session}") for session in range(config["sessions"])}
                if attack == "traffic":
                    profile,target = split_sessions(sessions)
                    known = [int(label) for _,labels in profile.values() for label in labels]
                    observed = [row for trace,_ in profile.values() for row in trace]
                    attacker = TrafficAttack().fit(observed,known)
                else:
                    target = sessions
                    attacker = FrequencyAttack()
                for session,(trace,labels) in target.items():
                    auxiliary = {"ranked_labels":[0,1],"majority":0} if attack == "frequency" else {}
                    result = attacker.run(trace,auxiliary) # target labels never enter the attacker
                    row = metrics(result,labels)
                    row.update(attack=attack,mode=mode,trial=trial,session=session)
                    row["payload_or_storage_bytes_mean"] = float(np.mean([r["bytes"] for r in trace]))
                    row["latency_ns_percentiles"] = list(map(float,np.percentile([r["latency_ns"] for r in trace],[50,95,99])))
                    current.append(row)
            accuracy = float(np.mean([r["accuracy"] for r in current]))
            majority = float(np.mean([r["majority_accuracy"] for r in current]))
            if mode in ["plaintext","encrypt_only","unpadded"] and accuracy <= majority+.1:
                raise RuntimeError(f"positive control failed: {attack}/{mode} accuracy={accuracy}, majority={majority}")
            records.extend(current)
    summary = []
    for attack,mode in dict.fromkeys((r["attack"],r["mode"]) for r in records):
        group = [r for r in records if r["attack"]==attack and r["mode"]==mode]
        values = [r["accuracy"] for r in group]
        summary.append({"attack":attack,"mode":mode,"accuracy":float(np.mean(values)),"accuracy_cluster_bootstrap_95":bootstrap(values,clusters=[r["trial"] for r in group]),"balanced_accuracy":float(np.mean([r["balanced_accuracy"] for r in group])),"majority_accuracy":float(np.mean([r["majority_accuracy"] for r in group])),"chance":.5,"sessions":len(group),"independent_trials":len(set(r["trial"] for r in group)),"auc_mean":float(np.mean([r["auc"] for r in group if r["auc"] is not None]))})
    report = {"config":config,"summary":summary,"session_metrics":records,"methodology":"5000-resample percentile bootstrap of equal-weight trial means; sessions sharing a fitted profiling model remain within one trial cluster. Target labels confined to scoring. Frequency uses offline unlabeled per-session counts and known popularity ordering; traffic profiles on the first half of sessions of each trial and tests on disjoint remaining sessions. Binary balanced-accuracy chance is 0.5; frequency accuracy must be compared with its imbalanced majority baseline.","limitations":"Simplified component attacks on synthetic workloads. Smoke runs with three trials provide weak uncertainty estimates; degenerate bootstrap intervals do not prove perfect generalization. No reproduction of published inference algorithms. No joint-transcript, scheduler, inter-arrival, cold-start, cache, adversarial-failure or full-pipeline classifier evaluation. Application payload lengths and local component durations are not TCP packet sizes. Near-chance performance is not a security proof. Frequency scores are hard ranking decisions, not calibrated confidence."}
    (output/"report.json").write_text(json.dumps(report,indent=2)+"\n")
    fig,axes = plt.subplots(1,2,figsize=(10,4))
    for axis,attack in zip(axes,["frequency","traffic"]):
        group = [r for r in summary if r["attack"]==attack]
        x = np.arange(len(group))
        means = np.array([r["accuracy"] for r in group])
        bounds = np.array([r["accuracy_cluster_bootstrap_95"] for r in group]).T
        axis.bar(x,means,color=["#c25e44"]*(len(group)-1)+["#366c95"])
        axis.errorbar(x,means,yerr=np.maximum(0,np.array([means-bounds[0],bounds[1]-means])),fmt="none",color="black",capsize=4)
        axis.plot(x,[r["majority_accuracy"] for r in group],"k--",label="majority baseline")
        axis.set(xticks=x,xticklabels=[r["mode"] for r in group],ylim=(0,1.05),ylabel="attack accuracy",title=attack)
        axis.legend(fontsize=8)
    fig.tight_layout();fig.savefig(output/"attack-controls.png",dpi=160);plt.close(fig)
    return report


if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("directory",type=Path);parser.add_argument("output",type=Path)
    args=parser.parse_args();report=evaluate(args.directory,args.output)
    print(json.dumps(report["summary"],indent=2))
