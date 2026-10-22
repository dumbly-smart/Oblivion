#!/usr/bin/env python3
"""Generate real component traces, save provenance, then validate attacks."""
import argparse
import hashlib
import json
import platform
import subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("config",type=Path)
    parser.add_argument("output",type=Path)
    parser.add_argument("--dev",action="store_true",help="use dev profile for smoke checks, recorded in metadata")
    args=parser.parse_args()
    if args.output.exists():
        parser.error("output exists: choose a new directory")
    profile=[] if args.dev else ["--release"]
    digest=hashlib.sha256()
    files=sorted([*ROOT.glob("crates/**/*"),*ROOT.glob("examples/**/*"),*ROOT.glob("research/**/*.py"),*ROOT.glob("scripts/*.py"),ROOT/"Cargo.toml",ROOT/"Cargo.lock"])
    for file in files:
        if file.is_file() and "__pycache__" not in file.parts:
            digest.update(str(file.relative_to(ROOT)).encode()+b"\0"+file.read_bytes()+b"\0")
    command=lambda *parts:subprocess.check_output(parts,cwd=ROOT,text=True).strip()
    metadata={"schema_version":1,"source_sha256":digest.hexdigest(),"git_head":command("git","rev-parse","HEAD"),"git_status":command("git","status","--porcelain"),"rustc":command("rustc","--version","--verbose"),"platform":platform.platform(),"cpu":Path("/proc/cpuinfo").read_text() if Path("/proc/cpuinfo").exists() else platform.processor(),"configuration":json.loads(args.config.read_text()),"resource_isolation":"shared host; no CPU pinning or exclusive resource reservation", "profile":"dev" if args.dev else "release","output":str(args.output.resolve()),"python_packages":command(str(ROOT/".venv/bin/python"),"-m","pip","freeze"),"threat_model":"A; component observer features declared in analysis report; synthetic workloads only"}
    subprocess.run(["cargo","run","--locked",*profile,"-p","oblivion-harness","--",str(args.config.resolve()),str(args.output.resolve())],cwd=ROOT,check=True)
    (args.output/"metadata.json").write_text(json.dumps(metadata,indent=2)+"\n")
    subprocess.run([str(ROOT/".venv/bin/python"),"-m","research.analysis.leakage",str(args.output.resolve()),str(args.output.resolve()/"analysis")],cwd=ROOT,check=True)


if __name__=="__main__":main()
