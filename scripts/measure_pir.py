#!/usr/bin/env python3
"""Run the fixed 30-trial 10,000-record PIR microbenchmark with provenance."""
import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]


def main():
    if len(sys.argv)!=2:
        raise SystemExit("usage: measure_pir.py NEW_OUTPUT_DIRECTORY")
    output=Path(sys.argv[1]).resolve()
    if output.exists():
        raise SystemExit("output exists")
    command=lambda *args:subprocess.check_output(args,cwd=ROOT,text=True).strip()
    digest=hashlib.sha256()
    for path in sorted([*ROOT.glob("crates/oblivion-pir/**/*"),ROOT/"Cargo.toml",ROOT/"Cargo.lock",Path(__file__).resolve()]):
        if path.is_file():
            digest.update(str(path.relative_to(ROOT)).encode()+b"\0"+path.read_bytes()+b"\0")
    metadata={"git_head":command("git","rev-parse","HEAD"),"git_status":command("git","status","--porcelain"),"source_sha256":digest.hexdigest(),"rustc":command("rustc","--version","--verbose"),"platform":platform.platform(),"cpu":Path("/proc/cpuinfo").read_text() if Path("/proc/cpuinfo").exists() else platform.processor(),"resource_isolation":"shared host, no CPU pinning", "profile":"release", "output":str(output)}
    subprocess.run(["cargo","run","--locked","--release","-p","oblivion-pir","--example","measure","--",str(output)],cwd=ROOT,check=True)
    (output/"metadata.json").write_text(json.dumps(metadata,indent=2)+"\n")


if __name__=="__main__":main()
