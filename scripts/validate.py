#!/usr/bin/env python3
"""Run requested local quality gates, retaining actual output and exit codes."""
import argparse,hashlib,json,pathlib,platform,subprocess,sys,time
ROOT=pathlib.Path(__file__).resolve().parents[1]
def digest():
    h=hashlib.sha256()
    paths=[p for d in ['crates','research','scripts'] for p in (ROOT/d).rglob('*') if p.is_file() and p.suffix in ['.rs','.py','.toml'] and not any(x in p.parts for x in ['target','upstream','__pycache__'])]+[ROOT/'Cargo.toml',ROOT/'Cargo.lock',ROOT/'research/requirements.lock']
    for p in sorted(paths):h.update(str(p.relative_to(ROOT)).encode()+b'\0'+p.read_bytes()+b'\0')
    return h.hexdigest()
def main():
    parser=argparse.ArgumentParser();parser.add_argument('output',type=pathlib.Path);args=parser.parse_args();args.output.mkdir(exist_ok=False)
    before=digest();records=[]
    commands=[['cargo','fmt','--all','--check'],['cargo','clippy','--locked','--workspace','--all-targets','--','-D','warnings'],['cargo','test','--locked','--workspace'],[sys.executable,'-m','unittest','discover','-s','research/tests'],['cargo','test','--locked','--release','-p','oblivion-store','million_operation_oracle','--','--ignored','--exact']]
    for i,command in enumerate(commands):
        print('Running', ' '.join(command),flush=True);start=time.time();log=args.output/f'{i}.log'
        with log.open('w') as output:result=subprocess.run(command,cwd=ROOT,stdout=output,stderr=subprocess.STDOUT)
        records.append({'command':command,'exit_code':result.returncode,'elapsed_seconds':time.time()-start,'log':log.name})
        (args.output/'commands.json').write_text(json.dumps(records,indent=2)+'\n')
    (args.output/'metadata.json').write_text(json.dumps({'source_sha256_before':before,'source_sha256_after':digest(),'platform':platform.platform(),'python':sys.version,'configuration':'workspace profiles; locked dependencies; explicit release stress tier','output':str(args.output.resolve())},indent=2)+'\n')
    raise SystemExit(int(any(r['exit_code'] for r in records)))
if __name__=='__main__':main()
