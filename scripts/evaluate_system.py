#!/usr/bin/env python3
"""Build/run the real A-G lab and record executable/config/host provenance."""
import argparse,hashlib,json,os,pathlib,platform,subprocess,sys,time,tempfile,shutil
ROOT=pathlib.Path(__file__).resolve().parents[1]
def command(args):
    p=subprocess.run(args,cwd=ROOT,text=True,capture_output=True)
    return p.stdout.strip() if p.returncode==0 else f'unavailable: {p.stderr.strip()}'
def source_hash(analysis=False):
    h=hashlib.sha256()
    paths=[p for p in (ROOT/'crates').rglob('*') if p.is_file()]+[ROOT/'Cargo.toml',ROOT/'Cargo.lock']
    if analysis:paths.extend([p for directory in ('research','scripts') for p in (ROOT/directory).rglob('*.py') if '__pycache__' not in p.parts])
    paths=sorted(paths)
    for path in paths:h.update(str(path.relative_to(ROOT)).encode()+b'\0'+path.read_bytes()+b'\0')
    return h.hexdigest()
def main():
    parser=argparse.ArgumentParser();parser.add_argument('config',type=pathlib.Path);parser.add_argument('output',type=pathlib.Path);args=parser.parse_args()
    if args.output.exists():raise SystemExit('output must be a new directory')
    config=json.loads(args.config.read_text())
    subprocess.run(['cargo','build','--locked','--release','-p','oblivion-harness'],cwd=ROOT,check=True)
    binary=ROOT/'target/release/oblivion-harness';built_source=source_hash();analysis_source=source_hash(analysis=True);started=time.time()
    with tempfile.TemporaryDirectory(prefix='oblivion-system-binary-') as temporary:
        executable=pathlib.Path(temporary)/'oblivion-harness';shutil.copy2(binary,executable)
        binary_hash=hashlib.sha256(executable.read_bytes()).hexdigest()
        result=subprocess.run([str(executable),'system',str(args.config.resolve()),str(args.output.resolve())],cwd=ROOT)
    metadata={'schema_version':1,'command':sys.argv,'configuration':config,'random_seed':config['seed'],'trial_count':config['trials'],
              'software_version':'0.1.0','git_head':command(['git','rev-parse','HEAD']),'git_status':command(['git','status','--porcelain']),
              'source_sha256_at_build':built_source,'source_sha256_after_run':source_hash(),'binary_sha256_before_launch':binary_hash,'binary_sha256_at_original_path_after_run':hashlib.sha256(binary.read_bytes()).hexdigest(),'analysis_and_script_source_sha256_at_launch':analysis_source,'analysis_and_script_source_sha256_after_run':source_hash(analysis=True),
              'rustc':command(['rustc','--version','--verbose']),'python':sys.version,'platform':platform.platform(),
              'cpuinfo':pathlib.Path('/proc/cpuinfo').read_text() if pathlib.Path('/proc/cpuinfo').exists() else None,
              'clock_ticks_per_second':os.sysconf('SC_CLK_TCK'),'memory_page_bytes':os.sysconf('SC_PAGE_SIZE'),
              'workload':'balanced shuffled half dummy, quarter echo, quarter stateful; fresh independent session seeds',
              'cryptographic_randomness':'OS secure source, not deterministic workload RNG',
              'elapsed_seconds':time.time()-started,'returncode':result.returncode,'output':str(args.output.resolve()),
              'isolation':'shared host, sequential modes in randomized session order, no CPU affinity',
              'measurement_scope':'actual component API-boundary payloads and full storage trace; no TCP packet capture or process separation',
              'statistical_methodology':'independent whole profiling/target sessions; bootstrap independent fitted-model trial means; majority and balanced baselines'}
    if args.output.exists():(args.output/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
    if result.returncode:raise SystemExit(result.returncode)
    subprocess.run([sys.executable,'-m','research.analysis.system',str(args.output.resolve())],cwd=ROOT,check=True)
if __name__=='__main__':main()
