import hashlib,json,os,subprocess,time,shutil
from pathlib import Path
out=Path('experiments/results/pipeline-ci-diagnosis-20261023');out.mkdir(exist_ok=False)
cpus=sorted(os.sched_getaffinity(0)); chosen=cpus[:2]
settings={'cpus_available':cpus,'chosen_cpus':chosen,'attempts_predeclared':['parallel14_on_two_cpus','serial1_on_two_cpus','strict_demo3_on_one_cpu_with_16_busy_processes'],'binary_sha256':hashlib.sha256(Path('target/debug/oblivion-server').read_bytes()).hexdigest(),'budgets_changed':False,'source_edits':False}
(out/'settings.json').write_text(json.dumps(settings,indent=2)+'\n')
records=[]
def execute(name,command):
 before=set(Path('/tmp').glob('oblivion-*')); start=time.monotonic()
 p=subprocess.run(command,capture_output=True,text=True,timeout=180)
 rec={'name':name,'command':command,'exit':p.returncode,'wall_seconds':time.monotonic()-start,'stdout':p.stdout,'stderr':p.stderr}
 records.append(rec);(out/'attempts.json').write_text(json.dumps(records,indent=2)+'\n')
 for folder in set(Path('/tmp').glob('oblivion-*'))-before:
  if folder.is_dir():shutil.copytree(folder,out/f'{name}-{folder.name}')
 print(name,p.returncode,rec['wall_seconds'],flush=True)
execute('parallel14_on_two_cpus',['taskset','-c',','.join(map(str,chosen)),'cargo','test','-p','oblivion-server','--test','pipeline','--','--test-threads=14'])
execute('serial1_on_two_cpus',['taskset','-c',','.join(map(str,chosen)),'cargo','test','-p','oblivion-server','--test','pipeline','--','--test-threads=1'])
burners=[subprocess.Popen(['taskset','-c',str(chosen[0]),'python3','-c','while True: pass'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL) for _ in range(16)]
try:
 execute('strict_demo3_on_one_cpu_with_16_busy_processes',['taskset','-c',str(chosen[0]),str(Path('target/debug/oblivion-server').resolve()),'demo',str((out/'contended-demo').resolve()),'50','3','mixed'])
finally:
 for b in burners:b.terminate()
 for b in burners:b.wait()
print(out,flush=True)
