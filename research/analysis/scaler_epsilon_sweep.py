"""Run paired autoscaler studies across public DP epsilon parameters."""
import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from research.analysis.scaler_seed_replay import evaluate as evaluate_seed_replay
from research.simulation.run import run as run_experiment
from research.simulation.scaler import Config


def validate_config(raw):
    required = {'version', 'seed', 'trials', 'sessions', 'workloads', 'epsilons', 'simulation'}
    if not isinstance(raw, dict) or set(raw) != required:
        raise ValueError('epsilon sweep config has unknown or missing keys')
    if type(raw['version']) is not int or raw['version'] != 1 or type(raw['seed']) is not int or raw['seed'] < 0:
        raise ValueError('unsupported version or invalid experiment seed')
    if (type(raw['trials']) is not int or not 2 <= raw['trials'] <= 100
            or type(raw['sessions']) is not int or not 8 <= raw['sessions'] <= 64
            or raw['sessions'] % 8):
        raise ValueError('trials or whole-session split is outside supported bounds')
    workloads = raw['workloads']
    if (not isinstance(workloads, list) or not workloads
            or any(type(workload) is not str for workload in workloads)
            or len(set(workloads)) != len(workloads)
            or set(workloads) - {'uniform', 'zipf', 'diurnal', 'burst'}):
        raise ValueError('invalid workload list')
    epsilons = raw['epsilons']
    if (not isinstance(epsilons, list) or len(epsilons) < 2
            or any(type(epsilon) not in (int, float) for epsilon in epsilons)
            or any(not 0 < float(epsilon) < float('inf') for epsilon in epsilons)
            or len(set(epsilons)) != len(epsilons)):
        raise ValueError('epsilon values must be unique, finite and positive')
    if not isinstance(raw['simulation'], dict):
        raise ValueError('simulation settings must be an object')
    simulation = dict(raw['simulation'])
    if 'dp_epsilon' in simulation:
        raise ValueError('set privacy budgets in epsilons, not simulation.dp_epsilon')
    simulation['dp_epsilon'] = 1.0
    cfg = Config(**simulation)
    cfg.validate()
    if cfg.functions != 2:
        raise ValueError('the binary function-pool workload requires functions=2')
    return cfg


def plot(output, summary):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    workloads = sorted({row['workload'] for row in summary if row['task'] == 'intensity'})
    fig, axes = plt.subplots(1, len(workloads), figsize=(5 * len(workloads), 4), squeeze=False)
    colors = {0.5: '#440154', 1.0: '#31688e', 2.0: '#35b779', 4.0: '#fde725'}
    for ax, workload in zip(axes[0], workloads):
        rows = [row for row in summary if row['workload'] == workload
                and row['task'] == 'intensity']
        for row in rows:
            marker = 'o' if row['attacker'].endswith('seed_replay') else 'x'
            color = colors.get(row['epsilon'], None)
            ax.scatter(row['instance_seconds'], row['balanced_accuracy'],
                color=color, marker=marker, alpha=.8)
        ax.axhline(.5, color='black', linestyle='--', linewidth=.7)
        ax.set(title=workload, xlabel='Instance seconds', ylabel='Balanced accuracy', ylim=(0, 1))
    fig.suptitle('Autoscaler demand inference vs simulated cost by epsilon')
    fig.tight_layout()
    fig.savefig(output / 'epsilon-cost-attack.png', dpi=160)
    plt.close(fig)


def run_sweep(config_path, output):
    config_path = Path(config_path).resolve()
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError('choose a fresh epsilon-sweep output directory')
    raw = json.loads(config_path.read_text())
    validate_config(raw)
    output.mkdir(parents=True)
    (output / 'sweep-config.json').write_text(json.dumps(raw, indent=2) + '\n')
    started = time.perf_counter()
    summary, positive_controls, runs = [], [], []

    for epsilon in raw['epsilons']:
        name = f"epsilon-{float(epsilon):g}"
        root = output / name
        root.mkdir()
        run_config = dict(version=1, seed=raw['seed'], trials=raw['trials'],
            sessions=raw['sessions'], workloads=raw['workloads'],
            policies=['naive', 'dp_laplace'], simulation=dict(raw['simulation'],
                dp_epsilon=float(epsilon)), imports=[])
        config_copy = root / 'run-config.json'
        config_copy.write_text(json.dumps(run_config, indent=2) + '\n')
        run_report = run_experiment(config_copy, root / 'run')
        attack_report = evaluate_seed_replay(root / 'run', root / 'attack', models=('forest',))
        performance = {(row['policy'], row['workload']): row
            for row in run_report['summary'] if row['task'] == 'intensity'}
        for row in attack_report['summary']:
            metrics = performance[row['policy'], row['workload']]
            summary.append(dict(epsilon=float(epsilon), **row,
                instance_seconds=metrics['instance_seconds'],
                mean_session_p99=metrics['p99'],
                slo_violation_rate=metrics['slo_violation_rate'],
                geometric_log_scale=1 / run_report['privacy_claims']['dp_laplace'][
                    'effective_per_release_epsilon']))
        positive_controls.extend(dict(epsilon=float(epsilon), **row)
                                 for row in attack_report['positive_controls'])
        runs.append(dict(epsilon=float(epsilon), run_summaries=len(run_report['summary']),
            attack_summaries=len(attack_report['summary']),
            run_git_head=run_report['provenance']['git_head'],
            attack_git_head=attack_report['git_head']))

    source_files = ['research/analysis/scaler_epsilon_sweep.py',
        'research/analysis/scaler_seed_replay.py', 'research/attacks/scaler_seed_replay.py',
        'research/simulation/run.py', 'research/simulation/scaler.py']
    report = dict(config=raw, epsilons=[float(value) for value in raw['epsilons']],
        paired_workloads=True, runs=runs, summary=summary, positive_controls=positive_controls,
        all_positive_controls_passed=all(row['passed'] for row in positive_controls),
        methodology='Each epsilon uses the same public experiment seed, generated workload streams, trials, session split, and policy-noise base streams. Each setting has a separate raw capture and attack reanalysis. The fixed 64-tree seed-replay forest uses whole-session profiling/target splits. Cost and SLO metrics are simulated, not deployment measurements.',
        limitations='The public seed makes each nominal Laplace transcript deterministic and invalidates a formal DP guarantee for these saved artifacts. Four epsilon values and multiple attack/task comparisons are exploratory; intervals are unadjusted. No CSPRNG-backed production mechanism, user-level adjacency, runtime integration, provider costs, or hardware TEE is evaluated.',
        provenance=dict(git_head=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
            git_dirty=bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True)),
            python=platform.python_version(), platform=platform.platform(),
            numpy=importlib.metadata.version('numpy'), sklearn=importlib.metadata.version('scikit-learn'),
            matplotlib=importlib.metadata.version('matplotlib'), elapsed_wall_seconds=time.perf_counter() - started,
            source_sha256={name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                           for name in source_files},
            config_sha256=hashlib.sha256(config_path.read_bytes()).hexdigest()))
    plot(output, summary)
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    manifest = {str(path.relative_to(output)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in output.rglob('*') if path.is_file() and path.name != 'artifact-sha256.json'}
    (output / 'artifact-sha256.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('config', type=Path)
    parser.add_argument('new_output', type=Path)
    args = parser.parse_args()
    result = run_sweep(args.config, args.new_output)
    print(json.dumps({'summary_rows': len(result['summary']),
        'positive_controls': len(result['positive_controls']),
        'all_positive_controls_passed': result['all_positive_controls_passed'],
        'elapsed_wall_seconds': result['provenance']['elapsed_wall_seconds']}, indent=2))
