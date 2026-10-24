"""Run: python -m research.simulation.run CONFIG NEW_OUTPUT; replot: --plot-only OUTPUT."""
import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import gzip
import hashlib
from contextlib import ExitStack
import io
import json
from pathlib import Path
import platform
import os
import importlib.metadata
import subprocess
import sys
import time
import numpy as np
from research.simulation.scaler import (Config, DEFAULT_POLICIES, POLICIES, ProfileAttack,
    dp_laplace_parameters, load_imported, session_features, simulate, trial_interval, workload)


def write_row(handle, row):
    handle.write(json.dumps(row, separators=(',', ':')) + '\n')


def score(prediction, truth, majority):
    classes = np.unique(truth)
    return dict(accuracy=float(np.mean(prediction == truth)),
                balanced_accuracy=float(np.mean([np.mean(prediction[truth == c] == c) for c in classes])),
                majority_accuracy=float(np.mean(truth == majority)),
                balanced_majority_accuracy=1 / len(classes), samples=len(truth))


def evaluate(profile, target, task):
    x = np.vstack([session_features(s['observer']) for s in profile])
    y = np.concatenate([np.array([r[task] for r in s['labels']]) for s in profile])
    attacker = ProfileAttack().fit(x, y)
    majority = int(np.bincount(y).argmax())
    scored = []
    for s in target:
        truth = np.array([r[task] for r in s['labels']])
        # Per-session latent classes may be constant. Compute balanced accuracy
        # across the whole held-out trial, never average singleton-class recalls.
        scored.append((attacker.predict(session_features(s['observer'])), truth))
    return score(np.concatenate([p for p, _ in scored]), np.concatenate([y for _, y in scored]), majority)


def nondominated(points, fields):
    return [not any(all(other[f] <= point[f] for f in fields) and any(other[f] < point[f] for f in fields)
                    for j, other in enumerate(points) if i != j) for i, point in enumerate(points)]


def privacy_claims(cfg, policies):
    if 'dp_laplace' not in policies:
        return {}
    parameters = dp_laplace_parameters(cfg)
    return {'dp_laplace': dict(
        mechanism_design_claim='Under ideal independent Laplace draws hidden from the observer, the declared scaler observer is pure epsilon-DP under add/remove-one-request adjacency.',
        artifact_guarantee='none: the reproducible experiment uses a deterministic seed that is recorded in public configuration',
        epsilon=cfg.dp_epsilon, delta=0.0, adjacency='workload request lists differ by exactly one added or removed Request record over the whole fixed horizon; not user-level adjacency',
        release_count=parameters['releases'],
        per_release_epsilon=parameters['epsilon_per_release'],
        per_release_l1_sensitivity_bound=parameters['l1_sensitivity_bound'],
        independent_laplace_scale_per_pool_per_tick=parameters['laplace_scale'],
        composition='basic pure-DP sequential composition over the fixed public release count; one request changes one pool EWMA by at most 1 at any tick',
        postprocessing_boundary='only epoch, instance counts, scale events and cold-start counts; no true queue term in the scaling target and no downscale/retirement, so worker busy state cannot alter observed pool counts or launches',
        exclusions=['one user contributing multiple requests', 'replace/move adjacency', 'response latency/errors and workload-private performance outputs', 'external billing or other runtime transcript'],
        randomness='the theorem is conditional on ideal independent hidden draws; this simulator uses deterministic NumPy PRNG output and publishes the experiment seed, so the saved transcript has no formal DP guarantee; this is not a production randomness implementation')}


def plot(output):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    report = json.loads((output / 'report.json').read_text())
    summary = report['summary']
    for task in ('intensity', 'hot'):
        workloads = sorted({r['workload'] for r in summary if r['task'] == task})
        if not workloads:
            continue
        fig, axes = plt.subplots(len(workloads), 2, figsize=(11, 3.5 * len(workloads)), squeeze=False)
        for row, kind in enumerate(workloads):
            points = [r for r in summary if r['workload'] == kind and r['task'] == task]
            for point in points:
                a, b = axes[row]
                color = plt.cm.viridis(point['balanced_accuracy'])
                a.scatter(point['p99'], point['instance_seconds'], color=color)
                a.annotate(point['policy'], (point['p99'], point['instance_seconds']), fontsize=7)
                low, high = point['balanced_accuracy_ci95']
                marker = 'o' if point['meets_slo_violation_1percent'] else 'x'
                b.errorbar(point['instance_seconds'], point['balanced_accuracy'],
                           yerr=[[max(0, point['balanced_accuracy'] - low)], [max(0, high - point['balanced_accuracy'])]],
                           fmt=marker, color=color, capsize=3)
                b.annotate(point['policy'], (point['instance_seconds'], point['balanced_accuracy']), fontsize=7)
            frontier = sorted([p for p in points if p['pareto_cost_leakage_slo']], key=lambda p: p['instance_seconds'])
            if frontier:
                axes[row, 1].plot([p['instance_seconds'] for p in frontier], [p['balanced_accuracy'] for p in frontier], 'k:', linewidth=1)
            a.set(xlabel='Mean session p99 latency (simulation seconds)', ylabel='Instance seconds', title=f'{kind}: latency/cost; color = attack balanced accuracy')
            b.axhline(.5, color='black', linestyle='--', linewidth=.7)
            b.set(xlabel='Instance seconds', ylabel='Attack balanced accuracy', ylim=(0, 1.05), title=f'{kind}: cost/leakage; x exceeds 1% SLO violation')
        fig.tight_layout()
        fig.savefig(output / f'pareto-{task}.png', dpi=160)
        plt.close(fig)


def run(config_path, output):
    raw = json.loads(config_path.read_text())
    if set(raw) - {'version', 'seed', 'trials', 'sessions', 'workloads', 'simulation', 'imports', 'policies'}:
        raise ValueError('unknown experiment parameter')
    if raw['version'] != 1 or not 2 <= raw['trials'] <= 100 or raw['sessions'] < 8 or raw['sessions'] > 64 or raw['sessions'] % 8:
        raise ValueError('version1; 2..100 trials; sessions multiple of8 in8..64')
    if type(raw['seed']) is not int or raw['seed'] < 0:
        raise ValueError('seed must be a nonnegative integer')
    policies = raw.get('policies', list(DEFAULT_POLICIES))
    if (not isinstance(policies, list) or not policies
            or any(not isinstance(policy, str) for policy in policies)
            or len(set(policies)) != len(policies)
            or set(policies) - set(POLICIES) or 'naive' not in policies):
        raise ValueError('policies must be unique known names and include the naive positive control')
    cfg = Config(**raw['simulation']); cfg.validate()
    if cfg.functions != 2:
        raise ValueError('binary hot-class experiment requires two function pools')
    if not raw['workloads'] or set(raw['workloads']) - {'uniform', 'zipf', 'diurnal', 'burst'}:
        raise ValueError('unsupported workload')
    imported = []
    for spec in raw.get('imports', []):
        if set(spec) != {'path', 'provenance'} or not spec['provenance']:
            raise ValueError('imports require path and provenance')
        path = Path(spec['path'])
        imported.append((spec, load_imported(path, cfg), hashlib.sha256(path.read_bytes()).hexdigest()))
    output.mkdir(exist_ok=False)
    (output / 'config.json').write_text(json.dumps(raw, indent=2) + '\n')
    start = time.perf_counter()
    trial_results, imports = [], []
    with ExitStack() as stack:
        def gzip_text(name):
            raw_file = stack.enter_context((output / name).open('wb'))
            compressed = stack.enter_context(gzip.GzipFile(
                filename='', fileobj=raw_file, mode='wb', mtime=0))
            return stack.enter_context(io.TextIOWrapper(compressed, encoding='utf-8'))

        obs = gzip_text('observer.jsonl.gz')
        private = gzip_text('private.jsonl.gz')
        truth = gzip_text('workloads-private.jsonl.gz')
        for trial in range(raw['trials']):
            for kind in raw['workloads']:
                sessions = {policy: [] for policy in policies}
                for session in range(raw['sessions']):
                    intensity, hot = (session % 4) // 2, session % 2
                    # SeedSequence separates policy randomness from arrivals, and
                    # repeats classes but never repeats a profiling/target stream.
                    seed = np.random.SeedSequence([raw['seed'], trial, session, raw['workloads'].index(kind)]).generate_state(1)[0]
                    requests, labels = workload(cfg, kind, int(seed), intensity, hot)
                    context = dict(trial=trial, session=session, workload=kind)
                    write_row(truth, dict(**context, seed=int(seed), labels=labels, requests=[asdict(r) for r in requests]))
                    for policy in policies:
                        result = simulate(cfg, requests, policy, int(seed) + 991)
                        write_row(obs, dict(**context, policy=policy, rows=result['observer']))
                        write_row(private, dict(**context, policy=policy, metrics=result['metrics'], requests=result['requests']))
                        sessions[policy].append(dict(observer=result['observer'], labels=labels, metrics=result['metrics']))
                for policy, samples in sessions.items():
                    split = raw['sessions'] // 2
                    for task in ['intensity'] + ([] if kind == 'uniform' else ['hot']):
                        metrics = evaluate(samples[:split], samples[split:], task)
                        # Performance uses target sessions matching inference evaluation.
                        targets = [s['metrics'] for s in samples[split:]]
                        for key in targets[0]:
                            values = [m[key] for m in targets if m[key] is not None]
                            metrics[key] = float(np.mean(values)) if values else None
                        trial_results.append(dict(trial=trial, workload=kind, policy=policy, task=task, **metrics))
            for spec, requests, digest in imported:
                for policy in policies:
                    result = simulate(cfg, requests, policy, raw['seed'] + trial)
                    context = dict(trial=trial, workload=spec['path'], policy=policy)
                    write_row(obs, dict(**context, rows=result['observer']))
                    write_row(private, dict(**context, metrics=result['metrics'], requests=result['requests']))
                    imports.append(dict(**context, provenance=spec['provenance'], sha256=digest, metrics=result['metrics'], inference='not evaluated: imported trace lacks independent labeled sessions'))
    summary = []
    for kind in raw['workloads']:
        for task in ['intensity'] + ([] if kind == 'uniform' else ['hot']):
            points = []
            for policy in policies:
                group = [r for r in trial_results if (r['workload'], r['task'], r['policy']) == (kind, task, policy)]
                result = dict(workload=kind, task=task, policy=policy, independent_trials=len(group))
                for key in group[0]:
                    if key not in ('trial', 'workload', 'task', 'policy'):
                        values = [r[key] for r in group if r[key] is not None]
                        result[key] = float(np.mean(values)) if values else None
                for key in ('balanced_accuracy', 'accuracy', 'instance_seconds', 'p99', 'slo_violation_rate'):
                    result[key + '_ci95'] = trial_interval([[r[key]] for r in group]) if all(r[key] is not None for r in group) else None
                points.append(result)
            frontier = nondominated(points, ('instance_seconds', 'p99', 'balanced_accuracy'))
            for point, member in zip(points, frontier):
                point['pareto_three_axes'] = member
                point['meets_slo_violation_1percent'] = point['slo_violation_rate'] <= .01
            eligible = [p for p in points if p['meets_slo_violation_1percent']]
            two = nondominated(eligible, ('instance_seconds', 'balanced_accuracy'))
            for point in points:
                point['pareto_cost_leakage_slo'] = next((v for p, v in zip(eligible, two) if p is point), False)
            summary.extend(points)
    positive = [dict(workload=p['workload'], task=p['task'], balanced_accuracy=p['balanced_accuracy'], passed=p['balanced_accuracy'] > .6) for p in summary if p['policy'] == 'naive']
    # Keep all measured failures and do not reinterpret them as defense success.
    source_paths = list(Path('research/simulation').glob('*.py'))
    provenance = dict(created_utc=datetime.now(timezone.utc).isoformat(), command=sys.argv,
        python=sys.version, platform=platform.platform(), machine=platform.machine(), processor=platform.processor(),
        numpy=np.__version__, matplotlib=importlib.metadata.version('matplotlib'), scipy=importlib.metadata.version('scipy'),
        logical_cpus=os.cpu_count(), cpu_model=next((line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), 'unknown') if Path('/proc/cpuinfo').exists() else platform.processor(),
        elapsed_wall_seconds=time.perf_counter() - start,
        source_sha256={str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_paths},
        config_sha256=hashlib.sha256(config_path.read_bytes()).hexdigest(),
        git_head=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
        git_dirty=bool(subprocess.check_output(['git', 'status', '--porcelain'], text=True)),
        workload_source='seeded synthetic Poisson arrivals; not calibrated to production traces')
    claims = privacy_claims(cfg, policies)
    report = dict(config=raw, provenance=provenance, summary=summary, trial_metrics=trial_results,
        imported_runs=imports, positive_controls=positive, privacy_claims=claims,
        methodology='Known-policy diagonal nearest-centroid profiler on current, previous and cumulative observer counts/events only. First half independent sessions profile; second half test. Session classes balanced across each half; trial-pooled balanced recall. Equal-weight independent trial bootstrap with5000 resamples. Public function pool identities are visible. Demand task is binary latent session demand regime, not exact arrival recovery. Uniform workload has no hot-function task.',
        limitations='Function-affine fixed-service single-request workers; no runtime/ORAM/network integration. Simulated seconds, not measured service latency. Horizon-censored requests count as SLO violations; p95/p99 concern completed requests only. Price is a hypothetical configurable input. The legacy noisy policy has no adjacency/sensitivity/composition guarantee. The optional dp_laplace policy has only a conditional mechanism-design claim for an event-level fixed-horizon observer under ideal independent hidden randomness; the recorded deterministic-seed experiment itself has no formal DP guarantee. No user-level or full-runtime guarantee, security proof, or universal attack bound. Public count/event observer excludes queue, true arrivals, response latency, billing, active scheduling and joint transcripts. Imported repeated traces support performance only. Pareto membership uses point estimates, not significance tests. No policy dominance required or forced.')
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    plot(output)
    manifest = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in output.iterdir() if path.is_file()}
    (output / 'artifact-sha256.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('config', type=Path, nargs='?')
    parser.add_argument('output', type=Path, nargs='?')
    parser.add_argument('--plot-only', type=Path)
    args = parser.parse_args()
    if args.plot_only:
        plot(args.plot_only)
    elif args.config and args.output:
        report = run(args.config, args.output)
        print(json.dumps({'summaries': len(report['summary']), 'positive_controls': report['positive_controls'], 'wall_seconds': report['provenance']['elapsed_wall_seconds']}, indent=2))
    else:
        parser.error('CONFIG NEW_OUTPUT or --plot-only OUTPUT required')
