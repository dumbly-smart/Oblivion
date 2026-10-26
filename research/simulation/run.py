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
    RequestAuthenticator, dp_laplace_parameters, load_imported, session_features,
    simulate, trial_interval, workload)


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


def privacy_claims(cfg, policies, dp_noise_source='seeded_experiment'):
    if 'dp_laplace' not in policies:
        return {}
    parameters = dp_laplace_parameters(cfg)
    if cfg.dp_user_contribution_cap:
        adjacency = (f'add/remove one stable authenticated principal and all its requests over the fixed horizon; '
                     f'at most {cfg.dp_user_contribution_cap} requests per user are counted')
        privacy_unit = 'bounded_user'
        contribution_exclusion = []
    else:
        adjacency = 'workload request lists differ by exactly one added or removed Request record over the whole fixed horizon; not user-level adjacency'
        privacy_unit = 'request'
        contribution_exclusion = ['one user contributing multiple requests']
    return {'dp_laplace': dict(
        mechanism_design_claim=(f'For the declared {privacy_unit} adjacency over this fixed horizon, the bounded discrete sampler has a conditional (epsilon, delta) guarantee '
            'for the count/event transcript under independent uniform random bits; it is not a code audit or an end-to-end runtime guarantee.'),
        artifact_guarantee=('none: deterministic noise is derived from the public experiment seed'
            if dp_noise_source == 'seeded_experiment' else
            'conditional on OS-CSPRNG output modeling independent uniform bits and the documented sampler/calibration; no independent implementation audit'),
        epsilon=cfg.dp_epsilon, delta=parameters['composed_delta_bound'],
        configured_delta=cfg.dp_delta,
        privacy_unit=privacy_unit,
        adjacency=adjacency,
        per_user_request_cap=cfg.dp_user_contribution_cap or None,
        release_count=parameters['releases'],
        per_release_epsilon=parameters['epsilon_per_release'],
        per_unit_epsilon=parameters['epsilon_per_unit'],
        effective_per_unit_epsilon=parameters['epsilon_effective_per_unit'],
        effective_per_release_epsilon=parameters['epsilon_effective_per_release'],
        per_release_l1_sensitivity_bound=parameters['l1_sensitivity_bound'],
        geometric_parameter_numerator=parameters['geometric_numerator'],
        geometric_parameter_denominator=parameters['geometric_denominator'],
        geometric_cap=parameters['geometric_cap'],
        per_release_delta_bound=parameters['per_release_delta_bound'],
        composition=(f'basic approximate-DP sequential composition over {parameters["releases"]} public releases; '
                     f'each per-tick integer arrival vector has L1 sensitivity at most {parameters["l1_sensitivity_bound"]:g}'),
        postprocessing_boundary='discrete noise is added to per-tick integer arrival counts; nonnegative clipping, EWMA smoothing, scaling targets, epoch, instance counts, scale events and cold-start counts are post-processing; no true queue term and no downscale/retirement, so worker busy state cannot alter observed pool counts or launches',
        exclusions=contribution_exclusion + ['same person/data spanning multiple sessions or deployments', 'replace/move adjacency', 'response latency/errors, sampler execution timing/CPU, and workload-private performance outputs', 'external billing or other runtime transcript'],
        randomness=(
            'seeded_experiment: deterministic Python PRNG output is derived from the public experiment seed; saved transcript has no DP guarantee'
            if dp_noise_source == 'seeded_experiment' else
            'os_csprng: each noise sample draws fixed-size random bits from Python secrets/OS CSPRNG; the finite-rational capped-geometric sampler has a stated approximate-DP bound under the documented assumptions'),
        noise_reproducible=dp_noise_source == 'seeded_experiment')}


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


def recorded_command(argv):
    """Keep local secret-file paths out of archived experiment metadata."""
    result = []
    redact_next = False
    for argument in argv:
        if redact_next:
            result.append('[REDACTED]')
            redact_next = False
        elif argument == '--identity-registry':
            result.append(argument)
            redact_next = True
        elif argument.startswith('--identity-registry='):
            result.append('--identity-registry=[REDACTED]')
        else:
            result.append(argument)
    return result


def run(config_path, output, identity_registry_path=None):
    raw = json.loads(config_path.read_text())
    if set(raw) - {'version', 'seed', 'trials', 'sessions', 'workloads', 'simulation', 'imports', 'policies', 'dp_noise_source'}:
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
    dp_noise_source = raw.get('dp_noise_source', 'seeded_experiment')
    if dp_noise_source not in ('seeded_experiment', 'os_csprng'):
        raise ValueError('dp_noise_source must be seeded_experiment or os_csprng')
    cfg = Config(**raw['simulation']); cfg.validate()
    identity_authenticator = None
    identity_registry_sha256 = None
    if cfg.require_authenticated_user_ids:
        if identity_registry_path is None:
            raise ValueError('authenticated run requires an external identity registry path')
        identity_registry_path = Path(identity_registry_path)
        if not identity_registry_path.is_absolute():
            identity_registry_path = Path(config_path).resolve().parent / identity_registry_path
        identity_authenticator = RequestAuthenticator.from_file(identity_registry_path)
        identity_registry_sha256 = identity_authenticator.registry_sha256
    elif identity_registry_path is not None:
        raise ValueError('identity registry is only accepted when authenticated IDs are required')
    if cfg.functions != 2:
        raise ValueError('binary hot-class experiment requires two function pools')
    if not raw['workloads'] or set(raw['workloads']) - {'uniform', 'zipf', 'diurnal', 'burst'}:
        raise ValueError('unsupported workload')
    imported = []
    for spec in raw.get('imports', []):
        if set(spec) != {'path', 'provenance'} or not spec['provenance']:
            raise ValueError('imports require path and provenance')
        path = Path(spec['path'])
        imported.append((spec, load_imported(path, cfg, identity_authenticator), hashlib.sha256(path.read_bytes()).hexdigest()))
    output.mkdir(exist_ok=False)
    recorded_config = dict(raw)
    if identity_registry_sha256:
        recorded_config['identity_registry_sha256'] = identity_registry_sha256
    (output / 'config.json').write_text(json.dumps(recorded_config, indent=2) + '\n')
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
                    requests, labels = workload(
                        cfg, kind, int(seed), intensity, hot,
                        identity_authenticator=identity_authenticator,
                    )
                    context = dict(trial=trial, session=session, workload=kind)
                    write_row(truth, dict(**context, seed=int(seed), labels=labels, requests=[asdict(r) for r in requests]))
                    for policy in policies:
                        result = simulate(cfg, requests, policy, int(seed) + 991,
                                          dp_noise_source=dp_noise_source,
                                          identity_authenticator=identity_authenticator)
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
                    result = simulate(cfg, requests, policy, raw['seed'] + trial,
                                      dp_noise_source=dp_noise_source,
                                      identity_authenticator=identity_authenticator)
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
    provenance = dict(created_utc=datetime.now(timezone.utc).isoformat(), command=recorded_command(sys.argv),
        python=sys.version, platform=platform.platform(), machine=platform.machine(), processor=platform.processor(),
        numpy=np.__version__, matplotlib=importlib.metadata.version('matplotlib'), scipy=importlib.metadata.version('scipy'),
        logical_cpus=os.cpu_count(), cpu_model=next((line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), 'unknown') if Path('/proc/cpuinfo').exists() else platform.processor(),
        elapsed_wall_seconds=time.perf_counter() - start,
        source_sha256={str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_paths},
        config_sha256=hashlib.sha256(config_path.read_bytes()).hexdigest(),
        identity_authentication='hmac-sha256' if identity_authenticator else None,
        identity_registry_sha256=identity_registry_sha256,
        git_head=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
        git_dirty=bool(subprocess.check_output(['git', 'status', '--porcelain'], text=True)),
        workload_source=('seeded synthetic Poisson arrivals with deterministic round-robin synthetic principals for bounded-user experiments; not calibrated to production traces'
            if cfg.dp_user_contribution_cap else
            'seeded synthetic Poisson arrivals; not calibrated to production traces'))
    claims = privacy_claims(cfg, policies, dp_noise_source)
    privacy_limit = (
        ('User IDs are verified with per-principal HMAC-SHA256 keys from an external registry; '
         'the registry is secret input and is not copied to the output. Exact replay is not '
         'deduplicated, but replayed requests remain subject to the same per-user cap. '
         'Each user contributes at most the configured request cap to the private scaling count. '
         if identity_authenticator else
         'User IDs are synthetic/account metadata assumed stable and non-spoofable; '
         'each user contributes at most the configured request cap to the private scaling count. ')
        if cfg.dp_user_contribution_cap else
        'No user-level contribution bound is enforced. ')
    report = dict(config=recorded_config, provenance=provenance, summary=summary, trial_metrics=trial_results,
        imported_runs=imports, positive_controls=positive, privacy_claims=claims,
        methodology='Known-policy diagonal nearest-centroid profiler on current, previous and cumulative observer counts/events only. First half independent sessions profile; second half test. Session classes balanced across each half; trial-pooled balanced recall. Equal-weight independent trial bootstrap with5000 resamples. Public function pool identities are visible. Demand task is binary latent session demand regime, not exact arrival recovery. Uniform workload has no hot-function task.',
        limitations='Function-affine fixed-service single-request workers; no runtime/ORAM/network integration. Simulated seconds, not measured service latency. Horizon-censored requests count as SLO violations; p95/p99 concern completed requests only. Price is a hypothetical configurable input. The legacy noisy policy has no adjacency/sensitivity/composition guarantee. The optional dp_laplace sampler has a conditional approximate-DP bound only for its declared fixed-horizon count/event observer with independent hidden uniform random bits; the recorded deterministic-seed experiment itself has no DP guarantee. This is not a formal code audit. ' + privacy_limit + 'No full-runtime guarantee or universal attack bound. Public count/event observer excludes queue, true arrivals, response latency, sampler execution timing/CPU, billing, active scheduling and joint transcripts. Imported repeated traces support performance only. Pareto membership uses point estimates, not significance tests. No policy dominance required or forced.')
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
    parser.add_argument('--identity-registry', type=Path,
                        help='private JSON mapping principal IDs to hex HMAC keys')
    args = parser.parse_args()
    if args.plot_only:
        plot(args.plot_only)
    elif args.config and args.output:
        report = run(args.config, args.output, args.identity_registry)
        print(json.dumps({'summaries': len(report['summary']), 'positive_controls': report['positive_controls'], 'wall_seconds': report['provenance']['elapsed_wall_seconds']}, indent=2))
    else:
        parser.error('CONFIG NEW_OUTPUT or --plot-only OUTPUT required')
