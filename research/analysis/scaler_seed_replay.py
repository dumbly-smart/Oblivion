"""Evaluate the seed-aware scaler attacker on retained public transcripts."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from research.attacks.scaler_seed_replay import public_policy_seed, seed_replay_features
from research.attacks.scaler_interval import interval_features
from research.simulation.run import score
from research.simulation.scaler import (Config, POLICIES, ProfileAttack, features,
    dp_laplace_parameters, session_features, trial_interval)


def read_jsonl(path):
    with gzip.open(path, 'rt', encoding='utf-8') as source:
        return [json.loads(line) for line in source]


def plot_summary(output, summary):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    panels = sorted({(row['workload'], row['task']) for row in summary})
    fig, axes = plt.subplots(1, len(panels), figsize=(max(6, 3.2 * len(panels)), 4),
                             squeeze=False)
    for axis, (workload, task) in zip(axes[0], panels):
        rows = [row for row in summary
                if row['workload'] == workload and row['task'] == task]
        labels = [f"{row['policy']}\n{row['attacker']}" for row in rows]
        means = [row['balanced_accuracy'] for row in rows]
        lower = [max(0., mean - row['balanced_accuracy_ci95'][0])
                 for mean, row in zip(means, rows)]
        upper = [max(0., row['balanced_accuracy_ci95'][1] - mean)
                 for mean, row in zip(means, rows)]
        colors = ['#4477aa' if row['policy'] == 'naive' else '#cc6677'
                  for row in rows]
        axis.bar(range(len(rows)), means, color=colors,
                 yerr=[lower, upper], capsize=2)
        axis.axhline(.5, color='black', linestyle='--', linewidth=.8)
        axis.set_xticks(range(len(rows)), labels, rotation=60, ha='right', fontsize=7)
        axis.set_ylim(0, 1)
        axis.set_title(f'{workload}: {task}')
        axis.set_ylabel('Balanced accuracy')
    fig.suptitle('Autoscaler workload inference: leaky control vs defense')
    fig.tight_layout()
    fig.savefig(output / 'attack-accuracy.png', dpi=160)
    plt.close(fig)


def classifier_score(profile, target, task, cfg, replay_seed, model='centroid',
                     random_state=1907, feature_mode='public'):
    if feature_mode == 'policy_interval':
        def feature(session):
            policy = session['policy']
            cap = (dp_laplace_parameters(cfg)['geometric_cap']
                   if policy == 'dp_laplace' else 0)
            intervals = interval_features(session['observer'], cfg, policy, cap)
            return np.hstack([session_features(session['observer']), intervals])
    elif feature_mode == 'public' and replay_seed:
        feature = lambda session: seed_replay_features(
            session['observer'], cfg, session['policy_seed'])
    elif feature_mode == 'public':
        feature = lambda session: session_features(session['observer'])
    else:
        raise ValueError('unknown scaler attack feature mode')
    x = np.vstack([feature(session) for session in profile])
    y = np.concatenate([np.asarray([label[task] for label in session['labels']])
                        for session in profile])
    if model == 'centroid':
        attack = ProfileAttack().fit(x, y)
    elif model == 'forest':
        from sklearn.ensemble import RandomForestClassifier
        attack = RandomForestClassifier(n_estimators=64, max_depth=6,
            min_samples_leaf=4, class_weight='balanced',
            random_state=int(random_state) % 2**32, n_jobs=1).fit(x, y)
    else:
        raise ValueError('unknown seed-replay attack model')
    majority = int(np.bincount(y).argmax())
    predictions, truths = [], []
    for session in target:
        truth = np.asarray([label[task] for label in session['labels']])
        predictions.append(attack.predict(feature(session)))
        truths.append(truth)
    return score(np.concatenate(predictions), np.concatenate(truths), majority)


def evaluate(source, output, models=('centroid', 'forest'), study_config=None):
    source = Path(source).resolve()
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError('choose a fresh analysis output directory')
    input_files = ['config.json', 'observer.jsonl.gz', 'workloads-private.jsonl.gz']
    input_hashes = {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                    for name in input_files}
    raw = json.loads((source / 'config.json').read_text())
    noise_source = raw.get('dp_noise_source', 'seeded_experiment')
    if noise_source not in ('seeded_experiment', 'os_csprng'):
        raise ValueError('unknown DP noise source in retained run')
    replay_applicable = noise_source == 'seeded_experiment'
    cfg = Config(**raw['simulation'])
    cfg.validate()
    study = None
    study_config_hash = None
    positive_control_min = 0.6
    include_policy_interval = False
    if study_config is not None:
        study_config = Path(study_config).resolve()
        study = json.loads(study_config.read_text())
        required = {
            'version', 'study_id', 'dp_noise_source', 'trials', 'sessions',
            'profile_sessions', 'target_sessions', 'models', 'feature_modes',
            'primary_metric', 'positive_control_min',
        }
        if not isinstance(study, dict) or set(study) != required:
            raise ValueError('invalid predeclared scaler attack configuration schema')
        if (study['version'] != 1 or not isinstance(study['study_id'], str)
                or not study['study_id'] or study['dp_noise_source'] != noise_source
                or study['trials'] != raw['trials'] or study['sessions'] != raw['sessions']
                or study['profile_sessions'] + study['target_sessions'] != raw['sessions']
                or study['profile_sessions'] != raw['sessions'] // 2
                or study['target_sessions'] != raw['sessions'] - raw['sessions'] // 2
                or study['models'] != list(models)
                or not isinstance(study['feature_modes'], list)
                or study['feature_modes'] != ['public', 'policy_interval']
                or study['primary_metric'] != 'balanced_accuracy'
                or not isinstance(study['positive_control_min'], (int, float))
                or not 0 <= study['positive_control_min'] <= 1):
            raise ValueError('predeclared scaler attack configuration does not match raw run')
        study_config_hash = hashlib.sha256(study_config.read_bytes()).hexdigest()
        positive_control_min = float(study['positive_control_min'])
        include_policy_interval = 'policy_interval' in study['feature_modes']
    policies = raw.get('policies', ['naive', 'ewma', 'quantized', 'fixed', 'noisy'])
    if 'dp_laplace' not in policies or 'naive' not in policies:
        raise ValueError('seed-replay analysis requires dp_laplace and naive positive control')
    if set(policies) - set(POLICIES) or len(set(policies)) != len(policies):
        raise ValueError('input configuration contains invalid policies')
    if (not models or len(set(models)) != len(models)
            or set(models) - {'centroid', 'forest'}):
        raise ValueError('models must select centroid and/or forest classifiers')
    expected_observers = {(trial, session, workload, policy)
        for trial in range(raw['trials']) for session in range(raw['sessions'])
        for workload in raw['workloads'] for policy in policies}
    expected_truths = {(trial, session, workload)
        for trial in range(raw['trials']) for session in range(raw['sessions'])
        for workload in raw['workloads']}

    observers = {}
    for row in read_jsonl(source / 'observer.jsonl.gz'):
        if not isinstance(row, dict) or set(row) != {'trial', 'session', 'workload', 'policy', 'rows'}:
            raise ValueError('invalid public observer session schema')
        key = (row['trial'], row['session'], row['workload'], row['policy'])
        if key not in expected_observers or key in observers:
            raise ValueError('duplicate or out-of-range public session')
        if not isinstance(row['rows'], list) or len(row['rows']) != int(np.ceil(cfg.duration / cfg.epoch)):
            raise ValueError('public session does not cover the fixed horizon')
        for epoch, event in enumerate(row['rows']):
            features(event)
            if type(event['epoch']) is not int or event['epoch'] != epoch:
                raise ValueError('public observer epochs are not ordered')
        observers[key] = row['rows']
    if set(observers) != expected_observers:
        raise ValueError('incomplete public observer session set')
    truths = {}
    for row in read_jsonl(source / 'workloads-private.jsonl.gz'):
        if not isinstance(row, dict) or set(row) != {'trial', 'session', 'workload', 'seed', 'labels', 'requests'}:
            raise ValueError('invalid private label session schema')
        key = (row['trial'], row['session'], row['workload'])
        if key not in expected_truths or key in truths:
            raise ValueError('duplicate or out-of-range private label session')
        if not isinstance(row['labels'], list) or len(row['labels']) != int(np.ceil(cfg.duration / cfg.epoch)):
            raise ValueError('private labels do not cover the fixed horizon')
        truths[key] = row['labels']
    if set(truths) != expected_truths:
        raise ValueError('incomplete private label session set')

    task_names = lambda workload: ['intensity'] + ([] if workload == 'uniform' else ['hot'])
    trial_metrics = []
    for trial in range(raw['trials']):
        for workload in raw['workloads']:
            workload_index = raw['workloads'].index(workload)
            session_sets = {}
            for policy in ('naive', 'dp_laplace'):
                sessions = []
                for session in range(raw['sessions']):
                    key = (trial, session, workload, policy)
                    truth_key = key[:3]
                    if key not in observers or truth_key not in truths:
                        raise ValueError('incomplete observer/label session set')
                    session_record = dict(observer=observers[key], labels=truths[truth_key],
                        policy=policy)
                    if replay_applicable:
                        session_record['policy_seed'] = public_policy_seed(
                            raw['seed'], trial, session, workload_index)
                    sessions.append(session_record)
                session_sets[policy] = sessions
            split = raw['sessions'] // 2
            for task in task_names(workload):
                profile, target = session_sets['naive'][:split], session_sets['naive'][split:]
                for model in models:
                    result = classifier_score(profile, target, task, cfg,
                        replay_seed=False, model=model, random_state=raw['seed'] + trial)
                    trial_metrics.append(dict(trial=trial, workload=workload, task=task,
                        policy='naive', attacker=f'{model}_public', **result))
                    if include_policy_interval:
                        interval_result = classifier_score(profile, target, task, cfg,
                            replay_seed=False, model=model, random_state=raw['seed'] + trial,
                            feature_mode='policy_interval')
                        trial_metrics.append(dict(trial=trial, workload=workload, task=task,
                            policy='naive', attacker=f'{model}_interval', **interval_result))
                profile, target = session_sets['dp_laplace'][:split], session_sets['dp_laplace'][split:]
                for model in models:
                    for replay in ((False, True) if replay_applicable else (False,)):
                        suffix = '_seed_replay' if replay else '_public'
                        attacker_name = f'{model}{suffix}'
                        result = classifier_score(profile, target, task, cfg,
                            replay_seed=replay, model=model, random_state=raw['seed'] + trial)
                        trial_metrics.append(dict(trial=trial, workload=workload, task=task,
                            policy='dp_laplace', attacker=attacker_name, **result))
                    if include_policy_interval:
                        interval_result = classifier_score(profile, target, task, cfg,
                            replay_seed=False, model=model, random_state=raw['seed'] + trial,
                            feature_mode='policy_interval')
                        trial_metrics.append(dict(trial=trial, workload=workload, task=task,
                            policy='dp_laplace', attacker=f'{model}_interval', **interval_result))

    summary = []
    for workload in raw['workloads']:
        for task in task_names(workload):
            for policy in ('naive', 'dp_laplace'):
                modes = ('public', 'seed_replay') if replay_applicable else ('public',)
                naive_modes = ('public', 'interval') if include_policy_interval else ('public',)
                dp_modes = (('public', 'seed_replay') if replay_applicable else ('public',))
                if include_policy_interval:
                    dp_modes += ('interval',)
                attackers = ([f'{model}_{mode}' for model in models
                              for mode in naive_modes]
                    if policy == 'naive' else [
                        f'{model}_{mode}' for model in models for mode in dp_modes])
                for attacker in attackers:
                    group = [row for row in trial_metrics if
                        (row['workload'], row['task'], row['policy'], row['attacker']) ==
                        (workload, task, policy, attacker)]
                    point = dict(workload=workload, task=task, policy=policy,
                        attacker=attacker, independent_trials=len(group))
                    for metric in ('accuracy', 'balanced_accuracy'):
                        point[metric] = float(np.mean([row[metric] for row in group]))
                        point[metric + '_ci95'] = trial_interval([[row[metric]] for row in group])
                    point['majority_accuracy'] = float(np.mean([row['majority_accuracy'] for row in group]))
                    point['balanced_chance'] = 0.5
                    summary.append(point)

    positive_controls = [dict(workload=row['workload'], task=row['task'],
        balanced_accuracy=row['balanced_accuracy'],
        passed=row['balanced_accuracy'] > positive_control_min)
        for row in summary if row['policy'] == 'naive']
    paired_feature_differences = []
    for workload in raw['workloads'] if include_policy_interval else ():
        for task in task_names(workload):
            for policy in ('naive', 'dp_laplace'):
                for model in models:
                    public = {
                        row['trial']: row['balanced_accuracy']
                        for row in trial_metrics
                        if (row['workload'], row['task'], row['policy'], row['attacker'])
                        == (workload, task, policy, f'{model}_public')
                    }
                    interval = {
                        row['trial']: row['balanced_accuracy']
                        for row in trial_metrics
                        if (row['workload'], row['task'], row['policy'], row['attacker'])
                        == (workload, task, policy, f'{model}_interval')
                    }
                    if set(public) != set(interval) or not public:
                        raise ValueError('paired public/interval trial set is incomplete')
                    differences = [interval[trial] - public[trial]
                                   for trial in sorted(public)]
                    paired_feature_differences.append(dict(
                        workload=workload, task=task, policy=policy, model=model,
                        independent_trials=len(differences),
                        balanced_accuracy_difference_mean=float(np.mean(differences)),
                        balanced_accuracy_difference_ci95=trial_interval(
                            [[value] for value in differences]),
                    ))
    source_files = ['research/attacks/scaler_seed_replay.py',
                    'research/attacks/scaler_interval.py',
                    'research/analysis/scaler_seed_replay.py',
                    'research/simulation/scaler.py',
                    'research/simulation/run.py']
    if input_hashes != {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                        for name in input_files}:
        raise ValueError('input artifacts changed during attack evaluation')
    interval_method = (' Policy-interval variants additionally derive conservative hidden-arrival intervals from public capacity transitions, public policy parameters and the sampler noise support; they do not replay or infer the noise draw.'
        if include_policy_interval else '')
    methodology = ('Whole-session known-policy attacks. First half sessions profile; second half are held out. Public variants use public per-epoch features.' + interval_method + ' Seed-replay variants regenerate the public deterministic discrete-geometric stream from the public seed derivation and invert public scale-up transitions, with capacity quantization and maximum clipping producing censored estimates. Labels are used for profile training and target scoring only.'
        if replay_applicable else
        'Whole-session known-policy attacks. First half sessions profile; second half are held out. Public variants use public per-epoch features.' + interval_method + ' For os_csprng, known-seed replay is skipped because the public experiment seed does not determine the OS-CSPRNG noise stream. Labels are used for profile training and target scoring only.')
    limitations = ('The retained DP-labeled transcript is deterministic because the seed is public, so its randomized-mechanism DP claim does not apply. This attack estimates EWMA signals from quantized capacity transitions and may lose information to clipping; failure to classify does not establish privacy. The naive arm is the leaky positive control. The experiment excludes latency, errors, billing, network and runtime observations.'
        if replay_applicable else
        'The OS-CSPRNG transcript cannot be replayed from the public seed. ' + ('Interval features are conservative deterministic transforms of public counts, not additional observations or an optimal likelihood attack; capacity censoring can make them uninformative. ' if include_policy_interval else '') + 'Its sampler has a conditional approximate-DP bound under independent uniform bits, but this analysis is not an independent implementation audit. Failure to classify does not establish privacy. The naive arm is the leaky positive control. The experiment excludes latency, sampler timing/CPU, errors, billing, network and runtime observations.')
    report = dict(config=raw, dp_noise_source=noise_source,
        known_seed_replay_applicable=replay_applicable,
        input_sha256=input_hashes, source_sha256={name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in source_files}, git_head=subprocess.check_output(
        ['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        git_dirty=bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True)),
        python=platform.python_version(), platform=platform.platform(), summary=summary,
        trial_metrics=trial_metrics, positive_controls=positive_controls,
        paired_feature_differences=paired_feature_differences,
        attack_models=list(models), attack_feature_modes=['public']
            + (['policy_interval'] if include_policy_interval else [])
            + (['seed_replay'] if replay_applicable else []),
        study_configuration=study, study_config_sha256=study_config_hash,
        positive_control_min=positive_control_min,
        methodology=methodology, limitations=limitations)
    output.mkdir(parents=True)
    if study is not None:
        (output / 'study-config.json').write_text(json.dumps(study, indent=2) + '\n')
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    plot_summary(output, summary)
    manifest = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in output.iterdir() if path.is_file()}
    (output / 'artifact-sha256.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('raw_source', type=Path)
    parser.add_argument('new_output', type=Path)
    parser.add_argument('--study-config', type=Path)
    args = parser.parse_args()
    result = evaluate(args.raw_source, args.new_output, study_config=args.study_config)
    print(json.dumps({'summaries': len(result['summary']),
        'positive_controls': result['positive_controls']}, indent=2))
