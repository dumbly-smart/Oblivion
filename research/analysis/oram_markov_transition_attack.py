"""Profile-based one-step transition attack for ORAM traces."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.metrics import accuracy_score, balanced_accuracy_score, roc_auc_score

from research.analysis.oram_isolated_replication import bootstrap_interval, load_trial


class MarkovTransitionAttack:
    """Estimate the next access label from the preceding visible tag only."""

    def fit(self, trace, labels):
        if not isinstance(trace, list) or not isinstance(labels, list) or len(trace) != len(labels):
            raise ValueError("profile rows and labels must be aligned lists")
        if not trace or any(type(label) is not int or label not in (0, 1) for label in labels):
            raise ValueError("non-empty binary labeled profiling trace required")
        paired = _paired_sessions(trace, labels)
        if set(labels) != {0, 1}:
            raise ValueError("both profiling classes are required")

        self.profile_sessions = set(paired)
        self.prior_hot = float(sum(labels) / len(labels))
        self.transitions = defaultdict(Counter)
        for sequence in paired.values():
            for previous, current in zip(sequence, sequence[1:]):
                self.transitions[previous[0]["tag"]][current[1]] += 1
        return self

    def run(self, trace, target_sessions):
        if not hasattr(self, "transitions") or not isinstance(target_sessions, set) or not target_sessions:
            raise ValueError("fit first and supply target whole-session identifiers")
        paired = _paired_sessions(trace)
        if set(paired) != target_sessions:
            raise ValueError("target whole-session identifiers must match observer rows")
        if self.profile_sessions & target_sessions:
            raise ValueError("profile and target sessions must be disjoint")

        scores = []
        for sequence in paired.values():
            scores.append(self.prior_hot)
            for previous, _current in zip(sequence, sequence[1:]):
                counts = self.transitions.get(previous[0]["tag"], {})
                total = sum(counts.values())
                # One prior pseudo-observation keeps rare transitions finite.
                scores.append((counts.get(1, 0) + self.prior_hot) / (total + 1.0))
        predictions = [int(score >= 0.5) for score in scores]
        return predictions, scores


def _paired_sessions(trace, labels=None):
    if not isinstance(trace, list) or not trace:
        raise ValueError("non-empty attacker-visible trace required")
    if labels is not None and (not isinstance(labels, list) or len(labels) != len(trace)):
        raise ValueError("profile rows and labels must be aligned lists")
    grouped = defaultdict(list)
    required = {"session", "step", "tag", "bytes", "latency_ns"}
    for index, row in enumerate(trace):
        if (not isinstance(row, dict) or set(row) != required
                or not isinstance(row["session"], str)
                or any(type(row[key]) is not int or row[key] < 0
                       for key in ("step", "tag", "bytes", "latency_ns"))):
            raise ValueError("strict attacker-visible operation rows required")
        label = None if labels is None else labels[index]
        grouped[row["session"]].append((row, label))
    result = {}
    for session, items in grouped.items():
        items.sort(key=lambda item: item[0]["step"])
        if [item[0]["step"] for item in items] != list(range(len(items))):
            raise ValueError("attacker-visible steps must be contiguous")
        result[session] = items
    return result


def _digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def analysis_provenance(protocol_status):
    if protocol_status == "post-hoc":
        return {
            "protocol_status": protocol_status,
            "analysis": "post-hoc exploratory one-step profile transition lookup",
            "limitations": (
                "This analysis was selected after seeing the primary result and reuses the same "
                "experimental collection; it is post-hoc, not an independent data collection. "
                "The attack is a simple profile-based lookup, not a reproduction of a published "
                "attack. Near-chance scores do not prove cryptographic security or exclude other attacks."
            ),
        }
    if protocol_status == "preregistered-secondary":
        return {
            "protocol_status": protocol_status,
            "analysis": "preregistered secondary one-step profile transition lookup",
            "limitations": (
                "The transition attack and metric were specified before collection. This secondary "
                "analysis uses the same experimental collection as the primary temporal study and "
                "is not an independent collection from that primary analysis. The attack is a simple "
                "profile-based lookup, not a reproduction of a published attack. Near-chance scores "
                "do not prove cryptographic security or exclude other attacks."
            ),
        }
    raise ValueError("unsupported protocol status")


def run_study(raw_root, config_path, output, protocol_status="post-hoc"):
    raw_root, config_path, output = Path(raw_root), Path(config_path), Path(output)
    provenance = analysis_provenance(protocol_status)
    config = json.loads(config_path.read_text())
    if output.exists():
        raise ValueError("output directory must be new")
    output.mkdir(parents=True)
    (output / "predictions").mkdir()

    summaries, all_trials = [], []
    modes = ("plaintext", "encrypt_only")
    for mode in modes:
        summary, trials = _evaluate_mode(mode, raw_root, config, output)
        summaries.append(summary)
        all_trials.extend(trials)
    controls_passed = all(
        row["auc_mean"] >= 0.80 and row["auc_ci95_trials"][0] > 0.5
        for row in summaries
    )
    if controls_passed:
        summary, trials = _evaluate_mode("oram", raw_root, config, output)
        summaries.append(summary)
        all_trials.extend(trials)

    raw_hashes = {
        str(path.relative_to(raw_root)): _digest(path)
        for path in sorted(raw_root.rglob("*.jsonl.gz"))
    }
    if not raw_hashes:
        raise ValueError("no compressed input traces found")
    report = {
        **provenance,
        "sessions_reused_from_primary_study": True,
        "positive_controls_passed": controls_passed,
        "defense_evaluated": controls_passed,
        "primary_metric": "mean per-trial ROC AUC with 5000-resample percentile bootstrap over trials",
        "attacker": "For each target operation, use only the immediately preceding visible storage tag. Profile labeled sessions map that tag to the next hot/cold label with a single prior pseudo-observation; the first target operation uses the profile class prior.",
        "target_labels": f"logical address in configured hot set {config['hot_addresses']} versus remaining addresses",
        "features": ["immediately previous visible bucket/leaf identifier"],
        "attacker_training": "first half of each trial's whole sessions, with driver labels; target sessions are disjoint and labels are used only for scoring",
        "configuration": config,
        "summary": summaries,
        "trials": all_trials,
        "input_raw_sha256": raw_hashes,
        "source_sha256": {
            "research/analysis/oram_markov_transition_attack.py": _digest(__file__),
            "research/analysis/oram_isolated_replication.py": _digest(
                Path(__file__).with_name("oram_isolated_replication.py")
            ),
            "research/attacks/leaf_timing.py": _digest(
                Path(__file__).parents[1] / "attacks" / "leaf_timing.py"
            ),
            str(config_path): _digest(config_path),
        },
    }
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(6, 4))
    x = np.arange(len(summaries))
    means = np.array([row["auc_mean"] for row in summaries])
    intervals = np.array([row["auc_ci95_trials"] for row in summaries]).T
    ax.bar(x, means, color=["#c25e44", "#c25e44", "#366c95"][:len(x)])
    ax.errorbar(x, means, yerr=np.maximum(0, np.array([means - intervals[0], intervals[1] - means])),
                fmt="none", color="black", capsize=4)
    ax.axhline(0.5, color="gray", linestyle="--")
    ax.set(xticks=x, xticklabels=[row["mode"] for row in summaries], ylabel="AUC", ylim=(0, 1.05))
    fig.tight_layout()
    fig.savefig(output / "attack-auc.png", dpi=150)
    plt.close(fig)
    return report


def _evaluate_mode(mode, raw_root, config, output):
    rows_out = []
    prediction_dir = output / "predictions" / mode
    prediction_dir.mkdir()
    for trial in range(config["trials"]):
        rows, labels, session_ids = load_trial(
            raw_root, mode, trial, config["sessions_per_trial"], config["hot_addresses"]
        )
        profile_count = config["sessions_per_trial"] // 2
        profile_ids = set(session_ids[:profile_count])
        target_ids = set(session_ids[profile_count:])
        profile_rows = [row for row in rows if row["session"] in profile_ids]
        target_rows = [row for row in rows if row["session"] in target_ids]
        profile_labels = [label for row, label in zip(rows, labels) if row["session"] in profile_ids]
        target_labels = [label for row, label in zip(rows, labels) if row["session"] in target_ids]
        attack = MarkovTransitionAttack().fit(profile_rows, profile_labels)
        predicted, scores = attack.run(target_rows, target_ids)
        majority = int(attack.prior_hot >= 0.5)
        row = {
            "trial": trial,
            "mode": mode,
            "auc": float(roc_auc_score(target_labels, scores)),
            "accuracy": float(accuracy_score(target_labels, predicted)),
            "balanced_accuracy": float(balanced_accuracy_score(target_labels, predicted)),
            "profile_majority_accuracy": float(accuracy_score(target_labels, [majority] * len(target_labels))),
            "profile_sessions": sorted(profile_ids),
            "target_sessions": sorted(target_ids),
        }
        rows_out.append(row)
        with gzip.open(prediction_dir / f"trial-{trial:02}.json.gz", "wt", encoding="utf-8") as stream:
            json.dump({"target_sessions": sorted(target_ids), "predictions": predicted, "scores": scores}, stream)
    return ({
        "mode": mode,
        "trials": len(rows_out),
        "auc_mean": float(np.mean([row["auc"] for row in rows_out])),
        "auc_ci95_trials": bootstrap_interval([row["auc"] for row in rows_out], config["seed"] + 101),
        "balanced_accuracy_mean": float(np.mean([row["balanced_accuracy"] for row in rows_out])),
        "accuracy_mean": float(np.mean([row["accuracy"] for row in rows_out])),
        "profile_majority_accuracy_mean": float(np.mean([row["profile_majority_accuracy"] for row in rows_out])),
    }, rows_out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", required=True, help="raw/ directory from the Markov replication")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--protocol-status",
        choices=("post-hoc", "preregistered-secondary"),
        default="post-hoc",
        help="how the attack and metric were selected relative to data collection",
    )
    args = parser.parse_args()
    report = run_study(args.raw, args.config, args.output, args.protocol_status)
    print(json.dumps({"output": str(args.output), "positive_controls_passed": report["positive_controls_passed"], "summary": report["summary"]}))


if __name__ == "__main__":
    main()
