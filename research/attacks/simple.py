"""Simplified component attacks; no claim to reproduce IKK, IHOP or Cash."""
from collections import Counter
from dataclasses import dataclass
import numpy as np


@dataclass
class AttackResult:
    predictions: list
    scores: list
    metadata: dict


class FrequencyAttack:
    def run(self, trace, auxiliary_knowledge):
        counts = Counter(row["tag"] for row in trace)
        ranked = sorted(counts, key=lambda tag: (-counts[tag], tag))
        mapping = dict(zip(ranked, auxiliary_knowledge["ranked_labels"]))
        majority = auxiliary_knowledge["majority"]
        predictions = [mapping.get(row["tag"], majority) for row in trace]
        return AttackResult(predictions, [float(p == 1) for p in predictions], {
            "algorithm": "offline frequency rank matching; unmapped tags use majority",
            "knowledge": "label popularity ordering, no target-session labels",
            "features": ["tag"],
        })


class TrafficAttack:
    """Supervised decision stump; explicitly permitted independent profiling."""
    def fit(self, trace, known_profile_labels):
        labels = np.array(known_profile_labels)
        if len(trace) != len(labels) or not len(trace):
            raise ValueError("empty or mismatched profiling data")
        best = -1
        for feature in ["bytes", "latency_ns"]:
            values = np.array([row[feature] for row in trace], dtype=float)
            unique = np.unique(values)
            thresholds = (unique[:-1] + unique[1:]) / 2
            if not len(thresholds):
                thresholds = unique
            if len(thresholds) > 256:
                thresholds = np.quantile(thresholds, np.linspace(0, 1, 256))
            for threshold in thresholds:
                left = values <= threshold
                probabilities = [(labels[mask].sum()+1)/(mask.sum()+2) for mask in [left, ~left]]
                scores = np.where(left, probabilities[0], probabilities[1])
                accuracy = np.mean((scores > .5) == labels)
                if accuracy > best:
                    best = accuracy
                    self.model = (feature, float(threshold), *map(float, probabilities))
        return self

    def run(self, trace, auxiliary_knowledge):
        feature, threshold, left, right = self.model
        scores = [left if row[feature] <= threshold else right for row in trace]
        return AttackResult([int(score > .5) for score in scores], scores, {
            "algorithm": "supervised decision stump",
            "features_considered": ["bytes", "latency_ns"],
            "selected_feature": feature, "threshold": threshold,
            "knowledge": "public defenses and labeled independent profiling sessions",
            "scores": "Laplace-smoothed profiling class proportions; not calibrated guarantees",
        })


def split_sessions(sessions):
    keys = sorted(sessions)
    if len(keys) < 2:
        raise ValueError("need independent profiling and target sessions")
    midpoint = len(keys)//2
    return ({key: sessions[key] for key in keys[:midpoint]}, {key: sessions[key] for key in keys[midpoint:]})
