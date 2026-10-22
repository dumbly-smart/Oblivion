"""Transparent SSE query recovery baselines; target truth is never an argument."""
from collections import Counter
import random


class CountVolumeAttack:
    """Nearest public-corpus count; public query prior breaks distance ties."""
    def run(self, observations, auxiliary, seed=0, pad_to=None):
        rng = random.Random(seed)
        counts = auxiliary["counts"]
        predictions = []
        for row in observations:
            # Knowing fixed padding removes the count evidence entirely.
            scores = [0 if pad_to is not None else abs(row["count"] - n) for n in counts]
            order = list(range(len(counts)))
            rng.shuffle(order)
            prior = auxiliary.get("query_counts", [0] * len(counts))
            order.sort(key=lambda label: (scores[label], -prior[label]))
            predictions.append(order)
        return predictions


class SearchPatternFrequencyAttack:
    """Offline stable-tag popularity ranking, not published MLE or IHOP."""
    def run(self, observations, auxiliary, seed=0, pad_to=None):
        rng = random.Random(seed)
        tags = list(dict.fromkeys(row["tag"] for row in observations))
        rng.shuffle(tags)
        frequencies = Counter(row["tag"] for row in observations)
        tags.sort(key=lambda tag: -frequencies[tag])
        labels = list(range(len(auxiliary["counts"])))
        rng.shuffle(labels)
        labels.sort(key=lambda label: -auxiliary["query_counts"][label])
        assigned = dict(zip(tags, labels))
        return [[assigned[row["tag"]]] + [label for label in labels if label != assigned[row["tag"]]] for row in observations]
