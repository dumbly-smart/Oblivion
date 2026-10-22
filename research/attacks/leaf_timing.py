"""Session-separated logical-record classifier from visible tags and durations."""
from collections import Counter
import math
from research.attacks.registry import PredictionResult

FIELDS = {'session', 'tag', 'bytes', 'latency_ns'}


def vectors(rows):
    if not isinstance(rows, list) or not 1 <= len(rows) <= 10_000:
        raise ValueError('bounded observer rows required')
    counts = Counter()
    totals = Counter()
    for row in rows:
        if not isinstance(row, dict) or set(row) != FIELDS or not isinstance(row['session'], str) or not 1 <= len(row['session']) <= 128:
            raise ValueError('strict observer schema required')
        for field in ('tag', 'bytes', 'latency_ns'):
            if type(row[field]) is not int or not 0 <= row[field] <= 10**15:
                raise ValueError('invalid observer metric')
        counts[row['session'], row['tag']] += 1
        totals[row['session']] += 1
    return [[counts[r['session'], r['tag']]/totals[r['session']], r['tag'], r['bytes'], math.log1p(r['latency_ns'])] for r in rows]


def sessions(rows, aux, key):
    if not isinstance(aux.get(key), list) or not aux[key] or any(not isinstance(s, str) for s in aux[key]) or set(aux[key]) != {r['session'] for r in rows}:
        raise ValueError('declare exact whole observer sessions')
    return set(aux[key])


class LeafTimingAttack:
    def fit(self, trace, aux):
        if not isinstance(aux, dict) or set(aux) != {'profile_labels', 'profile_session_ids'}:
            raise ValueError('profiling schema')
        x = vectors(trace)
        labels = aux['profile_labels']
        if not isinstance(labels, list) or len(labels) != len(x) or any(type(y) is not int or y not in (0, 1) for y in labels) or set(labels) != {0, 1}:
            raise ValueError('binary independent profiling labels required')
        self.profile_sessions = sessions(trace, aux, 'profile_session_ids')
        from sklearn.ensemble import RandomForestClassifier
        self.model = RandomForestClassifier(n_estimators=64, max_depth=6, min_samples_leaf=4, class_weight='balanced', random_state=1907, n_jobs=1).fit(x, labels)
        return self

    def run(self, trace, aux):
        if not isinstance(aux, dict) or set(aux) != {'target_session_ids'} or not hasattr(self, 'model'):
            raise ValueError('fit before running with target session identifiers')
        x = vectors(trace)
        if sessions(trace, aux, 'target_session_ids') & self.profile_sessions:
            raise ValueError('profile and target sessions must be disjoint')
        scores = self.model.predict_proba(x).tolist()
        return PredictionResult(self.model.predict(x).tolist(), None, dict(
            algorithm='64-tree bounded random forest', prediction_unit='logical-record class per access',
            score_semantics='UNCALIBRATED tree class proportions', original_scores=scores,
            features=['within-session visible tag frequency', 'visible tag/leaf', 'bytes', 'log1p visible duration ns'],
            knowledge='separately labeled complete profiling sessions; target tag frequencies are unlabeled transductive observations',
            limitations='Two logical-record classes only; no cryptographic security or full-sequence privacy claim.'))
