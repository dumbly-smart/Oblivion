"""Offline numerical label assignment; no protocol mutation or target interaction.

These are specified plug-in likelihood models, not SAP/IHOP reproductions.
"""
from itertools import permutations
import numpy as np
from scipy.optimize import linear_sum_assignment
from scipy.special import logsumexp


def statistics(observations, auxiliary, padded=False):
    """Build count + IID and count + Markov objectives without target labels."""
    k = len(auxiliary['counts'])
    tags = list(dict.fromkeys(row['tag'] for row in observations))
    m = len(tags)
    if not 1 <= m <= k <= 8:
        raise ValueError('bounded experiment requires 1 <= observed tags <= keywords <= 8')
    index = {tag: i for i, tag in enumerate(tags)}
    sequence = np.asarray([index[row['tag']] for row in observations], dtype=int)
    volumes = np.zeros(m)
    for tag, i in index.items():
        values = {row['count'] for row in observations if row['tag'] == tag}
        if len(values) != 1:
            raise ValueError('static-corpus model requires one count per search tag')
        volumes[i] = values.pop()
    n = int(auxiliary['corpus_documents'])
    if n <= 0 or np.any(volumes < 0) or (not padded and np.any(volumes > n)):
        raise ValueError('invalid public corpus bound or observed count')
    probability = (np.asarray(auxiliary['counts'], dtype=float) + .5) / (n + 1)
    if np.any(probability <= 0) or np.any(probability >= 1):
        raise ValueError('invalid auxiliary corpus counts')
    # Binomial coefficient depends on the observation, not its candidate label.
    count_log = volumes[:, None] * np.log(probability) + (n-volumes[:, None]) * np.log1p(-probability)
    if padded:
        count_log.fill(0)  # known fixed padding is not evidence of the real count
    profile = np.asarray(auxiliary['profile_labels'], dtype=int)
    if len(profile) < 2 or np.any(profile < 0) or np.any(profile >= k):
        raise ValueError('invalid independent public query profile')
    frequencies = np.bincount(profile, minlength=k)
    query_probability = (frequencies + 1) / (len(profile) + k)
    observed_frequency = np.bincount(sequence, minlength=m)
    iid = count_log + observed_frequency[:, None] * np.log(query_probability)
    transitions = np.ones((k, k))
    np.add.at(transitions, (profile[:-1], profile[1:]), 1)
    transitions /= transitions.sum(axis=1, keepdims=True)
    observed_transitions = np.zeros((m, m))
    np.add.at(observed_transitions, (sequence[:-1], sequence[1:]), 1)
    markov_unary = count_log.copy()
    markov_unary[sequence[0], :] += np.log(query_probability)
    return {'tags': tags, 'sequence': sequence, 'iid_unary': iid,
            'markov_unary': markov_unary, 'transition_counts': observed_transitions,
            'transition_log_probability': np.log(transitions)}


def objective(mapping, unary, transitions, log_probability):
    mapping = np.asarray(mapping, dtype=int)
    return float(unary[np.arange(len(mapping)), mapping].sum() +
                 (transitions * log_probability[mapping[:, None], mapping[None, :]]).sum())


def linear_assignment(unary):
    rows, labels = linear_sum_assignment(-unary)
    mapping = np.empty(len(unary), dtype=int)
    mapping[rows] = labels
    return mapping


def iterative_hungarian(stats, seed=0, iterations=200, free_size=3):
    """Freeze a complement, solve cross-complement LAP, accept full-objective gains.

    Interactions between distinct free tokens are omitted in the LAP only;
    the exact full objective controls acceptance. Missing candidate labels are
    allowed when some vocabulary items were not queried.
    """
    unary, transitions, logp = (stats[key] for key in
        ('markov_unary', 'transition_counts', 'transition_log_probability'))
    mapping = linear_assignment(stats['iid_unary'])
    value = objective(mapping, unary, transitions, logp)
    history = [value]
    rng = np.random.default_rng(seed)
    m, k = unary.shape
    for _ in range(iterations):
        free = np.sort(rng.choice(m, min(free_size, m), replace=False))
        fixed = np.asarray([i for i in range(m) if i not in set(free)], dtype=int)
        available = np.asarray([c for c in range(k) if c not in set(mapping[fixed])], dtype=int)
        score = unary[np.ix_(free, available)].copy()
        for row, token in enumerate(free):
            for column, label in enumerate(available):
                # Self-transition term is also linear in this token's label.
                score[row, column] += transitions[token, token] * logp[label, label]
                for other in fixed:
                    score[row, column] += transitions[token, other] * logp[label, mapping[other]]
                    score[row, column] += transitions[other, token] * logp[mapping[other], label]
        local_rows, local_labels = linear_sum_assignment(-score)
        candidate = mapping.copy()
        candidate[free[local_rows]] = available[local_labels]
        new_value = objective(candidate, unary, transitions, logp)
        if new_value > value + 1e-10:
            mapping, value = candidate, new_value
            history.append(value)
    return mapping, history


def exhaustive(stats, markov=False):
    """Exact bounded-vocabulary optimum and plug-in model posterior marginals."""
    unary = stats['markov_unary' if markov else 'iid_unary']
    m, k = unary.shape
    mappings = np.asarray(list(permutations(range(k), m)), dtype=int)
    scores = unary[np.arange(m)[None, :], mappings].sum(axis=1)
    if markov:
        transitions, logp = stats['transition_counts'], stats['transition_log_probability']
        for a in range(m):
            for b in range(m):
                scores += transitions[a, b] * logp[mappings[:, a], mappings[:, b]]
    weights = np.exp(scores - logsumexp(scores))
    marginals = np.zeros((m, k))
    for token in range(m):
        np.add.at(marginals[token], mappings[:, token], weights)
    return mappings[int(np.argmax(scores))], float(scores.max()), marginals


def infer(observations, auxiliary, padded=False, seed=0):
    stats = statistics(observations, auxiliary, padded)
    linear = linear_assignment(stats['iid_unary'])
    exact_iid, iid_value, iid_marginal = exhaustive(stats)
    if not np.isclose(stats['iid_unary'][np.arange(len(linear)), linear].sum(), iid_value):
        raise RuntimeError('Hungarian result does not attain enumerated linear optimum')
    approximate, history = iterative_hungarian(stats, seed)
    exact, exact_value, markov_marginal = exhaustive(stats, markov=True)
    result = {}
    for name, mapping, marginals in [('likelihood_assignment', linear, iid_marginal),
                                    ('iterative_hungarian_markov', approximate, markov_marginal),
                                    ('exact_markov_bound', exact, markov_marginal)]:
        # The optimizer's own mapping is first; remaining candidates follow the
        # exact posterior of the specified bounded model, explicitly disclosed.
        ranks = [[int(mapping[t])] + [int(c) for c in np.argsort(-marginals[t], kind='stable') if c != mapping[t]] for t in stats['sequence']]
        result[name] = {'rankings': ranks, 'mapping': mapping.tolist(),
                        'objective': (float(stats['iid_unary'][np.arange(len(mapping)), mapping].sum()) if name == 'likelihood_assignment' else objective(mapping, stats['markov_unary'], stats['transition_counts'], stats['transition_log_probability'])),
                        'exact_objective': iid_value if name == 'likelihood_assignment' else exact_value,
                        'posterior_marginals': marginals.tolist(),
                        'accepted_objective_history': history if name == 'iterative_hungarian_markov' else [],
                        'observed_tags': stats['tags']}
    return result
