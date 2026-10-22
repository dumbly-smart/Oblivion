"""Strict, offline adapters for the repository's existing baseline algorithms.

No algorithm or existing analysis is replaced. Confidence is deliberately absent:
raw scores and model posteriors are not calibrated success probabilities.
"""
from dataclasses import dataclass, asdict
import math
from typing import Callable, Protocol

MAX_ROWS = 10_000
MAX_LABELS = 256
MAX_VALUE = 10**15
JOINT_FEATURES = ('request_bytes', 'response_bytes', 'registry_bytes', 'registry_index',
                  'storage_events', 'storage_bytes', 'last_bucket', 'storage_span_ns',
                  'latency_ns', 'late_by_ns', 'instance_count', 'cold_start_ns')
INFERENCE_NAMES = {'likelihood': 'likelihood_assignment',
                   'iterativeLAP': 'iterative_hungarian_markov',
                   'exactboundedcomparison': 'exact_markov_bound'}
LIMITATIONS = 'Simple offline approximation; not a published attack reproduction. No calibrated probability or security proof.'


@dataclass
class PredictionResult:
    predictions: list
    confidence: list | None
    metadata: dict

    def to_dict(self):
        return asdict(self)


class Attack(Protocol):
    """A plugin consumes observer data plus explicit auxiliary knowledge."""
    def run(self, trace: list[dict], aux: dict) -> PredictionResult: ...


@dataclass(frozen=True)
class AttackSpec:
    name: str
    description: str
    observation_fields: tuple[str, ...]
    auxiliary_fields: tuple[str, ...]
    supports_fit: bool = False
    limitations: str = LIMITATIONS


_REGISTRY: dict[str, tuple[AttackSpec, Callable[[], Attack]]] = {}


def register_attack(spec: AttackSpec, factory: Callable[[], Attack]):
    """Register a zero-argument plugin factory; duplicate names are errors.

    Plugins are responsible for enforcing their declared input schema and bounds.
    """
    if not isinstance(spec, AttackSpec) or not spec.name or not callable(factory):
        raise ValueError('expected an AttackSpec and a callable factory')
    if spec.name in _REGISTRY:
        raise ValueError(f'attack already registered: {spec.name}')
    _REGISTRY[spec.name] = (spec, factory)


def list_attacks():
    """Stable JSON descriptions, without importing optional numerical packages."""
    return [dict(asdict(_REGISTRY[name][0]),
                 observation_fields=list(_REGISTRY[name][0].observation_fields),
                 auxiliary_fields=list(_REGISTRY[name][0].auxiliary_fields))
            for name in sorted(_REGISTRY)]


def create_attack(name: str) -> Attack:
    try:
        factory = _REGISTRY[name][1]
    except KeyError:
        raise ValueError(f'unknown attack: {name}') from None
    return factory()


def _object(value, allowed, required=()):
    if not isinstance(value, dict) or set(value) - set(allowed) or set(required) - set(value):
        raise ValueError(f'expected object with fields {sorted(allowed)}; required {sorted(required)}')


def _number(value, integer=False, upper=MAX_VALUE):
    if type(value) not in (int, float) or not 0 <= value <= upper or not math.isfinite(value):
        raise ValueError('expected a finite bounded nonnegative number')
    if integer and type(value) is not int:
        raise ValueError('expected an integer')


def _array(value, lower=1, upper=MAX_ROWS):
    if not isinstance(value, list) or not lower <= len(value) <= upper:
        raise ValueError(f'expected a list with {lower}..{upper} entries')


def _tag(value):
    if type(value) is int:
        _number(value, integer=True)
    elif not isinstance(value, str) or not 1 <= len(value) <= 256:
        raise ValueError('expected a bounded string or nonnegative integer tag')


def _sessions(value):
    _array(value)
    for item in value:
        _tag(item)
    return set(value)


def _rows(trace, fields, required):
    _array(trace)
    for row in trace:
        _object(row, fields, required)
        for key, value in row.items():
            if key == 'tag':
                _tag(value)
            else:
                _number(value, integer=key == 'count')
    if 'tag' in fields:
        # The original frequency matcher sorts tied tags, requiring one type.
        if len({type(row['tag']) for row in trace if 'tag' in row}) > 1:
            raise ValueError('all tags must have the same scalar type')


def _opaque(value):
    _array(value, upper=256)
    for part in value:
        _number(part, integer=True, upper=255)


def _link_rows(trace, mode):
    _array(trace)
    total_entries = 0
    for row in trace:
        _object(row, ('mode', 'phase', 'slot', 'injection', 'request', 'response'), ('mode', 'phase', 'request'))
        if not isinstance(row['mode'], str) or not 1 <= len(row['mode']) <= 64:
            raise ValueError('invalid local mode')
        phase = row['phase']
        if phase not in ('past_search', 'fresh_search', 'injected_update'):
            raise ValueError('invalid observation phase')
        if phase == 'injected_update':
            _object(row['request'], ('address', 'stable_tag'), ('address',))
        else:
            _object(row, ('mode', 'phase', 'slot', 'request', 'response'), ('slot', 'response', 'mode', 'phase', 'request'))
            _object(row['request'], ('tag',), ('tag',))
        for key in ('slot', 'injection'):
            if key in row:
                _number(row[key], integer=True)
        for value in row['request'].values():
            _opaque(value)
        if 'response' in row:
            _object(row['response'], ('entries',), ('entries',))
            entries = row['response']['entries']
            _array(entries, lower=0)
            total_entries += len(entries)
            if total_entries > MAX_ROWS:
                raise ValueError('too many posting entries')
            for entry in entries:
                _object(entry, ('address', 'ciphertext'), ('address',))
                for value in entry.values():
                    _opaque(value)
    selected = [r for r in trace if r['mode'] == mode]
    old = [r for r in selected if r['phase'] == 'past_search']
    fresh = [r for r in selected if r['phase'] == 'fresh_search']
    tags = [tuple(r['request']['tag']) for r in old]
    if len(tags) != len(set(tags)) or len({r['slot'] for r in old}) != len(old):
        raise ValueError('ambiguous past observer slots or tags')
    if any(tuple(r['request']['tag']) not in tags for r in fresh):
        raise ValueError('fresh observation has no past observer tag')


class _Adapter:
    def __init__(self, name):
        self.name = name
        self.spec = _REGISTRY[name][0]
        self.model = None
        self.profile_sessions = set()

    def fit(self, trace, aux):
        if not self.spec.supports_fit:
            raise ValueError('this adapter has no fit stage')
        _rows(trace, self.spec.observation_fields, self.spec.observation_fields)
        _object(aux, ('profile_labels', 'profile_session_ids'), ('profile_labels', 'profile_session_ids'))
        sessions = _sessions(aux['profile_session_ids'])
        labels = aux['profile_labels']
        _array(labels)
        if len(labels) != len(trace):
            raise ValueError('mismatched independent profiling labels')
        for label in labels:
            _number(label, integer=True, upper=2 if self.name == 'joint' else 1)
        if self.name == 'traffic':
            from research.attacks.simple import TrafficAttack
            model = TrafficAttack()
        else:
            from research.attacks.joint import JointAttack
            model = JointAttack()
        model.fit(trace, labels)
        self.model, self.profile_sessions = model, sessions
        return self

    def _validate(self, trace, aux):
        _object(aux, self.spec.auxiliary_fields)
        if self.name == 'chosenupdateassociation':
            _link_rows(trace, aux.get('mode'))
            if not isinstance(aux.get('mode'), str) or not 1 <= len(aux['mode']) <= 64:
                raise ValueError('mode is required')
        else:
            required = self.spec.observation_fields
            if self.name == 'count':
                required = ('count',)
            _rows(trace, self.spec.observation_fields, required)
        if 'seed' in aux:
            _number(aux['seed'], integer=True, upper=2**32-1)
        if 'pad_to' in aux and aux['pad_to'] is not None:
            _number(aux['pad_to'], integer=True)
        if 'padded' in aux and type(aux['padded']) is not bool:
            raise ValueError('padded must be a boolean')
        if self.spec.supports_fit:
            if self.model is None:
                raise ValueError('fit on independent profiling sessions before run')
            target = _sessions(aux.get('target_session_ids'))
            if target & self.profile_sessions:
                raise ValueError('profiling and target sessions must be disjoint')
        elif self.name == 'frequency':
            labels = aux.get('ranked_labels')
            _array(labels, upper=MAX_LABELS)
            for label in labels:
                _number(label, integer=True, upper=MAX_LABELS-1)
            _number(aux.get('majority'), integer=True, upper=MAX_LABELS-1)
            if len(set(labels)) != len(labels) or aux['majority'] not in labels:
                raise ValueError('label ranking must be unique and include majority')
        elif self.name != 'chosenupdateassociation':
            counts = aux.get('counts')
            _array(counts, upper=8 if self.name in INFERENCE_NAMES else MAX_LABELS)
            for value in counts:
                _number(value, integer=True)
            if 'query_counts' in aux:
                _array(aux['query_counts'], upper=MAX_LABELS)
                if len(aux['query_counts']) != len(counts):
                    raise ValueError('query count vocabulary mismatch')
                for value in aux['query_counts']:
                    _number(value, integer=True)
            if self.name == 'searchpattern':
                if 'query_counts' not in aux or len({r['tag'] for r in trace}) > len(counts):
                    raise ValueError('need query prior and enough candidate labels for observed tags')
            if self.name in INFERENCE_NAMES:
                _number(aux.get('corpus_documents'), integer=True)
                if not aux['corpus_documents'] or any(n > aux['corpus_documents'] for n in counts):
                    raise ValueError('counts exceed public corpus bound')
                profile = aux.get('profile_labels')
                _array(profile, lower=2)
                for label in profile:
                    _number(label, integer=True, upper=len(counts)-1)

    def run(self, trace, aux):
        self._validate(trace, aux)
        metadata = {'adapter': self.name, 'limitations': LIMITATIONS,
                    'confidence_semantics': 'unavailable; raw scores/ranks/posteriors are UNCALIBRATED',
                    'prediction_unit': 'observation'}
        if self.name in ('frequency', 'traffic', 'joint'):
            if self.name == 'frequency':
                from research.attacks.simple import FrequencyAttack
                model = FrequencyAttack()
            else:
                model = self.model
            result = model.run(trace, aux)
            metadata.update(original_metadata=result.metadata, original_scores=result.scores)
            return PredictionResult(result.predictions, None, metadata)
        if self.name in ('count', 'searchpattern'):
            from research.attacks.sse import CountVolumeAttack, SearchPatternFrequencyAttack
            model = CountVolumeAttack() if self.name == 'count' else SearchPatternFrequencyAttack()
            ranks = model.run(trace, aux, seed=aux.get('seed', 0), pad_to=aux.get('pad_to'))
            metadata['rankings'] = ranks
            return PredictionResult([r[0] for r in ranks], None, metadata)
        if self.name in INFERENCE_NAMES:
            from research.attacks.inference import infer
            result = infer(trace, aux, padded=aux.get('padded', False), seed=aux.get('seed', 0))[INFERENCE_NAMES[self.name]]
            metadata.update(rankings=result['rankings'], original_result=result,
                            optimizer_scope='existing infer computes all three bounded comparisons')
            return PredictionResult([r[0] for r in result['rankings']], None, metadata)
        from research.attacks.linkability import recover_links
        result = recover_links(trace, aux['mode'], seed=aux.get('seed', 0))
        metadata.update(original_result=result, prediction_unit='injected_update',
                        prediction_stage='before fresh search; after-stage predictions retained in original_result')
        return PredictionResult(result['before_predictions'], None, metadata)


for _spec in [
    AttackSpec('frequency', 'Opaque-tag frequency rank matcher', ('tag',), ('ranked_labels', 'majority')),
    AttackSpec('traffic', 'Independent-profile supervised decision stump', ('bytes', 'latency_ns'), ('target_session_ids',), True),
    AttackSpec('joint', 'Independent-profile bounded classification forest', JOINT_FEATURES, ('target_session_ids',), True),
    AttackSpec('count', 'Nearest public-corpus count with prior tie breaks', ('count', 'tag'), ('counts', 'query_counts', 'seed', 'pad_to')),
    AttackSpec('searchpattern', 'Stable-tag popularity ranking', ('tag', 'count'), ('counts', 'query_counts', 'seed', 'pad_to')),
    *[AttackSpec(name, description, ('tag', 'count'), ('counts', 'corpus_documents', 'profile_labels', 'padded', 'seed'))
      for name, description in [('likelihood', 'Count plus IID plug-in likelihood assignment'),
                                ('iterativeLAP', 'Markov objective with iterative partial linear assignments'),
                                ('exactboundedcomparison', 'Exact enumerated Markov objective for at most eight labels')]],
    AttackSpec('chosenupdateassociation', 'Controlled local chosen-posting association to opaque past slots',
               ('mode', 'phase', 'slot', 'injection', 'request', 'response'), ('mode', 'seed')),
]:
    register_attack(_spec, lambda name=_spec.name: _Adapter(name))
del _spec
