"""Seeded discrete-event function-affine autoscaling research model, not a deployment."""
from collections import deque
from dataclasses import asdict, dataclass, replace
import csv
from decimal import Decimal, ROUND_CEILING, localcontext
import hashlib
import heapq
import hmac
import json
import math
import os
from pathlib import Path
import random
import secrets
import stat

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
import numpy as np

DEFAULT_POLICIES = ('naive', 'ewma', 'quantized', 'fixed', 'noisy')
POLICIES = DEFAULT_POLICIES + ('dp_laplace',)
OBSERVABLE = {'epoch', 'instances', 'scale_up', 'scale_down', 'cold_starts'}
DP_NOISE_SOURCES = ('seeded_experiment', 'os_csprng')


@dataclass(frozen=True)
class Config:
    duration: float = 20
    epoch: float = 1
    service: float = .2
    cold_start: float = .8
    initial: int = 1  # prewarmed instances PER publicly named function pool
    maximum: int = 8
    functions: int = 2
    queue_limit: int = 128
    slo: float = 1.5
    utilization: float = .7
    alpha: float = .35
    quantum: int = 2
    hysteresis: int = 3
    noise_scale: float = 2
    dp_epsilon: float = 1.0
    dp_delta: float = 1e-6
    dp_user_contribution_cap: int = 0
    require_authenticated_user_ids: bool = False
    user_identity_scheme: str | None = None
    low_rate: float = 2
    high_rate: float = 12
    price_per_instance_second: float = .00001  # explicit hypothetical input

    def validate(self):
        values = asdict(self)
        if type(self.require_authenticated_user_ids) is not bool:
            raise ValueError('require_authenticated_user_ids must be a boolean')
        numeric_values = {key: value for key, value in values.items()
                          if key not in ('require_authenticated_user_ids',
                                         'user_identity_scheme')}
        if not all(isinstance(v, (int, float)) and not isinstance(v, bool)
                   and math.isfinite(v) for v in numeric_values.values()):
            raise ValueError('finite numeric parameters required')
        for key in ('initial', 'maximum', 'functions', 'queue_limit', 'quantum',
                    'hysteresis', 'dp_user_contribution_cap'):
            if type(values[key]) is not int:
                raise ValueError(f'{key} must be an integer')
        if not (0 < self.duration <= 86400 and 0 < self.epoch <= self.duration and self.duration / self.epoch <= 10000):
            raise ValueError('invalid simulation horizon/epoch')
        if not (0 <= self.initial <= self.maximum <= 128 and 1 <= self.functions <= 16 and 1 <= self.queue_limit <= 100000):
            raise ValueError('invalid capacity')
        if min(self.service, self.slo) <= 0 or self.cold_start < 0 or not 0 < self.utilization <= 1 or not 0 < self.alpha <= 1:
            raise ValueError('invalid time/control parameters')
        if min(self.quantum, self.hysteresis) < 1 or min(self.noise_scale, self.low_rate, self.high_rate, self.price_per_instance_second) < 0:
            raise ValueError('invalid signal/cost parameters')
        if self.dp_epsilon <= 0:
            raise ValueError('dp_epsilon must be positive')
        if not 0 <= self.dp_user_contribution_cap <= 1000000:
            raise ValueError('dp_user_contribution_cap must be in 0..1,000,000')
        if self.require_authenticated_user_ids and not self.dp_user_contribution_cap:
            raise ValueError('authenticated user IDs require a positive per-user contribution cap')
        if self.user_identity_scheme not in (None, 'hmac-sha256', 'ed25519'):
            raise ValueError('user_identity_scheme must be hmac-sha256 or ed25519')
        if self.user_identity_scheme is not None and not self.require_authenticated_user_ids:
            raise ValueError('identity scheme requires authenticated user IDs')
        if not 0 < self.dp_delta < 1:
            raise ValueError('dp_delta must be strictly between zero and one')
        if self.high_rate * self.duration > 1e6:
            raise ValueError('workload exceeds prototype allocation cap')


@dataclass(frozen=True)
class Request:
    time: float
    function: int
    user_id: str | None = None
    auth_tag: str | None = None


class RequestAuthenticator:
    """In-memory per-principal HMAC signer/verifier for simulation inputs.

    Each client and verifier share a distinct 256-bit key. This can prevent
    one registered client from claiming another client's ID when the key
    registry stays secret. It is not an identity provider and does not protect
    against compromise of the verifier or its key registry.
    """

    def __init__(self, keys):
        if not isinstance(keys, dict) or not keys:
            raise ValueError('a nonempty per-principal key registry is required')
        if any(not isinstance(user_id, str) or not user_id
               or not isinstance(key, bytes) or len(key) < 32
               for user_id, key in keys.items()):
            raise ValueError('principal IDs and keys must be nonempty and keys at least 32 bytes')
        self._keys = dict(keys)
        self.registry_sha256 = None

    @classmethod
    def from_file(cls, path):
        """Load an out-of-band JSON map of principal IDs to hex HMAC keys."""
        source = Path(path)
        with source.open('rb') as stream:
            if stat.S_IMODE(os.fstat(stream.fileno()).st_mode) & 0o077:
                raise ValueError(
                    'identity registry must not be accessible by group or other users'
                )
            data = stream.read(16 * 1024 * 1024 + 1)
        if len(data) > 16 * 1024 * 1024:
            raise ValueError('identity registry exceeds 16 MiB')
        try:
            encoded = json.loads(data.decode('utf-8'))
            if not isinstance(encoded, dict):
                raise ValueError('identity registry must be a JSON object')
            keys = {user_id: bytes.fromhex(key)
                    for user_id, key in encoded.items()}
        except (AttributeError, TypeError, ValueError, UnicodeError) as error:
            raise ValueError('invalid identity registry file') from error
        authenticator = cls(keys)
        authenticator.registry_sha256 = hashlib.sha256(data).hexdigest()
        return authenticator

    @staticmethod
    def _message(request):
        if (not isinstance(request, Request) or not isinstance(request.user_id, str)
                or not request.user_id or type(request.function) is not int
                or request.function < 0 or not isinstance(request.time, (int, float))
                or isinstance(request.time, bool) or not math.isfinite(request.time)):
            raise ValueError('valid request fields are required for authentication')
        user_id = request.user_id.encode('utf-8')
        return (b'oblivion-autoscaler-request-v1\0'
                + len(user_id).to_bytes(4, 'big') + user_id
                + float(request.time).hex().encode('ascii') + b'\0'
                + request.function.to_bytes(8, 'big'))

    def sign(self, request):
        message = self._message(request)
        key = self._keys.get(request.user_id)
        if key is None:
            raise ValueError('principal is not registered')
        tag = hmac.new(key, message, 'sha256').hexdigest()
        return replace(request, auth_tag=tag)

    def verify(self, request):
        if (not isinstance(request, Request) or not isinstance(request.user_id, str)
                or not isinstance(request.auth_tag, str) or len(request.auth_tag) != 64
                or any(char not in '0123456789abcdef' for char in request.auth_tag)):
            return False
        key = self._keys.get(request.user_id)
        if key is None:
            return False
        try:
            expected = hmac.new(key, self._message(request), 'sha256').hexdigest()
        except (OverflowError, UnicodeError, ValueError):
            return False
        return hmac.compare_digest(expected, request.auth_tag)


class Ed25519RequestVerifier:
    """Verifier-only registry; it contains no client signing private keys."""

    def __init__(self, keys):
        if not isinstance(keys, dict) or not keys or any(
                not isinstance(user_id, str) or not user_id
                or not isinstance(key, bytes) or len(key) != 32
                for user_id, key in keys.items()):
            raise ValueError('principal IDs and Ed25519 public keys must be valid 32-byte values')
        self._keys = {user_id: Ed25519PublicKey.from_public_bytes(key)
                      for user_id, key in keys.items()}
        self.registry_sha256 = None

    @classmethod
    def from_file(cls, path):
        """Load a bounded JSON map of principal IDs to raw public-key hex."""
        with Path(path).open('rb') as stream:
            data = stream.read(16 * 1024 * 1024 + 1)
        if len(data) > 16 * 1024 * 1024:
            raise ValueError('identity registry exceeds 16 MiB')
        try:
            encoded = json.loads(data.decode('utf-8'))
            if not isinstance(encoded, dict):
                raise ValueError('identity registry must be a JSON object')
            keys = {user_id: bytes.fromhex(key)
                    for user_id, key in encoded.items()}
        except (AttributeError, TypeError, ValueError, UnicodeError) as error:
            raise ValueError('invalid Ed25519 public-key registry') from error
        verifier = cls(keys)
        verifier.registry_sha256 = hashlib.sha256(data).hexdigest()
        return verifier

    def verify(self, request):
        if (not isinstance(request, Request) or not isinstance(request.user_id, str)
                or not isinstance(request.auth_tag, str) or len(request.auth_tag) != 128
                or any(char not in '0123456789abcdef' for char in request.auth_tag)):
            return False
        key = self._keys.get(request.user_id)
        if key is None:
            return False
        try:
            key.verify(bytes.fromhex(request.auth_tag), RequestAuthenticator._message(request))
        except (InvalidSignature, OverflowError, UnicodeError, ValueError):
            return False
        return True


class Ed25519RequestSigner:
    """Client-side signing keys, loaded separately from the public verifier."""

    def __init__(self, keys):
        if not isinstance(keys, dict) or not keys or any(
                not isinstance(user_id, str) or not user_id
                or not isinstance(key, bytes) or len(key) != 32
                for user_id, key in keys.items()):
            raise ValueError('principal IDs and Ed25519 private seeds must be valid 32-byte values')
        self._keys = {user_id: Ed25519PrivateKey.from_private_bytes(key)
                      for user_id, key in keys.items()}

    @classmethod
    def from_file(cls, path):
        """Load private signing seeds from a permission-restricted JSON file."""
        with Path(path).open('rb') as stream:
            if stat.S_IMODE(os.fstat(stream.fileno()).st_mode) & 0o077:
                raise ValueError(
                    'identity signing keys must not be accessible by group or other users'
                )
            data = stream.read(16 * 1024 * 1024 + 1)
        if len(data) > 16 * 1024 * 1024:
            raise ValueError('identity signing-key file exceeds 16 MiB')
        try:
            encoded = json.loads(data.decode('utf-8'))
            if not isinstance(encoded, dict):
                raise ValueError('identity signing keys must be a JSON object')
            keys = {user_id: bytes.fromhex(key)
                    for user_id, key in encoded.items()}
        except (AttributeError, TypeError, ValueError, UnicodeError) as error:
            raise ValueError('invalid Ed25519 signing-key file') from error
        return cls(keys)

    def sign(self, request):
        message = RequestAuthenticator._message(request)
        key = self._keys.get(request.user_id)
        if key is None:
            raise ValueError('principal is not registered for signing')
        return replace(request, auth_tag=key.sign(message).hex())

    def matches_verifier(self, verifier, principal_ids):
        """Fail early unless each synthetic client's key matches its verifier entry."""
        for user_id in principal_ids:
            key = self._keys.get(user_id)
            if key is None:
                return False
            probe = Request(0.0, 0, user_id)
            signed = replace(probe, auth_tag=key.sign(RequestAuthenticator._message(probe)).hex())
            if not verifier.verify(signed):
                return False
        return True


def load_imported(path, cfg, identity_authenticator=None):
    """User-supplied CSV time,function in simulation seconds; never fetches traces."""
    cfg.validate()
    with Path(path).open() as source:
        reader = csv.DictReader(source)
        expected = (['time', 'function', 'user_id', 'auth_tag']
                    if cfg.require_authenticated_user_ids else
                    ['time', 'function', 'user_id']
                    if cfg.dp_user_contribution_cap else ['time', 'function'])
        if reader.fieldnames != expected:
            raise ValueError(f'expected CSV header {",".join(expected)}')
        requests = [Request(float(r['time']), int(r['function']),
                            r.get('user_id'), r.get('auth_tag')) for r in reader]
    validate_requests(requests, cfg, identity_authenticator)
    return requests


def validate_requests(requests, cfg, identity_authenticator=None):
    last = -1.
    if len(requests) > 1000000:
        raise ValueError('too many requests')
    for r in requests:
        if not math.isfinite(r.time) or not last <= r.time < cfg.duration or r.time < 0 or not 0 <= r.function < cfg.functions:
            raise ValueError('requests must be sorted, in horizon and valid pools')
        last = r.time
        if r.user_id is not None and (not isinstance(r.user_id, str) or not r.user_id):
            raise ValueError('user_id must be a nonempty string when provided')
        if cfg.dp_user_contribution_cap and not r.user_id:
            raise ValueError('user-level DP requires a stable user_id on every request')
        if cfg.require_authenticated_user_ids:
            scheme = cfg.user_identity_scheme or 'hmac-sha256'
            verifier_type = (Ed25519RequestVerifier if scheme == 'ed25519'
                             else RequestAuthenticator)
            if not isinstance(identity_authenticator, verifier_type):
                if scheme == 'ed25519':
                    raise ValueError('ed25519 user IDs require a matching identity verifier')
                raise ValueError('authenticated user IDs require an identity authenticator')
            if not identity_authenticator.verify(r):
                raise ValueError('request identity authentication failed')


def bounded_arrival_counts(requests, cfg, identity_authenticator=None):
    """Return per-epoch integer counts after the public per-user contribution cap."""
    cfg.validate()
    validate_requests(requests, cfg, identity_authenticator)
    horizon = math.ceil(cfg.duration / cfg.epoch)
    counts = np.zeros((horizon, cfg.functions), dtype=np.int64)
    contributions = {}
    for request in requests:
        if cfg.dp_user_contribution_cap:
            used = contributions.get(request.user_id, 0)
            if used >= cfg.dp_user_contribution_cap:
                continue
            contributions[request.user_id] = used + 1
        epoch = min(horizon - 1,
                    max(0, math.ceil(request.time / cfg.epoch) - 1))
        counts[epoch, request.function] += 1
    return counts


def workload(cfg, kind, seed, intensity=0, hot=0, identity_authenticator=None,
             identity_signer=None):
    cfg.validate()
    if kind not in ('uniform', 'zipf', 'diurnal', 'burst') or intensity not in (0, 1) or not 0 <= hot < cfg.functions:
        raise ValueError('invalid workload')
    rng = np.random.default_rng(seed)
    requests, labels = [], []
    # Uniform deliberately carries no hot-function signal; do not evaluate that task.
    weights = np.ones(cfg.functions)
    if kind != 'uniform':
        weights = 1 / np.arange(1, cfg.functions + 1, dtype=float) ** 1.8
        weights = np.roll(weights, hot)
    weights /= weights.sum()
    for epoch in range(math.ceil(cfg.duration / cfg.epoch)):
        start = epoch * cfg.epoch
        width = min(cfg.epoch, cfg.duration - start)
        rate = [cfg.low_rate, cfg.high_rate][intensity]
        factor = 1.
        if kind == 'diurnal':
            factor = 1 + .7 * math.sin(2 * math.pi * start / cfg.duration)
        elif kind == 'burst':
            factor = 3 if .35 * cfg.duration <= start < .55 * cfg.duration else .5
        n = rng.poisson(rate * factor * width)
        times = rng.uniform(start, start + width, n)
        pools = rng.choice(cfg.functions, n, p=weights)
        requests.extend(Request(float(t), int(f)) for t, f in zip(times, pools))
        labels.append({'epoch': epoch, 'intensity': intensity, 'hot': hot, 'arrivals': int(n), 'rate': rate * factor})
    requests.sort(key=lambda r: r.time)
    if cfg.dp_user_contribution_cap:
        requests = [Request(request.time, request.function,
                            f'synthetic-user-{index % 64}')
                    for index, request in enumerate(requests)]
    if cfg.require_authenticated_user_ids:
        signer = identity_signer or identity_authenticator
        if not callable(getattr(signer, 'sign', None)):
            raise ValueError(
                'authenticated synthetic workload requires an identity authenticator (signer)'
            )
        requests = [signer.sign(request) for request in requests]
    return requests, labels


def simulate(cfg, requests, policy, seed, dp_noise_source='seeded_experiment',
             identity_authenticator=None):
    cfg.validate()
    if policy not in POLICIES:
        raise ValueError('unknown scaling policy')
    if dp_noise_source not in DP_NOISE_SOURCES:
        raise ValueError('unknown DP noise source')
    validate_requests(requests, cfg, identity_authenticator)
    rng = np.random.default_rng(seed)
    replayable_noise_rng = random.Random(seed)
    dp_noise_parameters = dp_laplace_parameters(cfg) if policy == 'dp_laplace' else None
    dp_arrival_counts = (bounded_arrival_counts(requests, cfg, identity_authenticator)
                         if policy == 'dp_laplace' else None)
    queues = [deque() for _ in range(cfg.functions)]
    workers, events, records, observer = {}, [], [], []
    arrivals = np.zeros(cfg.functions, dtype=int)
    signal = np.zeros(cfg.functions)
    lower = np.zeros(cfg.functions, dtype=int)
    up = np.zeros(cfg.functions, dtype=int)
    down = np.zeros(cfg.functions, dtype=int)
    cold = np.zeros(cfg.functions, dtype=int)
    serial, next_worker = 0, 0
    instance_seconds = queue_seconds = 0.
    last, queue_max = 0., 0

    def event(t, priority, kind, data):
        nonlocal serial
        heapq.heappush(events, (t, priority, serial, kind, data))
        serial += 1

    def launch(pool, t, warm=False):
        nonlocal next_worker
        wid = next_worker
        next_worker += 1
        workers[wid] = dict(pool=pool, ready=warm, busy=False, retiring=False)
        if not warm:
            up[pool] += 1
            cold[pool] += 1
            event(t + cfg.cold_start, 1, 'ready', wid)

    def dispatch(t):
        for wid, w in list(workers.items()):
            pool = w['pool']
            if w['ready'] and not w['busy'] and not w['retiring'] and queues[pool]:
                rid = queues[pool].popleft()
                w['busy'] = True
                records[rid]['started'] = t
                event(t + cfg.service, 0, 'done', (wid, rid))

    for pool in range(cfg.functions):
        for _ in range(cfg.initial):
            launch(pool, 0, warm=True)
    for r in requests:
        event(r.time, 2, 'arrival', r)
    # Initial prewarm is public setup; reactive policies first observe one full epoch.
    for tick in range(1, math.ceil(cfg.duration / cfg.epoch) + 1):
        event(min(tick * cfg.epoch, cfg.duration), 3, 'tick', tick - 1)
    event(cfg.duration, 4, 'end', None)
    while events:
        t, _, _, kind, data = heapq.heappop(events)
        if t > cfg.duration:
            break
        instance_seconds += (t - last) * len(workers)
        queue_seconds += (t - last) * sum(map(len, queues))
        last = t
        if kind == 'end':
            break
        if kind == 'arrival':
            pool = data.function
            arrivals[pool] += 1
            rid = len(records)
            dropped = len(queues[pool]) >= cfg.queue_limit
            records.append(dict(arrived=t, function=pool, dropped=dropped, started=None, finished=None))
            if not dropped:
                queues[pool].append(rid)
        elif kind == 'ready':
            if data in workers:
                workers[data]['ready'] = True
        elif kind == 'done':
            wid, rid = data
            records[rid]['finished'] = t
            if workers[wid]['retiring']:
                down[workers[wid]['pool']] += 1
                del workers[wid]
            else:
                workers[wid]['busy'] = False
        elif kind == 'tick':
            for pool in range(cfg.functions):
                group = [(wid, w) for wid, w in workers.items() if w['pool'] == pool]
                active = sum(not w['retiring'] for _, w in group)
                raw = (float(dp_arrival_counts[data, pool])
                       if policy == 'dp_laplace' else float(arrivals[pool]))
                if policy == 'dp_laplace':
                    # Noise the integer per-epoch count query first; smoothing
                    # afterward is post-processing of the released count stream.
                    noise = discrete_laplace_from_bits(
                        dp_noise_parameters,
                        secrets.randbits if dp_noise_source == 'os_csprng'
                        else replayable_noise_rng.getrandbits)
                    noisy_count = max(0.0, raw + noise)
                    signal[pool] = (cfg.alpha * noisy_count
                                    + (1 - cfg.alpha) * signal[pool])
                    measured = signal[pool]
                else:
                    signal[pool] = cfg.alpha * raw + (1 - cfg.alpha) * signal[pool]
                    measured = raw if policy == 'naive' else signal[pool]
                if policy == 'noisy':
                    measured = max(0., measured + rng.laplace(0, cfg.noise_scale))
                backlog = len(queues[pool])
                scaler_load = measured if policy == 'dp_laplace' else measured + backlog
                target = math.ceil(scaler_load * cfg.service / (cfg.epoch * cfg.utilization))
                if policy == 'fixed':
                    target = cfg.initial
                if policy == 'quantized':
                    target = math.ceil(target / cfg.quantum) * cfg.quantum
                    lower[pool] = lower[pool] + 1 if target < active else 0
                    if target < active and lower[pool] < cfg.hysteresis:
                        target = active
                target = min(cfg.maximum, max(0, target))
                if policy == 'dp_laplace':
                    # No busy/queue-dependent retirement: observable pool counts
                    # remain post-processing of the noisy signal transcript.
                    target = max(active, target)
                for _ in range(min(max(0, target - active), cfg.maximum - len(group))):
                    launch(pool, t)
                retire = max(0, active - target)
                # Retire idle workers first, then let busy requests finish.
                for wid, w in sorted(group, key=lambda item: item[1]['busy']):
                    if retire and not w['retiring']:
                        retire -= 1
                        if w['busy']:
                            w['retiring'] = True
                        else:
                            down[pool] += 1
                            del workers[wid]
            observer.append(dict(epoch=data, instances=[sum(w['pool'] == pool for w in workers.values()) for pool in range(cfg.functions)], scale_up=up.tolist(), scale_down=down.tolist(), cold_starts=cold.tolist()))
            arrivals.fill(0); up.fill(0); down.fill(0); cold.fill(0)
        dispatch(t)
        queue_max = max(queue_max, sum(map(len, queues)))
    latencies = [r['finished'] - r['arrived'] for r in records if r['finished'] is not None]
    dropped = sum(r['dropped'] for r in records)
    unfinished = sum(not r['dropped'] and r['finished'] is None for r in records)
    violations = dropped + unfinished + sum(t > cfg.slo for t in latencies)
    metrics = dict(arrivals=len(records), completed=len(latencies), dropped=dropped, unfinished=unfinished,
                   instance_seconds=instance_seconds, cost=instance_seconds * cfg.price_per_instance_second,
                   p95=float(np.percentile(latencies, 95)) if latencies else None,
                   p99=float(np.percentile(latencies, 99)) if latencies else None,
                   queue_max=queue_max, queue_mean=queue_seconds / cfg.duration,
                   slo_violation_rate=violations / len(records) if records else 0.,
                   cold_starts=sum(sum(o['cold_starts']) for o in observer))
    return dict(observer=observer, requests=records, metrics=metrics)


def dp_laplace_parameters(cfg):
    """Conservative finite-randomness parameters for the finite-horizon policy."""
    releases = math.ceil(cfg.duration / cfg.epoch)
    sensitivity = max(1, cfg.dp_user_contribution_cap)
    changed_dimensions = min(cfg.functions, sensitivity)
    with localcontext() as context:
        context.prec = 100
        epsilon = (Decimal(str(cfg.dp_epsilon))
                   / Decimal(releases * sensitivity))
        delta = Decimal(str(cfg.dp_delta)) / Decimal(releases)
        denominator = 1 << 64
        # Decimal.exp is correctly rounded. The small positive margin makes
        # integer ceiling conservative despite its finite decimal precision.
        q_upper = (-epsilon).exp() + Decimal('1e-90')
        numerator = int((q_upper * denominator).to_integral_value(rounding=ROUND_CEILING))
        if not 0 < numerator < denominator:
            raise ValueError('dp_epsilon per release is below sampler resolution')
        q = Decimal(numerator) / Decimal(denominator)
        epsilon_effective = Decimal(sensitivity) * -q.ln()
        tail_bound = (Decimal(2 * changed_dimensions)
                      * (Decimal(1) + epsilon_effective.exp()) * q)
        cap = 0
        while tail_bound > delta:
            cap += 1
            if cap > 100000:
                raise ValueError('dp_delta requires an impractical geometric sampler cap')
            tail_bound *= q
        composed_delta = Decimal(releases) * tail_bound
        return dict(
            releases=releases,
            epsilon_per_release=cfg.dp_epsilon / releases,
            epsilon_per_unit=float(epsilon),
            epsilon_effective_per_unit=float(-q.ln()),
            epsilon_effective_per_release=float(epsilon_effective),
            l1_sensitivity_bound=float(sensitivity),
            privacy_unit='user' if cfg.dp_user_contribution_cap else 'request',
            user_contribution_cap=cfg.dp_user_contribution_cap or None,
            geometric_numerator=numerator,
            geometric_denominator=denominator,
            geometric_cap=cap,
            coin_bits=64,
            per_release_delta_bound=float(tail_bound),
            composed_delta_bound=float(composed_delta),
            dp_epsilon=float(cfg.dp_epsilon),
            dp_delta=float(composed_delta))


def discrete_laplace_from_bits(parameters, randbits):
    """Sample capped difference-of-geometric noise from a fixed-size bit draw.

    The uncapped difference is a two-sided geometric distribution. Capping
    each geometric variate at K changes the joint draw with probability at
    most 2*q**(K+1); the reported delta bound composes that coupling error
    with the ideal geometric mechanism's pure-DP bound.
    """
    bits = parameters['coin_bits']
    cap = parameters['geometric_cap']
    numerator = parameters['geometric_numerator']
    denominator = parameters['geometric_denominator']
    if (bits != 64 or type(cap) is not int or cap < 0
            or type(numerator) is not int or not 0 < numerator < denominator
            or denominator != 1 << bits):
        raise ValueError('invalid discrete-noise parameters')
    requested = 2 * cap * bits
    word = randbits(requested)
    if type(word) is not int or not 0 <= word < (1 << requested):
        raise ValueError('entropy source returned an invalid word')
    counts = [0, 0]
    active = [True, True]
    mask = denominator - 1
    for position in range(cap):
        for stream in range(2):
            coin = (word >> ((stream * cap + position) * bits)) & mask
            success = coin < numerator
            if active[stream] and success:
                counts[stream] += 1
            else:
                active[stream] = False
    return counts[0] - counts[1]


def features(row):
    if set(row) != OBSERVABLE:
        raise ValueError('observer schema mismatch; private fields prohibited')
    sizes = [len(row[key]) for key in OBSERVABLE - {'epoch'}]
    if len(set(sizes)) != 1:
        raise ValueError('pool shape mismatch')
    return np.array([v for key in ('instances', 'scale_up', 'scale_down', 'cold_starts') for v in row[key]], dtype=float)


def session_features(rows):
    current = np.array([features(row) for row in rows])
    previous = np.vstack([np.zeros_like(current[:1]), current[:-1]])
    # Public past only; no target labels, true load, queues, service latency or billing.
    return np.hstack([current, previous, np.cumsum(current, axis=0) / np.arange(1, len(rows) + 1)[:, None]])


def trial_interval(clusters, seed=907):
    values = np.array([np.mean(cluster) for cluster in clusters])
    rng = np.random.default_rng(seed)
    estimates = rng.choice(values, size=(5000, len(values)), replace=True).mean(axis=1)
    return list(map(float, np.quantile(estimates, [.025, .975])))


class ProfileAttack:
    """Known-policy diagonal nearest-centroid profiler; honest weak-model limitation."""
    def fit(self, x, y):
        self.labels = np.unique(y)
        self.centers = np.array([x[y == label].mean(axis=0) for label in self.labels])
        self.variance = np.maximum(np.var(x, axis=0), .1)
        return self

    def predict(self, x):
        distances = ((x[:, None, :] - self.centers[None, :, :]) ** 2 / self.variance).sum(axis=2)
        return self.labels[np.argmin(distances, axis=1)]
