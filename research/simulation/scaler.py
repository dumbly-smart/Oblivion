"""Seeded discrete-event function-affine autoscaling research model, not a deployment."""
from collections import deque
from dataclasses import asdict, dataclass
import csv
import heapq
import math
from pathlib import Path
import secrets
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
    low_rate: float = 2
    high_rate: float = 12
    price_per_instance_second: float = .00001  # explicit hypothetical input

    def validate(self):
        values = asdict(self)
        if not all(isinstance(v, (int, float)) and math.isfinite(v) for v in values.values()):
            raise ValueError('finite numeric parameters required')
        for key in ('initial', 'maximum', 'functions', 'queue_limit', 'quantum', 'hysteresis'):
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
        if self.high_rate * self.duration > 1e6:
            raise ValueError('workload exceeds prototype allocation cap')


@dataclass(frozen=True)
class Request:
    time: float
    function: int


def load_imported(path, cfg):
    """User-supplied CSV time,function in simulation seconds; never fetches traces."""
    cfg.validate()
    with Path(path).open() as source:
        reader = csv.DictReader(source)
        if reader.fieldnames != ['time', 'function']:
            raise ValueError('expected CSV header time,function')
        requests = [Request(float(r['time']), int(r['function'])) for r in reader]
    validate_requests(requests, cfg)
    return requests


def validate_requests(requests, cfg):
    last = -1.
    if len(requests) > 1000000:
        raise ValueError('too many requests')
    for r in requests:
        if not math.isfinite(r.time) or not last <= r.time < cfg.duration or r.time < 0 or not 0 <= r.function < cfg.functions:
            raise ValueError('requests must be sorted, in horizon and valid pools')
        last = r.time


def workload(cfg, kind, seed, intensity=0, hot=0):
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
    return requests, labels


def simulate(cfg, requests, policy, seed, dp_noise_source='seeded_experiment'):
    cfg.validate()
    if policy not in POLICIES:
        raise ValueError('unknown scaling policy')
    if dp_noise_source not in DP_NOISE_SOURCES:
        raise ValueError('unknown DP noise source')
    validate_requests(requests, cfg)
    rng = np.random.default_rng(seed)
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
                raw = float(arrivals[pool])
                signal[pool] = cfg.alpha * raw + (1 - cfg.alpha) * signal[pool]
                measured = raw if policy == 'naive' else signal[pool]
                if policy == 'noisy':
                    measured = max(0., measured + rng.laplace(0, cfg.noise_scale))
                elif policy == 'dp_laplace':
                    if dp_noise_source == 'os_csprng':
                        noise = laplace_from_bits(dp_laplace_scale(cfg), secrets.randbits)
                    else:
                        noise = rng.laplace(0, dp_laplace_scale(cfg))
                    measured = max(0., measured + noise)
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
    """Conservative per-tick composition parameters for the finite-horizon policy."""
    releases = math.ceil(cfg.duration / cfg.epoch)
    epsilon_per_release = cfg.dp_epsilon / releases
    return dict(releases=releases, epsilon_per_release=epsilon_per_release,
                l1_sensitivity_bound=1.0,
                laplace_scale=1.0 / epsilon_per_release)


def laplace_from_bits(scale, randbits):
    """Finite-precision inverse-CDF Laplace draw from a 53-bit word source.

    Pass secrets.randbits for OS-CSPRNG-backed sampling. This finite digital
    sampler is research tooling and has not been proved to implement exact DP.
    """
    # 52 midpoint bits are exactly representable as binary64 and stay strictly
    # inside (0, 1), including the two extreme words.
    bits = 52
    if not isinstance(scale, (int, float)) or not math.isfinite(scale) or scale <= 0:
        raise ValueError('Laplace scale must be finite and positive')
    word = randbits(bits)
    if type(word) is not int or not 0 <= word < (1 << bits):
        raise ValueError('entropy source returned an invalid word')
    centered = (word + 0.5) / (1 << bits) - 0.5
    sign = 1.0 if centered > 0 else -1.0
    return -float(scale) * sign * math.log1p(-2.0 * abs(centered))


def dp_laplace_scale(cfg):
    return dp_laplace_parameters(cfg)['laplace_scale']


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
