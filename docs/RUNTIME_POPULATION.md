# Full-path 64-offer population load

This study extends the earlier [open-loop measurements](RUNTIME_BENCHMARKS.md)
from 32 to 64 offered invocations per fresh process. It uses the actual local
server path: bounded admission, authenticated invocation envelopes, two PIR
server requests, stateful Wasmtime execution, and 16 actual ORAM operations
per admitted invocation. Each output and state update is checked against the
client oracle; the analysis verifies the 128 expected bucket events per
successful invocation.

The [configuration](../experiments/configs/runtime-population-64-20261024.json)
and [raw trial records](../experiments/results/runtime-population-64-20261024/)
retain 30 independent processes per profile, 3,840 offers total. The runner
records the immutable executable digest, before/after source fingerprints,
host/compiler details, launch order, offered arrivals, admission/drop counts,
private executor results and storage observer events. Both source fingerprints
match, all 60 launches exited zero, and all 64-offer counts validated.

## Results

Intervals are 95% percentile bootstrap intervals over the 30 whole-process
trial statistics. Per-process latency quantiles are computed first, then
summarized across trials. Latency includes admitted requests only; dropped
offers remain in the offered-load SLO denominator.

| Profile | Admitted / offered | Dropped | Mean admitted E2E ms (95% interval) | Mean trial p50 / p95 / p99 ms | Successful completions/s | Offered SLO failure fraction |
|---|---:|---:|---:|---:|---:|---:|
| Underload: 150 ms interval, queue 2 | 64 / 64 | 0% | 100.527 [100.500, 100.552] | 100.528 / 100.702 / 100.772 | 6.701 [6.700, 6.701] | 0% |
| Overload: 25 ms interval, queue 2 | 18 / 64 | 71.88% | 265.163 [264.815, 265.460] | 281.932 / 287.455 / 287.928 | 9.926 [9.923, 9.930] | 96.88% |

The overload profile admits more work per second than the underload profile,
but drops most offers and violates the 250 ms SLO for 96.88% of offers. The
underload rate is the deliberate 150 ms client pacing, not a saturation
capacity measurement. These results do not estimate production capacity,
future traffic tails, remote network behavior or cloud billing. All clients,
PIR servers and the executor run locally on a shared host; WASM is precompiled
before readiness. No other local experiment ran concurrently, though general
OS scheduling and shared-host noise remain.

## Reproduction

```sh
.venv/bin/python scripts/benchmark_open_loop.py \
  experiments/configs/runtime-population-64-20261024.json \
  --mode runtime \
  --runtime-output experiments/results/runtime-population-64-new \
  --batch-output /tmp/oblivion-no-batch
.venv/bin/python -m research.analysis.open_loop \
  --runtime experiments/results/runtime-population-64-new
```

Use a new output directory. The copied release binary is measured and hashed;
reanalysis reads only retained trial artifacts.
