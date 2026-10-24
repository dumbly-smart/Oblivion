# Batcher population and epoch timing sweep

The [configuration](../experiments/configs/population-sweep-20261025.json),
[aggregate report](../experiments/results/population-sweep-20261025/report.json),
[figure](../experiments/results/population-sweep-20261025/population-throughput-latency.png),
and hash-manifested raw observer/private traces retain the 2026-10-25 run.
The runner records 30 independent process trials at each of 1, 8, 32 and 64
client slots. Each trial runs 100 epochs at a 25 ms period, with 50% real and
50% dummy envelopes. The system uses the real authenticated EpochBatcher and
fixed 164-byte envelopes.

## Results

| Client slots | Emitted frames/s | Queue wait p95 | Queue wait p99 | Emission lateness p95 | Maximum batch bytes |
|---:|---:|---:|---:|---:|---:|
| 1 | 40.0 | 23.55 ms | 24.59 ms | 0.199 ms | 164 |
| 8 | 320.0 | 23.71 ms | 24.75 ms | 0.144 ms | 1,312 |
| 32 | 1,279.97 | 23.72 ms | 24.75 ms | 0.092 ms | 5,248 |
| 64 | 2,559.94 | 23.74 ms | 24.71 ms | 0.079 ms | 10,496 |

The near-linear frame rate follows the configured 25 ms epoch and slot count.
Queue wait remains close to one epoch because requests are intentionally held
for scheduled emission. The 95% intervals over the 30 independent process
trials are in the report. These timings describe this local batcher fixture;
they do not establish full-platform throughput or a service-level objective.

The observer trace contains arrival/emission timestamps, slot IDs, frame
counts, and sizes. Planned client-side phases, real/dummy identity and dummy
counts are stored in separate private files. The tool verifies that the
observer export contains no real/dummy labels and that the private accounting
matches each emitted batch.

## Scope

All simulated clients and the batcher run on one local host. This is a
population-size and epoch-timing component experiment, not a network test or
a full invocation path: WASM execution, ORAM storage, autoscaling, independent
client processes, and provider billing are not measured. No provider price
was available for calibration, so the report records local process wall time
and leaves monetary cost undefined. External deployment, longer production
load, and provider-specific resource calibration remain open.

## Reproduce

    .venv/bin/python -m research.analysis.population_sweep \
      --config experiments/configs/population-sweep-20261025.json \
      --output experiments/results/population-sweep-new

The command builds the release batcher example when no binary is supplied.
Use a new output directory for each run; raw observer and private files are
kept separate and individually hashed in the report.
