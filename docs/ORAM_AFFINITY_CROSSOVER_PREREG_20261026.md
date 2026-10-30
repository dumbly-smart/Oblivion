# Preregistered ORAM service-affinity crossover

**Status:** frozen before collection. Planned output:
`experiments/results/oram-affinity-crossover-20261026/`.

## Question and primary contrast

For this fixed classifier and workload, does pinning the isolated bucket
service process to CPU 0 change hot/cold logical-address prediction AUC
relative to leaving that same service process unpinned? This follow-up
compares detection performance under counterbalanced within-host conditions.
It does not establish constant-time execution or prove that CPU affinity
causes all observed differences in a broader deployment.

The sole primary metric is the paired difference
`mean(AUC_pinned - AUC_unpinned)` across 30 trial pairs. Each trial's two
conditions use the same deterministic per-session logical-address and
read/write schedules, the same profiling/target session split, and the same
classifier seed. ORAM placement randomness and service-process state are
fresh between conditions. A 95% percentile bootstrap interval uses 5,000
resamples of the 30 within-trial AUC differences. A negative difference is
lower measured attack AUC when pinned; an interval containing zero is
inconclusive for this design.

## Frozen configuration and execution order

The machine-readable configuration is
[`oram-affinity-crossover-20261026.json`](../experiments/configs/oram-affinity-crossover-20261026.json).
It fixes 30 trials, eight sessions per trial, four profile and four disjoint
target sessions, 128 measured operations per session, eight warm-up
operations, 32 blocks, 64-byte blocks, bucket capacity four, seed
`20261031`, and order seed `41103`. The workload uses the eight-address
distribution `[0.25, 0.18, 0.15, 0.12, 0.10, 0.08, 0.07, 0.05]`, hot set
`{0, 1}`, Markov retention 0.80 and read probability 0.60.

The service-only conditions are CPU 0 affinity and no affinity. The driver
remains unpinned in both. Exactly 15 trials collect pinned first and 15
unpinned first; the assignment is shuffled deterministically with the
predeclared order seed. Within each trial and condition, plaintext and
encrypt-only controls are collected before ORAM. All controls are evaluated
before any ORAM data is collected. If any of the four control groups has mean
AUC below 0.80 or a 95% bootstrap lower bound at or below 0.50, collection
stops without the ORAM comparison.

The only changed system setting is the service child's CPU affinity. Both
conditions run on this shared Linux host, whose allowed CPUs at preregistration
were `0-23`; the selected CPU is 0. Pinning does not reserve a core or control
interrupts, SMT sibling work, frequency, thermal behavior, host load or OS
scheduling. Service-side effective affinity is checked from
`/proc/<pid>/status`. No benchmarks or tests run concurrently with collection.

No trial, feature, model, seed, threshold, metric, CPU, exclusion rule or
collection order will be changed after inspecting outcomes. The experiment
reuses the fixed temporal random forest and whole-session split from prior
studies. It is not an independent attack implementation or a cryptographic
security test.

## Reproduction

Run the focused tests and build both release examples, then collect into a new
output directory:

```sh
.venv/bin/python -m unittest \
  research.tests.test_oram_affinity_crossover \
  research.tests.test_oram_isolated_replication \
  research.tests.test_oram_isolated_timing
cargo build --locked --release -p oblivion-store \
  --example oram-measure --example oram-control
.venv/bin/python -m research.analysis.oram_affinity_crossover \
  --config experiments/configs/oram-affinity-crossover-20261026.json \
  --output experiments/results/oram-affinity-crossover-20261026
```

Raw per-session observer and private driver traces must remain separate. The
result record must include source/binary/configuration hashes, paired schedule
verification, condition order, all positive-control results, effective CPU
sets, paired confidence interval, and host observations. A near-chance score
or interval containing zero is not proof that either condition hides all
workload information.
