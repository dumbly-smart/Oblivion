# Isolated ORAM timing replication with service CPU affinity

This study follows the frozen [preregistration](ORAM_PINNED_REPLICATION_20261026_PREREG.md)
and [configuration](../experiments/configs/oram-isolated-pinned-replication-20261026.json).
The bucket-service child in each mode was restricted to CPU 0; the workload
driver remained unpinned. This is an independent fresh-seed run, not a
controlled paired comparison with earlier unpinned collections.

## Results

The primary metric is mean per-access ROC AUC over 30 fitted trials, with a
95% percentile bootstrap interval over per-trial AUCs (5,000 resamples). The
preregistered plaintext and encrypt-only positive controls both passed before
Path ORAM was evaluated.

| Mode | Mean AUC (95% trial-bootstrap interval) | Mean balanced accuracy (95% interval) | Profile-majority accuracy |
|---|---:|---:|---:|
| Plaintext | 1.0000 [1.0000, 1.0000] | 1.0000 [1.0000, 1.0000] | 0.5260 |
| Encrypt-only | 1.0000 [1.0000, 1.0000] | 0.9997 [0.9992, 1.0000] | 0.5260 |
| Path ORAM | 0.4937 [0.4756, 0.5130] | 0.4971 [0.4844, 0.5108] | 0.5260 |

The ORAM AUC interval includes 0.50, and its balanced accuracy is below the
profile-majority baseline. This attacker did not distinguish the configured
hot class from the cold addresses in this experiment. That result does not
show that CPU pinning reduced a timing signal: seed, collection time and host
conditions differ from prior runs. It is not evidence of cryptographic
indistinguishability or a guarantee for remote timing or other workloads.

## Workload and observer

The workload used eight logical addresses, hot set `{0, 1}`, a Markov
retention probability of 0.80 and a read probability of 0.60. The refresh
distribution was `[0.25, 0.18, 0.15, 0.12, 0.10, 0.08, 0.07, 0.05]`. Seed
`20261029` produced 30,720 measured accesses. The observed adjacent-address
retention was 82.90%, hot-address frequency was 43.33%, and reads were
60.01%. Each trial used four whole profiling sessions and four disjoint whole
target sessions. Schedules were paired across plaintext, encrypt-only and
ORAM; leaf placement, keys and nonces were fresh OS-random values.

The attacker received visible leaf/bucket identifiers, fixed-shape byte
counts, handler-only service times and the fixed short temporal features. The
service time is measured inside a separate local process after request decode
and before reply encoding. It is not network timing. The 90 retained
`isolated-service.json` records (one final session from each eight-session
collector invocation) reported `Cpus_allowed_list: 0`; `taskset -c 0` was
configured for all 720 service-child sessions. Individual child PIDs and
affinity records were not retained. The driver retained `0-23`.
Restricting affinity does not reserve the core or prevent host tasks,
interrupts, sibling activity, frequency changes, thermal effects or
scheduling noise.

## Retained evidence and reproduction

The preregistration was pushed in commit `8c23206b` before collection. The
run used source/binaries at `8c23206b` and verified five source/configuration/
binary hashes, 1,440 raw trace hashes, 90 prediction files, all 240
trial/session schedule pairs and all 90 retained final-session affinity
records. Raw
traces and predictions are retained in
[`trace-data.tar.gz`](../experiments/results/oram-isolated-pinned-replication-20261026/trace-data.tar.gz)
(SHA-256 `89ed4dc2aa799e090f9a58bdcb52ea255147ab78cb509056b0775a8210d0da16`).
The result directory also contains the report, plot, configuration,
verification record and host observation.

Correction: one metadata JSON record was retained per eight-session collector
invocation, so the 90 recorded CPU masks are the final session of each
invocation, not all 720 service-child sessions. `taskset -c 0` was passed for
each session. Individual child PIDs and affinity masks were not retained.
The verification record reflects this distinction.

```sh
.venv/bin/python -m unittest \
  research.tests.test_oram_isolated_replication \
  research.tests.test_oram_isolated_timing
cargo build --locked --release -p oblivion-store \
  --example oram-measure --example oram-control
.venv/bin/python -m research.analysis.oram_isolated_replication \
  --config experiments/configs/oram-isolated-pinned-replication-20261026.json \
  --output /tmp/oram-isolated-pinned-replication-reproduced
```

The nine focused harness tests passed before collection, as did formatting,
warning-denied Clippy for `oblivion-store`, and a CPU-affinity smoke run. The
host load averages were 4.15/3.30/3.51 before and 2.10/2.40/3.00 after. These
load readings do not establish a quiet host; raw evidence and the pinned
configuration should be used when interpreting or reproducing this result.
