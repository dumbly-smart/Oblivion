# Preregistered isolated ORAM timing replication with service CPU affinity

**Status:** frozen before collection. Planned output:
`experiments/results/oram-isolated-pinned-replication-20261026/`.

## Question

Does the existing temporal leaf/timing classifier distinguish two hot
logical addresses from six cold addresses when each separate bucket-service
process is restricted to one CPU, with the driver left unpinned? This tests a
fresh seeded workload under a narrower scheduling configuration. It is not a
controlled treatment comparison against the earlier unpinned runs because the
workload seed and collection date differ.

## Frozen design

The machine-readable configuration is
[`oram-isolated-pinned-replication-20261026.json`](../experiments/configs/oram-isolated-pinned-replication-20261026.json).
It fixes 30 trials, eight independent controller sessions per trial, four
complete profiling sessions and four disjoint target sessions, 128 measured
operations per session, eight warm-up accesses, 32 blocks, 64-byte blocks,
and bucket capacity four. The address refresh distribution is
`[0.25, 0.18, 0.15, 0.12, 0.10, 0.08, 0.07, 0.05]`; addresses 0 and 1 are
the hot class. The Markov process retains the previous address with
probability 0.80, and reads occur with probability 0.60. The seed is
`20261029`; every trial/session receives an independent deterministic stream,
paired exactly across plaintext, encrypt-only, and ORAM modes. ORAM leaves,
AEAD keys, and nonces use OS cryptographic randomness.

Only the service child is pinned. CPU selection is fixed as the lowest CPU ID
in the process's allowed affinity set at the time of collection; this host's
allowed set is `0-23`, so the preregistered CPU is 0. The service's actual
`/proc/<pid>/status` affinity must be exactly `0`, otherwise collection stops.
The workload-driver process remains unpinned. `taskset` is required. This
setting limits migration but does not reserve a core or isolate it from other
tasks, interrupts, SMT siblings, frequency changes, thermal throttling, or
scheduler noise.

## Primary metric and stopping rules

The sole primary metric is mean per-access ROC AUC over 30 fitted trials.
Uncertainty is the percentile bootstrap 95% interval over the 30 per-trial
AUCs with 5,000 resamples. Chance is 0.5. Balanced accuracy and
profile-majority accuracy are secondary descriptions. Plaintext and
encrypt-only positive controls run first; each must have mean AUC at least
0.80 and a bootstrap lower bound above 0.50. If either fails, stop without
evaluating ORAM. The existing fixed random forest, feature set, session split,
classifier seed, and analysis are unchanged. An ORAM interval containing
chance is inconclusive for this attacker and workload, never a proof of
indistinguishability.

No workload parameter, feature, classifier, threshold, metric, CPU, or trial
may be changed after inspecting outcomes. Any interrupted or failed collection
is recorded as such; it is not silently resumed under the same output path.

## Collection environment and method

Before collection on 2026-10-26, the host reported an Intel Core i7-14650HX,
Linux 7.2.11 x86_64, 24 allowed logical CPUs (`0-23`), and load averages
`4.15, 3.30, 3.51`. The selected CPU follows the fixed lowest-allowed-ID rule,
not an outcome-dependent selection. These are host observations, not a claim
that the CPU is otherwise idle. The driver remains unrestricted and normal OS
activity may run on CPU 0.

Run focused harness tests before collection, then build the two release
examples and run the replication command below. No repository benchmark or
test suite runs concurrently with collection. The harness records effective
child affinity, controller/service PIDs, binary/source hashes, paired schedule
verification, raw trace hashes, and host metadata. Preserve raw traces and
predictions in the output archive.

```sh
.venv/bin/python -m unittest \
  research.tests.test_oram_isolated_replication \
  research.tests.test_oram_isolated_timing
cargo build --locked --release -p oblivion-store --example oram-measure
cargo build --locked --release -p oblivion-store --example oram-control
.venv/bin/python -m research.analysis.oram_isolated_replication \
  --config experiments/configs/oram-isolated-pinned-replication-20261026.json \
  --output experiments/results/oram-isolated-pinned-replication-20261026
```

The observer receives physical bucket identifiers, fixed-shape byte counts,
and handler-only time from a local child process. It does not receive private
logical-address or operation labels. This is not remote-network timing, a TEE,
or a general workload result.
