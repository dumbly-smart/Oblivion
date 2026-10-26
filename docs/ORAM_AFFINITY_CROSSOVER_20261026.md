# ORAM service-affinity crossover

This result follows the frozen [preregistration](ORAM_AFFINITY_CROSSOVER_PREREG_20261026.md)
and [configuration](../experiments/configs/oram-affinity-crossover-20261026.json).
The study used paired deterministic address/operation schedules under pinned
and unpinned service-process conditions, with condition order counterbalanced
across 30 trials.

## Results

All four leaky control groups passed: plaintext and encrypt-only AUC was 1.000
in both conditions. ORAM attack performance was:

| Service condition | Mean AUC (95% trial-bootstrap interval) | Mean balanced accuracy (95% interval) | Profile-majority accuracy |
|---|---:|---:|---:|
| Pinned to CPU 0 | 0.5120 [0.4909, 0.5322] | 0.5078 [0.4950, 0.5210] | 0.5514 |
| Unpinned | 0.4948 [0.4739, 0.5167] | 0.4985 [0.4834, 0.5141] | 0.5514 |

The preregistered primary contrast was the paired per-trial AUC difference,
pinned minus unpinned. Its mean was `+0.0172`, with a paired bootstrap 95%
interval `[-0.0162, +0.0497]`. The interval includes zero. The study does not
show a reliable change in attacker performance from pinning. Both ORAM
conditions' intervals include chance, and balanced accuracy is below the
profile-majority baseline. These observations do not show that either
condition hides all workload information.

## Workload and collection

Both conditions used the same seeded address and operation schedule per trial
and session: eight addresses, hot set `{0, 1}`, a Markov retention probability
of 0.80, read probability 0.60, and refresh weights
`[0.25, 0.18, 0.15, 0.12, 0.10, 0.08, 0.07, 0.05]`. The 30,720 measured
accesses in each condition had 82.89% adjacent-address retention, 43.40% hot
addresses, and 60.06% reads. ORAM state and cryptographic randomness were
fresh per session. Each trial used four whole profiling sessions and four
disjoint target sessions.

Pinned-first and unpinned-first ordering each occurred in 15 trials. The
measurement used 180 collector-process invocations and produced 1,440
service-child sessions. Each pinned collector invocation's retained final
session metadata showed effective CPU set `0`; `taskset -c 0` was configured
for every service child. The collector overwrote `isolated-service.json` on
each session, so individual child PIDs and masks were not retained. The
unpinned condition did not invoke `taskset`. The host was shared; no
pre-collection load snapshot was retained. Pinning does not reserve CPU 0 or
control OS activity, frequency, thermal effects, or sibling work.

The attacker saw physical bucket identifiers, fixed-shape byte counts,
handler-only isolated service times, and the fixed temporal features. This is
a local process measurement, not remote timing or a TEE evaluation.

## Collection recovery and retained evidence

All 2,880 raw observer/private trace files were collected. The first report
assembly attempt then raised a `NameError` for `Path`; it occurred after the
controls, ORAM collection, affinity metadata checks and raw schedule checks.
The preserved traces were reanalyzed offline, without recollecting sessions.
The recovery is recorded in the report and verification record.

The archive contains 2,880 raw traces and 180 prediction files:
[`trace-data.tar.gz`](../experiments/results/oram-affinity-crossover-20261026/trace-data.tar.gz),
SHA-256 `c17651b78dc73bd3fcefd81446e1e90360b022685da9d5282cef251ee4e1d5ba`.
The result directory also contains the machine-readable report, plot,
configuration, condition-order/metadata records, verification summary and
host observation. Source hashes identify commit `26460042` used for
collection; report repair code is recorded separately.

To reproduce the analysis from extracted raw files, use a fresh output
directory with `raw/` and `predictions/` extracted at its root:

```sh
mkdir -p /tmp/oram-affinity-crossover
tar -xzf experiments/results/oram-affinity-crossover-20261026/trace-data.tar.gz \
  -C /tmp/oram-affinity-crossover
.venv/bin/python -m research.analysis.oram_affinity_crossover \
  --config experiments/configs/oram-affinity-crossover-20261026.json \
  --output /tmp/oram-affinity-crossover \
  --analyze-existing --collection-head 26460042
```

This paired study reduces seed mismatch between conditions, but the host was
not isolated and only one classifier/workload family was tested. Its
confidence interval is compatible with small leakage changes in either
direction. It is not a cryptographic security result.
