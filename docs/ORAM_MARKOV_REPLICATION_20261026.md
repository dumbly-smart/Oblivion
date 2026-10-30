# ORAM leakage evaluation with Markov-locality workload

The experiment followed the frozen [preregistration](ORAM_MARKOV_REPLICATION_20261026_PREREG.md)
and [configuration](../experiments/configs/oram-markov-signal-20261026.json).
Its retained [report](../experiments/results/oram-markov-replication-20261026/report.json),
[raw traces](../experiments/results/oram-markov-replication-20261026/raw/),
[predictions](../experiments/results/oram-markov-replication-20261026/predictions/),
[AUC figure](../experiments/results/oram-markov-replication-20261026/auc.png),
and [host observation](../experiments/results/oram-markov-replication-20261026/host-observation.json)
are preserved.

## Workload and attacker

This was a fresh workload run of the already-fixed per-access temporal random
forest. Each session contained 128 operations over eight logical addresses.
The first address was sampled from the configured skew; each subsequent access
retained the previous address with probability 0.85 and otherwise sampled a new
address from that same distribution. The distribution assigns address 0
probability 0.35 and addresses 1–7 probabilities 0.20, 0.15, 0.10, 0.08, 0.05,
0.04, and 0.03. Read probability was 0.70. The process has expected adjacent
repeat probability `0.85 + 0.15 * sum(p_i^2) = 0.88096`; the independent audit
measured 0.88068. The pooled hot-address rate was 0.3621.

Each of the 30 trials used four whole profiling sessions and four disjoint
whole target sessions. Plaintext and encrypt-only controls were evaluated
first; the fixed Path ORAM configuration was run only after both controls
passed. The classifier received only the declared visible per-access features.
It was not retrained or tuned for this workload.

## Results

| Mode | Mean per-access AUC (95% trial-bootstrap interval) | Balanced accuracy | Profile-majority raw accuracy |
|---|---:|---:|---:|
| Plaintext | 1.0000 [1.0000, 1.0000] | 0.9996 | 0.6277 |
| Encrypt-only | 1.0000 [1.0000, 1.0000] | 0.9996 | 0.6277 |
| Path ORAM | 0.5105 [0.4838, 0.5389] | 0.5105 | 0.6277 |

Both positive controls exceed the preregistered mean-AUC threshold of 0.80
and their 95% lower bounds exceed 0.50, so the ORAM result is interpretable
under the predeclared control rule. The ORAM AUC interval includes chance;
this fixed classifier did not reliably infer hot versus cold accesses in this
synthetic Markov-locality workload. The observed raw accuracy is below the
profile-majority baseline. These findings do not establish cryptographic
indistinguishability, and do not cover other temporal, scheduler, network, or
cross-layer attacks.

## Integrity and environment

The run retained 1,440 compressed observer/private files. A separate audit
verified every raw-file SHA-256 listed in the report, all 240 paired
session-schedule comparisons across the three modes, 128 operations per
session, and address bounds. The paired logical-address and operation
schedules were identical across modes. The per-mode operation count was
30,720. Source and binary digests are recorded in `report.json`.

Collection took approximately 63 seconds. Immediately beforehand, host load
averages were 5.20, 4.79, and 4.81 with unrelated desktop and virtual-machine
processes active. CPU affinity was not pinned. The separate bucket service
isolates the timing interval from the controller's own work, but not from
host scheduling or CPU contention; that noise could reduce power. This is a
local component experiment, not remote timing or TEE evaluation.

## Reproduction

```sh
cargo build --locked --release -p oblivion-store \
  --example oram-measure --example oram-control
cargo test --locked -p oblivion-store --examples
.venv/bin/python -m unittest \
  research.tests.test_oram_isolated_replication \
  research.tests.test_oram_isolated_timing
.venv/bin/python -m research.analysis.oram_isolated_replication \
  --config experiments/configs/oram-markov-signal-20261026.json \
  --output experiments/results/oram-markov-replication-20261026 \
  --oram-binary target/release/examples/oram-measure \
  --control-binary target/release/examples/oram-control
```
