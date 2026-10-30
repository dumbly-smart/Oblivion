# Preregistration: fresh-seed rank-64 transition attack

**Status:** frozen before collecting or analyzing the data in
`oram-isolated-rank64-transition-replication-20261030/`. The experiment uses a
new seed and higher address persistence. The transition attack is a
preregistered secondary analysis of the collector's temporal study on the
same new sessions. Its design was informed by prior ORAM attack studies, so it
is not blind.

## Question

Can a simple one-step profile transition lookup predict hot versus cold
logical addresses from the immediately previous visible storage tag when the
rank-64 workload has 0.80 address persistence? Do plaintext and encrypt-only
controls pass the frozen positive-control gate while Path ORAM remains
indistinguishable to this particular lookup within the trial uncertainty?

This is a controlled empirical attack evaluation, not an implementation of
IHOP or another published attack. The model estimates the next hot/cold label
from the preceding visible tag using labeled complete profile sessions. It
uses one prior pseudo-observation and the profile hot-class prior for each
target session's first operation. It resets at session boundaries.

## Frozen workload

The machine-readable configuration is
[`oram-isolated-rank64-transition-replication-20261030.json`](../experiments/configs/oram-isolated-rank64-transition-replication-20261030.json),
SHA-256
`d98f808f4450c77168953951a3d741e454573d8efca11616c6e80f7f3c6acf14`.
It preserves the rank-64 Zipf-like distribution and ORAM geometry, while
using a new seed `20261104` and address persistence `0.80`:

- 64 addresses; hot addresses 0–7; 64-byte logical blocks; bucket capacity 4.
- 55% read probability, 512 measured operations and 32 warmups per session.
- 30 trials and eight separately initialized sessions per trial.
- Sessions 0–3 form the complete labeled profile; sessions 4–7 are disjoint
  target sessions. Resampling is over the 30 trial clusters.
- Driver CPU 2; isolated bucket service requests CPU 0 affinity.
- Primary metric: mean per-trial target ROC AUC.
- 5,000-resample percentile bootstrap with seed `20261205` (workload seed
  plus 101).

No session from earlier rank-64 collections is an input. The new raw data are
not pooled with the persistence-0.40 or persistence-0.60 studies.

## Attack and control gate

Use the unchanged
`MarkovTransitionAttack` through
`research.analysis.oram_markov_transition_attack`, with
`--protocol-status preregistered-secondary`. Each target operation receives a
score from its immediately preceding visible bucket/leaf identifier. The
attacker does not receive target labels, private logical addresses, byte
counts, timing values, or operation type. The first target operation uses
the profile hot-class prior. Predictions are saved per trial without labels.

The collector's temporal random-forest controls run first and must both
achieve mean AUC at least 0.80 and a 95% lower bound above 0.50 before it
captures Path ORAM. The transition attack then independently applies the same
positive-control gate to plaintext and encrypt-only. If either gate fails,
retain the partial output and do not interpret a Path ORAM transition result.
Do not change the feature, smoothing, prior, split, metric, gate, trial set,
or output path after seeing results.

An AUC interval containing 0.50 is inconclusive for this attack and workload;
it is not a cryptographic proof or a claim of indistinguishability.

## Frozen outputs and commands

The raw collector path is
`experiments/results/oram-isolated-rank64-transition-replication-20261030/`;
the transition analysis path is
`experiments/results/oram-rank64-transition-replication-20261030/`. Both were
absent when this plan was prepared. Never overwrite them or alter prior raw
traces.

After this document and the configuration are committed, run:

```sh
cargo build --locked --release -p oblivion-store \
  --example oram-measure --example oram-control

taskset -c 2 .venv/bin/python -m research.analysis.oram_isolated_replication \
  --config experiments/configs/oram-isolated-rank64-transition-replication-20261030.json \
  --output experiments/results/oram-isolated-rank64-transition-replication-20261030 \
  --oram-binary target/release/examples/oram-measure \
  --control-binary target/release/examples/oram-control

.venv/bin/python -m research.analysis.oram_markov_transition_attack \
  --raw experiments/results/oram-isolated-rank64-transition-replication-20261030/raw \
  --config experiments/configs/oram-isolated-rank64-transition-replication-20261030.json \
  --output experiments/results/oram-rank64-transition-replication-20261030 \
  --protocol-status preregistered-secondary
```

After collection, independently validate the raw bundle, raw/source hashes,
target-only predictions, fixed session split, positive-control gate, saved
per-trial metrics, and bootstrap intervals. Preserve any validation receipt
beside the outputs. The verifier must not refit on target labels or change the
frozen attack.

## Frozen implementation and context hashes

| Input | SHA-256 |
| --- | --- |
| `research/analysis/oram_markov_transition_attack.py` | `fbd791e44e70ad4c3a8bb446b3a69bb9cc50ffbf8b000ed7005729592e9a8010` |
| `research/analysis/oram_isolated_replication.py` | `b07bf0ea683bd1064c92fd4043aae6fcbe3d7553237a3493fbb8dfcdb595a709` |
| `research/attacks/leaf_timing.py` | `353d3c21d5661e294f9af5afc610e73ea0a54a313f3230d2d72d5fb44fbe980a` |
| Rank-64 transition workload config | `d98f808f4450c77168953951a3d741e454573d8efca11616c6e80f7f3c6acf14` |
| Earlier primary rank-64 report | `56e58b9da6446a9c3bc684fbc512f6d9a5537e2efc9d94b6608b4e1930ed8c3b` |

The system continues to use a local isolated bucket-service process, not a
TEE or remote network. Host timing, scheduler noise, and process isolation
limitations remain those stated in [`THREAT_MODEL.md`](THREAT_MODEL.md).
