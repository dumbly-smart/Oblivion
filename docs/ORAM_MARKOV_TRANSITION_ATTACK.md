# Post-hoc one-step transition attack on ORAM Markov traces

This exploratory analysis reuses the raw traces from the [preregistered Markov
locality study](ORAM_MARKOV_REPLICATION_20261026.md). The attack was designed
after the primary temporal-classifier scores were known. It is therefore a
post-hoc secondary analysis, not an independent replication.

## Attack

For every target operation after the first in a session, the attacker looks up
the immediately preceding visible bucket/leaf identifier in labeled profiling
sessions. It scores the next access as hot or cold using the observed
transition frequency with one profile-prior pseudo-observation. The first
target operation receives the profile class prior. The target's current
identifier and all target labels are excluded from prediction. Profiling uses
four complete sessions per trial; scoring uses four disjoint sessions.

This simple lookup tests a different inductive bias from the primary random
forest. It is not a published attack reproduction. The primary Markov study's
30 trials are reused, and all results should be interpreted as exploratory.

## Results

| Mode | Mean AUC (95% trial-bootstrap interval) | Balanced accuracy | Raw accuracy | Profile-majority raw accuracy |
|---|---:|---:|---:|---:|
| Plaintext | 0.9216 [0.9162, 0.9271] | 0.9178 | 0.9257 | 0.6277 |
| Encrypt-only | 0.9216 [0.9162, 0.9271] | 0.9178 | 0.9257 | 0.6277 |
| Path ORAM | 0.4967 [0.4891, 0.5043] | 0.4968 | 0.5916 | 0.6277 |

Both positive controls exceeded the 0.80 mean-AUC threshold, with lower
confidence limits above 0.50, before ORAM was evaluated. On the retained ORAM
sessions, this attack did not distinguish the hot/cold labels; its AUC interval
contains chance, and its raw accuracy is below the profile-majority baseline.
This result does not exclude other attacks, features, workloads, or
cross-layer leakage and is not a security proof.

## Provenance and reproduction

The derived [report, predictions, and figure](../experiments/results/oram-markov-transition-20261026/)
record the 30 trial metrics and hashes for the analysis, attack, configuration,
and every input trace. A separate post-run check verified all 1,440 raw input
hashes and all four source/config hashes.

```sh
.venv/bin/python -m unittest research.tests.test_oram_markov_transition_attack
.venv/bin/python -m research.analysis.oram_markov_transition_attack \
  --raw experiments/results/oram-markov-replication-20261026/raw \
  --config experiments/configs/oram-markov-signal-20261026.json \
  --output experiments/results/oram-markov-transition-20261026
```
