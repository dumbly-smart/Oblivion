# Fresh-seed rank-64 ORAM transition attack replication

**Status:** completed from the protocol frozen in
[`ORAM_RANK64_TRANSITION_REPLICATION_PREREG_20261030.md`](ORAM_RANK64_TRANSITION_REPLICATION_PREREG_20261030.md).
The collection is a new seeded workload at address-persistence 0.80. The
one-step transition analysis is a preregistered secondary analysis of the
same raw sessions as the collector's temporal attack. It is not an independent
sample from that temporal analysis, and the protocol was informed by earlier
ORAM studies, so it is not blind.

## Question and attacker

The study asked whether a simple profile-based one-step transition lookup
could predict whether the next logical address was hot or cold from only the
immediately preceding visible ORAM tag. It is a small, explicitly bounded
attack, not an implementation or reproduction of IHOP or another published
attack.

For each trial, sessions 0–3 are labeled profile sessions and sessions 4–7 are
disjoint target sessions. The attacker learns which hot/cold label tends to
follow each visible tag from the complete profile sessions. It adds one prior
pseudo-observation to each transition count and uses the profile hot-class
prior for the first operation in each target session. State resets at session
boundaries. Target labels are read only after predictions have been saved.

The attack uses no target labels, logical addresses, request direction, byte
counts, service time, or wall-clock timing as features. Its only feature is
the immediately previous visible bucket/leaf identifier. The target is whether
the current logical address is one of addresses 0–7. A correct positive
control shows that this feature and model detect the deliberately exposed
control trace; it does not establish that the attack is optimal.

## Frozen workload and collection

The configuration is
[`oram-isolated-rank64-transition-replication-20261030.json`](../experiments/configs/oram-isolated-rank64-transition-replication-20261030.json),
SHA-256 `d98f808f4450c77168953951a3d741e454573d8efca11616c6e80f7f3c6acf14`.
It uses 64 logical addresses and 64-byte blocks, Path ORAM bucket capacity
four, hot addresses 0–7, a Zipf-like address distribution, and 0.80 Markov
address persistence. Each of 30 trials has eight separately initialized
sessions, with 512 measured operations and 32 warmups per session. The read
probability is 0.55. Four sessions per trial profile the attack and four
disjoint sessions are targets. The primary metric is mean per-trial ROC AUC;
its 95% percentile interval resamples 30 whole-trial AUCs 5,000 times using
seed 20261205.

The collector ran plaintext and encrypt-only positive controls before Path
ORAM. Its temporal random-forest controls passed, allowing ORAM collection.
The transition scorer independently required both its plaintext and
encrypt-only controls to have mean AUC at least 0.80 and a bootstrap lower
bound above 0.50 before scoring ORAM. Both gates passed. The driver was pinned
to CPU 2 and the isolated bucket-service process to CPU 0. The shared
24-logical-CPU host was busy: the recorded 1/5/15-minute load averages rose
from 11.35/6.59/3.95 at collection start to 12.10/7.71/4.54 at completion.

## Results

| Mode | Mean AUC | 95% trial-bootstrap interval | Balanced accuracy | Raw accuracy | Profile-majority accuracy |
| --- | ---: | ---: | ---: | ---: | ---: |
| Plaintext | 0.898148 | [0.895392, 0.900593] | 0.881434 | 0.881396 | 0.506445 |
| Encrypt only | 0.898148 | [0.895392, 0.900593] | 0.881434 | 0.881396 | 0.506445 |
| Path ORAM | 0.502017 | [0.497459, 0.506447] | 0.501285 | 0.502620 | 0.506445 |

The ORAM interval includes 0.50. The result is inconclusive for this single
previous-tag transition lookup on this workload, machine, and measurement
boundary. Its raw accuracy is below the profile-majority baseline. The
pooled ORAM target set contains 29,772 hot operations out of 61,440 (48.457%);
the labels remain private truth and are not features supplied to the attacker.

The identical plaintext and encrypt-only values are expected here: the
controls expose the same paired logical-address schedules to the transition
attacker. The collector's separate temporal random-forest result on these
same sessions was ORAM AUC 0.502353 [0.493573, 0.510796]. These are two attack
views over one new collection, not two independent replications.

Near-chance AUC does not show indistinguishability, cryptographic security,
absence of a timing signal, or resistance to other attacks. The finding is
limited to the declared transition feature, profile split, hot/cold target,
workload, local process topology, and host. In particular, it does not assess
a network observer, a different feature set, or the executor's internal view.

## Independent integrity and metric verification

The raw collector bundle retains 1,440 compressed driver/observer files,
source and executable identity, host observations, and the collector's
independent receipt. The transition bundle retains 90 compressed
target-only prediction files, the immutable attack report, and the plot.
The strengthened verifier independently checked:

- all 1,440 raw-file hashes against both analysis and collector manifests;
- the frozen configuration and attack, collector, and feature-code hashes;
- the exact 30-trial/mode coverage and four-profile/four-target whole-session
  split;
- that prediction artifacts contain only target session IDs, classes, and
  scores, with no target labels;
- score thresholds, labels reconstructed from private driver traces, and all
  90 per-trial AUC, accuracy, balanced-accuracy, and profile-majority values;
- the 5,000-resample interval for each mode and the positive-control gate.

Four focused verifier tests pass, including rejection of target labels in
prediction artifacts, rejection of scores inconsistent with reported
metrics, and correct retention of controls without ORAM scoring if a control
gate fails. The authoritative strengthened receipt is
[`independent-verification-v2.json`](../experiments/results/oram-rank64-transition-replication-20261030/independent-verification-v2.json).
The earlier `independent-verification.json` is preserved as the first
successful receipt; the v2 receipt records the final verifier source hash.

## Reproduction

Read the preregistration before changing any parameter. Reanalysis of the
retained collection must use a new output directory:

```sh
.venv/bin/python -m research.analysis.oram_markov_transition_attack \
  --raw experiments/results/oram-isolated-rank64-transition-replication-20261030/raw \
  --config experiments/configs/oram-isolated-rank64-transition-replication-20261030.json \
  --output experiments/results/oram-rank64-transition-reanalysis-NEW \
  --protocol-status preregistered-secondary

.venv/bin/python -m research.analysis.verify_oram_markov_transition_bundle \
  --raw experiments/results/oram-isolated-rank64-transition-replication-20261030/raw \
  --config experiments/configs/oram-isolated-rank64-transition-replication-20261030.json \
  --analysis experiments/results/oram-rank64-transition-reanalysis-NEW
```

The verifier refuses to overwrite an existing receipt. A fresh data
collection additionally requires building the locked ORAM measurement
examples and using new collector and analysis output directories, as frozen
in the preregistration.

## Retained evidence

- Frozen protocol: [`ORAM_RANK64_TRANSITION_REPLICATION_PREREG_20261030.md`](ORAM_RANK64_TRANSITION_REPLICATION_PREREG_20261030.md)
- Configuration: [`oram-isolated-rank64-transition-replication-20261030.json`](../experiments/configs/oram-isolated-rank64-transition-replication-20261030.json)
- Raw collector output and collector receipt: [`oram-isolated-rank64-transition-replication-20261030/`](../experiments/results/oram-isolated-rank64-transition-replication-20261030/)
- Attack report, prediction files, plot, and transition verifier receipts: [`oram-rank64-transition-replication-20261030/`](../experiments/results/oram-rank64-transition-replication-20261030/)
