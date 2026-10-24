# ORAM tag-frequency attack

This is a post-hoc second attacker on the hash-verified raw sessions from the
[eight-address ORAM study](ORAM_EIGHT_ADDRESS.md). It collected no new system
traces and did not rewrite the source raw data. The separately retained
[derived report](../experiments/results/oram-eight-address-frequency-20261024/report.json)
hashes all 1,440 input traces and records its own code/config provenance.

## Attacker

The frequency-only attacker counts visible leaf tags by hot/cold class in
labeled profiling sessions. It uses a 0.5 smoothing prior, then maps each
unlabeled target tag to its profile-derived hot probability. It does not use
timing, packet sizes, operation type, target-session frequencies, or target
labels. The input schema rejects private labels or additional fields. Four
complete profiling sessions and four disjoint target sessions are used in
each of 30 trials. The hot class is addresses 0 and 1; the other six addresses
are cold.

The plaintext and encrypt-only positive controls are evaluated first. ORAM is
scored only if each control's mean AUC is at least the configured 0.8 threshold
and its 95% interval lower bound exceeds 0.5. Both controls passed. The
temporal random-forest figures below come from the original analysis of these
same sessions; the two attackers therefore have paired target data, not
independent repetitions.

## Results

| Mode | Tag-frequency AUC (95% trial interval) | Tag-frequency balanced accuracy | Temporal RF AUC (95% trial interval) |
|---|---:|---:|---:|
| Plaintext | 1.000 [1.000, 1.000] | 1.000 | 1.000 [1.000, 1.000] |
| Encrypt-only | 1.000 [1.000, 1.000] | 1.000 | 1.000 [1.000, 1.000] |
| Path ORAM | 0.498 [0.488, 0.508] | 0.497 | 0.507 [0.496, 0.517] |

On ORAM, frequency-only raw accuracy was 0.585, below the 0.617
profile-majority baseline; its balanced accuracy was 0.497. Both ORAM attack
intervals include 0.5. These are finite results against two chosen attackers
on one synthetic workload, not a security proof or evidence of universal
indistinguishability. The frequency-only method is a deliberately simple
profile-to-tag classifier, not a reproduction of a named published attack.

## Reproduction

```sh
.venv/bin/python -m unittest research.tests.test_oram_attack_families
.venv/bin/python -m research.analysis.oram_attack_families \
  --config experiments/configs/oram-isolated-eight-address.json \
  --raw experiments/results/oram-isolated-eight-address-20261024 \
  --output experiments/results/oram-eight-address-frequency-new
```

The evaluator requires a new derived-output directory. It reads observer
features and private evaluation labels from separate raw files; only labeled
profile rows enter model fitting.
