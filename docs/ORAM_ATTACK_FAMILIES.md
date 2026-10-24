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

## Frequency-only attack on the workload follow-ups

The same profile-to-tag scorer was also run after the read-heavy,
write-heavy, and uniform-address experiments. Each analysis used the matching
predeclared workload config, all 30 trials, and the existing rule to score
ORAM only after both controls passed. It collected no new storage traces. Raw
hashes and the analysis source/config hashes were rechecked independently.

| Workload | Plaintext AUC | Encrypt-only AUC | Path ORAM AUC (95% trial interval) | ORAM balanced accuracy | ORAM raw / majority accuracy |
|---|---:|---:|---:|---:|---:|
| 90% reads, skewed addresses | 1.000 | 1.000 | 0.49871 [0.49076, 0.50692] | 0.49767 | 0.58451 / 0.61693 |
| 10% reads, skewed addresses | 1.000 | 1.000 | 0.48877 [0.47959, 0.49859] | 0.49245 | 0.57207 / 0.61569 |
| 50/50 reads, uniform addresses | 1.000 | 1.000 | 0.50462 [0.49350, 0.51545] | 0.49907 | 0.73138 / 0.74681 |

The write-heavy result is below chance for this fixed score direction, with an
unadjusted interval whose upper endpoint is just below 0.5. This does not show
that an attacker can use an inverse score: target labels were not available to
choose a direction, and no held-out orientation-selection step was run. It is
also not evidence that the workload is private. A future attack should
predeclare any orientation-selection rule using profile-only validation.
Across these finite workloads, the observed controls show the scorer works on
the leaky systems while ORAM scores stay near chance and raw accuracy stays
below the profile-majority baseline.

## Reproduction

```sh
.venv/bin/python -m unittest research.tests.test_oram_attack_families
.venv/bin/python -m research.analysis.oram_attack_families \
  --config experiments/configs/oram-isolated-eight-address.json \
  --raw experiments/results/oram-isolated-eight-address-20261024 \
  --output experiments/results/oram-eight-address-frequency-new
```

The same command can be replayed with the read-heavy, write-heavy or
uniform-address config and raw directory. The retained reports are under
`experiments/results/oram-{read-heavy,write-heavy,uniform}-frequency-20261024/`.

The evaluator requires a new derived-output directory. It reads observer
features and private evaluation labels from separate raw files; only labeled
profile rows enter model fitting.
