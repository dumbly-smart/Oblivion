# Leaf/tag and timing inference on historical ORAM traces

This experiment reanalyzes actual saved component traces from `leakage-30trials-20261020/`; it is not a new execution of the current process pipeline. [Report](../experiments/results/oram-leaf-timing-20261023/report.json) and [figure](../experiments/results/oram-leaf-timing-20261023/leaf-timing.png) retain all 30 trial scores, source/attacker hashes and every input-file digest.

## Attacker and observations

Each trial has eight independently initialized sessions. The first four sessions provide labeled profiling data; the other four complete sessions are targets. The workload accesses two logical records with 75/25 popularity. In ORAM these are logical addresses 0 and 1 in a 16-block, 64-byte configuration. Plaintext and encrypt-only controls expose independently permuted physical/logical tags per session, so a classifier cannot simply memorize one session's address-to-label mapping.

The bounded 64-tree depth-six forest uses visible tag/leaf, bytes, log duration and within-session tag frequency. Frequencies are computed from unlabeled complete target observations, a declared transductive capability. Only profiling labels enter fitting; target labels enter scoring afterward. Target sessions must be disjoint from profiling sessions. No guest status, logical address or private stash field enters the attacker. Raw tree scores are uncalibrated; the common adapter returns `confidence=None`.

Duration is the historical local API measurement, including controller and trace-draining work. It is not isolated storage server time or a remote packet measurement. The original ORAM observer derives the accessed leaf from the physical tree trace. Controls perform actual plaintext lookups or AEAD decryptions and expose their addresses. All three modes run through the saved genuine harness; no cryptographic primitive or storage backend is mocked by this reanalysis.

## Results

95% intervals bootstrap equal-weight complete fitted-model trial scores, with 5,000 resamples. There are 30 models/mode and four held-out target sessions/model. Balanced binary chance is 50%; raw accuracy must additionally be compared with the profiling-majority predictor (74.50%).

| Mode | Balanced accuracy, 95% trial interval | AUC, 95% trial interval |
| --- | --- | --- |
| Plaintext | 100.00% [100.00,100.00] | 1.000 [1.000,1.000] |
| Encrypt-only | 99.62% [98.87,100.00] | 0.998 [0.994,1.000] |
| Path ORAM | 50.70% [49.80,51.62] | 0.511 [0.501,0.521] |

Both deliberately leaky controls passed before the ORAM results were interpreted. ORAM raw accuracy is 55.13%, below its majority predictor; class balancing changes the forest decision rule. The balanced-accuracy interval crosses chance, while the exploratory AUC interval excludes 0.5 narrowly. That possible weak signal is retained. These are unadjusted intervals across several reported metrics, not a preregistered multiplicity-controlled finding. Neither a near-chance metric nor a small effect establishes a cryptographic theorem. Follow-up measurements should isolate controller timing and repeat with independent new workloads and a declared primary metric.

This closes a bounded two-record leaf-plus-timing inference experiment. It does not assess arbitrary address universes, operation-type inference, full sequences, cache/page faults, the current process scheduler or every host observation.

## Reproduce

```sh
.venv/bin/python -m pip install -r research/requirements.lock
.venv/bin/python -m unittest research.tests.test_leaf_timing research.tests.test_attack_registry
.venv/bin/python -m research.analysis.oram_classifier experiments/results/leakage-30trials-20261020 experiments/results/oram-leaf-timing-new
```

The output directory must be new. Profiling/target IDs and schemas are checked by the reusable `leafTiming` adapter; two focused tests cover the permuted-session leaky control and rejection of shared sessions, truth fields and malformed observations.
