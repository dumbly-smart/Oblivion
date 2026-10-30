# Presence/intersection sensitivity evaluation

This is a reproducible **synthetic** sensitivity analysis. It explores how a candidate-ranking attacker responds to changes in semantic beacon strength and false positives, enrollment churn, missed cover observations, and the client population size. It is not a network capture, a replication of real network conditions, or a differential privacy evaluation. The simulated noisy beacon is not differential privacy.

## Method

Each scenario generates 240 independent sessions of 64 epochs. Sessions are deterministically divided into 60 training sessions and 180 held-out test sessions using seed `20261024`; epochs are never split across partitions. The attacker sees only each epoch's client identity presence markers and one semantic beacon bit. It does not receive the owner label, enrollment state, or generated latent truth. It ranks candidates by a per-session likelihood score. Training sessions estimate the beacon's base event rate, which is reported as a calibration baseline; inference uses the scenario's declared beacon sensitivity, false-positive rate, and missed-cover rate.

Accuracy is computed per held-out session. The report includes a bootstrap 95% interval resampling whole sessions, a uniform-random expected accuracy adjusted for each session's population, and a fixed-first-candidate baseline interval. Two positive controls are checked before results are written: strong semantic signal with stable enrollment, and strong semantic signal with high churn and a changing population. Both must have a lower 95% accuracy bound above their uniform-random expected baseline.

## Results

The deterministic run is retained in [`summary.json`](../experiments/results/presence-sensitivity-20261024/summary.json), with scenario settings in [`presence-sensitivity.json`](../experiments/configs/presence-sensitivity.json).

| Scenario | Attacker accuracy (95% session bootstrap CI) | Uniform-random expected accuracy |
|---|---:|---:|
| Strong stable positive control | 0.800 (0.744–0.856) | 0.125 |
| Strong churn positive control | 1.000 (1.000–1.000) | 0.118 |
| Weaker semantic beacon | 0.944 (0.906–0.978) | 0.125 |
| High beacon noise | 0.350 (0.283–0.422) | 0.125 |
| High enrollment churn | 1.000 (1.000–1.000) | 0.125 |
| High missed cover | 0.767 (0.706–0.828) | 0.125 |
| Changing population | 0.994 (0.983–1.000) | 0.113 |
| Combined adverse conditions | 0.794 (0.733–0.850) | 0.115 |

High beacon noise lowers accuracy but remains above chance in this simulated run, while combining weaker beacon semantics with churn, missed observations, and changing populations also leaves accuracy above the changing-population random baseline. This is evidence about this synthetic model and attacker only; it does not establish the attacker's performance against actual network traces.

## Reproduction

```sh
python -m research.analysis.presence_sensitivity \
  --config experiments/configs/presence-sensitivity.json \
  --out experiments/results/presence-sensitivity-20261024
python -m unittest research.tests.test_presence_sensitivity
```

The output records SHA-256 fingerprints for the config, this analysis script, and the frozen pre-existing presence analysis and attack modules. This evaluation did not modify those existing modules or results.
