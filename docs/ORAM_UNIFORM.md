# Uniform eight-address ORAM timing study

This fresh-seed workload changes the logical-address distribution to uniform
while preserving the existing eight-address operation count, 50/50 read/write
configuration, isolated bucket-handler timing observer, classifier, and
control-first methodology. The predeclared primary metric is ROC AUC. Both
plaintext and encrypt-only controls passed before ORAM evaluation.

The [configuration](../experiments/configs/oram-isolated-eight-address-uniform.json),
[report](../experiments/results/oram-isolated-eight-address-uniform-20261024/report.json),
[AUC plot](../experiments/results/oram-isolated-eight-address-uniform-20261024/auc.png),
and compressed traces are retained. The report includes SHA-256 hashes for
1,440 raw session files and five source/config/binary inputs. An independent
check verified all hashes and identical address/read/write sequences across
all 240 paired trial/session schedules.

## Method and results

There were 30 trials per mode with eight process sessions per trial; each trial
used four complete labeled profile sessions and four disjoint target sessions.
Each session contained 128 accesses over eight addresses, with addresses 0 and
1 as the hot class. Across 30,720 measured accesses per mode, 15,494 were reads
(50.44%) and 15,226 were writes. Address counts ranged from 3,736 to 3,916.
State and service processes were fresh; workloads were paired across modes.

| Mode | Mean AUC (95% trial interval) | Mean balanced accuracy (95% interval) | Profile-majority raw accuracy |
|---|---:|---:|---:|
| Plaintext | 1.00000 [1.00000, 1.00000] | 0.99852 [0.99556, 1.00000] | 0.74681 |
| Encrypt-only | 1.00000 [1.00000, 1.00000] | 0.99938 [0.99841, 1.00000] | 0.74681 |
| Path ORAM | 0.49267 [0.48190, 0.50309] | 0.49905 [0.49113, 0.50688] | 0.74681 |

The ORAM AUC interval includes 0.5 and its raw accuracy is below the
profile-majority baseline. This result applies only to the tested uniform
eight-address distribution and timing features. It neither proves zero
leakage nor predicts performance for other address spaces, classifiers, or
remote networks.

The separate tag-frequency-only attacker measured AUC 0.50462
[0.49350, 0.51545] and balanced accuracy 0.49907 on these same sessions; both
leaky controls passed. See the [cross-workload comparison](ORAM_ATTACK_FAMILIES.md).

## Reproduction

```sh
cargo build --locked --release -p oblivion-store \
  --example oram-measure --example oram-control
.venv/bin/python -m unittest \
  research.tests.test_oram_isolated_replication \
  research.tests.test_oram_isolated_timing
.venv/bin/python -m research.analysis.oram_isolated_replication \
  --config experiments/configs/oram-isolated-eight-address-uniform.json \
  --output experiments/results/oram-isolated-eight-address-uniform-new \
  --oram-binary target/release/examples/oram-measure \
  --control-binary target/release/examples/oram-control
```
