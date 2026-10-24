# Write-heavy eight-address ORAM timing study

This independent operation-mix follow-up uses a fresh seed and the same
eight-address distribution, hot/cold partition, isolated bucket-service timer,
classifier, and positive-control criteria as the prior read-heavy study. The
predeclared configuration requests a 10% read probability and uses ROC AUC as
the primary metric. Plaintext and encrypt-only controls must pass before the
ORAM condition is evaluated; both passed.

The [configuration](../experiments/configs/oram-isolated-eight-address-write-heavy.json),
[report](../experiments/results/oram-isolated-eight-address-write-heavy-20261024/report.json),
[AUC plot](../experiments/results/oram-isolated-eight-address-write-heavy-20261024/auc.png),
and compressed raw observer/private traces are retained. The report records
SHA-256 hashes for all 1,440 raw session files and five source/config/binary
inputs. A separate post-run check verified every hash and compared workload
sequences across all modes: all 240 trial/session pairs had identical address
and read/write schedules.

## Method and results

There were 30 trials per mode, eight independent process sessions per trial,
four profile sessions and four disjoint target sessions. Each session had 128
operations across eight logical addresses. Addresses 0 and 1 formed the hot
class. Across the 30,720 measured operations per mode, 3,040 were reads
(9.90%) and 27,680 were writes. ORAM state and service processes were fresh;
workload seeds and schedules were paired across modes.

| Mode | Mean AUC (95% trial interval) | Mean balanced accuracy (95% interval) | Profile-majority raw accuracy |
|---|---:|---:|---:|
| Plaintext | 0.99999 [0.99997, 1.00000] | 0.99665 [0.99458, 0.99850] | 0.61569 |
| Encrypt-only | 0.99999 [0.99998, 1.00000] | 0.99727 [0.99515, 0.99895] | 0.61569 |
| Path ORAM | 0.49572 [0.48678, 0.50489] | 0.49842 [0.49060, 0.50590] | 0.61569 |

The ORAM AUC interval includes 0.5, and the raw accuracy is below the
profile-majority baseline. The 90%-read matched workload measured AUC 0.49737
[0.48987, 0.50495]; the prior 50/50 operation-mix study measured 0.50670
[0.49593, 0.51749]. These finite results do not establish that operation mix
is irrelevant or that ORAM is indistinguishable. The observer still sees local
bucket-handler service time and access identifiers; it excludes remote
network timing, controller work, and pipe waiting.

## Reproduction

```sh
cargo build --locked --release -p oblivion-store \
  --example oram-measure --example oram-control
.venv/bin/python -m unittest \
  research.tests.test_oram_isolated_replication \
  research.tests.test_oram_isolated_timing
.venv/bin/python -m research.analysis.oram_isolated_replication \
  --config experiments/configs/oram-isolated-eight-address-write-heavy.json \
  --output experiments/results/oram-isolated-eight-address-write-heavy-new \
  --oram-binary target/release/examples/oram-measure \
  --control-binary target/release/examples/oram-control
```
