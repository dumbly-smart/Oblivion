# Read-heavy eight-address ORAM timing study

This follow-up changes the access operation mix while holding the eight-address
workload, seed and address schedules constant. The configuration requests a
90% read probability; the 30,720 measured operations per mode contain 3,024
writes (9.84%). Address sequences match the earlier 50/50 eight-address study
for every paired session. ORAM position state, service process and control
keys remain fresh.

The [configuration](../experiments/configs/oram-isolated-eight-address-read-heavy.json),
[report](../experiments/results/oram-isolated-eight-address-read-heavy-20261024/report.json),
[AUC plot](../experiments/results/oram-isolated-eight-address-read-heavy-20261024/auc.png),
and compressed observer/private traces are retained. The report hashes all
1,440 raw files; an independent verification checked their hashes, matching
address/read/write schedules across modes, and matching address schedules
against the 50/50 study. A separate fresh-seed [write-heavy study](ORAM_WRITE_HEAVY.md)
uses the same observer and primary metric at a 10% read probability. The
[uniform-address study](ORAM_UNIFORM.md) changes the address prior with the
balanced operation mix.

## Method and results

The study has 30 trials per mode, eight complete process sessions per trial,
four labeled profiling sessions and four disjoint target sessions. Each
session has 128 operations over eight logical addresses. Addresses 0 and 1
are the hot class. The same temporal random-forest classifier and local
bucket-handler timing observation are used as in the [50/50 study](ORAM_EIGHT_ADDRESS.md).
Both leaky controls must pass before ORAM is evaluated; both did.

| Mode | Mean AUC (95% trial interval) | Mean balanced accuracy (95% interval) | Profile-majority raw accuracy |
|---|---:|---:|---:|
| Plaintext | 0.99998 [0.99994, 1.00000] | 0.99803 [0.99644, 0.99938] | 0.61693 |
| Encrypt-only | 0.99999 [0.99997, 1.00000] | 0.99684 [0.99417, 0.99902] | 0.61693 |
| Path ORAM | 0.49737 [0.48987, 0.50495] | 0.49760 [0.49027, 0.50514] | 0.61693 |

The ORAM interval includes 0.5 and the raw accuracy is below the majority
baseline. The 50/50 ORAM AUC on the matched address schedules was 0.50670
[0.49593, 0.51749]. These results do not establish that operation mix is
irrelevant or that ORAM is indistinguishable; they report two finite workload
conditions for one classifier. The service timing remains local and excludes
pipe/controller timing, and no remote-network or TEE result is implied.

## Reproduction

```sh
cargo build --locked --release -p oblivion-store \
  --example oram-measure --example oram-control
.venv/bin/python -m unittest \
  research.tests.test_oram_isolated_replication \
  research.tests.test_oram_isolated_timing
.venv/bin/python -m research.analysis.oram_isolated_replication \
  --config experiments/configs/oram-isolated-eight-address-read-heavy.json \
  --output experiments/results/oram-isolated-eight-address-read-heavy-new \
  --oram-binary target/release/examples/oram-measure \
  --control-binary target/release/examples/oram-control
```
