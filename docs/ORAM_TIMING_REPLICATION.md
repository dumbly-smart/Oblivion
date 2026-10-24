# Fresh isolated ORAM leaf/timing replication

The [recorded config](../experiments/configs/oram-isolated-replication.json),
[aggregate report](../experiments/results/oram-isolated-replication-20261025-v2/report.json),
[AUC figure](../experiments/results/oram-isolated-replication-20261025-v2/auc.png),
and compressed raw sessions in [the raw directory](../experiments/results/oram-isolated-replication-20261025-v2/raw/)
retain the 2026-10-25 run. The report includes SHA-256 hashes for every raw
observer and private-driver file, the analysis and attack code, the binaries,
and the configuration. A post-run check re-read all 1,440 raw files, verified
their hashes, and confirmed the workload schedule was identical across all
three modes.

## Design

The config fixes 30 independent seeded classifier trials. Each trial contains
eight complete process sessions: four labeled profiling sessions and four
disjoint target sessions. Every session runs 128 logical accesses over two
records, with address 0 selected with probability 0.75, address 1 with
probability 0.25, and a 0.5 write probability. The same seeded address and
operation schedule is verified against private driver labels in plaintext,
encrypt-only, and Path ORAM modes. ORAM position state and AEAD keys are fresh
per session; cryptographic randomness comes from the operating system.

The controls and ORAM all use a separate bucket-service process with fixed
request and response sizes. A direct control performs one visible read and one
visible write per logical access, even when the client operation is a read.
The plaintext control stores actual plaintext blocks. The encrypt-only control
stores ChaCha20-Poly1305 records with a fresh session key, a unique
prefix-plus-counter nonce, and address-bound associated data, while the
service still receives the direct logical address. These are deliberately
leaky positive controls.

Only after both controls clear the configured threshold does the harness run
ORAM. Its observer rows are reduced to one row per logical access using the
physical leaf bucket identifier, total visible bytes, and the sum of
bucket-handler service times. The attacker does not receive the logical
address or operation-type labels. It gets labeled complete control profiling
sessions and unlabeled target sessions. The nonlinear random forest uses
within-session tag frequency, tag identifiers, service time, recent tag
repetitions, and short 4/8/16-access windows. Target sessions are fully
unlabeled transductive observations when those frequencies are calculated.
The predeclared primary metric is per-access ROC AUC; intervals bootstrap the
30 fitted-trial means with 5,000 resamples.

## Result

| Mode | Mean AUC (95% trial-bootstrap interval) | Mean balanced accuracy | Profile-majority raw accuracy |
|---|---:|---:|---:|
| Plaintext | 1.000 [1.000, 1.000] | 1.000 | 0.747 |
| Encrypt-only | 1.000 [1.000, 1.000] | 1.000 | 0.747 |
| Path ORAM | 0.502 [0.491, 0.513] | 0.502 | 0.747 |

Both positive controls succeeded before ORAM was evaluated. Under this
two-record workload and this observer/attacker, ORAM AUC is near chance and
its interval includes 0.5. This is an empirical failure to distinguish the
classes in these trials, not a proof of indistinguishability or cryptographic
security. ORAM raw accuracy should be read beside the 0.747 profile-majority
baseline; balanced accuracy is the more appropriate class-sensitive summary.

The timing is measured inside the local bucket-service process. It includes
the in-memory bucket handler and excludes controller work, pipe waiting,
request decoding and reply encoding. It is not remote service/network timing,
and the process boundary is not a TEE. The study has only two addresses, one
hot/cold distribution, one operation mix, one RF family and short temporal
features. It does not replicate every possible attack or replace the earlier
historical result.

The initial same-day run in
[the superseded report](../experiments/results/oram-isolated-replication-20261025/report.json)
is preserved but marked superseded: its warm-up advanced the workload RNG
differently across controls and ORAM, so the address/read-write streams were
not paired. The corrected v2 run uses a separate identically seeded warm-up
stream and verifies measured address and operation schedules from private
driver records before scoring.

## Reproduce

```sh
cargo build --locked --release -p oblivion-store \
  --example oram-measure --example oram-control
.venv/bin/python -m unittest \
  research.tests.test_oram_isolated_replication \
  research.tests.test_oram_isolated_timing
.venv/bin/python -m research.analysis.oram_isolated_replication \
  --config experiments/configs/oram-isolated-replication.json \
  --output experiments/results/oram-isolated-replication-new \
  --oram-binary target/release/examples/oram-measure \
  --control-binary target/release/examples/oram-control
```

Use a new output directory for every run. Raw observer traces and private
labels are stored in distinct subdirectories. Keep those files separate when
providing traces to another attacker.
