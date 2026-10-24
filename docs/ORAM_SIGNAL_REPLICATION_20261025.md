# Independent ORAM leaf/timing replication: fresh workload

The run followed the frozen [preregistration](ORAM_SIGNAL_REPLICATION_20261025_PREREG.md)
and configuration
[`oram-isolated-signal-replication-20261025.json`](../experiments/configs/oram-isolated-signal-replication-20261025.json).
The [report](../experiments/results/oram-isolated-replication-20261025-v3/report.json),
[raw session traces](../experiments/results/oram-isolated-replication-20261025-v3/raw/),
[predictions](../experiments/results/oram-isolated-replication-20261025-v3/predictions/),
[AUC figure](../experiments/results/oram-isolated-replication-20261025-v3/auc.png),
and [host observation](../experiments/results/oram-isolated-replication-20261025-v3/host-observation.json)
are retained. The workload seed, address distribution, hot/cold partition,
read probability, attacker, positive-control gate, and primary metric were
fixed before collection.

## Workload and observer

This is an independent workload replication using the existing, fixed attack
implementation; it is not an independent reimplementation of the classifier.
It uses a fresh eight-address workload with probabilities
`[0.35, 0.20, 0.15, 0.10, 0.08, 0.05, 0.04, 0.03]`. Address `0` is hot and
addresses `1..7` are cold; reads occur with probability `0.70`. The seed is
`20261026`. The study ran 30 attack trials per mode, eight independent ORAM
sessions per trial, and 128 accesses per session. Four complete sessions train
the classifier and four disjoint complete sessions supply its unlabeled
targets. Each paired session schedule was identical across plaintext,
encrypt-only and ORAM modes. ORAM state and bucket-service child processes
were fresh per session, with system CSPRNG leaves and keys.

The fixed random forest uses bucket/leaf identifiers, total visible bytes,
service time measured inside the separate bucket-service process, and the
predeclared short temporal features. It does not receive logical-address or
read/write labels during fit or prediction. `service_ns` includes the
in-memory bucket handler and excludes controller work, pipe waiting, request
decoding, response encoding, and trace output.

## Results

The primary metric is the predeclared mean per-access ROC AUC across 30 fitted
trials. The intervals are 95% percentile bootstraps over trial AUCs with 5,000
resamples.

| Mode | Mean AUC (95% trial-bootstrap interval) | Mean balanced accuracy | Profile-majority raw accuracy |
|---|---:|---:|---:|
| Plaintext | 1.0000 [1.0000, 1.0000] | 0.9989 | 0.6424 |
| Encrypt-only | 1.0000 [1.0000, 1.0000] | 0.9990 | 0.6424 |
| Path ORAM | 0.5015 [0.4935, 0.5095] | 0.5005 | 0.6424 |

Both deliberately leaky controls passed the preregistered gate before ORAM
was evaluated. The Path ORAM interval contains chance. For this workload and
attacker, the study did not distinguish the hot address from the cold class.
The majority-class accuracy is included because raw accuracy alone is
misleading under the 35/65 label split. This result is not a security proof
and does not show that other timing or leaf attacks fail.

## Provenance and limitations

The run retained 1,440 compressed observer/private trace files. A separate
post-run audit verified all 1,440 SHA-256 values from the report and compared
all 240 paired session schedules; each mode had 30 trials of 512 target
observations. The report records hashes for the config, analysis code, attack
code, and both release binaries. The targeted harness tests passed before the
run (9 tests), and the run completed in about 29 seconds.

The report's `platform.processor()` field is empty on this host. The sidecar
records the CPU model and 24 visible logical CPUs from `lscpu`. Immediately
before collection, load averages were 2.26, 3.52 and 4.33, with unrelated
desktop CPU activity; no other repository benchmark or correctness workload
was running, and CPU affinity was not pinned. Thus the bucket-handler timing
was process-isolated, but not isolated from host scheduling contention. That
noise may reduce power to detect subtle timing leakage. The result applies
only to this synthetic workload, local process boundary, selected features,
and one random-forest family. It is neither remote timing nor a TEE result.

## Reproduction

```sh
cargo build --locked --release -p oblivion-store \
  --example oram-measure --example oram-control
.venv/bin/python -m unittest \
  research.tests.test_oram_isolated_replication \
  research.tests.test_oram_isolated_timing
.venv/bin/python -m research.analysis.oram_isolated_replication \
  --config experiments/configs/oram-isolated-signal-replication-20261025.json \
  --output experiments/results/oram-isolated-replication-20261025-v3 \
  --oram-binary target/release/examples/oram-measure \
  --control-binary target/release/examples/oram-control
```

For another independent run, select a new output directory and a new seed
before collection. Keep the private driver files separate from attacker-visible
observer traces.
