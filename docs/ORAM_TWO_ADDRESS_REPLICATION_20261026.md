# Isolated two-address ORAM timing replication

**Result:** both positive controls passed; the preregistered ORAM AUC interval
includes chance. This is a workload-specific non-detection, not evidence of
indistinguishability or a general ORAM timing guarantee.

## Question and design

This fresh-seed follow-up revisits the two-address 75/25 workload in
[`ORAM_LEAF_TIMING.md`](ORAM_LEAF_TIMING.md), which had a possible weak
exploratory AUC signal. It preserves the logical workload but deliberately
changes the measurement boundary: this run observes bucket-handler-only time
inside a separate bucket-service process, while the historical study included
controller and trace-draining time. It is therefore not an exact timing
replication.

The frozen configuration is
[`oram-isolated-two-address-replication-20261026.json`](../experiments/configs/oram-isolated-two-address-replication-20261026.json),
and the pre-collection plan is
[`ORAM_TWO_ADDRESS_REPLICATION_PREREG_20261026.md`](ORAM_TWO_ADDRESS_REPLICATION_PREREG_20261026.md).
It uses 30 trials, eight fresh sessions per trial, four complete profiling
sessions and four disjoint target sessions, 128 measured accesses per session,
eight warmups, a 16-block Path ORAM with 64-byte blocks and bucket capacity
four, 75/25 address popularity, and a 50/50 read/write mix. Paired workload
sequences are shared across plaintext, encrypt-only, and ORAM modes. The
temporal random forest and its features were fixed before collection. Mean
per-trial ROC AUC is the sole primary metric; the 95% interval is a percentile
bootstrap over 30 trial scores with 5,000 resamples. Each leaky control had to
score mean AUC at least 0.80 with its interval lower bound above 0.50.

The service process was pinned to logical CPU 0 and its driver to CPU 2. This
does not reserve a core or remove OS, interrupt, thermal, frequency, or other
host activity. The host is an Intel i7-14650HX with 24 logical CPUs. Load
averages were already 18.4/19.5/19.3 at collection start and reached
22.0/20.4/19.6 at the end. In particular, affinity separation is not a quiet
host or hardware isolation.

## Results

| Mode | Mean AUC | 95% trial-bootstrap interval | Balanced accuracy |
| --- | ---: | ---: | ---: |
| Plaintext positive control | 1.000 | [1.000, 1.000] | 1.000 |
| Encrypt-only positive control | 1.000 | [1.000, 1.000] | 1.000 |
| Path ORAM | 0.4989 | [0.4888, 0.5083] | 0.5029 [0.4959, 0.5107] |

The primary interval contains AUC 0.5. ORAM raw accuracy was 0.5029 versus a
0.7476 profile-majority baseline. The controls demonstrate that the attack
pipeline can distinguish this workload when visible identifiers expose the
address; they do not establish that the attacker has adequate power to detect
small effects under Path ORAM. The result does not resolve the earlier
exploratory interval, bound untested effect sizes, or support a cryptographic
security claim. A quieter-host replication and additional attacker/workload
families remain useful.

## Integrity and retained artifacts

The result directory
[`oram-isolated-two-address-replication-20261026`](../experiments/results/oram-isolated-two-address-replication-20261026/)
retains 1,440 compressed raw driver/observer files, configuration, host
observations, 90 prediction records, a figure, the analysis report, and
`verification.json`. The independent post-run check recomputed all raw-file
hashes, all five source/configuration/binary hashes, 240 paired trial-session
schedules, 430,080 observer events, 720 service-child records (720 unique
worker PIDs), and all 90 per-trial AUCs and their aggregates. The saved
verification record reports the checks and reproduced primary metrics. The
one-off verifier itself was not retained as a general-purpose audit tool.

The isolated replication/timing harness tests passed (12 tests), and both
release measurement examples built before collection. These checks validate
the harness and artifact accounting, not the classifier implementation or
the system's cryptographic security.

## Reproduction

From the repository root, rerun the frozen configuration into a new output
directory (collection uses fresh OS randomness for ORAM state, so a rerun is
new evidence and need not reproduce the same trace bytes):

```sh
.venv/bin/python -m unittest \
  research.tests.test_oram_isolated_replication \
  research.tests.test_oram_isolated_timing
cargo build --locked --release -p oblivion-store \
  --example oram-measure --example oram-control
taskset -c 2 .venv/bin/python -m research.analysis.oram_isolated_replication \
  --config experiments/configs/oram-isolated-two-address-replication-20261026.json \
  --output experiments/results/oram-isolated-two-address-reproduction
```

The full machine-readable output and raw traces are retained in the result
directory above. The configuration's seed reproduces the workload schedules;
it is not used as a cryptographic randomness source.
