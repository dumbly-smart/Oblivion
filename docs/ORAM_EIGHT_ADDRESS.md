# Eight-address isolated ORAM timing replication

This follow-up expands the [two-address isolated timing study](ORAM_TIMING_REPLICATION.md)
to eight logical addresses with a fixed skewed distribution. The
[configuration](../experiments/configs/oram-isolated-eight-address.json),
[aggregate report](../experiments/results/oram-isolated-eight-address-20261024/report.json),
[AUC plot](../experiments/results/oram-isolated-eight-address-20261024/auc.png),
and 1,440 compressed public/private session traces are retained. Reported
SHA-256 values were independently rechecked after the run, and address plus
read/write schedules were verified identical in all three modes.

## Method

The study runs 30 seeded trials per mode. Each trial has eight fresh isolated
process sessions, four complete labeled profiling sessions, and four disjoint
unlabeled target sessions. Every session makes 128 actual accesses over eight
addresses. Their probabilities are 0.40, 0.22, 0.13, 0.09, 0.06, 0.045,
0.03, and 0.025. Addresses 0 and 1 form the hot class; all others form the
cold class. Reads and writes are equally likely. Every operation is checked
against its private full-record oracle.

The same seeded schedule is executed first against plaintext and encrypt-only
direct-address controls. ORAM is run only after both controls meet the
preregistered AUC and confidence-interval thresholds. The attacker is the
same bounded random forest as in the two-address study, trained on labeled
control sessions and applied to whole unlabeled target sessions. The primary
metric is per-access ROC AUC, with the interval bootstrapping 30 fitted-trial
means.

## Results

| Mode | Mean AUC (95% trial-bootstrap interval) | Mean balanced accuracy (95% interval) | Profile-majority raw accuracy |
|---|---:|---:|---:|
| Plaintext | 0.99995 [0.99987, 1.00000] | 0.99826 [0.99625, 0.99975] | 0.61693 |
| Encrypt-only | 0.99994 [0.99986, 1.00000] | 0.99682 [0.99412, 0.99902] | 0.61693 |
| Path ORAM | 0.50670 [0.49593, 0.51749] | 0.50226 [0.49344, 0.51097] | 0.61693 |

Both controls strongly exceed chance, so the chosen classifier and labels
produce successful positive controls for this workload. The ORAM AUC interval
includes 0.5, while raw accuracy is below the profile-majority baseline and
balanced accuracy remains near 0.5. This is an empirical result for the
specified observer, model, classifier and workload; it is not evidence of
indistinguishability or a security proof.

The experiment was run without another local test workload executing
concurrently. General shared-host scheduling noise still applies. The
service-time observation is measured inside a separate local bucket
service process. It excludes pipe waiting, Path ORAM controller work, request
decoding and reply encoding. The study still uses one synthetic skew, one
random-forest family and a local in-memory backend; it is neither remote
network timing nor a hardware trust-boundary experiment. Additional attacker
families, operation mixes, and workload distributions remain open. A separate
[tag-frequency-only attacker](ORAM_ATTACK_FAMILIES.md) has since been scored
against these same retained sessions with its own positive controls. The
[read-heavy follow-up](ORAM_READ_HEAVY.md) also evaluates a 90% read mix on
the same address schedules. The fresh-seed [write-heavy follow-up](ORAM_WRITE_HEAVY.md)
evaluates a 10% read mix; both follow-ups retain complete raw evidence and
positive controls. A [uniform-address study](ORAM_UNIFORM.md) changes the
address distribution independently and retains the same control-first timing
method.

## Reproduction

```sh
cargo build --locked --release -p oblivion-store \
  --example oram-measure --example oram-control
.venv/bin/python -m unittest \
  research.tests.test_oram_isolated_replication \
  research.tests.test_oram_isolated_timing
.venv/bin/python -m research.analysis.oram_isolated_replication \
  --config experiments/configs/oram-isolated-eight-address.json \
  --output experiments/results/oram-isolated-eight-address-new \
  --oram-binary target/release/examples/oram-measure \
  --control-binary target/release/examples/oram-control
```

Use a new output directory. The runner hashes public observer and private
driver files separately and refuses to overwrite prior raw results.
