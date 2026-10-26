# Uniform-32 ORAM timing replication

This fresh-seed study followed its
[preregistration](ORAM_UNIFORM32_REPLICATION_PREREG_20261026.md) and
[machine-readable configuration](../experiments/configs/oram-isolated-uniform32-replication-20261026.json).
The [collector report](../experiments/results/oram-isolated-uniform32-replication-20261026/report.json),
[raw-trace and prediction archive](../experiments/results/oram-isolated-uniform32-replication-20261026/trace-data.tar.gz),
[host observations](../experiments/results/oram-isolated-uniform32-replication-20261026/host-observation.json),
[process metadata](../experiments/results/oram-isolated-uniform32-replication-20261026/process-metadata.json),
[raw SHA-256 manifest](../experiments/results/oram-isolated-uniform32-replication-20261026/raw-session-sha256.json),
[verification record](../experiments/results/oram-isolated-uniform32-replication-20261026/verification.json),
[artifact hashes](../experiments/results/oram-isolated-uniform32-replication-20261026/artifact-sha256.json),
and [AUC figure](../experiments/results/oram-isolated-uniform32-replication-20261026/auc.png)
are retained.

## Workload and primary metric

The workload used seed 20261034, 32 uniformly selected logical addresses,
addresses 0–15 as the public hot class, 35% reads, and no address persistence.
Each of 30 trials ran eight fresh sessions with 16 warmup and 256 measured
operations per session. A fixed temporal random forest trained on four whole
sessions and predicted four disjoint sessions. The sole primary metric was mean
per-trial ROC AUC with a 5,000-resample bootstrap over the 30 trial values.
The observer measured local bucket-service handler time. Plaintext and
encrypt-only controls were scored before Path ORAM.

## Results

| Mode | Mean per-trial AUC (95% trial-bootstrap interval) | Balanced accuracy | Profile-majority accuracy |
| --- | ---: | ---: | ---: |
| Plaintext | 1.0000 [1.0000, 1.0000] | 1.0000 | 0.5007 |
| Encrypt-only | 1.0000 [1.0000, 1.0000] | 1.0000 | 0.5007 |
| Path ORAM | 0.5018 [0.4965, 0.5078] | 0.5010 | 0.5007 |

Both positive controls passed the preregistered gate. The ORAM interval
includes 0.50, and the point estimate is close to the profile-majority
baseline. This study did not resolve hot-versus-cold inference with the
specified classifier and features. It does not establish indistinguishability,
rule out other attacks, or prove security.

## Host and integrity observations

The runner reported an Intel Core i7-14650HX, 24 logical CPUs, and an allowed
CPU set of 0–23. Load averages were sampled immediately before and after each
mode; for ORAM they were 3.36/2.90/3.16 and 3.08/2.86/3.14. These coarse
snapshots do not measure load per access, and the service was not pinned or
isolated from other host processes.

The collection report records source, config, and executable fingerprints.
A post-collection audit verified all 1,440 raw file hashes and all 240 paired
trial/session workload schedules. It recomputed the saved metrics for all 90
prediction files from their retained predictions and private target labels;
classifier fitting was not independently reimplemented. The archive SHA-256
is `10a81958c524cf8c1f7f7ce5c8945fdf59d76dbc31b67fd758529601e5dccadd`.

## Reproduction and limits

The preregistration contains the build and collection command. Run it from the
repository root with the recorded Rust and Python dependencies. Repeated
runs reproduce deterministic workload schedules, not operating-system
cryptographic randomness or exact timing. This is local process-isolated
bucket-handler timing, not remote-network timing or a TEE evaluation. It
excludes pipe waiting, Path ORAM controller work, request parsing, and response
encoding. The results apply only to this workload, observer, and attack.
