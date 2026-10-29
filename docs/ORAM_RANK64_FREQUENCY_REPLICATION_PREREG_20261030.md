# Preregistration: fresh-seed rank-64 frequency attack replication

**Status:** frozen before collecting or analyzing the sessions in
`oram-isolated-rank64-frequency-replication-20261030/`. This is a prospective
replication on new seeded sessions of a post-hoc analysis whose original
result was already known. It provides independent session draws, but it is
not an independent research question or a blind replication.

## Question

Does the profile-only tag-frequency attack retain its positive-control
behavior and its near-chance Path ORAM result when address persistence is
increased from 0.40 to 0.60 on a new set of rank-64 seeded sessions?

The first frequency analysis used the primary study's 0.40-persistence raw
sessions and found controls at AUC 1.000 and ORAM at 0.496447
[0.491316, 0.501515]. The new study changes persistence and the random seed,
then collects a new raw session set. Its results will not be pooled with the
earlier sessions or treated as proof of indistinguishability.

## Frozen configuration

The machine-readable configuration is
[`oram-isolated-rank64-frequency-replication-20261030.json`](../experiments/configs/oram-isolated-rank64-frequency-replication-20261030.json)
with SHA-256
`7fd28923708a20c2ad9c969ece9647e231aa0a9ad685ad8809983148f77d1ad5`.
It preserves the earlier rank-64 distribution and system geometry while
changing only the session seed to `20261102` and the Markov persistence to
`0.60`:

- 64 logical addresses, 64-byte logical blocks, Path ORAM bucket capacity 4.
- Zipf-like configured address distribution with hot addresses 0–7.
- 55% read probability, 512 measured operations and 32 warmups per session.
- 30 trials, eight independently initialized sessions per trial.
- Four complete labeled profile sessions and four disjoint target sessions.
- Driver pinned to CPU 2; isolated bucket service requests CPU 0 affinity.
- Primary metric: mean per-trial target ROC AUC.
- 5,000 trial-bootstrap resamples; AUC seed is workload seed + 201 =
  `20261303`. Fixed-direction AUC and balanced-accuracy seeds are +203 and
  +205 respectively.

The four profile sessions and four target sessions remain grouped by trial.
No target session, label, or score is used to choose the orientation or fit the
frequency model. The prior result's session files are not reused.

## Attack, observer, and positive controls

Use the unchanged `TagFrequencyAttack` and profile-only orientation selection
through `research.analysis.oram_frequency_selected`. The scoring feature is
visible tag identity and its count in labeled profile sessions. The score
does not use timing, byte count, read/write identity, private logical
addresses, or target labels. Score orientation is selected from
leave-one-profile-session-out predictions, then the scorer is fitted on all
four profile sessions and applied once to the four targets.

Plaintext and encrypt-only are the deliberately leaky positive controls. Both
must have mean per-trial AUC at least 0.80 and a 95% trial-bootstrap lower
bound strictly above 0.50. The collector separately requires its own temporal
random-forest controls to pass before it captures Path ORAM. If that gate
fails, retain the partial collector output and stop; do not invoke the
frequency runner on a raw bundle with no ORAM sessions. After successful
collection, the frequency analysis must independently pass its own two
frequency-attack controls before it scores the ORAM arm. If either attack's
control gate fails, retain all partial outputs, mark the relevant comparison
invalid/incomplete, and do not interpret that attack's ORAM result.

## Outputs and integrity

The raw collector output is
`experiments/results/oram-isolated-rank64-frequency-replication-20261030/`;
the profile-frequency analysis output is
`experiments/results/oram-rank64-frequency-replication-20261030/`. Both paths
were absent when this plan was prepared. Never overwrite them or alter the
earlier rank-64 raw sessions.

The collector must record its configuration, software and binary hashes,
raw-session hashes, process affinity, and host observations. The frequency
report must record all raw input hashes and analysis source hashes. Run the
existing independent verifier against the frequency output with this plan;
it must check the complete configured raw-session file set, target-only
prediction artifacts, session split, per-trial metrics, positive-control
gate, and bootstrap intervals. Keep the collector and frequency reports,
plots, all per-trial predictions, and verifier receipt beside their raw
outputs.

The planned commands, after this document and configuration are committed,
are:

```sh
cargo build --locked --release -p oblivion-store \
  --example oram-measure --example oram-control

taskset -c 2 .venv/bin/python -m research.analysis.oram_isolated_replication \
  --config experiments/configs/oram-isolated-rank64-frequency-replication-20261030.json \
  --output experiments/results/oram-isolated-rank64-frequency-replication-20261030 \
  --oram-binary target/release/examples/oram-measure \
  --control-binary target/release/examples/oram-control

.venv/bin/python -m research.analysis.oram_frequency_selected \
  --config experiments/configs/oram-isolated-rank64-frequency-replication-20261030.json \
  --raw experiments/results/oram-isolated-rank64-frequency-replication-20261030 \
  --output experiments/results/oram-rank64-frequency-replication-20261030

.venv/bin/python -m research.analysis.oram_frequency_secondary_verifier \
  --plan docs/ORAM_RANK64_FREQUENCY_REPLICATION_PREREG_20261030.md \
  --config experiments/configs/oram-isolated-rank64-frequency-replication-20261030.json \
  --raw experiments/results/oram-isolated-rank64-frequency-replication-20261030 \
  --output experiments/results/oram-rank64-frequency-replication-20261030
```

## Frozen code and context hashes

| Input | SHA-256 |
| --- | --- |
| `research/analysis/oram_frequency_selected.py` | `2d34dada66b7aa7d727065ca2127926baae2b3fa56ba6c80f68979ecf70a7462` |
| `research/analysis/oram_frequency_orientation.py` | `0243f6ce7d32eed18983c53c6f06298602d50b10e38c9e22d79589583877de18` |
| `research/analysis/oram_attack_families.py` | `c19447a434b0658e9f9721118d407ce562fc56c3ee449684233352dbfe63a833` |
| `research/analysis/oram_isolated_replication.py` | `b07bf0ea683bd1064c92fd4043aae6fcbe3d7553237a3493fbb8dfcdb595a709` |
| Rank-64 workload config | `7fd28923708a20c2ad9c969ece9647e231aa0a9ad685ad8809983148f77d1ad5` |
| Primary study `report.json` | `56e58b9da6446a9c3bc684fbc512f6d9a5537e2efc9d94b6608b4e1930ed8c3b` |

The independent frequency-result verifier is pinned at
`research/analysis/oram_frequency_secondary_verifier.py`, SHA-256
`33751fab7f471d3c7f59d705e1ce5343ae0560703847e4ec40327f083f4908fa`.

## Interpretation limits

This is a new random-seed sample under a changed address-persistence
parameter, using the same attack family and the same local isolated-process
observer. It can test whether the earlier measured frequency result repeats
under this specified change. It cannot establish general ORAM security,
network indistinguishability, hardware isolation, or the absence of stronger
attacks. The trusted executor and all other project assumptions remain as
documented in [`THREAT_MODEL.md`](THREAT_MODEL.md).
