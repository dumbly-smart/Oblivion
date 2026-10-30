# Frozen secondary analysis plan: rank-64 ORAM tag-frequency attack

**Status:** this plan is committed before running the secondary analysis, but
after the primary rank-64 study was collected and its result was inspected.
This is a post-hoc secondary analysis of the same sessions, not an independent
replication or a preregistration of the primary study.

## Question

Can a simple tag-frequency-only scorer distinguish hot from cold logical
addresses in the retained rank-64 plaintext, encrypt-only, and Path ORAM
sessions when it receives labeled profile sessions and no target labels?
The primary rank-64 experiment used a random forest over visible identifiers,
timing, and short windows. This analysis removes timing and byte features from
the scoring rule and uses a separate attack family.

## Fixed input data

Use only the immutable raw sessions in
[`oram-isolated-rank64-markov-replication-20261030/`](../experiments/results/oram-isolated-rank64-markov-replication-20261030/).
The machine-readable workload remains
[`oram-isolated-rank64-markov-replication-20261030.json`](../experiments/configs/oram-isolated-rank64-markov-replication-20261030.json):
30 trials, eight sessions/trial, 64 addresses, hot set 0–7, 512 measured
operations/session, and the original paired address/read-write schedules.
No recollection, schedule regeneration, or target-label-based exclusion is
permitted. The original 1,440 raw-file manifest and original positive-control
gate remain authoritative for collection integrity.

## Attacker and split

Use `TagFrequencyAttack` from
[`oram_attack_families.py`](../research/analysis/oram_attack_families.py)
and `select_profile_orientation` from
[`oram_frequency_orientation.py`](../research/analysis/oram_frequency_orientation.py)
through the unchanged
[`oram_frequency_selected.py`](../research/analysis/oram_frequency_selected.py)
runner. For each mode and trial, keep the four complete profile sessions and
four disjoint target sessions from the original collection.

The scorer counts hot/cold labels for each visible tag in the labeled profile
data and applies the existing 0.5 smoothing and profile prior for unseen tags.
The orientation sign is chosen only from leave-one-profile-session-out
predictions: fit on the other three profile sessions, score the held-out
session, pool the four out-of-fold profile scores, and choose the sign from
their AUC. A tie at AUC 0.5 keeps the original sign. Refit the frequency
scorer on all four profile sessions, then predict the four target sessions.
Target labels must not affect the sign, fit, or predictions; they are read
only after prediction for scoring.

The scoring rule uses visible tag identity and profile tag counts. It does
not use service time, byte count, read/write identity, private logical
addresses, or target labels. The target prediction artifact must contain only
the target session identifiers, prediction scores, and predicted classes.

## Metrics and positive controls

The analysis-level primary metric is mean per-trial target ROC AUC after the
profile-only orientation selection. Report the 95% percentile bootstrap over
the 30 trial AUCs with 5,000 resamples and seed `20261231` (workload seed plus
201). Report fixed-direction AUC, balanced accuracy, raw accuracy, reversed
orientation count, and profile-majority accuracy as secondary descriptive
metrics. Include target hot-class prevalence and the class-aware baselines.
Do not pool this scorer's AUC with the primary random-forest AUC.

Evaluate plaintext and encrypt-only first. Require mean AUC at least 0.80 and
95% bootstrap lower bound above 0.50 in both controls. If either fails, retain
the partial analysis output and do not score Path ORAM. If both pass, run the
Path ORAM scorer once. An interval excluding 0.50 is a detectable association
for this scorer and these sessions; an interval including 0.50 is inconclusive.
Do not invert score direction, alter features, remove sessions, or tune after
looking at target results.

## Reproducibility and output

The selected scorer and original raw report/configuration were hashed before
analysis:

| Input | SHA-256 |
| --- | --- |
| `research/analysis/oram_frequency_selected.py` | `2d34dada66b7aa7d727065ca2127926baae2b3fa56ba6c80f68979ecf70a7462` |
| `research/analysis/oram_frequency_orientation.py` | `0243f6ce7d32eed18983c53c6f06298602d50b10e38c9e22d79589583877de18` |
| `research/analysis/oram_attack_families.py` | `c19447a434b0658e9f9721118d407ce562fc56c3ee449684233352dbfe63a833` |
| `research/analysis/oram_isolated_replication.py` | `b07bf0ea683bd1064c92fd4043aae6fcbe3d7553237a3493fbb8dfcdb595a709` |
| Rank-64 workload config | `0ab3eb3143582c77d0fc3c26e95aba94869b462ff080c6febb2df53bf78af50d` |
| Primary study `report.json` | `56e58b9da6446a9c3bc684fbc512f6d9a5537e2efc9d94b6608b4e1930ed8c3b` |

The new output directory is
`experiments/results/oram-rank64-frequency-orientation-secondary-20261030/`;
it was absent when this plan was prepared. The runner refuses to overwrite an
existing directory. Run the existing pinned Python analysis command only after
this plan is committed:

```sh
.venv/bin/python -m research.analysis.oram_frequency_selected \
  --config experiments/configs/oram-isolated-rank64-markov-replication-20261030.json \
  --raw experiments/results/oram-isolated-rank64-markov-replication-20261030 \
  --output experiments/results/oram-rank64-frequency-orientation-secondary-20261030
```

The runner must record hashes for all raw input sessions and analysis source
files. Afterward, independently verify those hashes, confirm the predictions
contain no target labels, recompute per-trial metrics from predictions and
private labels, and preserve the verification receipt beside the raw
secondary-analysis report. Do not edit either study's captured raw files.

## Interpretation limit

The primary result was already known when this plan was written. This analysis
reuses the same sessions and probes a different scoring rule; it may reveal a
feature-family difference but cannot provide independent sample evidence.
It is not a statistical test comparing two models on independent observations,
and it is not a cryptographic security result.
