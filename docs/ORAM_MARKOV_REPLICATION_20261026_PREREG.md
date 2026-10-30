# Preregistered ORAM Markov-Locality Replication

**Status:** preregistered before implementation of the workload generator and before any data collection.

## Question

Does the existing per-access temporal classifier infer whether a logical ORAM access is to hot address 0 when accesses have strong temporal locality, and does Path ORAM reduce this inference relative to plaintext and encrypt-only direct-address controls?

This tests a distinct workload family from the prior independent address draws. It does not test arbitrary application workloads or establish cryptographic indistinguishability.

## Workload

The machine-readable configuration is `experiments/configs/oram-markov-signal-20261026.json`. Each session contains 128 measured operations over 8 logical addresses. Address 0 has stationary base probability 0.35; addresses 1–7 have probabilities 0.20, 0.15, 0.10, 0.08, 0.05, 0.04, and 0.03. A first address is sampled from this distribution. For each subsequent operation, retain the previous address with probability 0.85; otherwise sample a new address from the base distribution. Thus, conditional address transitions have explicit locality while retaining the configured stationary distribution. Read probability is 0.70. The warmup sequence is generated independently and is not part of scored labels.

The same seeded logical-address and operation schedule is run against plaintext, encrypt-only, and Path ORAM modes. ORAM state and cryptographic randomness remain fresh for each session. Data collection uses the isolated local bucket-service process already used by the replication harness. The host is not CPU-pinned; load and host details will be retained.

## Attacker and metric

Use the already-implemented `TemporalLeafTimingAttack` without tuning: the 128-tree random forest, depth 8, minimum leaf 5, balanced class weights, and random state 1907. It uses only the recorded observer features: visible bucket identifier, fixed bytes, handler-only service duration, within-session visible-tag frequency, previous four tags/timings, and short-window summaries. Profiling uses four complete sessions per trial and scoring uses four disjoint complete sessions. Ground-truth logical addresses are unavailable to fitting and prediction.

The sole primary metric is mean per-trial ROC AUC across 30 independently seeded trials. The 95% interval is the preregistered 5,000-resample percentile bootstrap over the 30 trial-level AUCs. Do not treat an interval including 0.5 as a proof of security.

## Positive controls and decision rule

Evaluate plaintext and encrypt-only controls first. Each must achieve mean AUC at least 0.80 and a lower 95% trial-bootstrap bound above 0.50. If either fails, preserve its output, report the experiment as inconclusive, and do not score ORAM as a defense result. Only after controls pass may ORAM be run and evaluated. No attack parameter or workload adjustment may be made after inspecting scores.

## Provenance and interpretation

Retain all raw observer and private-driver traces, predictions, configuration, source/binary SHA-256 hashes, software versions, host observation, and trial-level metrics. The local service timing excludes ORAM controller work, process-pipe waiting, request decoding, response encoding, and trace writing. This is a bounded local component experiment, not remote network timing. Report positive controls, class prevalence, majority baseline, and the exact visible features. Near-chance ORAM scores mean only that this fixed classifier did not distinguish the tested labels and workload under this measurement setup.
