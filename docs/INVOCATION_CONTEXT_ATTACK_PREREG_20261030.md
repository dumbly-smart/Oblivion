# Session-Normalized Invocation Timing Attack Preregistration

**Frozen:** 2026-10-30, after the control-gate failure reported in
[`INVOCATION_BOUNDARY_ATTACK_20261030.md`](INVOCATION_BOUNDARY_ATTACK_20261030.md)
and before this collection.  
**Status:** fresh-seed follow-up; not a blind replication. It is motivated by
the prior encrypt-only control shortfall. No observations for this protocol
have been collected at freeze time.

## Question and relationship to the prior study

Does within-session robust normalization of response timings let a supervised
observer infer which WASM function ran at the modeled invocation boundary,
and does it pass the encrypt-only positive-control gate on an independent
session collection?

The prior study is not used for fitting, feature selection, or tuning. Its
held-out sessions remain untouched. The new attack and fresh workload are
specified here before collecting new data. Results will not be pooled with
the earlier protocol because the feature transform, session/operation
geometry, seed, and attack differ.

## System and observer boundary

Use the existing A–G `oblivion-harness system` modes and their actual
component implementations. The observer is the harness's local modeled
invocation boundary, not a TCP capture or remote service. It sees request and
response lengths, their event timestamps, and session boundaries. Frames are
paired in trusted analysis by a private step key; frame contents and that
step key are removed before model fitting and prediction.

The A–G mode meanings are unchanged from the prior report: plaintext direct
storage; encrypt-only direct storage; encrypted ORAM; encrypted PIR;
encrypted batching; fixed-deadline execution; and combined ORAM/PIR/batching/
padding.

## Workload, labels, and split

Use seed `20261032`, 30 trials, 4 sessions per trial, 16 operations per
session, and a 100 ms epoch. Each session contains 8 dummy, 4 echo, and 4
stateful operations, shuffled by the harness using a unique derived session
seed. The same private schedule is paired across A–G within that session.
The target is executed function identity: echo/function ID 0 versus
stateful/function ID 4. In modes E and G, dummy envelopes are dispatched to
function ID 4 and labeled accordingly. In unbatched modes, dummy opportunities
produce no invocation message and are not samples in this per-visible-request
classifier. This protocol does not measure missing-request detection.

Sessions 0–1 of each trial train the per-mode classifier; sessions 2–3 are
held out. The attacker may use function labels from the training sessions as
declared auxiliary knowledge. Test labels are used only after prediction.

## Frozen attacker features

For each invocation in a session, use exactly:

1. Request frame bytes.
2. Response frame bytes.
3. `log1p(response_latency_ns)`.
4. Robust latency score `(latency - session_median) / max(1, 1.4826 * MAD)`;
   median and median absolute deviation use every visible invocation in that
   session, without labels.
5. `log1p(interarrival_ns)`, where the first request's interarrival is its
   timestamp from the session observer start and later values are request
   timestamp differences.
6. The latency's average rank among visible requests in that session divided
   by the number of visible requests; ties receive their average rank.

The feature set excludes raw frame content, function IDs, labels, private
step IDs, registry data, storage traces, executor instrumentation, process
counters, and the seed. Because the normalization and rank use the entire
session, this is an offline session attack, not an online per-request model.

## Classifier and control gate

Fit an independent `RandomForestClassifier` for each mode with 500 trees,
maximum depth 6, minimum leaf size 2, balanced class weights, one worker, and
model seed `20261220`. Function ID 0 is the positive class. Classification
threshold is fixed at 0.5; direction is not selected after target scoring.

Score A (plaintext) and B (encrypt-only) first. Each must have mean per-trial
ROC AUC at least 0.70 and the lower endpoint of the two-sided 95% percentile
bootstrap interval above 0.50. Bootstrap 30 test-trial units with 5,000
resamples and seed `20261221`. If either fails, retain only A/B results and
do not calculate or publish C–G scores. Do not tune this attack from the new
held-out observations.

## Metrics and evidence

Primary: unweighted mean of the 30 per-trial ROC AUC values. Secondary:
per-trial balanced accuracy, raw accuracy, majority-class baseline, class
counts, sample counts, and 95% trial-bootstrap intervals. Retain attacker
predictions separately from private labels, all raw traces and hashes,
source/executable hashes, exact configuration, software versions, host/OS
details, and start/end load observations.

Configuration:
[`invocation-context-attack-20261030.json`](../experiments/configs/invocation-context-attack-20261030.json).
Collection and analysis must use fresh directories under
`experiments/results/invocation-context-attack-20261030/` and refuse to
overwrite evidence.

## Limitations

This is a local in-process component-boundary simulation, not packet capture,
remote timing, or TEE evaluation. It covers two functions, synthetic
workloads, and one supervised attack. PIR workers share a process. A result
cannot establish cryptographic indistinguishability or security. A failed
control gate makes the protected comparison inconclusive by design.
