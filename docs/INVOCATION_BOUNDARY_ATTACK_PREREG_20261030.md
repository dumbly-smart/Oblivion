# Invocation Boundary Function-Identity Attack Preregistration

**Frozen:** 2026-10-30  
**Status:** protocol frozen before collection; no observations collected at
preregistration time.

## Research question

Can an observer at Oblivion's modeled invocation request/response boundary
infer which WASM function ran from frame lengths and request/response timing?
How does that attack change across the existing plaintext, encrypt-only,
single-mechanism, and combined A–G configurations?

## System and scope

Use the existing `oblivion-harness system` experiment. The harness records
request/response events at its modeled invocation boundary and exercises the
real Path ORAM, PIR, batching, authenticated-encryption, and fixed-deadline
executor components used by its A–G modes. The harness is a local,
single-process component-boundary simulation. Its `elapsed_ns` fields are
application instrumentation timestamps; this is not packet capture, a TCP
service, remote timing, or evidence about a deployed network.

The modes are the harness's existing definitions: A plaintext direct store;
B encrypted direct store; C encrypted ORAM; D encrypted PIR; E encrypted
batching; F encrypted padded execution; and G encrypted ORAM, PIR, batching,
and padding. These are component-level experimental modes, not separate
production deployments.

## Observer and attacker knowledge

The modeled observer sees invocation request and response frame lengths and
their event timestamps, session boundaries, and the public protocol schedule.
The attack feature set is frozen to:

1. Request frame bytes.
2. Response frame bytes.
3. Response-event time minus request-event time.
4. Time since the previous visible invocation request in that session (the
   first request uses its elapsed time from the session observer start).

The attack does not receive frame contents, function IDs, private step
numbers, real/dummy labels, registry indices, storage addresses or leaves,
storage traces, private executor timings/status, CPU counters, memory data,
experiment seeds, or the mode's result labels. Raw traces retain frame bytes
for independent auditing; the feature extractor must use only the four
fields above. Request and response events are paired by the trusted analysis
tool using their private step key, then that key is removed before model
fitting and prediction.

The evaluator knows the public workload distribution and the protocol. The
deterministic experimental seed is retained for reproducibility but withheld
from attacker features and auxiliary knowledge; it is not a runtime system
configuration parameter. No claim is made for an adversary who knows the
exact generated test schedule.

The attack is supervised: the adversary may use function labels from the
separate training sessions as declared auxiliary knowledge. Test-session
labels remain unavailable to model fitting and prediction and are joined only
after predictions are frozen for evaluation.

## Workload and labels

Use seed `20261031`, 30 trials, 8 independently seeded sessions per trial,
8 operations per session, and a 100 ms public epoch. The harness generates
exactly four dummy, two echo, and two stateful labels per session and shuffles
them with a session-specific deterministic seed. The same private schedule
is reused across A–G within a paired session; modes are run in randomized
order by the harness.

The target is the executed module identity: class 0 is the echo module
(registry/function ID 0), and class 4 is the stateful module (ID 4). In
batched modes E and G, a cover request is dispatched to module 4 and is
labeled class 4. In unbatched modes, dummy opportunities produce no
invocation frame and are not samples in this per-visible-invocation attack.
The study therefore measures function identity conditional on a visible
invocation; it does not measure request-presence or dummy-detection leakage.

## Split and attack

For every trial and mode, sessions 0–3 form training data and sessions 4–7
form test data. No session is split across training and testing. Fit a
separate `RandomForestClassifier` per mode with 200 trees, maximum depth 4,
minimum leaf size 2, balanced class weights, one worker, and fixed model seed
`20261210`. Class 0 is the positive class for ROC AUC; direction is not
selected after observing results. The classification threshold for accuracy
metrics is fixed at probability 0.5.

## Positive controls and stop rule

Score plaintext A and encrypt-only B first. Each control passes only if mean
per-trial ROC AUC is at least 0.70 and the lower endpoint of its two-sided
95% trial-bootstrap interval is greater than 0.50. Use 5,000 bootstrap
resamples of the 30 test-trial units with bootstrap seed `20261211`.

If either control fails, emit the two control results and an explicit failed
gate, and do not calculate or publish C–G attack scores. Do not tune the
features, classifier, threshold, or direction using these held-out targets.

## Metrics

Primary: unweighted mean of the 30 per-trial ROC AUC values.  
Secondary: unweighted mean per-trial balanced accuracy, raw accuracy, and
the per-trial majority-class accuracy. Report 95% percentile bootstrap
intervals over trial units, class counts, sample counts, and every per-trial
metric. Do not interpret a near-chance score as a proof of security.

## Reproducibility and outputs

Configuration: `experiments/configs/invocation-boundary-attack-20261030.json`.
Raw collection: a new directory under
`experiments/results/invocation-boundary-attack-20261030/collection/`.
Analysis: a new directory under
`experiments/results/invocation-boundary-attack-20261030/analysis/`.
The run must retain the raw A–G network observations, private ground truth,
private executor traces, per-mode metrics, source and executable hashes,
software versions, hardware/OS details, host load observations, attack
predictions, analysis metadata, and output hashes. Collection and analysis
must refuse to overwrite an existing output directory.

## Known limitations

This study evaluates only two WASM modules in one local harness process.
PIR servers are modeled within that process and share a host. The observer
timestamps are not kernel packet timestamps. The workloads are synthetic,
the session seed is excluded from the attack, and results do not generalize
to all functions, networks, hardware, clients, or attacks. It does not test
cryptographic security, TEE isolation, or exact-schedule attackers.
