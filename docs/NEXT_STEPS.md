# Optional research and deployment work

## Current focus (updated 2026-10-30)

The fresh-seed rank-64 transition attack has now been collected and checked.
The transition controls passed at mean AUC 0.898148
[0.895392, 0.900593]; ORAM scored 0.502017 [0.497459, 0.506447]. Its
interval includes chance, so this result is inconclusive for the declared
single-previous-tag lookup. The attack is a preregistered secondary analysis
of the same sessions as the collector's temporal classifier, not an
independent sample from that classifier. See the
[protocol](ORAM_RANK64_TRANSITION_REPLICATION_PREREG_20261030.md),
[result](ORAM_RANK64_TRANSITION_REPLICATION_20261030.md), and
[final independent receipt](../experiments/results/oram-rank64-transition-replication-20261030/independent-verification-v2.json).

**Completed 2026-10-30:** the preregistered invocation-boundary study ran 30
trials across A–G. Plaintext A passed at AUC 1.000; encrypt-only B scored
0.6896 [0.6531, 0.7260], below the frozen 0.70 threshold. The evaluator
therefore withheld all C–G scores. An independent verifier checked all 8,404
raw-file hashes, 1,680 sessions, 13,440 private labels, and the two control
metrics. See
[the protocol](INVOCATION_BOUNDARY_ATTACK_PREREG_20261030.md) and
[the result](INVOCATION_BOUNDARY_ATTACK_20261030.md). This observer is the
local harness boundary, not a network capture.

**Completed follow-up 2026-10-30:** a second preregistered study used fresh
sessions and six features including per-session robust latency normalization,
latency rank, and interarrival time. Plaintext A scored AUC 1.000; encrypt-only
B scored 0.698958 [0.668229, 0.731771], below the unchanged 0.70 mean
threshold. The control gate failed, so C–G were again withheld. Its separate
report and independent raw-feature/model replay are in
[the result](INVOCATION_CONTEXT_ATTACK_20261030.md) and
[evidence bundle](../experiments/results/invocation-context-attack-20261030/).
The second study is fresh-data evidence for its controls, not a blind
replication, and it is not pooled with the earlier attack.

**Implemented 2026-10-30:** `oblivion-harness system-tcp` now runs the actual
A–G registry/PIR/WASM/storage path through loopback TCP between a controller
and a separate worker process. The channel root crosses only the inherited
stdin pipe; request/response bodies use bounded length-prefix framing. The
worker-side socket trace records frame bytes and local socket-boundary timing.
Focused codec, process, malformed-frame, and all-mode integration tests passed.
This provides a new observer boundary; it has not yet been used to produce an
attack result. Its PIR pair and memory-backed ORAM remain local to the worker,
and it is not packet capture or TEE evidence. See [the protocol](PROTOCOL.md)
and [the architecture](ARCHITECTURE.md).

The socket-boundary attack is now preregistered in
[the frozen protocol](SOCKET_INVOCATION_ATTACK_PREREG_20261030.md), with its
machine-readable config, design, and implementation plan committed before any
collection. The TCP CLI now accepts an optional canonicalized mode subset;
`system-tcp CONFIG OUT` still runs A–G and records that full selection.
Duplicate, empty, and unknown selections fail before output creation. The
focused process suite passes all six tests. The socket extractor validates
private schedule counts, exact per-mode frame sizes, prefix-inclusive lengths,
complete ordered sequence pairs, monotonic timestamps, and event/body shape.
It maps private labels to evaluator metadata while returning only the frozen
four base size/timing values; the existing context transform supplies the six
model features. Focused tests pass, and a release A/B socket smoke run
successfully extracted 128 visible invocations across 16 sessions. The
controls-only evaluator now reuses the frozen model and session split, computes
the 5,000-trial-unit bootstrap interval, and applies both frozen thresholds.
Synthetic tests cover pass/fail behavior for each gate condition; when B fails,
only A/B metrics and predictions are written.

The phased runner is implemented as
`research.analysis.collect_socket_invocation_attack`. It creates a new bundle,
captures A/B first, records source/binary/config/environment provenance and
raw hashes, and invokes C–G only after validating both reported metrics and
gate decisions. Failed or timed-out phases keep their partial files and
metadata. A successful protected collection is marked pending evaluation;
the runner does not claim the experiment is fully evaluated.

**Next:** implement the independent bundle verifier and final target analysis.
Rebuild manifests, features, splits, predictions, trial metrics, confidence
intervals, and stop-rule compliance without reading saved predictions as
inputs. Do not collect the 30-trial study until that verifier is ready. Only
if both actual controls pass may C–G be collected. Keep earlier in-process
studies separate and do not treat absent protected scores as privacy evidence.
Hardware-backed execution remains unimplemented; no local timing result is a
security proof.

## Immediate continuation (updated 2026-10-30)

The preregistered rank-64 Zipf/Markov ORAM leaf/timing study is complete. Both
positive controls scored AUC 1.000; Path ORAM scored 0.502474 with a 95%
trial-bootstrap interval [0.496502, 0.508492]. The interval includes chance,
so this is inconclusive for the frozen classifier, workload, host, and
handler-only timing interface. The report, immutable raw bundle, and final
independent verification are linked from
[`REPORTS.md`](../REPORTS.md) and described in
[`ORAM_RANK64_MARKOV_REPLICATION_20261030.md`](ORAM_RANK64_MARKOV_REPLICATION_20261030.md).

The planned frequency-only tag attack is now complete as a post-hoc secondary
analysis of those same sessions. Plaintext and encrypt-only controls both
scored AUC 1.000; Path ORAM scored 0.496447 [0.491316, 0.501515]. Its interval
includes 0.50, and the result is inconclusive for this tag-frequency scorer;
because it reuses the primary study's sessions, it is not independent sample
evidence. The plan, output, and independent verification are in
[`ORAM_RANK64_FREQUENCY_ORIENTATION_SECONDARY_20261030.md`](ORAM_RANK64_FREQUENCY_ORIENTATION_SECONDARY_20261030.md).

A fresh-seed, preregistered frequency replication then increased address
persistence to 0.60 and collected 30 new trials. Both the collector's
temporal-attack controls and the frequency attack's controls passed. The new
ORAM frequency AUC was 0.502248 [0.498132, 0.506253]. Its interval includes
chance; it is independent session evidence for the changed workload, but the
protocol was informed by the earlier result and is not blind. See
[`ORAM_RANK64_FREQUENCY_REPLICATION_20261030.md`](ORAM_RANK64_FREQUENCY_REPLICATION_20261030.md)
and its two verified result bundles.

The distinct one-step transition study is now complete; it does not settle
other attack families or observer boundaries. Do not describe the
same-session post-hoc scorer as an independent replication or the fresh-seed
studies as blind. Preserve the earlier 100 ms mixed-invocation timeout as
unresolved: six focused executions and a full serial rerun passed, but the
cause of the original retained failure is still unknown. If it recurs, collect
host-load and per-phase evidence while preserving the original runtime limits
and retry behavior.

A separate current-head full-suite failure on 2026-10-30 was traced to the
three-client mixed correctness fixture occasionally crossing the default
100 ms class deadline. That fixture now explicitly requests 250 ms; production
deadlines and retry behavior remain unchanged. The subsequent complete serial
workspace suite passed with 206 tests, zero failures, and one intentionally
ignored million-operation ORAM stress test. This does not retroactively prove
the cause of the older `24ded25d` incident.

The independent bundle verifier is
[`research/analysis/verify_oram_isolated_bundle.py`](../research/analysis/verify_oram_isolated_bundle.py);
its six tests cover raw hashes, paired schedules, event/frame shape, saved
trial scores, and bootstrap intervals. Keep future preregistrations,
implementations, result bundles, and analysis corrections in separate small
reviewable commits when they represent separate changes.

The secondary-analysis verifier is
[`research/analysis/oram_frequency_secondary_verifier.py`](../research/analysis/oram_frequency_secondary_verifier.py);
its tests cover prediction-label separation, raw-manifest completeness,
private write/read label semantics, trial metric recomputation, and plan hash
parsing. It checked 1,440 raw session files and 90 trial predictions in both
frequency analyses. The fresh-seed collection also passed
[`research/analysis/verify_oram_isolated_bundle.py`](../research/analysis/verify_oram_isolated_bundle.py),
which checked paired schedules and five source/binary hashes. The full Python
suite and focused test counts are recorded in
[`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md).

The fresh-seed transition analysis has its own checker at
[`research/analysis/verify_oram_markov_transition_bundle.py`](../research/analysis/verify_oram_markov_transition_bundle.py).
It rechecks the raw manifest and collector receipt, target-only prediction
schema, private-label-derived trial metrics, bootstrap intervals, and the
positive-control decision. Four focused tests pass; the final receipt is
`independent-verification-v2.json` because the first successful receipt is
preserved rather than overwritten.

**Selected-scope acceptance:** the [serial local gate](../experiments/results/validation-20261023-serial/commands.json) passed all ten commands, including 91 core Rust tests, one reference test, 120 Python tests without skips and the million-operation oracle. [Before/after source fingerprints](../experiments/results/validation-20261023-serial/metadata.json) match: `a83d606782f63e9f5c9f8b95a3c80b299f57da30c916de670f61751e8068becc`. All three jobs in [hosted run 39971009249](https://github.com/dumbly-smart/Oblivion/actions/runs/39971009249) for `ade31d2c` passed. The selected roadmap software and empirical deliverables, local gate and hosted source gate are accepted within the documented boundaries. [PR #1](https://github.com/dumbly-smart/Oblivion/pull/1) is ready for delivery; no merge is claimed. Subsequent closing Markdown-only checks are accessible on the PR and do not create a new unfinished source requirement.

The later failed [historical run 39969711451](https://github.com/dumbly-smart/Oblivion/actions/runs/39969711451) remains preserved: Rust failed while analysis/stress passed, and its specific cause remains unproved. [Three-arm scheduling diagnostics](PIPELINE_TEST_SCHEDULING.md) reproduced authenticated timeouts under CPU contention: pinned two-CPU parallel tests had two timeouts, the same serial suite passed, and one CPU with 16 competitors produced an actual 218 ms Timeout with both PIR operations and 128 storage events. Correctness suites explicitly use `--test-threads=1`; production budgets, benchmark concurrency and retry behavior are unchanged.

Updated 2026-10-23. The selected roadmap software and empirical deliverables and serial local/hosted source gates are accepted. PR #1 is ready for delivery, without a merge or deployment claim. Subsequent closing Markdown-only revision checks are accessible on the PR; the items below are optional research or deployment extensions, not unfinished selected software gates.

[The completion audit](COMPLETION_AUDIT.md) maps the original scope, and [figure reproduction](FIGURE_REPRODUCTION.md) rebuilds required reports/plots from retained data without ignored measurement executables. Preserve both failed local validation attempts and both failed batch-load forest controls. The earlier Python authenticated sweep failure's private cause remains unknown; its deterministic Timeout regression does not establish that cause. Research sweeps now retain masked failures and charge all trial costs through ratios of sums, with undefined denominators explicit. Historical raw campaigns were not rewritten.

Further work is optional and should begin with its own threat model and acceptance criteria:

1. **Isolated ORAM timing replication completed for two- and eight-address workloads, with frequency-only, operation-mix, address-prior and profile-only orientation follow-ups.** All 30-trial studies passed plaintext/encrypt-only positive controls. On the skewed 50/50 eight-address data, temporal RF AUC was 0.507 [0.496, 0.517] and frequency-only AUC was 0.498 [0.488, 0.508]. On matched skewed schedules with 90% reads, temporal RF AUC was 0.497 [0.490, 0.505]; a fresh-seed 10%-read run measured 0.496 [0.487, 0.505]. A separate uniform eight-address distribution with a 50/50 operation mix measured temporal RF AUC 0.493 [0.482, 0.503] and frequency-only AUC 0.505 [0.494, 0.515]. Profile-only direction selection measured ORAM AUC 0.499 [0.491, 0.507], 0.507 [0.497, 0.517], and 0.494 [0.483, 0.504] on those read-heavy, write-heavy and uniform workloads; intervals include chance and accuracy remains below the profile-majority baseline. See [skewed 50/50](ORAM_EIGHT_ADDRESS.md), [attack families](ORAM_ATTACK_FAMILIES.md), [orientation-selection results](ORAM_FREQUENCY_ORIENTATION.md), [read-heavy](ORAM_READ_HEAVY.md), [write-heavy](ORAM_WRITE_HEAVY.md), and [uniform addresses](ORAM_UNIFORM.md). A preregistered 30-trial Markov-locality workload (85% retain probability; observed adjacent repeats 88.07%) passed both positive controls and measured temporal RF ORAM AUC 0.510 [0.484, 0.539], with raw accuracy below its majority baseline; the host was CPU-contended. A post-hoc, one-step profile transition lookup on those same sessions passed controls at AUC 0.922 and scored ORAM 0.497 [0.489, 0.504]; it is not an independent replication. See [the preregistration](ORAM_MARKOV_REPLICATION_20261026_PREREG.md), [primary results](ORAM_MARKOV_REPLICATION_20261026.md), and [transition-attack results](ORAM_MARKOV_TRANSITION_ATTACK.md). A preregistered 75/25 two-address handler-only timing follow-up passed both controls and measured ORAM AUC 0.4989 [0.4888, 0.5083]; it does not reproduce the historical weak signal, but uses a changed timing boundary and a highly loaded host. See [its preregistration](ORAM_TWO_ADDRESS_REPLICATION_PREREG_20261026.md) and [result record](ORAM_TWO_ADDRESS_REPLICATION_20261026.md). Other distributions and attack families remain open; these near-chance results are not a security proof.
2. **Synthetic presence sensitivity completed:** eight scenarios test noisy semantic beacons, enrollment churn, missed cover observations, and changing populations over 240 sessions/scenario. The combined adverse synthetic case still enabled 79.4% owner recovery (95% whole-session bootstrap interval 73.3–85.0%) against 11.5% population-adjusted random accuracy. This is not real network evidence or differential privacy; see [the study](PRESENCE_SENSITIVITY.md). Real-network validation is data-dependent: no consented capture/access was available, so none was collected.
3. **Bounded human-query corpus evaluation completed:** the pinned MIMICS-Click query text drove the existing constrained-GGM SSE evaluator over 30 whole-query split trials. Exact-count and unpadded positive controls succeeded; public-bound padding reduced the count-volume attack to profile-majority levels on the 12.2%-coverage subset. See [corpus study and terms](HUMAN_QUERY_EVALUATION.md) and [aggregate output](../experiments/results/human-query-20261024/). MIMICS has no query arrival frequencies or temporal histories, its README has ambiguous licensing language, and this result is not representative of Bing traffic. Broader licensed trace access/query-prior drift remains open.
4. **Local batcher and full-path offer studies completed; deployment capacity/cost remain open.** The component sweep covers 100 epochs at populations 1/8/32/64. Full-path studies include 64 offers and a preregistered extension with 128 offers at 150 ms and 256 offers at 25 ms, each over 30 fresh processes/profile with actual PIR/WASM/ORAM work. The 128-offer schedule admitted all offers; the 256-offer schedule dropped 74.22% and missed the offered-load SLO for 99.22%. A ratio-of-sums CPU normalization and whole-process bootstrap sensitivity now use the retained 128/256-offer data; the overloaded profile's lower CPU per success reflects dropped offers and its 99.22% SLO failure, not better useful capacity. See [batcher results](POPULATION_SWEEP.md), [64-offer results](RUNTIME_POPULATION.md), [extended-offer results](RUNTIME_POPULATION_EXTENDED.md), and [CPU cost sensitivity](COST_SENSITIVITY.md). These are single-host, single-producer schedules, not remote capacity, multi-host population, long-term traffic tails, or provider-calibrated costs. Those remain open.
5. **Request-level and bounded-user autoscaler samplers implemented conditionally:** the finite-rational capped geometric mechanism reports a composed `(epsilon, delta)` bound for the fixed-horizon count/event observer under independent hidden uniform bits. Exact-rational tests enumerate the capped one-function request-level distribution for three parameter sets and all nonnegative pool shifts up to the user cap in three bounded-user parameter sets. These checks support the per-release bounds for those settings, but do not prove the coupling bound or composition for arbitrary parameters. A source-level sampler review found and fixed boolean acceptance in numeric configuration fields; it did not find a discrepancy in the reviewed sampler path. See [the sampler audit](SAMPLER_AUDIT.md). The simulation API and batch runner support optional per-principal HMAC or Ed25519 verification; existing empirical campaigns remain unauthenticated. An opt-in local SQLite ledger now composes releases across runs for authenticated bounded-user `dp_laplace` experiments, keyed with domain-separated HMAC pseudonyms and atomic budget checks. It binds one ledger to a fixed key, identity-registry fingerprint, and budget configuration. It does not prevent privileged edits or database rollback, perform identity issuance/rotation/migration, or turn seeded artifacts into DP outputs; see [the ledger design and usage](PRIVACY_LEDGER.md). The cap still bounds included scaling counts only for authenticated IDs; it does not clip queue or service effects. Public-seed artifacts have no DP guarantee. External cryptographic review and a complete runtime transcript remain. A predeclared CSPRNG policy-interval attack passed all 28 naive controls; its interval features did not reliably improve paired protected accuracy, though four unadjusted protected results were above chance for hot-pool inference. See [the attack study](AUTOSCALER_INTERVAL_ATTACK.md). A fresh 30-trial OS-CSPRNG likelihood study passed all seven clear-count controls; the particle-filter attack scored 0.525–0.717 balanced accuracy over the tested workload/task cells, with four of seven unadjusted intervals above chance. See [the likelihood study](AUTOSCALER_LIKELIHOOD.md). This is workload-inference evidence, not a DP audit or privacy proof. Actual TEE/attestation and hardware side channels require supported hardware; recursive maps/native Circuit storage, DPF/native single-server runtime selection, and real worker-pool provisioning remain extensions.
6. Runtime signed-registry/PIR integration carries verified 160-byte Ed25519 records through both local secure-PIR workers, with bounded database bootstrap and per-query exact pin checks. Workers verify an externally provisioned publisher-signed catalog against a pinned public key before readiness; optionally, `OBLIVION_REGISTRY_ANCHOR_SOCKET` activates its version and digest in the local SQLite anchor, rejecting rollback/equivocation before PIR startup. The development fallback signer remains ephemeral, and location digests are synthetic. The wire-v2 worker verifies a signed invocation ID and canonical request digest, can restore the latest checkpoint when configured with `OBLIVION_ANCHOR_SOCKET` and `OBLIVION_ANCHOR_STATE_DIR`, looks up receipts before execution, returns saved responses through a reserved dummy path, and atomically commits response/checkpoint on a new signed request. A same-host per-slot advisory lock now allows one cooperating durable worker before checkpoint restore/readiness; raw protocol/database callers and separate hosts can bypass it. The worker restart test verifies response replay, recovered state and same-ID/different-digest rejection. The local anchor service still uses an OS permission boundary on one host; restoring an old SQLite backup defeats local catalog and invocation freshness. A separate mTLS witness now supports standalone SSE journals, signed catalog clients, and `TlsCheckpointAnchor`; the runtime worker now supports remote mTLS durable checkpoints/receipts as well as the local anchor, and there is no hardware anti-rollback source. The remote checkpoint witness receives the snapshot key in its secret handle and is trusted with snapshot confidentiality. Arbitrary external side effects are not atomic. Built-in clients use ephemeral per-run keys and IDs, so applications must persist client keys/IDs for reconnect retries. Durable mode performs visible full-tree snapshot work on misses, skips checkpoint creation on receipt hits, and retains only the anchor-current snapshot after successful commits/startup recovery; a crash after publication can leave obsolete encrypted files until the next startup. Host-root inspection, authenticated publisher-key provisioning, remote publication, partial-catalog inclusion proofs, rollback-resistant/backward-private SSE, and production deployment remain open.

The remote SSE journal now has stale-writer and barrier-synchronized race
tests. Two clients opened from the same anchored generation can attempt an
update together; one advances the witness, while a reopened client recovers
the winner's exact request. The synchronized race passed 10 repetitions. This
completes the bounded S11 reservation/recovery behavior under the configured
single trusted anchor. Witness rollback resistance, multi-host availability,
and an atomic transaction with the SSE server remain extensions.

The remote mTLS witness now applies process-local token buckets per authenticated
certificate and slot (default 100 requests/second, burst 200); the CLI can
override the rate, interval, and burst together. Focused anchor tests and
warning-denied workspace Clippy pass. The serial workspace test gate passed
194 tests with one intentionally ignored million-operation ORAM stress test;
hosted validation remains to be run. The limits reset on witness restart and
do not cover TCP accepts, TLS handshakes, or slow unauthenticated clients.

The deterministic built-in demo remains a correctness/topology exercise. Its code/configuration can reveal the entire real/dummy/function schedule; encryption cannot conceal an identity already fixed by auxiliary knowledge. Experimental workload seeds/truth are separate private driver inputs under the declared attacker contracts, while mechanism parameters remain public. Accepted bounded experiments do not establish global indistinguishability or production security.

An additional preregistered independent ORAM leaf/timing run used a fresh eight-address skew, address 0 as the hot class, and 70% reads. Plaintext and encrypt-only controls both scored AUC 1.000; ORAM scored 0.5015 [0.4935, 0.5095] over 30 whole-session trials. A post-hoc frequency-only attacker on the same sessions scored ORAM AUC 0.5017 [0.4931, 0.5101], with both controls at 1.000. The [protocol](ORAM_SIGNAL_REPLICATION_20261025_PREREG.md), [results](ORAM_SIGNAL_REPLICATION_20261025.md), raw sessions, predictions, figure, and host observation are retained. All raw hashes and paired session schedules were rechecked. Host load was present during collection, so this is process-isolated service timing with host scheduling noise, not a quiet-host replication or a security proof.

A separate 2026-10-26 preregistered Markov-locality workload B changed the seed, hot set, refresh distribution, retention probability and read/write mix. Both controls scored AUC 1.000; Path ORAM scored 0.5021 [0.4803, 0.5242] over 30 trials. All 1,440 raw trace hashes and 240 paired schedules were independently rechecked. The [preregistration](ORAM_SIGNAL_REPLICATION_20261026_B_PREREG.md), [results](ORAM_SIGNAL_REPLICATION_20261026_B.md), [raw session and prediction archive](../experiments/results/oram-isolated-replication-20261026-b/trace-data.tar.gz), figure, verification and host observation are retained. Load averages reached 7.71 on this 24-logical-CPU host; this run also cannot rule out smaller effects. Other workload families, attack families and quieter-host replications remain open.

The service-pinned 2026-10-26 replication has now completed with both
positive controls successful and ORAM AUC 0.4937 [0.4756, 0.5130]. Its 90
retained final-session metadata records showed CPU 0; `taskset -c 0` was
configured for all 720 child sessions, but individual PIDs/masks were not
retained. The driver remained unpinned. This is an independent run, not a paired test of
pinning versus no pinning, and the host remains shared. See the
[preregistration](ORAM_PINNED_REPLICATION_20261026_PREREG.md) and
[results](ORAM_PINNED_REPLICATION_20261026.md). A useful follow-up is a
preregistered within-host crossover with paired seeds and randomized
pinned/unpinned collection order, if a suitable controlled host is available.

That crossover has now completed. Across 30 paired trials, pinned minus
unpinned ORAM AUC was +0.0172 [−0.0162, +0.0497]; the interval includes zero.
All four controls succeeded. The result does not establish a pinning effect.
The initial report assembly failed after capture on a missing Python import;
all raw data were retained, verified, and reanalyzed without recollection.
See the [preregistration](ORAM_AFFINITY_CROSSOVER_PREREG_20261026.md) and
[result record](ORAM_AFFINITY_CROSSOVER_20261026.md). A follow-up on a
dedicated host with per-child PID/affinity logging would improve execution
provenance; broader classifiers/workloads and real remote timing remain open.

The measurement output now records every service-child PID and effective CPU
mask for new runs, with an in-process check for requested affinity. This
improves future per-child provenance; historical raw campaigns remain limited
to their retained metadata.

A new 32-address Zipf workload replication completed with the frozen
classifier and isolated bucket-handler timing. Both controls scored AUC 1.000;
Path ORAM scored 0.5003 [0.4929, 0.5073]. Raw hashes, paired schedules, saved
predictions, and metrics were independently checked. Collection-time host
load was not captured, a preregistration deviation that limits timing-noise
interpretation. See the
[preregistration](ORAM_ZIPF32_REPLICATION_PREREG_20261026.md) and
[result](ORAM_ZIPF32_REPLICATION_20261026.md). More workloads and a run with
collection-time host monitoring remain open. The replication collector now
records platform, CPU model/count, allowed CPU set, and load average before and
after each mode; this instrumentation does not retroactively repair the
completed study.

A second Zipf-32 run with a fresh seed and those host snapshots is complete.
Both controls scored AUC 1.000; ORAM scored 0.5052 [0.4995, 0.5109]. The
collector's incomplete raw-hash map was corrected without modifying captured
data; the original report and complete hash manifest are retained. See the
[preregistration](ORAM_ZIPF32_MONITORED_PREREG_20261026.md) and
[independent result](ORAM_ZIPF32_MONITORED_REPLICATION_20261026.md). The two
runs are separate estimates, not a pooled analysis.

A uniform-32 comparison was preregistered in
[`ORAM_UNIFORM32_REPLICATION_PREREG_20261026.md`](ORAM_UNIFORM32_REPLICATION_PREREG_20261026.md).
It used a balanced public hot/cold partition and preserved the same operation
mix, classifier, positive controls, and primary metric; its completed result is
recorded below.

The uniform-32 replication is now complete. Both positive controls passed and
Path ORAM scored AUC 0.5018 [0.4965, 0.5078]; the interval includes chance.
All 1,440 raw hashes, 240 paired schedules, and 90 saved prediction metrics
were checked. See the [preregistration](ORAM_UNIFORM32_REPLICATION_PREREG_20261026.md)
and [result](ORAM_UNIFORM32_REPLICATION_20261026.md). This remains a bounded
local synthetic experiment. Other workload and attack families, quieter-host
replication, and real remote timing remain open.

A fresh higher-skew 32-address Zipf replication (exponent 1.5; top-four mass
0.7389) also completed with the frozen classifier. Both controls scored
approximately AUC 1.000; Path ORAM scored 0.4997 [0.4913, 0.5073], with raw
accuracy below the profile-majority baseline. All raw hashes, paired schedules,
and prediction metrics were checked. See the
[protocol](ORAM_ZIPF32_ALPHA15_REPLICATION_PREREG_20261026.md) and
[result](ORAM_ZIPF32_ALPHA15_REPLICATION_20261026.md). This does not resolve
other distributions, attacks, quiet-host effects, or remote timing.

A fresh Markov-locality collection also tested the preregistered one-step
previous-visible-tag attack. Both controls passed at AUC 0.9198; ORAM scored
0.5013 [0.4916, 0.5106], with raw accuracy below the profile-majority
baseline. All raw hashes, paired schedules, and prediction metrics were
checked. The transition analysis shares the new collection with its temporal
classifier and is not an independent collection from that primary analysis.
See the [protocol](ORAM_MARKOV_TRANSITION_REPLICATION_PREREG_20261026.md) and
[result](ORAM_MARKOV_TRANSITION_REPLICATION_20261026.md). This does not settle
other attacks, workloads, or remote timing.

## Subsequent software action (after the active ORAM replication)

**Completed 2026-10-28:** the preregistered 30-trial 16-address Zipf/Markov
replication passed both positive controls and measured Path ORAM ROC AUC
0.4968 [0.4864, 0.5072]. The interval includes chance; this does not establish
privacy or rule out a smaller signal. Raw traces, hashes, paired schedules,
verification, host observations and the figure are in the result bundle. See
the [preregistration](ORAM_ZIPF16_MARKOV_REPLICATION_PREREG_20261028.md) and
[result report](ORAM_ZIPF16_MARKOV_REPLICATION_20261028.md).

The opt-in persistent autoscaler privacy ledger is implemented and measured;
its separate OS rollback/key-custody limitations remain documented. The
schema-v4 encrypted SQLite slot, additive protocol-v3 Unix operations,
`SseJournalAnchor` adapter and process-restart integration are implemented.

**Completed follow-up (2026-10-28):** the preregistered persistent SSE journal
benchmark ran all 30 trials at sizes 64, 257, 1,024, and 4,093 against the
actual Unix SQLite anchor service. Five fresh-process reopens were measured per
index. The independent verifier checked all 120 trial/size samples, 600
distinct recovery child processes, byte/generation invariants, and descriptive
statistics. Mean application journal-byte amplification increased from
84.037× to 244.754×; mean build time ranged from 3.316 s to 242.889 s. The
[result report](SSE_JOURNAL_BENCHMARK_20261028_RESULT.md) and raw result bundle
state the warm-page-cache, single-host, and application-level-byte limits.

The current serial workspace test command exits 0 with all enabled tests
passing; the default command intentionally ignores the million-operation ORAM
stress tier. The venv Python suite passed 240 tests with four skips. An earlier
run's timing-sensitive 100 ms mixed-invocation timeout is retained as
historical evidence; the same test and a fresh full workspace run passed
without changing production deadlines. The independent result verifier and
artifact checksum validation also pass.

**Freshness extension (2026-10-29):** standalone SSE clients, runtime
signed-registry activation, and standalone ORAM checkpoint clients can use a
separately administered mTLS witness. It detects rollback of the application
host's encrypted journal, stale/equivocating catalog activation, or stale ORAM
checkpoint handles while the witness preserves its current SQLite state. The
witness itself remains a single trusted operator/database and can be rolled
back or made unavailable. The runtime worker can select the remote catalog
anchor through six all-or-none mTLS environment settings, mutually exclusive
with its local Unix anchor. The external manifest and pinned publisher key
remain required, and the worker fails closed before readiness on configuration,
TLS, witness, rollback, or uncertain-CAS failures. `TlsCheckpointAnchor`
implements the existing `CheckpointAnchor` contract over mTLS and passes a
real ORAM recovery/restart/stale-writer integration test. Its 88-byte secret
handle includes the snapshot decryption key, so the remote witness is trusted
with snapshot confidentiality. At the time that checkpoint-adapter increment landed, runtime invocation receipts were still local. The follow-up runtime integration in code commit `7bee2666` now also supports remote mTLS invocation checkpoint/receipt commits.

**Completed 2026-10-29 (code commit `7bee2666`):** the pinned serial
`cargo test --locked --workspace -- --test-threads=1` command passed 187 tests;
one million-operation ORAM stress test remains intentionally ignored by the
normal suite and also passed separately with the dedicated release command in
88.76 seconds. Workspace warning-denied Clippy, formatting, and whitespace
checks passed. Hosted run [40824696959](https://github.com/dumbly-smart/Oblivion/actions/runs/40824696959)
passed Rust quality and analysis; its separate stress job was skipped. The
remote integration test covers real mTLS witness restart, signed stateful WASM
execution, exact replay, a later state transition, and an older receipt replay
without checkpoint rollback. No performance benchmark or local Python suite
was run for this Rust-only change. Full details and the limitation of the
current ambiguous-reply transport test are recorded in
[implementation status](IMPLEMENTATION_STATUS.md).

**Completed 2026-10-29 (source commit `4e66221d`):** a focused mTLS fault test
commits an invocation receipt and checkpoint through the production request
handler, drops the TLS reply, then reconnects to confirm the exact receipt and
response. It also checks the checkpoint remains at the committed generation.
The test uses a one-shot test server and suppresses the response after handler
completion; it does not simulate killing the production `serve_mtls` process
inside its network write path. The full serial workspace suite passed 188
tests, with the million-operation ORAM stress test intentionally ignored by
the default tier. Warning-denied workspace Clippy, formatting, and whitespace
checks passed. This Rust-only test increment did not run benchmarks or the
Python suite.

**Next:** before multiple remote workers are supported, design and test a
host-independent writer-fencing protocol; checkpoint CAS alone rejects stale
publication but is not a distributed lease. Keep witness rollback, snapshot
key custody, single-operator trust, no TEE, and no arbitrary external-side-
effect guarantee explicit. At the time of that recorded update, S11 remained
partial; that historical entry claimed no hardware anti-rollback or backward
privacy. The current bounded S11 status is recorded at the top of this file and
in the requirements matrix.
