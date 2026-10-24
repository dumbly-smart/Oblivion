# Implementation and evidence status

**Selected-scope acceptance:** the [serial local gate](../experiments/results/validation-20261023-serial/commands.json) passed all ten commands, including 91 core Rust tests, one reference test, 120 Python tests without skips and the million-operation oracle. [Before/after source fingerprints](../experiments/results/validation-20261023-serial/metadata.json) match: `a83d606782f63e9f5c9f8b95a3c80b299f57da30c916de670f61751e8068becc`. All three jobs in [hosted run 39971009249](https://github.com/dumbly-smart/Oblivion/actions/runs/39971009249) for `ade31d2c` passed. The selected roadmap software and empirical deliverables, local gate and hosted source gate are accepted within the documented boundaries. [PR #1](https://github.com/dumbly-smart/Oblivion/pull/1) is ready for delivery; no merge is claimed. Subsequent closing Markdown-only checks are accessible on the PR and do not create a new unfinished source requirement.

The later failed [historical run 39969711451](https://github.com/dumbly-smart/Oblivion/actions/runs/39969711451) remains preserved: Rust failed while analysis/stress passed, and its specific cause remains unproved. [Three-arm scheduling diagnostics](PIPELINE_TEST_SCHEDULING.md) reproduced authenticated timeouts under CPU contention: pinned two-CPU parallel tests had two timeouts, the same serial suite passed, and one CPU with 16 competitors produced an actual 218 ms Timeout with both PIR operations and 128 storage events. Correctness suites explicitly use `--test-threads=1`; production budgets, benchmark concurrency and retry behavior are unchanged.

After adding the isolated ORAM service and fresh timing study, the current
source passed all ten commands in
[`validation-20261025-oram`](../experiments/results/validation-20261025-oram/commands.json).
The before/after source fingerprints match. The gate covered workspace and
reference formatting, clippy, tests and builds; 133 Python tests with four
existing skips; and the million-operation ORAM oracle. The Python validator
also supplied freshly built ORAM binaries to the isolated-process integration
tests.

After adding the population-sweep analysis and tests, a fresh
`.venv/bin/python -m unittest discover -s research/tests` run passed all 143
tests with four existing runtime-fixture skips. The population runner's
configured 120-trial execution and raw-hash verification also completed; see
[`POPULATION_SWEEP.md`](POPULATION_SWEEP.md). After extending the ORAM timing
runner to configured address domains and hot/cold labels, the 139-test
suite passed. The new eight-address experiment passed both positive
controls and post-run verification of all 1,440 hashes and paired schedules;
its ORAM hot/cold AUC was 0.507 [0.496, 0.517]. See
[`ORAM_EIGHT_ADDRESS.md`](ORAM_EIGHT_ADDRESS.md).

The frequency-only tag attack passed its plaintext/encrypt-only positive
controls and measured ORAM AUC 0.498 [0.488, 0.508] on the same held-out
sessions. The full 143-test research suite passed with four existing skips;
see [`ORAM_ATTACK_FAMILIES.md`](ORAM_ATTACK_FAMILIES.md). A separate 90%-read
study retained the same address schedules, passed both controls, and measured
ORAM AUC 0.497 [0.490, 0.505]. All 1,440 trace hashes were verified; see
[`ORAM_READ_HEAVY.md`](ORAM_READ_HEAVY.md).

A fresh-seed 10%-read ORAM run then tested the write-heavy mix with the same
primary AUC metric and positive controls. Both controls passed; ORAM measured
0.49572 [0.48678, 0.50489]. An independent check verified 1,440 raw hashes and
all 240 paired address/read-write schedules. See
[`ORAM_WRITE_HEAVY.md`](ORAM_WRITE_HEAVY.md).

A separate fresh-seed uniform-address run with a 50/50 operation mix passed
both controls and measured ORAM AUC 0.49267 [0.48190, 0.50309]. Independent
verification checked all 1,440 raw hashes and all 240 paired schedules. See
[`ORAM_UNIFORM.md`](ORAM_UNIFORM.md).

The frequency-only tag scorer was also applied to all three follow-up raw
datasets. All six leaky control conditions passed, all 4,320 referenced raw
hashes and nine source/config inputs were independently verified, and the ORAM
scores were 0.49871 (read-heavy), 0.48877 (write-heavy), and 0.50462 (uniform
addresses). The write-heavy fixed score direction is slightly below chance;
no target-label-based inversion was used. A profile-only cross-validation
orientation follow-up passed all six controls and retained its three reports,
predictions and plots. ORAM AUC became 0.49909 [0.49106, 0.50726], 0.50653
[0.49657, 0.51666], and 0.49374 [0.48298, 0.50437], respectively; all
intervals include chance and oriented raw accuracy remains below the
profile-majority baseline. The full research suite passed (169 tests, four
skipped). See [`ORAM_FREQUENCY_ORIENTATION.md`](ORAM_FREQUENCY_ORIENTATION.md)
and [`ORAM_ATTACK_FAMILIES.md`](ORAM_ATTACK_FAMILIES.md).

The checkpoint recovery API now includes a caller-supplied `CheckpointAnchor`
CAS path that atomically stores an opaque snapshot ID with the secret handle.
It rejects a controller whose generation is stale before publishing, and its
recovery tests cover successful advancement, stale writers, invalid IDs and a
definite non-commit retry. Fresh package verification passed formatting,
`cargo test -p oblivion-store -- --test-threads=1` (20 passed, one million-op
stress test intentionally ignored), and warning-free Clippy. The anchor service,
snapshot catalog, durable invocation acknowledgment/side-effect transaction,
and ambiguous remote-CAS recovery remain unimplemented.

The `oblivion-registry` crate implements fixed-size Ed25519-signed records, a
signed catalog digest, bounded exact parsing, per-record strict verification,
and monotonic activation through a caller-provided version-anchor CAS. Its
tampering, omission, reorder, duplicate, key, version, rollback and CAS-conflict
tests pass. The runtime now builds and verifies a signed catalog in the trusted
executor and supplies its 160-byte rows to both secure-PIR workers over bounded
inherited-pipe framing. Recovered rows must match the verified local pin. This
demo signer is ephemeral and establishes no external publisher identity. A
durable version anchor, signer custody, remote publication and partial-catalog
inclusion proofs remain open.

Updated 2026-10-24. The selected pipeline and later bounded research artifacts now have evidence in [the requirements matrix](REQUIREMENTS_MATRIX.md) and [completion audit](COMPLETION_AUDIT.md). The selected artifacts and earlier passing gates are recorded. PR #1 is the review artifact while latest validation closure is held; no production-security or merge claim follows. TrustedExecutor is simulated by ordinary processes, without a hardware TEE or attestation.

## Implemented system

Seven Rust crates implement encrypted Path ORAM, two-server XOR PIR, Wasmtime execution, authenticated epoch batching, process orchestration, trace generation and constrained GGM SSE. The current process path supports one to four clients, all five actual functions, disjoint user/dummy state, SSE metadata discovery, encrypted PIR, independent output/counter oracles and fixed 164-byte invocation/response envelopes.

Protected execution reads eight blocks at the public 25 ms phase and commits eight at 50 ms. Guest failures discard staged mutations; uncertain backend failure can poison partially written state. At eight logical blocks an invocation emits 128 actual bucket events of 316 bytes, with O(M log N) bandwidth for public working-set M. Trusted drivers prepare encrypted responses/private instrumentation before the 100 ms publication wait. Clients prepare requests before their public epoch. Slot starts are epoch arrival plus slot × 100 ms. OS scheduling and work overruns remain visible.

The current response reader timestamps completion immediately after `read_exact`, before channel handoff and later client decryption/oracle/logging. Public pipe timing and separate private client latency are not interchangeable. The process demo remains ephemeral. Separate bounded file/checkpoint recovery authenticates full snapshots and rekeys against a trusted latest handle; it does not implement durable invocation acknowledgments, whole-anchor replay protection or persistent SSE.

The built-in demo's real/dummy/function schedule is public given its code, real percentage and epoch. It validates correctness/topology, not anonymity against an adversary who knows that schedule. Research datasets keep workload labels/seeds outside each declared attack input; public cadence, classes, batch size and geometry remain known. Encryption cannot hide an identity already determined by auxiliary knowledge.

## Accepted bounded measurements

| Evidence | What actually ran | Result and boundary |
| --- | --- | --- |
| [Joint A–G/ablations](SYSTEM_EXPERIMENTS.md) | 30 fitted-model trials; 1,920 observations/mode on actual libraries | Final G balanced accuracy 33.40% [32.29,34.51], chance 33.33%. Declared summary-feature attacker, not every host observation |
| [Execution/errors](EXECUTION_EVALUATION.md) | Five functions plus three failures, 30 trials, visible-selector control first | Protected eight-class accuracy 11.67% [9.38,13.75], chance 12.5%; 960 protected output/status checks, fixed frames/storage shapes; saved earlier binary |
| [Actual trace validation](TRACE_VALIDATION.md) | 100k ORAM accesses/workload and 30 scoped encrypted PIR captures | 1.4M bucket events/workload; 3,000 verified PIR retrievals, 6,000 streams, 61,363 packets and zero reported drops. Unvalidated packet classifier excluded |
| [ORAM leaf+timing](ORAM_LEAF_TIMING.md) | Independent profile/target sessions and 30 fitted trials | Balanced accuracy 50.70% [49.80,51.62]; AUC 0.511 [0.501,0.521] is a possible weak signal, retained with unadjusted/multiple-metric caveats |
| [Individual-server PIR timing](PIR_TARGET_TIMING.md) | 46,080 oracle-checked requests at two geometries; real visible-index control first | Protected joint/timing/share intervals include three-class chance; only own share/local answer time, not collusion or network timing |
| [SSE methods](SSE_ATTACKS.md), [inference](ADVANCED_ATTACKS.md), [chosen updates](UPDATE_LINKABILITY.md) | Actual encrypted postings/capabilities and 30 trial clusters | Six bounded SSE-facing methods and successful controls; equality/volume/later authorization still leak; not faithful published attack reproductions |
| [Real corpus/drift](CORPUS_EVALUATION.md) | Licensed UCI text associations, genuine SSE/dummy padding, 30 conditional resamples | Likelihood 64.35% matched auxiliary → 36.35% strongest document drift; padded 38.88%. Synthetic queries; shared corpus across resamples |
| [Presence/intersection](PRESENCE_EVALUATION.md) | Actual authenticated batcher frames with virtual epochs | Online-only fixed-rate clients remain identifiable under the explicit semantic beacon. Always-participating endpoints leave eight candidates; no packet-timing claim |
| [Geometry/stash](GEOMETRY_EVALUATION.md) | 42 cells × 30 trials; 138,240 ORAM accesses / 2,880 PIR queries | Genuine full-record oracles, payload/map/stash accounting and histograms; observed maxima are not rare-overflow bounds or remote RSS |
| [Matched Path/Circuit reference](CIRCUIT_ORAM_REFERENCE.md) | Genuine MobileCoin 2.3.0 implementations; 61,440 timed accesses / 193,920 full-record checks | Matched unencrypted trusted heap, 30 trials/cell, separate GPL workspace. Not core Path ORAM replacement or network/TEE comparison |
| [Square-root PIR](SQRT_PIR.md) | Actual packed-row queries/recovery; 5,760 checked retrievals | Smaller queries, potentially much larger answers; all padded bytes still scanned. Private column, non-colluding servers, no symmetric-PIR claim |
| [SimplePIR reference](SIMPLEPIR_REFERENCE.md) and [100k summary](../experiments/results/simplepir-100k-20261023/summary.json) | Genuine pinned Go/C SimplePIR and matched XOR, 30 setups each; 100,020 queries/scheme | Every full eight-byte output matches. Real hint/setup/online accounting; within-setup outcomes dependent, no worst-case LWE failure theorem |
| [Executor resources/CPU](EXECUTOR_RESOURCES.md) | Separate original resource and direct-CPU campaigns, each 180 processes / 2,160 calls | Setup/compile, first/warm, public classes, process/thread invocation CPU and success/failure denominators. Wall padding is not CPU waste |
| [Extended open loop](RUNTIME_BENCHMARKS.md) | 180 fresh processes / 5,760 offers, six load/queue cells | Queue/drop/admitted latency/SLO tradeoffs retained; 32 offers/trial do not establish population tails or production capacity |
| [Integrated epochs](EPOCH_SYSTEM_EVALUATION.md) | Final reader-thread pipe campaign: 360 process trees / 2,160 verified calls | 12 cells × 30; strict public/private separation, 1,080 real/1,080 dummy successes, 2,955 artifact hashes; scoped provenance differences below |
| [Joint batching load](BATCH_LOAD_EVALUATION.md) | 720 independent processes; 30 fitted models/mode, 180 held-out targets/mode | Actual plaintext control 100%; AEAD protected 28.33% [22.78,33.89] against 33.33%. Same 22 public features/metric; two failed forest controls retained |
| [Repeated faults](FAULT_CAMPAIGN.md) | Seven assertion-bearing fixtures × 30, 210 launches | All assertions pass for stated scenarios. Original ENOSPC/truncated-publication attempt remains excluded/incomplete, not silently overwritten |
| [Autoscaler](AUTOSCALER.md), [bounded discrete-geometric mechanism and attack studies](AUTOSCALER_DP.md) | Five-policy baseline campaigns, event-level 30-trial CSPRNG runs, and a 30-trial bounded-user cap-2 run with separate whole-session attack evaluation; all naive controls pass | Conditional `(epsilon, delta)` claims for fixed-horizon count/event observers under independent hidden bits. Synthetic IDs are not authenticated; sampler timing, repeated sessions and full runtime are excluded. One event-level burst-hot interval is marginally above chance; all cap-2 protected intervals include chance. Cost is simulator-only |
| [Attack API](ATTACK_INTERFACE.md) | 13 registered adapters with common PredictionResult and strict schemas | Uncalibrated confidence remains absent. Adapter availability is not extra experimental evidence |
| [Actual demo](DEMO.md) | Three-client mixed SSE/PIR/WASM/ORAM run | 24 calls, 12 real, all five functions, 24 metadata queries and 3,072 storage events; MP4/terminalcast/raw records. Public deterministic schedule, not privacy evidence |

The final A–G report's per-real API p95/p99 are 100.159/100.200 ms; opportunity wall time 116.268 ms and goodput 4.3004/s include the stated initial wait/oracle/logging scope. Accounted payload is 82,484 bytes/real at 50% dummy load. A/E/G nominal three-axis membership uses explicitly hypothetical executor-wall/egress prices. Neither provider calibration nor universal statistical dominance is claimed or required to possess the stated plots.

## Chronology and provenance limits

The stopped 18-trial `system-30-20261021/` pilot has an incorrect measurement/oracle boundary and is excluded. The genuine earlier corrected system run retains possible conditional function inference 54.58% [50.21,59.17]. Later encrypted preparation/publication changes and fresh data do not erase that result.

The first integrated epoch campaign mixed private instrumentation into an observer-named file and is excluded from attacker input. The second separates fields but timestamps client consumption after channel handoff. Only `epoch-system-pipe-timestamps-20261023/` claims the reader-thread pipe boundary. Its immutable binary/source copies are authoritative: 251 live checkout fingerprints matched the snapshot; 109 reflect an unrelated PIR timing example's Clippy edit. Later checked default-wrapper input bounds/regressions differ from the measured tree but do not change the measured valid `demo-sweep` path or reader. No false global before/after checkout equality is asserted.

The two failed batch-load forest controls never generated protected data. Original source snapshots/retrospective provenance explicitly retain their missing terminal/start-time proof limitation. The final class-centroid campaign writes durable source/config/binary/hardware provenance before measurement and verifies hashes afterward. Older 10 ms/two-ORAM-operation demos remain historical; current protected calls use sixteen logical accesses and 100 ms classes.

## Validation and delivery gates

Historical `validation-20261022-frozen/` has five zero exits and matching source fingerprints, including 53 Python checks with one explicit optional skip and a separate million-operation stress tier. It does not validate later additions. All three jobs in [historical hosted run 39969191581](https://github.com/dumbly-smart/Oblivion/actions/runs/39969191581) for `d80f258c` passed on the earlier locally verified source. Those green records and the later failed hosted run remain preserved. The new explicit serial correctness-test policy changed CI/validator inputs; validation-20261023-serial and hosted ade31d2c/39971009249 subsequently passed, as recorded above. [PR #1](https://github.com/dumbly-smart/Oblivion/pull/1) is the review artifact; no merge is claimed.

Two ten-command local attempts remain preserved and unaccepted as complete gates. `validation-20261023-final/` has nine zero exits and a workspace harness Timeout. `validation-20261023-current-source/` passes workspace tests but its 112-test Python run has one authenticated `demo-sweep` invocation failure; its private cause was not retained and remains unknown. A deterministic Timeout regression does not establish that historical cause.

The fresh [verified local gate](../experiments/results/validation-20261023-verified/commands.json) passed all ten commands: 90 core Rust tests, one reference test, 119 Python tests with all four runtime fixtures and no skips, both workspaces' quality/build checks, and the million-operation oracle. [Before/after source fingerprints](../experiments/results/validation-20261023-verified/metadata.json) match; that historical gate passed for its recorded source. The default validator builds core release fixtures and the separate GPL reference, runs both workspaces' gates, enables all four Python runtime fixtures and executes million-operation stress. The ten-command local pass applies to that recorded source identity; it does not substitute for final-head hosted CI.

The research-only `demo-sweep` now retains authenticated masked runtime failures, including their timing, CPU and completed interface work, while successful outputs still require full independent oracles. Legacy `demo`/`demo-sse` stay strict; budgets, reader timestamps and retry behavior are unchanged. Primary CPU/byte cost per real success is a ratio of sums that includes zero-success trials' costs; unknown partial PIR-byte costs, undefined totals and bootstrap draws are explicit, with no unconditional finite interval when a draw is undefined. Historical completed campaigns had zero runtime errors and were not rerun or rewritten. See [the post-measurement policy](EPOCH_SYSTEM_EVALUATION.md#post-measurement-runtime-error-retention).

[The figure reproduction audit](FIGURE_REPRODUCTION.md) now records raw-derived regeneration of all eight required main figures and the supplemental three-axis/SLO plot without ignored measurement executables. Both autoscaler campaigns rebuild from four raw/config files rather than cached reports; audited numerical reports and PNG bytes matched, and accepted inputs stayed unchanged. The serial local and hosted source gates are accepted; subsequent closing Markdown-only checks are accessible on PR #1.

Selected implementation/evaluation and the serial local/hosted source gates are accepted within their bounded scope. [PR #1](https://github.com/dumbly-smart/Oblivion/pull/1) is ready for delivery on `codex/oblivion-research-platform`; no main merge is claimed. A bounded-user autoscaler simulator mode now exists, but authenticated identity binding, cross-session composition, production DP integration, and an external sampler/code audit remain open. Expanded finite exact-rational checks and the source-review findings are recorded in [SAMPLER_AUDIT.md](SAMPLER_AUDIT.md). Hardware isolation, recursive/native Circuit storage, DPF/native single-server runtime selection, persistent/backward-private SSE and durable application acknowledgments remain deployment/research extensions. Human P1–P12 study and mutable bibliography/course listings are context, not machine-proof software gates.

## Optional follow-up: isolated ORAM timing

The ORAM measurement example now has an opt-in child-process bucket service.
A fresh 30-trial study passed plaintext and encrypt-only positive controls and
measured ORAM AUC 0.502 [0.491, 0.513] with a declared primary metric and
whole-session split. Raw event and private label hashes were independently
verified; the initial unpaired run is marked superseded. See the
[two-address replication report](ORAM_TIMING_REPLICATION.md). The configurable
runner now also supports an eight-address hot/cold workload; its controls
passed and ORAM AUC was 0.507 [0.496, 0.517]. See the
[eight-address follow-up](ORAM_EIGHT_ADDRESS.md). Additional operation mixes,
attacker families, and network timing remain open. The same runner now accepts
a configured read probability; the 90%-read follow-up retained paired address
schedules and measured AUC 0.497 [0.490, 0.505] after passing both controls.
See [operation-mix results](ORAM_READ_HEAVY.md) and the
[frequency-only attacker](ORAM_ATTACK_FAMILIES.md).

## Optional follow-up: real query content

A 30-trial MIMICS-Click token-workload evaluation now uses the real constrained
GGM SSE implementation. Exact-count and unpadded positive controls pass;
padding reduces the measured count-volume attack to the profile-majority range
on the evaluated 12.2%-coverage subset. Aggregate-only output and source
provenance are retained in
[the human-query report](HUMAN_QUERY_EVALUATION.md). The source has no
arrival-frequency or temporal data and licensing terms remain ambiguous, so
this is not a representative search-traffic study.

## Optional follow-up: population and epoch load

The authenticated epoch batcher ran 30 process trials each at 1, 8, 32 and 64
configured client slots, for 100 epochs at 25 ms. The aggregate report retains
240 separately hashed observer/private files and shows emitted frame rates
from 40 to 2,560 per second; p95 scheduled queue wait is about 23.6–23.7 ms.
The actual server path also completed 30 fresh processes at each of two
64-offer schedules with authenticated exchange, two PIR servers, Wasmtime and
ORAM. All 60 runs and 3,840 offers were accounted; underload admitted all 64
per process, while overload dropped 71.88% and had a 96.88% offered SLO-failure
fraction. These are local single-host results; broader steady-state capacity,
remote clients and provider costs remain unmeasured. See the [batcher
population sweep](POPULATION_SWEEP.md) and [full-path load study](RUNTIME_POPULATION.md).

## Optional follow-up: event-level autoscaler Laplace mechanism

Commit `8dc591f3` adds the optional `dp_laplace` simulator policy, explicit
fixed-horizon add/remove-one-request sensitivity and basic-composition fields,
and configuration-selected policy lists. Commit `30f35815` makes seeded gzip
traces byte-reproducible. The raw-session reanalysis now preserves both the
legacy five-policy defaults and the configured optional policy set, and emits
artifact hash manifests.

The fresh study at
[`scaler-dp-event-20261024`](../experiments/results/scaler-dp-event-20261024/)
uses 30 trials, eight whole sessions, four synthetic workloads, and six
policies. All seven naive positive controls passed. The declared centroid
attack's `dp_laplace` balanced accuracy ranges from 0.489 to 0.562 across
tasks; six of seven unadjusted intervals include 0.5 and Zipf intensity is
56.2% [50.1%, 62.5%]. The policy met the simulator's 1% SLO filter only for
burst workloads. These measurements describe one classifier and this model.

The design argument assumes ideal independent hidden Laplace samples, but the
reproducible experiment publishes its deterministic seed. It therefore has no
formal DP guarantee. The post-hoc seed-replay classifier uses public capacity
changes to estimate the de-noised EWMA; all fourteen naive positive controls
pass across centroid and forest variants. Every centroid seed-replay interval
includes chance. In the forest seed-replay arm, burst intensity reached
56.3% [50.6%, 61.9%], an unadjusted result among multiple attacks. In the
original centroid DP-arm profiler, the Zipf-intensity interval began at
0.501, another marginal unadjusted result. A simple adjacent-input test also
observes distinct transcripts under one public seed. This remains a bounded
classifier evaluation, not a universal
attack result. The mechanism is not connected to the Rust request path,
scheduler, or a full runtime observer. See [`AUTOSCALER_DP.md`](AUTOSCALER_DP.md)
for the derivation, raw hashes, attack protocol, and remaining CSPRNG,
user-level, stronger-inversion, and full-runtime work. The full Python
research suite passed 154 tests with four existing fixture skips after the
epsilon-sweep driver and seed-replay regressions were added. The current
research suite passed 158 tests with four existing fixture skips after the
CSPRNG sampler and retained-raw reanalysis support were added. The current
research suite passed 159 tests with four existing fixture skips after the
CSPRNG-aware attack evaluator was added. The separate CSPRNG study passed all
14 centroid/forest naïve controls; protected forest intervals include chance.
The four-budget study passed all 28 naive positive controls; results and its root hash
manifest are retained at
[`scaler-dp-epsilon-sweep-20261024`](../experiments/results/scaler-dp-epsilon-sweep-20261024/).

## Optional follow-up: bounded discrete-geometric CSPRNG mechanism

The autoscaler now noises each integer per-pool arrival count with the
difference of two capped geometric samples. The finite 64-bit rational `q` is
rounded conservatively; the configured cap supplies a reported composed
approximate-DP delta for the fixed-horizon event-level observer. EWMA,
nonnegative clipping and capacity decisions follow as post-processing. The
public deterministic-seed mode uses the same sampler for debugging but makes
no DP claim. The OS-CSPRNG mode's claim remains conditional on independent
uniform entropy and the fixed observer definition; it has no independent code
audit and does not cover a full runtime transcript or user-level adjacency.

The fresh 30-trial CSPRNG campaign is retained in
[`scaler-dp-discrete-csprng-20261024`](../experiments/results/scaler-dp-discrete-csprng-20261024/)
with its separate whole-session attack analysis in
[`scaler-dp-discrete-csprng-attack-20261024`](../experiments/results/scaler-dp-discrete-csprng-attack-20261024/).
All 14 naive controls passed. The final v2 artifacts are in
[`scaler-dp-discrete-csprng-20261024-v2`](../experiments/results/scaler-dp-discrete-csprng-20261024-v2/)
and [`scaler-dp-discrete-csprng-attack-20261024-v2`](../experiments/results/scaler-dp-discrete-csprng-attack-20261024-v2/);
the earlier run is preserved but superseded after expanding observer
exclusions. In v2, the protected burst hot-pool forest interval was 0.559
[0.501, 0.613], a marginal above-chance interval before multiplicity
correction. The other six protected forest intervals include chance. This is
a residual inference result, not a contradiction of request-level DP and not
a security proof. `.venv/bin/python -m unittest discover -s research/tests`
passed 161 tests with four existing fixture skips after this change.

## Optional follow-up: bounded-user autoscaler adjacency

The simulator now supports `dp_user_contribution_cap`. With cap 2, each
per-tick count vector has L1 sensitivity at most 2; calibration uses
`epsilon_unit=0.025`, 20 releases and a sampler cap of 756, yielding reported
composed `epsilon=1`, `delta=9.9104e-7`. Synthetic principals are round-robin
IDs, not authenticated users. Imported CSVs must add a `user_id` column in
this mode. The claim applies to the private count/event observer, not queue,
response or sampler processing signals.

The 30-trial cap-2 run and attack report are retained at
[`scaler-dp-user-csprng-20261024`](../experiments/results/scaler-dp-user-csprng-20261024/)
and [`scaler-dp-user-csprng-attack-20261024`](../experiments/results/scaler-dp-user-csprng-attack-20261024/).
All 14 naive centroid/forest controls passed; all seven protected forest
intervals include chance. Mean simulated instance-seconds were higher than
the request-level CSPRNG run on all four workloads. The raw trial intervals,
performance comparisons and limitations are in [AUTOSCALER_DP.md](AUTOSCALER_DP.md).
The full `.venv/bin/python -m unittest discover -s research/tests` suite passed
166 tests with four existing fixture skips after this addition.

A separate exact-rational test enumerates the capped one-function noise PMF
and both one-count hockey-stick directions for three parameter sets. A second
test checks both directions for the two-pool cap-2 user-level shifts `(2, 0)`
and `(1, 1)`. The exact divergences were below their configured conservative
bounds; all three one-function composed bounds remained within the requested
total delta. This verifies the finite law for these test cases, not arbitrary
pool counts, user caps or the end-to-end mechanism. See
[`SAMPLER_AUDIT.md`](SAMPLER_AUDIT.md). Both focused checks passed; the full
research suite then passed 172 tests with four existing fixture skips.

A preregistered profile-trained interval attack was then evaluated against
the retained 30-trial OS-CSPRNG scaler data. It derived conservative arrival
bounds from public scale transitions and the public finite noise support,
without replaying the noise. All 28 naive controls passed. Paired protected
interval-feature differences from public-feature baselines all include zero;
four individual protected intervals were unadjusted and just above chance for
hot-pool prediction. This is a possible residual signal in these synthetic
workloads, not evidence of general attacker advantage. See
[`AUTOSCALER_INTERVAL_ATTACK.md`](AUTOSCALER_INTERVAL_ATTACK.md). Full-suite
verification after the final implementation refinement passed: 176 tests,
with four existing fixture skips. After adding the finite PMF helper, the
full research suite passed 180 tests with four existing fixture skips.

The autoscaler likelihood attack fits class-conditional per-epoch, per-pool
Poisson rates from labeled whole profile sessions. It scores a clear-count
positive control with exact Poisson likelihood and DP instance transcripts
with a bootstrap particle filter over the exact finite capped-noise PMF. It
enforces disjoint profile/target sessions and gates DP scoring on positive
controls. A fresh 30-trial OS-CSPRNG run passed all seven plaintext controls;
the protected model scored between 0.525 and 0.717 balanced accuracy across
seven workload/task cells. Four unadjusted intervals exclude chance. All
1,680 particle likelihood scores were finite. See
[`AUTOSCALER_LIKELIHOOD.md`](AUTOSCALER_LIKELIHOOD.md); these synthetic
workload results are not a DP audit or privacy proof. The full research suite
passed 187 tests with four existing fixture skips.
Reanalysis from the retained CSPRNG observer and profile/target labels
reproduced the final attack report and prediction file byte for byte.

## 2026-10-25: bounded sampler review

Expanded the exact bounded-user hockey-stick regression across three
parameter sets, enumerating every nonnegative pool shift up to the cap and
both neighboring directions. All exact divergences stayed below the reported
per-release bounds. A source-level pass over the finite sampler and calibration
found no discrepancy in that path, but does not establish arbitrary-parameter
composition or cover timing, authenticated identity, CSPRNG implementation,
or a deployable transcript. The review did find that `Config.validate`
accepted Python booleans as numeric fields; added rejection and regression
coverage before parameter calibration. The full research suite passed 188
tests with four existing fixture skips.

The isolated ORAM timing replication was independently rechecked: all 1,440
retained observer/driver files match their hashes, schedules are paired across
plaintext, encrypt-only, and ORAM modes, deterministic analysis matches the
saved trial AUCs, and the nine focused replication/timing tests pass. The
confidence interval still supports only the specified two-address synthetic
workload and observer boundary.

A preregistered full-path load extension ran 30 fresh processes/profile at
128 offers/150 ms and 256 offers/25 ms. All 60 launches succeeded, source and
binary fingerprints stayed stable, trial accounting and 128 storage events
per completion validated, and archive-based reanalysis reproduced the
analysis byte for byte. See
[`RUNTIME_POPULATION_EXTENDED.md`](RUNTIME_POPULATION_EXTENDED.md). The full
86 MB local result is retained as a 5.8 MB raw-trial archive plus summaries
and a hash manifest; multi-host capacity and provider cost remain unmeasured.

## 2026-10-25: runtime signed registry over PIR

The live executor now creates and verifies a signed registry catalog at
startup, sends its bounded 160-byte records to both secure-PIR worker
processes, and checks each recovered row against the verified local pin before
module dispatch. Focused unit checks passed (8 tests), and the full server
pipeline integration suite passed (15 tests). An initial per-invocation
Ed25519 verification exceeded the 100 ms class deadline in this debug build;
private phase timings showed 11–38 ms in repeated signature checks while PIR
itself took 3–5 ms. Signature validation now occurs once at startup, followed
by the exact pinned-row comparison per invocation. The production deadline
was unchanged. The ephemeral signer, same-host PIR workers, synthetic module
location digests, and absent durable version anchor remain explicit limits;
see [REGISTRY_RUNTIME.md](REGISTRY_RUNTIME.md). The full workspace test suite
also passed (`cargo test --workspace -- --test-threads=1`, exit 0; the million-
operation ORAM stress test remains intentionally ignored), as did workspace
formatting, warning-denied Clippy, and `git diff --check`.

## 2026-10-25: persistent anchor adapter

Added `oblivion-anchor`, a SQLite-backed adapter for both checkpoint and
registry version CAS contracts. Checkpoint handles use HKDF-separated
ChaCha20-Poly1305 keys, bound associated data, OS-random nonces reserved
uniquely in the database, and encrypted persistence. Tests cover reopen,
stale and concurrent CAS, wrong keys, ciphertext tampering, and registry
namespace isolation, plus a deliberate database-copy rollback control
(9 passed), including schema-version rejection, real Path ORAM recovery and signed registry activation
through the persistent adapters. This adapter is not wired into the demo and
is not a remote anchor service; the database operator and separately supplied
master key are trusted, and restoring a previous database copy defeats
freshness. The post-adapter workspace suite passed with the million-operation
ORAM stress test intentionally ignored; warning-denied workspace Clippy and
formatting also pass. The full pinned Python research suite passed 188 tests
with 4 documented skips. See [ANCHOR_SERVICE.md](ANCHOR_SERVICE.md).

## 2026-10-25: research CI oracle follow-up

The signed registry increased each PIR answer from 128 to 160 bytes. CI found
an epoch-system evaluator still expecting the old 466-byte two-server
application-frame total; it now derives the expected total from the current
fixed registry and frame geometry (530 bytes). CI also found a test assuming
the particle filter could never report a non-finite class likelihood. Since
the documented Monte Carlo model deliberately reports zero-particle events as
`-inf`, the test now checks that every such score is represented as `null` and
included in the health counter. The full research test suite passed after both
changes (188 tests, 4 documented skips).

## 2026-10-25: indeterminate anchor commits

SQLite transaction commit errors now surface as explicit unknown outcomes,
because an I/O error does not prove whether state became durable. ORAM marks
the controller poisoned and requires restore before reuse; registry activation
returns a typed unknown-commit result so callers reload the anchored version.
Tests verify both fail-closed caller paths. The full workspace suite passed
after this change; the checkpoint recovery integration target now has 9 tests,
and the registry integration target has 5.

## 2026-10-25: anchor schema versioning

Anchor databases now initialize schema version 1 transactionally and reject
unknown SQLite schema versions without changing them. The anchor package has
9 tests. The full workspace suite passed after this change, with the
million-operation ORAM test intentionally ignored.

## 2026-10-25: WASM correctness-test budget

A full-suite run once hit the production 100 ms deadline in the five-module
WASM correctness test under host load; two isolated reruns passed. The test
now uses a 500 ms test-only budget to exercise module behavior, while the
dedicated deadline-interruption test continues to check enforcement. The full
workspace suite passed after this adjustment.

## 2026-10-25: local anchor service protocol

Added a separate `oblivion-anchor serve` process with protocol-v1 bounded
length-prefixed JSON over Unix-domain sockets, 0600/0660 access modes, a
restricted raw key-file input, and typed checkpoint/registry client adapters.
The adapters classify uncertain CAS transport outcomes as indeterminate.
Two in-process socket tests pass for registry/checkpoint round trips and
transport failure handling; two process-level tests check socket access,
persistent CAS and key-file permissions. The 11 anchor unit tests, CLI help,
and warning-denied anchor Clippy pass. The post-service full workspace suite
also passed, with the million-operation ORAM stress test intentionally ignored.
Remote authenticated transport, host-root isolation, whole-database rollback
resistance, and demo integration remain open.

## 2026-10-25: anchor database file permissions

The Unix service now rejects database symlinks and special files, verifies the
opened path remains a regular file, and restricts its mode to `0600` before
binding the socket. The database parent directory remains a trusted deployment
boundary to prevent path replacement. Process tests verify mode enforcement
and specific symlink rejection. A process-level integration test now writes a
real Path ORAM checkpoint through the Unix service, restarts the service, and
restores the snapshot from the persisted SQLite anchor. Anchor package tests,
formatting, whitespace checks, and warning-denied workspace Clippy pass. The
full workspace suite passed immediately before this integration-test-only
follow-up; the million-operation ORAM stress test remains intentionally ignored
in the default suite.

## 2026-10-25: million-operation ORAM stress run

Ran the ignored ORAM oracle in release mode after the anchor follow-ups:
`cargo test -p oblivion-store --release --test oracle million_operation_oracle
-- --ignored --exact --test-threads=1`. The one-million-operation HashMap
oracle test passed in 41.87 seconds; it remains excluded from the fast default
suite and is independently runnable with that command.

## 2026-10-25: anchor master-key file opening

The CLI now opens the key path with `O_NOFOLLOW | O_NONBLOCK`, validates
permissions and regular-file type on the opened descriptor, and reads at most
33 bytes to enforce the exact 32-byte key size. This closes the metadata/read
symlink-swap window and avoids blocking on a FIFO. Process tests cover symlink,
permission and 0/31/33-byte files. Anchor package tests, formatting, whitespace
checks, and warning-denied workspace Clippy pass; CI is pending after push.

## 2026-10-25: preregistered fresh ORAM signal replication

Committed the configuration and preregistration before collection. The new
eight-address workload uses a 35% hot-address class and 70% reads, paired
across plaintext, encrypt-only and ORAM controls. The predeclared per-access
AUC primary metric gave 1.000 for each positive control and 0.5015
([0.4935, 0.5095]) for ORAM across 30 whole-session trials. Post-run audit
verified all 1,440 raw-file hashes and all 240 paired schedules. Targeted
harness tests passed before collection. The separate service process measured
bucket-handler time, but host load was present and affinity was not pinned;
the study is limited to this workload and classifier, with no security or
quiet-host claim. See the preregistration, result report and retained raw data.

The same retained workload was then analyzed with the existing frequency-only
tag scorer as a post-hoc secondary attack. Plaintext/encrypt-only controls
scored AUC 1.000; ORAM scored 0.5017 ([0.4931, 0.5101]), balanced accuracy
0.5002 and raw accuracy 0.6031 versus the 0.6424 majority baseline. It reuses
the primary study's 30 trials and is not an additional independent repetition.
All 1,440 input hashes in the derived report were independently rechecked.

## 2026-10-25: preregistered Markov-locality ORAM study

Added a seeded first-order Markov address generator to the isolated ORAM and
direct-address control runners. Its test checks persistence endpoints,
resampling distribution and invalid inputs. Clippy, example tests, focused
Python harness tests, formatting, and release builds passed. After committing
the workload implementation, the preregistered 30-trial experiment passed both
positive controls (mean AUC 1.000) and measured ORAM AUC 0.5105 (95% trial
bootstrap interval 0.4838–0.5389), balanced accuracy 0.5105, and raw accuracy
below the profile-majority baseline. An independent audit verified the 1,440
raw hashes, 240 paired schedules, per-session operation counts, and workload
range; the measured adjacent-repeat rate was 0.8807 against 0.8810 expected.
The host was CPU-contended and unpinned. This is bounded empirical evidence,
not a proof or remote timing result. See the preregistration, results, and
retained data.
