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
stress test intentionally ignored), and warning-free Clippy. Later work added a
local anchor service and optional durable invocation response/checkpoint
transaction. A hardware anti-rollback source and arbitrary external-side-effect
transactions remain unimplemented. At the time of this historical entry,
remote authenticated transport was also unimplemented. A later 2026-10-28
increment adds an independent mTLS witness for standalone SSE journal heads;
the same transport now also supports standalone digest-bound registry catalog
activation. The runtime worker's remote catalog configuration was added in the
2026-10-29 increment below. At this historical point, remote checkpoint and invocation-receipt anchors had not yet been implemented; the later standalone checkpoint adapter is recorded below.

The `oblivion-registry` crate implements fixed-size Ed25519-signed records, a
signed catalog digest, bounded exact parsing, per-record strict verification,
and monotonic activation through a caller-provided version-anchor CAS. Its
tampering, omission, reorder, duplicate, key, version, rollback and CAS-conflict
tests pass. The runtime now builds and verifies a signed catalog in the trusted
executor and supplies its 160-byte rows to both secure-PIR workers over bounded
inherited-pipe framing. Recovered rows must match the verified local pin.
Workers can now load a publisher-signed catalog and pinned public key from
bounded files before readiness; the offline publisher example creates the
embedded-module catalog. The built-in fallback signer remains ephemeral and
does not establish external publisher identity. When
`OBLIVION_REGISTRY_ANCHOR_SOCKET` is configured alongside those files, the
worker activates the verified version and catalog digest in the local SQLite
anchor before readiness. This rejects lower versions and same-version content
changes, while exact restarts remain valid. Restoring an older anchor database
or allowing host root to replace it defeats freshness; there is no hardware
anti-rollback source. Remote publication and partial-catalog inclusion proofs
remain open.

Updated 2026-10-26. The selected pipeline and later bounded research artifacts have evidence in [the requirements matrix](REQUIREMENTS_MATRIX.md) and [completion audit](COMPLETION_AUDIT.md). The selected artifacts and earlier passing gates are recorded. PR #1 is the review artifact; no production-security or merge claim follows. TrustedExecutor is simulated by ordinary processes, without a hardware TEE or attestation.

## Implemented system

Seven Rust crates implement encrypted Path ORAM, two-server XOR PIR, Wasmtime execution, authenticated epoch batching, process orchestration, trace generation and constrained GGM SSE. The current process path supports one to four clients, all five actual functions, disjoint user/dummy state, SSE metadata discovery, encrypted PIR, independent output/counter oracles and fixed 228-byte v2 invocation/response envelopes with signed request identities.

Protected execution reads eight blocks at the public 25 ms phase and commits eight at 50 ms. Guest failures discard staged mutations; uncertain backend failure can poison partially written state. At eight logical blocks an invocation emits 128 actual bucket events of 316 bytes, with O(M log N) bandwidth for public working-set M. Trusted drivers prepare encrypted responses/private instrumentation before the 100 ms publication wait. Clients prepare requests before their public epoch. Slot starts are epoch arrival plus slot × 100 ms. OS scheduling and work overruns remain visible.

The current response reader timestamps completion immediately after `read_exact`, before channel handoff and later client decryption/oracle/logging. Public pipe timing and separate private client latency are not interchangeable. The default process demo remains ephemeral. Opt-in durable invocation receipts/checkpoints use the local anchor service. Persistent SSE journal recovery and runtime signed-catalog activation can use the separate mTLS witness. A standalone remote Path ORAM checkpoint adapter is also available. The 2026-10-29 runtime extension now supports local or remote mTLS for durable invocation checkpoints and receipts; remote mode sends the checkpoint secret handle to the witness and provides no distributed lease or host failover. The local anchor does not resist privileged SQLite rollback; remote freshness depends on the witness retaining its current database, and the checkpoint witness also receives snapshot decryption keys.

The built-in demo's real/dummy/function schedule is public given its code, real percentage and epoch. It validates correctness/topology, not anonymity against an adversary who knows that schedule. Research datasets keep workload labels/seeds outside each declared attack input; public cadence, classes, batch size and geometry remain known. Encryption cannot hide an identity already determined by auxiliary knowledge.

## Accepted bounded measurements

| Evidence | What actually ran | Result and boundary |
| --- | --- | --- |
| [Joint A–G/ablations](SYSTEM_EXPERIMENTS.md) | 30 fitted-model trials; 1,920 observations/mode on actual libraries | Final G balanced accuracy 33.40% [32.29,34.51], chance 33.33%. Declared summary-feature attacker, not every host observation |
| [Execution/errors](EXECUTION_EVALUATION.md) | Five functions plus three failures, 30 trials, visible-selector control first | Protected eight-class accuracy 11.67% [9.38,13.75], chance 12.5%; 960 protected output/status checks, fixed frames/storage shapes; saved earlier binary |
| [Actual trace validation](TRACE_VALIDATION.md) | 100k ORAM accesses/workload and 30 scoped encrypted PIR captures | 1.4M bucket events/workload; 3,000 verified PIR retrievals, 6,000 streams, 61,363 packets and zero reported drops. Unvalidated packet classifier excluded |
| [ORAM leaf+timing](ORAM_LEAF_TIMING.md) | Independent profile/target sessions and 30 fitted trials | Balanced accuracy 50.70% [49.80,51.62]; AUC 0.511 [0.501,0.521] is a possible weak signal, retained with unadjusted/multiple-metric caveats |
| [32-address Zipf ORAM timing](ORAM_ZIPF32_REPLICATION_20261026.md) | 30 trials × eight sessions × 256 operations; fixed temporal classifier | Controls AUC 1.000; ORAM 0.5003 [0.4929, 0.5073]. 1,440 raw hashes and 240 paired schedules checked; collection-time host load missing |
| [Monitored Zipf-32 repeat](ORAM_ZIPF32_MONITORED_REPLICATION_20261026.md) | Fresh seed, same frozen workload/attack; mode-boundary host snapshots | Controls AUC 1.000; ORAM 0.5052 [0.4995, 0.5109]. Collector hash-map omission corrected and original report retained |
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
| [Full-path CPU sensitivity](COST_SENSITIVITY.md) | 60 retained process trials; ratio-of-sums CPU normalization and whole-trial bootstrap | 9.758 CPU seconds/1,000 successes at steady load, 7.237 under overload; overload drops 74.22% and has 99.22% SLO failure. No provider rates supplied |
| [Integrated epochs](EPOCH_SYSTEM_EVALUATION.md) | Final reader-thread pipe campaign: 360 process trees / 2,160 verified calls | 12 cells × 30; strict public/private separation, 1,080 real/1,080 dummy successes, 2,955 artifact hashes; scoped provenance differences below |
| [Joint batching load](BATCH_LOAD_EVALUATION.md) | 720 independent processes; 30 fitted models/mode, 180 held-out targets/mode | Actual plaintext control 100%; AEAD protected 28.33% [22.78,33.89] against 33.33%. Same 22 public features/metric; two failed forest controls retained |
| [Repeated faults](FAULT_CAMPAIGN.md) | Seven assertion-bearing fixtures × 30, 210 launches | All assertions pass for stated scenarios. Original ENOSPC/truncated-publication attempt remains excluded/incomplete, not silently overwritten |
| [Autoscaler](AUTOSCALER.md), [bounded discrete-geometric mechanism and attack studies](AUTOSCALER_DP.md) | Five-policy baseline campaigns, event-level 30-trial CSPRNG runs, and a 30-trial bounded-user cap-2 run with separate whole-session attack evaluation; all naive controls pass | Conditional `(epsilon, delta)` claims for fixed-horizon count/event observers under independent hidden bits. Existing campaigns remain unauthenticated. The low-level API and runner now support optional HMAC or Ed25519 request verification; the synthetic Ed25519 runner still holds client signer and verifier in one process. Sampler timing, repeated sessions and full runtime are excluded. One event-level burst-hot interval is marginally above chance; all cap-2 protected intervals include chance. Cost is simulator-only |

| [Attack API](ATTACK_INTERFACE.md) | 13 registered adapters with common PredictionResult and strict schemas | Uncalibrated confidence remains absent. Adapter availability is not extra experimental evidence |
| [Actual demo](DEMO.md) | Three-client mixed SSE/PIR/WASM/ORAM run | 24 calls, 12 real, all five functions, 24 metadata queries and 3,072 storage events; MP4/terminalcast/raw records. Public deterministic schedule, not privacy evidence |

## 2026-10-26: per-user autoscaler identity limitation

Added an adversarial characterization test for the user-level contribution cap.
With cap 2, eight requests under one caller-declared ID count as two, but the
same requests under eight caller-chosen IDs count as eight. Added an opt-in
`RequestAuthenticator` using per-principal 256-bit HMAC-SHA256 keys; authenticated
mode binds user ID, function, and timestamp and rejects tampering before
clipping. Tests cover valid synthetic/imported requests, identity/time tampering,
malformed MACs, missing verifier, cap application, and the batch runner's
initial explicit refusal when key provisioning was absent. Existing empirical
runs remain unauthenticated. This API does not provide a
production identity service or protect against compromise of the verifier/key
registry. Replay requests are not deduplicated; they remain charged to the same
capped identity. A subsequent HMAC runner integration and Ed25519 verifier
option are recorded in the 2026-10-26 entries below. See
[the autoscaler DP notes](AUTOSCALER_DP.md).

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

Selected implementation/evaluation and the serial local/hosted source gates are accepted within their bounded scope. [PR #1](https://github.com/dumbly-smart/Oblivion/pull/1) is ready for delivery on `codex/oblivion-research-platform`; no main merge is claimed. A bounded-user autoscaler simulator now supports optional HMAC-authenticated request identities from an external local key registry; this does not add production identity binding, cross-session composition, production DP integration, or an external sampler/code audit. Expanded finite exact-rational checks and the source-review findings are recorded in [SAMPLER_AUDIT.md](SAMPLER_AUDIT.md). Hardware isolation, rollback-resistant/backward-private SSE, recursive/native Circuit storage, DPF/native single-server runtime selection and durable application side effects remain deployment/research extensions. Human P1–P12 study and mutable bibliography/course listings are context, not machine-proof software gates.

## 2026-10-29: runtime mTLS registry catalog configuration

Worker startup now accepts either the existing local registry-anchor socket or
the complete six-setting mTLS witness configuration. The two modes are
mutually exclusive. Remote configuration requires the external signed
manifest and pinned publisher key; partial settings, invalid numeric address,
TLS/configuration errors, witness unavailability, rollback/equivocation, or an
indeterminate CAS fail startup before readiness. There is no local fallback.
The real worker integration test uses generated CA/server/client certificates,
an actual mTLS witness and SQLite state. It covers partial configuration,
catalog activation, rollback rejection, version advancement, and witness state.
The focused integration test first failed against the unimplemented setting
path, then passed after the worker wiring. On source commit `1befc5c2`, the
serial workspace suite initially hit a `Timeout` in the system ablation test
under host scheduling load. The retained private trace showed 80.7 ms of total
work and a 55.4 ms storage span against the existing 50 ms commit boundary.
The isolated target reproduced once without affinity, then passed pinned to a
quiet CPU. The complete pinned run
`taskset -c 21 cargo test --locked --workspace -- --test-threads=1` exited 0;
all enabled tests passed, including the 100,000-operation SSE oracle, and the
million-operation ORAM stress test remained intentionally ignored. This is
consistent with the already documented scheduler sensitivity; no runtime
deadline or test oracle was weakened.

`taskset -c 21 cargo clippy --locked --workspace --all-targets -- -D warnings`,
`cargo fmt --all --check`, and `git diff --check` passed. A local validator
resolved 309 relative Markdown links in the 12 changed Markdown files. Hosted
run [40758604155](https://github.com/dumbly-smart/Oblivion/actions/runs/40758604155)
passed all three jobs for this exact source commit: Rust format/Clippy/tests,
the million-operation ORAM stress oracle, and the research analysis checks.

The remote witness remains one trusted operator and database and can be rolled back or made unavailable. A versioned SHA-256 DER leaf-certificate-to-exact-slot policy now limits which slots each mTLS client may address; policy changes require restart. Per-slot quotas and rate limits remain unimplemented. The selected function remains visible to the trusted executor. The runtime now supports remote mTLS invocation anchoring. Host-independent writer fencing, witness replication and rollback resistance, and a TEE remain unfinished.

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

The same traces were then scored by a post-hoc one-step profile transition
lookup. Plaintext and encrypt-only controls scored AUC 0.9216
([0.9162, 0.9271]); ORAM scored 0.4967 ([0.4891, 0.5043]) over the same 30
trials, with raw accuracy below the profile-majority baseline. The controls
passed before ORAM was scored. All 1,440 raw input hashes and four source/config
hashes were rechecked. Since this attack was selected after the primary result
and reuses those sessions, it is exploratory rather than an independent
replication. See the transition-attack report and retained predictions.

## 2026-10-25: signed durable invocation receipts

`oblivion-anchor` now verifies a client Ed25519 signature over a
domain-separated 16-byte invocation ID and 32-byte request digest. It derives
an HMAC lookup token and stores the request digest, snapshot/generation, and
response bytes in an AEAD-protected receipt. SQLite schema v1 migrates to v2.
`commit_invocation` atomically compare-and-swaps the checkpoint and inserts the
receipt; repeated same-ID/same-digest commits return the original receipt, and
same-ID/different-digest requests conflict. The local Unix protocol and client
adapter expose receipt lookup and commit; ambiguous transport outcomes map to
`CommitIndeterminate` so callers can look up the receipt.

Tests cover invalid signatures, independent client namespaces, replay after
database reopen, response confidentiality at rest, stale checkpoint and
request-digest conflicts, response size bounds, migration, and injected SQL
failures on each insert to prove transaction rollback. The anchor package has
15 library tests and 6 process-level service tests; formatting, warning-denied
Clippy, and package tests pass. Runtime pipeline integration is not complete:
the executor must recompute the digest against its canonical authenticated
request and perform lookup before execution and commit after checkpoint
creation. Concurrent duplicate execution remains unfenced; arbitrary external
side effects, host-root inspection, and SQLite backup rollback remain
unprotected. See [the contract](INVOCATION_DURABILITY.md).

## 2026-10-26: fixed invocation envelope v2 foundation

The authenticated client/executor envelope now uses wire version 2 with a
fixed 192-byte encrypted payload (228 bytes total). Existing invocation fields
retain their offsets; 123 trailing payload bytes are currently opaque padding,
reserved for the signed idempotency identity. The worker does not yet validate
or use those bytes, so this change alone does not provide durable invocation
semantics. The protocol document says this explicitly.

Rust batcher tests verify v2 framing and replay behavior, and server/harness
size assertions now use the exported envelope size. Research validators accept
the retained v1 164-byte traces as well as v2 228-byte traces; attack feature
normalization and presence byte accounting use the observed public frame size.
Tests cover generated v2 batch-load and presence traces. The affected batcher,
analysis, presence, and execution-timing tests pass. A serialized full-workspace
run and repeated server-suite runs encountered deadline-sensitive invocation
timeouts on a host with load averages above 12. The individual SSE discovery
and harness ablation tests and a manual default demo passed on separate runs,
but the default-demo integration test also timed out on an isolated rerun.
Retained private rows show `Status::Timeout` before the 100 ms outer deadline,
consistent with the executor's earlier staging/commit cutoff; no protocol
parse/authentication failure was recorded. These are runtime scheduling
outcomes, not evidence of a wire-format failure, and no timeout threshold was
changed. Signed payload verification and opt-in checkpoint/receipt handling
were integrated in follow-on changes below; that earlier validation attempt
did not cover these later changes.

## 2026-10-26: signed invocation request binding

The v2 payload suffix now carries a 16-byte invocation ID, client Ed25519
public key and signature, followed by 11 canonical zero bytes. The signature
binds the domain-separated digest of the real/dummy flag, registry index,
fixed-size input and authenticated endpoint slot. The executor validates this
after channel AEAD authentication; absent, forged, wrong-slot or noncanonical
identities take the existing fixed-shape cover path. Demo and open-loop clients
use OS-random ephemeral signing keys and IDs. This is identity proof for one
request, not authorization or a built-in stable client identity. The later
durable worker integration below provides signed receipt replay when an
application retains its client key and invocation ID across sessions.

The two codec tests and the unsigned-request integration test pass. The full
server pipeline suite ran 16 tests: 15 passed; its real/dummy demo hit the
existing 100 ms execution cutoff (`work_ns` 104.36 ms) under host load. An
isolated rerun completed epoch 0 but timed out a later dummy at 81 ms of
reported work during the earlier staging cutoff. No deadline was changed.
Formatting and warning-denied package Clippy pass. Timing-sensitive demo
reliability remains open and is not attributed to identity verification alone.

## 2026-10-26: durable worker receipts and restart recovery

When both `OBLIVION_ANCHOR_SOCKET` and `OBLIVION_ANCHOR_STATE_DIR` are set,
the worker loads the latest anchor record, validates its snapshot identifier,
generation and regular-file status, and restores the encrypted full-store
checkpoint. New authenticated signed requests are executed, then their exact
192-byte response and a fresh encrypted snapshot handle are committed in one
anchor transaction before response publication. An indeterminate commit is
resolved by looking up the signed receipt; unresolved results fail closed. A
same-ID/different-digest request is rejected before real execution. A matching
receipt runs the reserved dummy function and returns the prior response.

The runtime integration test starts the real Unix anchor service, commits a
stateful invocation, restarts the executor with a fresh in-memory bucket
backend, verifies byte-identical receipt replay, rejects an ID/digest conflict,
and confirms the next invocation sees the recovered application state. The
focused test passes. In the full 18-test server pipeline run, 16 passed and
two pre-existing 100 ms deadline-sensitive demos timed out under host load;
the durable integration test itself passed in that run. Deadlines were not
changed. The separately run anchor and ORAM recovery packages passed 15 and 9
tests, respectively, before this runtime integration; rerun the full relevant
quality gates after final documentation changes.

The implementation is opt-in and retains the simulator's instrumented
in-memory bucket backend, reconstructing it from an encrypted full-tree
snapshot. New requests visibly add full-tree snapshot reads/writes; receipt
hits skip that checkpoint work, and the anchor operator sees lookup/commit
traffic. Snapshots currently accumulate without bound. Built-in clients still
generate ephemeral signing keys and IDs, so cross-process retry requires an
application to persist these values. Same-ID concurrency is not fenced,
external effects are not transactional, SQLite rollback remains possible,
and host root can inspect state.

Before external-registry provisioning, a serialized workspace run completed successfully with
`cargo test --locked --workspace -- --test-threads=1`. All test binaries
passed, including all 18 server pipeline tests and the 100,000-operation SSE
oracle test (160.70 seconds). The million-operation ORAM oracle remains
intentionally ignored in the default suite and is independently runnable in
release mode as recorded above. Earlier parallel/host-loaded runs did hit
deadline-sensitive demos; this successful serial run changes no production or
test deadlines and does not erase those historical failures.

## 2026-10-26: anchored checkpoint restore bootstrap

The executor now rejects partial `OBLIVION_ANCHOR_SOCKET` /
`OBLIVION_ANCHOR_STATE_DIR` configuration before announcing readiness. With
both configured it loads the anchor's current checkpoint, checks the bounded
snapshot ID and matching generation, rejects symlink/non-file snapshots, and
restores the authenticated whole-store checkpoint. Without anchor settings it
retains the ephemeral-memory path. Restore uses `MemoryBackend` to preserve the
existing per-bucket trace instrumentation; the checkpoint itself is the
durable encrypted snapshot, not a live bucket-file service. Receipt lookup,
per-invocation checkpoint commit, and restart/replay are integrated and covered
by the server pipeline test.

The partial-configuration regression test, full serialized workspace suite,
formatting, warning-denied workspace Clippy, and whitespace checks pass.
Snapshot retention, same-ID concurrency fencing, external-side-effect
transactions, and rollback resistance against an anchor database backup remain
open limitations.

## 2026-10-26: external publisher-signed registry provisioning

`OBLIVION_REGISTRY_MANIFEST` and `OBLIVION_REGISTRY_PUBLIC_KEY` are now a
paired worker configuration. The executor bounds both files, verifies the
Ed25519 catalog signature, requires exactly five ordered records, and checks
each module digest, embedded-location digest, and resource class before it
starts PIR workers or announces readiness. The selected records remain pinned
byte-for-byte for every recovered PIR response. A wrong key, partial
configuration, 33-byte public key, and oversized manifest all failed before
readiness in a process test; a valid external catalog reached readiness.

The offline `publish-registry` example creates this versioned catalog and its
raw 32-byte public key from a separately provisioned seed. It rejects seed
files with group/other access on Unix. With neither runtime environment value,
the development demo retains its ephemeral signer. This optional mode does
not authenticate the public-key-to-publisher binding or anchor catalog-version
freshness.

The signed-catalog unit test, publisher-example test, process test, formatting,
whitespace checks, and warning-denied server Clippy passed. The first two
serialized full-workspace attempts stopped at deadline failures in the server
pipeline, executor storage-schedule test, and harness ablation test; each
affected case passed in isolation. A third serialized run completed the full
workspace successfully, including all 19 server pipeline tests and the
100,000-operation SSE oracle (145.92 seconds). The million-operation ORAM
oracle remains intentionally ignored in this default run. No timing budget was
changed.

## 2026-10-26: worker catalog rollback anchor

The worker accepts `OBLIVION_REGISTRY_ANCHOR_SOCKET` only alongside an
external signed catalog and pinned key. It verifies the manifest and exact
embedded-module records, then activates the catalog version and digest in the
`runtime-functions` SQLite anchor before starting PIR workers or announcing
readiness. Process coverage verifies initial activation, exact-version restart,
rollback rejection without readiness or anchor mutation, and a subsequent
higher-version activation. Freshness is conditional on the anchor database
remaining current and trusted; an old database backup or host-root replacement
can roll back the floor.

The new process test passed. Two serialized full-workspace attempts stopped in
server timing tests: one harness mode-G timeout, then four pipeline invocations
that exceeded their fixed execution classes under this host. All five affected
tests passed on isolated reruns. The server pipeline group had 16/20 pass in
the second run; its four failures were the fixed-budget invocations. The
remaining workspace suite passed with the 100,000-operation SSE oracle
(176.14 seconds); the million-operation ORAM oracle remains intentionally
ignored. Server unit tests and publisher example passed, warning-denied
workspace Clippy passed, and formatting/whitespace checks passed. The full
workspace command is not green on this host because repeated grouped server
runs encounter the existing fixed-deadline sensitivity; no timing budget was
changed.

## 2026-10-26: independent ORAM Markov workload replication

Added and pushed the preregistered workload/configuration before collection.
The new eight-address Markov workload used two hot addresses, 80% address
retention, 60% reads and seed `20261027`, with the fixed temporal random-forest
attacker and isolated bucket-handler timer. Both leaky positive controls scored
AUC 1.000. Path ORAM scored AUC 0.5021 [0.4803, 0.5242] across 30 trials; the
interval includes chance and does not establish privacy. Observed address
retention was 82.39% over 30,720 accesses.

The run retained raw traces, predictions, report and figure. Independent
post-run checks verified five source/binary hashes, 1,440 raw-trace hashes and
240 paired schedules. Harness tests passed before collection. The shared host
had load averages 3.78/4.68/6.00 before and 7.71/6.30/6.46 after collection;
no repository job ran concurrently, but host scheduling noise limits the
result. See [the preregistration](ORAM_SIGNAL_REPLICATION_20261026_B_PREREG.md)
and [the results](ORAM_SIGNAL_REPLICATION_20261026_B.md).

## 2026-10-26: durable worker single-writer lock

The local `UnixAnchorClient::invocation` adapter now holds a per-slot
nonblocking OS file lock for its lifetime. Durable worker startup acquires it
before reading the checkpoint or announcing readiness, so a second
cooperating worker for the same local slot fails closed. The kernel releases
the lock at process exit. The persistent 0600 lock file is adjacent to the
anchor socket and opened with no-follow/close-on-exec flags. Its parent
directory must be writable by the executor account and trusted against
replacement. This is a cooperative same-host client-API guarantee; raw
protocol/database callers, separate hosts and host root can bypass it.

Test-driven verification first reproduced the missing exclusion, then passed
cross-process contention, independent-slot, release, 0600 permission and
symlink-rejection checks. The worker readiness regression and durable restart,
receipt replay and state recovery tests passed. Anchor tests passed (19 unit,
9 process); warning-denied workspace Clippy, formatting and whitespace checks
passed. This does not make arbitrary external side effects transactional or
provide remote or cross-host writer fencing.

## 2026-10-26: bounded durable snapshot retention

Durable startup now prunes obsolete `*.snapshot` files after restoring the
anchor-current snapshot and before readiness. After each successful atomic
checkpoint/receipt commit, the worker retains only the snapshot referenced by
the anchor and syncs the snapshot directory after deletion. A crash between
anchor commit and cleanup can leave extra encrypted snapshots until the next
restart. Cleanup failures fail startup or suppress response publication after
commit, allowing the client to recover the committed response by retrying.

The durable worker restart test injects an orphan snapshot, then verifies
startup cleanup and one retained anchored snapshot after a later commit. The
test passed along with anchor lock tests, warning-denied workspace Clippy,
formatting and whitespace checks. Snapshot pruning does not reduce the
visible full-tree checkpoint I/O or make external side effects transactional.

## 2026-10-26: pinned-service ORAM timing replication

The isolated ORAM measurement harness now optionally pins only its service
child on Linux via `taskset`, records the child's effective CPU set from
`/proc`, and leaves the workload driver's affinity unchanged. Both positive
controls passed in the frozen fresh-seed study. Across 30 trials, plaintext
and encrypt-only controls scored AUC 1.000; Path ORAM scored 0.4937
[0.4756, 0.5130], an interval containing chance. All 90 retained
final-session metadata records reported CPU 0; `taskset -c 0` was configured
for all 720 service-child sessions, but individual PIDs and masks were not
retained. The study is not paired against earlier unpinned collections
and does not isolate CPU 0 from host activity.

The 1,440 raw trace hashes, 90 predictions, 240 paired schedules, five
source/binary hashes and 90 retained final-session affinity records were
independently rechecked. The archive, plot, verification and host observation are retained.
The focused 10 Python harness tests passed; both ORAM example suites passed
(7 tests each), warning-denied package Clippy, formatting, diff checks and a
CPU-affinity smoke invocation passed. The experiment remains empirical and
workload-specific; it establishes no general ORAM timing guarantee.

The latest benchmark-instrumentation change stores one `isolated-service.json`
record per service-child session instead of overwriting metadata after each
session. Linux allowed-CPU masks are read for every child, and a requested CPU
affinity mismatch fails that run. Focused ORAM timing tests, both example test
suites, warning-denied package Clippy, and a two-session pinned smoke check
passed. Older raw campaigns retain only their previously recorded final-
session metadata; their archived limitations are not retroactively removed.

## 2026-10-26: paired ORAM service-affinity crossover

A new preregistered 30-trial crossover paired identical per-session workloads
under pinned CPU 0 and unpinned service conditions, with 15 pinned-first and
15 unpinned-first trials. All four plaintext/encrypt-only control groups
scored AUC 1.000. ORAM AUC was 0.5120 [0.4909, 0.5322] pinned and 0.4948
[0.4739, 0.5167] unpinned. The paired primary difference was +0.0172
[-0.0162, +0.0497], including zero; it does not show a reliable affinity
effect for this classifier/workload.

All 2,880 trace hashes and 240 six-stream paired schedule sets were
recomputed. Collection completed before a report-assembly `NameError`; the
report was regenerated from preserved traces without recollecting. The raw
archive, paired predictions, condition order, hashes and result figure are
retained. Individual service PIDs/affinity masks were not retained; the final
session mask was checked per pinned collector invocation. Host isolation,
other classifiers, and other workloads remain open.

## 2026-10-26: preregistered 32-address Zipf ORAM timing replication

After the configuration and protocol were committed, the fresh 32-address
Zipf run used 30 trials, eight sessions/trial, 256 measured operations/session,
and a 35% read mix. Plaintext and encrypt-only controls both scored AUC 1.000;
Path ORAM's primary mean per-trial AUC was 0.5003 [0.4929, 0.5073]. Its
balanced accuracy was 0.5028 [0.4972, 0.5085], below the profile-majority raw
accuracy of 0.5880. These data do not resolve the declared hot/cold signal for
this classifier and workload and do not establish indistinguishability.

The 1,440 raw session hashes, all 240 paired schedules, source/config/binary
hashes, 720 child process records, and all saved prediction metrics were
verified. Ten focused harness tests passed. The report's host CPU description
was empty and collection-time instantaneous load was not captured; the
post-run host snapshot cannot repair this preregistration deviation. The result
must therefore not be described as a quiet-host replication. See the
[preregistration](ORAM_ZIPF32_REPLICATION_PREREG_20261026.md) and
[result record](ORAM_ZIPF32_REPLICATION_20261026.md).

## 2026-10-26: future ORAM collection host context

The isolated replication collector now writes UTC-timestamped host snapshots
at run start and before/after each mode. Snapshots include platform, CPU model
(with a Linux `/proc/cpuinfo` fallback), logical CPU count, the runner's
allowed CPU set, and 1/5/15-minute load averages where available. The snapshot
file is flushed around mode capture, including capture failures. Positive-
control failure reports now also retain source/raw hashes and process context
instead of returning an unhashed partial report. The focused replication
suite passes, the complete Python research suite passed 203 tests with four
existing fixture skips, and a real one-session ORAM child-process smoke
produced before/after snapshots and compressed traces. The already-published
Zipf result predates this fix and retains its documented collection-time host
observation gap.

## 2026-10-26: full-path CPU cost sensitivity

Added a reproducible analysis over the retained 30-trial steady and overloaded
full-path profiles. It validates the source artifact manifest, normalizes CPU
by both successful outputs and offered requests as ratios of sums, and uses
5,000 whole-process bootstrap resamples. Steady load measured 9.758 CPU seconds
per 1,000 successes [9.458, 10.086], with no offered-load SLO failures. The
overload profile measured 7.237 CPU seconds per 1,000 successes [6.965, 7.500]
after dropping 74.22% of offers, while its offered-load SLO failure fraction
was 99.22%. The lower success-normalized CPU under overload therefore reflects
drops, not better useful capacity. Sampled aggregate RSS was about 25.64 MiB;
it is neither peak nor billable memory.

No price scenario was supplied, and the report contains no dollar estimate.
The calculation excludes network, storage, idle capacity, autoscaler
instance-seconds, startup/teardown CPU, and provider-specific accounting.
Zero-success bootstrap draws are counted explicitly; the corrected report had
5,000 defined draws and zero undefined draws for both profiles. Reproduction,
result hashes and limits are recorded in [`COST_SENSITIVITY.md`](COST_SENSITIVITY.md).
Remote/multi-host capacity and provider-calibrated costs remain unmeasured.

## 2026-10-26: monitored Zipf-32 timing replication

A preregistered fresh-seed repeat of the 32-address Zipf workload retained
mode-boundary host snapshots. Both leaky controls scored AUC 1.000; Path ORAM
scored 0.5052 [0.4995, 0.5109]. This separate interval includes chance and is
not pooled with the first Zipf run. The machine had 24 allowed logical CPUs
for the process and reported an Intel Core i7-14650HX model. Load averages
were sampled around each mode but not continuously.

The initial report omitted ORAM from its raw-hash map because the collector
hashed after controls but before ORAM capture. The initial report is preserved;
the corrected report and separate 1,440-entry raw SHA-256 manifest were
created after collection without changing raw traces or predictions. An
independent check confirmed all hashes, paired schedules, source/binary
hashes, session splits, process metadata, and saved prediction metrics. The
focused replication suite passes and the full research suite passed 203 tests
with four existing skips. See the
[preregistration](ORAM_ZIPF32_MONITORED_PREREG_20261026.md) and
[result](ORAM_ZIPF32_MONITORED_REPLICATION_20261026.md).

## 2026-10-26: preregistered uniform-32 ORAM timing replication

A fresh-seed uniform workload used 32 logical addresses with a balanced
public hot/cold partition, 35% reads, and 30 whole-session trials. Both
plaintext and encrypt-only controls scored AUC 1.000. The frozen temporal
classifier scored Path ORAM AUC 0.5018 [0.4965, 0.5078], with balanced
accuracy 0.5010 and profile-majority accuracy 0.5007. The interval includes
chance; this is a bounded non-detection result, not an indistinguishability or
security proof.

The collection captured coarse host snapshots around each mode. Independent
post-collection checks verified all 1,440 raw hashes, 240 paired schedules,
90 saved predictions and their recomputed metrics, plus source/config/binary
fingerprints. Classifier fitting was not independently reimplemented. The
12 focused ORAM replication/timing tests passed before collection. See the
[preregistration](ORAM_UNIFORM32_REPLICATION_PREREG_20261026.md) and
[result record](ORAM_UNIFORM32_REPLICATION_20261026.md). Other workload and
attack families, quiet-host replication, and remote timing remain open.

## 2026-10-26: preregistered higher-skew Zipf-32 ORAM timing replication

A fresh 32-address Zipf workload with exponent 1.5 and top-four probability
mass 0.7389 passed both positive controls (AUC approximately 1.000). Path
ORAM scored 0.4997 [0.4913, 0.5073] over 30 whole-session trials; the interval
includes chance, and raw accuracy is below the 0.7380 profile-majority
baseline. All 1,440 raw hashes, 240 paired schedules, 90 prediction files and
their saved metrics were independently verified. This is a bounded local
synthetic result, not a security proof. See the
[preregistration](ORAM_ZIPF32_ALPHA15_REPLICATION_PREREG_20261026.md) and
[result](ORAM_ZIPF32_ALPHA15_REPLICATION_20261026.md). Focused ORAM harness
tests passed (12 tests).

## 2026-10-26: preregistered independent ORAM transition-attack replication

A fresh-seed Markov-locality collection (address-retention probability 0.85)
was evaluated with the predeclared one-step previous-visible-tag attack.
Plaintext and encrypt-only controls passed at AUC 0.9198 [0.9144, 0.9253];
Path ORAM scored 0.5013 [0.4916, 0.5106]. Raw accuracy was below the
profile-majority baseline. All 1,440 raw hashes, 240 paired schedules, source
fingerprints, and 90 transition prediction metrics were checked. The attack
is a simple profile lookup, and the transition analysis shares collection
sessions with the separate temporal classifier. It is not a security proof.
See the [preregistration](ORAM_MARKOV_TRANSITION_REPLICATION_PREREG_20261026.md)
and [result](ORAM_MARKOV_TRANSITION_REPLICATION_20261026.md). The report
writer now distinguishes post-hoc from preregistered secondary analyses.

## 2026-10-26: authenticated autoscaler experiment input

The batch autoscaler runner now accepts an external JSON registry of
per-principal HMAC keys for authenticated bounded-user simulations. It rejects
registry files with group/other permission bits, caps the file at 16 MiB,
authenticates retained imported requests before simulation, and records only
the registry content hash. The offline regeneration tool requires the same
registry fingerprint and revalidates retained request MACs. Registry paths
are redacted from recorded CLI provenance. This is a shared-secret simulator
feature: it has no issuer/rotation/revocation service, replay cache, durable
person-level binding, or protection against an operator/verifier that can
read the keys. It does not change the interpretation of earlier unauthenticated
bounded-user studies. Four focused autoscaler tests and the full research
Python suite passed (216 tests, 4 skipped; 2026-10-26). Rust and hosted CI were
not rerun for that Python-only increment.

## 2026-10-26: Ed25519 autoscaler identity verification

Added an Ed25519 option for authenticated bounded-user inputs using the
maintained `cryptography` package (pinned to 50.0.2 in the research lockfile).
The verifier loads only raw public keys; the synthetic client generator loads
matching private seeds from a separate permission-restricted file. Key mismatch
fails before run output is created. Signed synthetic requests are verified
during simulation and again during offline regeneration using only the public
registry. Paths for both key files are redacted and only the public registry
fingerprint is written to the artifact. Tests cover changed fields, unknown and
malformed signatures, imported requests, file permissions, key mismatch,
provenance redaction, and raw-data rebuilding. The full Python suite passed
(218 tests, 4 skipped; 2026-10-26). The experiment runner still holds client
signer and verifier in the same process; this does not establish scheduler
confidentiality or real user identity. Key binding/lifecycle, replay handling,
and cross-horizon composition remain open. Prior unauthenticated campaigns are
unchanged. Hosted workflows for the preceding commit passed; this increment's
hosted workflow will be checked after push.

## 2026-10-26: per-principal composition across retained horizons

Added `SequentialUserPrivacyAccountant` with basic sequential composition,
optional epsilon/delta budget enforcement, duplicate-release rejection, and
aggregate summaries that never emit principal IDs. The autoscaler batch runner
records each `dp_laplace` fixed horizon in the generated and imported workload
sessions, using request identities held only in memory. The offline
regenerator derives the same per-artifact summary from retained private
requests. Reports scope the result to the count/event transcript and state the
stable-ID assumption plus the seeded/CSPRNG artifact guarantee. This is not a
persistent cross-run ledger; deterministic public-seed artifacts still have no
DP guarantee, and historical campaigns are unchanged. Focused composition,
rebuild, identity, and selected-policy tests passed; the full Python suite
passed (220 tests, 4 skipped; 2026-10-26). Hosted CI has not yet run for this
increment.

## 2026-10-26: preregistered two-address isolated ORAM timing follow-up

Repeated the historical two-address 75/25 logical workload with fresh seed,
paired plaintext/encrypt-only/ORAM schedules, whole-session profiling/target
splits, and a frozen AUC primary metric. Both positive controls scored AUC
1.000. Path ORAM scored 0.4989 [0.4888, 0.5083] over 30 trials, including
chance; this does not reproduce the earlier weak exploratory signal. The
timing boundary is different: service-handler-only time in a separate child
process, rather than historical controller plus trace-drain duration. The
shared host was heavily loaded, so smaller effects remain unresolved.

The independent artifact audit rechecked 1,440 compressed raw files, five
source/configuration/binary hashes, 240 paired schedules, 430,080 observer
events, 720 distinct service workers and 90 prediction AUCs. The 12 focused
replication/timing tests passed and both release examples built before
collection. Raw output, host observations, predictions, figure and audit
summary are in
[`experiments/results/oram-isolated-two-address-replication-20261026`](../experiments/results/oram-isolated-two-address-replication-20261026/);
see the [experiment report](ORAM_TWO_ADDRESS_REPLICATION_20261026.md) and
[pre-registration](ORAM_TWO_ADDRESS_REPLICATION_PREREG_20261026.md). These
measurements are not a remote timing study or an ORAM security proof.

## 2026-10-26: persistent autoscaler privacy accountant

Added an opt-in SQLite ledger for basic per-principal composition across
separate autoscaler runs. It stores exact decimal totals under
domain-separated HMAC-SHA256 pseudonyms, serializes budget checks and updates
in one transaction, rejects duplicate release IDs, and pins the ledger to its
HMAC key fingerprint, identity-registry fingerprint, and configured lifetime
limits. The batch runner requires authenticated user IDs, a nonzero user cap,
and the bounded-user `dp_laplace` policy; its artifact separates the current
run's reproducible composition from a cumulative external-ledger snapshot.
Offline reanalysis checks snapshot consistency against the source artifact's
local manifest and labels it as copied, not recomputed.

Twelve focused ledger tests cover reopen composition, duplicate and atomic
budget rejection, concurrent writers, key/identity/configuration mismatch,
filesystem permissions, path redaction, and two actual runner invocations.
The full research Python suite passed (232 tests, 4 skips; 2026-10-26), and
the core ledger modules compiled successfully. A 30-trial microbenchmark at
1/16/64/256 principals per release measured p50 commit latency of
0.154/0.521/1.713/5.196 ms and final database sizes of
49,152/172,032/659,456/2,498,560 bytes. The raw percentiles were independently
recomputed from all 120 saved latencies. This is a heavily loaded single-host
measurement, not a remote capacity estimate; see
[`PRIVACY_LEDGER_BENCHMARK_20261026.md`](PRIVACY_LEDGER_BENCHMARK_20261026.md).
This local mechanism does not protect against a privileged operator, active
database tampering or backup rollback; stable real-world identity and
key/registry migration remain assumptions. The ledger does not upgrade seeded
artifacts to a DP guarantee. See [`PRIVACY_LEDGER.md`](PRIVACY_LEDGER.md).
Hosted CI passed for the persistent-ledger source and benchmark/report commits
(`40367691708`, `40367666514`, `40368680632`, `40368659343` as of 2026-10-26).

## Persistent SSE journal increment (2026-10-26)

Added opt-in `PersistentClient<A: SseJournalAnchor>` while preserving the
existing ephemeral `Client`. Client keys, counters, and pending requests are
stored in ChaCha20-Poly1305 protected journal records with HKDF domain
separation, OS-random nonces, an 8 MiB serialized plaintext bound, and a 64 MiB
record bound. Mutations are append-only, full checkpoints are written every
256 state changes, and the previous record digest is authenticated. Files and
their directory are synced before the external anchor CAS; failed or
indeterminate updates poison the live client. Tests cover byte-identical
pending retries after restart, actual server retry/search behavior, wrong
keys, record tampering, stale-file replay, one-winner stale-writer CAS,
checkpoint compaction/recovery, file-size bounds, plaintext absence, and
serialized-state validation.

The full `oblivion-sse` suite passed 18 tests (12 unit and 6 integration; the
100,000-operation plaintext-oracle test included). Review follow-up tests now
extend the sparse oversized-record fixture beyond 64 MiB and verify that a
valid authenticated chain longer than the replay cap returns `JournalError::Limit`.
`cargo clippy --locked -p oblivion-sse --all-targets -- -D warnings` and
`cargo fmt --all --check` passed.
Hosted CI for this code has not run yet. S11 remains partial: only an in-memory
test anchor is connected to `PersistentClient`; the SQLite anchor service's
new journal slot is not yet exposed over its Unix protocol. Rollback protection
requires an independent durable anchor and caller-managed key custody. The
local file journal itself is not a TEE, and the 8 MiB plaintext cap is a current
capacity limit. Journal write amplification and restart cost have not been
benchmarked.

## SSE anchor SQLite slot increment (2026-10-26)

Added schema-v4 `sse_journal_anchor` storage to `oblivion-anchor`. Each caller-
supplied validated slot stores a clear generation for CAS and an encrypted
index ID/digest under a slot- and purpose-separated key derived from the
service master key. Generation 0 is the initial SSE checkpoint; later changes
must advance exactly one generation and keep the original index ID. Ciphertext
and nonce reads are length-bounded even if SQLite check constraints are
bypassed. Indeterminate transaction commit errors are preserved distinctly.

The schema-v3 migration/reopen test preserves a registry catalog row. Wrong-key,
same-size and oversized ciphertext corruption, plaintext absence, independent
slots, invalid generation transitions, index substitution, and a concurrent
two-writer single-winner CAS are covered. Protocol-v3 Unix `SseJournalLoad` and
`SseJournalCas` requests expose the slot through
`UnixAnchorClient::sse_journal`; existing protocol-v2 operations remain at v2.
The socket test covers load/CAS, stale conflict, invalid version, and slot
validation; a missing-service test confirms CAS transport failure is
indeterminate. The full anchor suite passed 25 unit tests and 9 local-service
integration tests; warning-denied package Clippy and formatting passed. The SSE
trait adapter and actual `PersistentClient` process-restart test remain
pending. The service master key must remain stable; privileged rollback of its
SQLite database still defeats freshness.

Workspace formatting and `cargo clippy --locked --workspace --all-targets -- -D
warnings` passed. The first serial workspace test attempt hit two executor
storage tests' 100 ms deadlines; their storage-only tests now use a 1 s test
deadline, and that target passed 5/5 without changing production classes. The
next two serial workspace attempts each hit a different invocation timeout in
the end-to-end server pipeline at its public 100 ms schedule. The entire
server-pipeline test target passed 21/21 on a separate run. This host therefore
has not produced a clean full-workspace test run yet; do not treat the
standalone pass as a substitute. Deadline behavior and shared-host sensitivity
remain visible limitations to investigate.

`cargo build --locked --release --workspace --bins --examples` completed
successfully after reclaiming space from the rebuildable development cache.
This verifies optimized compilation for the workspace binaries and examples;
it does not replace the pending clean full-workspace test run.

## 2026-10-27: persistent SSE Unix anchor integration

`PersistentClient` now implements its anchor contract through
`UnixSseJournalAnchor`. A child-process integration test creates a pending SSE
add, stops and restarts the local anchor service, reopens the client, verifies
the retry bytes are unchanged, completes the real server update, confirms a
stale client's compare-and-swap is rejected, then restarts the service again
and searches the recovered state. The caller must reuse a stable opaque slot
and the same anchor service master key. This covers process restart only: a
privileged host operator can restore an older SQLite database, and there is no
distributed transaction with the SSE server or backward privacy.

Fresh verification for this increment: `cargo test --locked -p oblivion-sse
-- --test-threads=1` passed 20 tests across its unit and integration targets,
including the 100,000-operation oracle; `cargo test --locked -p oblivion-anchor
-- --test-threads=1` passed 34 tests. The service integration target was rerun
after the final test cleanup (2 passed). Warning-denied Clippy for both crates,
workspace formatting, and `git diff --check` passed. A clean full-workspace test
run has not been established on this host; prior serial attempts hit different
100 ms runtime deadline failures, so these package results do not replace that
gate. Journal write amplification and recovery cost remain unmeasured.

Review of `844b2047` found no Critical or Important issues. One Minor test-harness
cleanup issue is deferred: if anchor startup times out before the RAII process
guard is constructed, the child can remain orphaned. This affects the failing
startup path, not the exercised restart path.

## 2026-10-28: independent ORAM leaf/timing replication

The preregistered 16-address Zipf-1.10 workload with 0.65 Markov retention,
80% reads and 32-block Path ORAM completed 30 trials × eight sessions across
plaintext, encrypt-only and ORAM. The fixed temporal random forest used four
whole profiling sessions and four disjoint target sessions per trial. Both
positive controls scored AUC 1.000 [1.000, 1.000]. Path ORAM scored 0.4968
[0.4864, 0.5072]; the interval includes chance and the point estimate was not
post-hoc reversed. This does not reproduce the prior possible weak signal for
this workload, classifier and local handler-time boundary; it is not evidence
of cryptographic privacy. The 57.85% realized hot-class proportion and 57.06%
majority raw-accuracy baseline are reported so raw accuracy is not mistaken for
chance.

The runner retained 1,440 compressed raw files and hashes, 240 paired schedules,
720 service-process records, predictions, host snapshots and `auc.png`. A
separate post-run check matched every raw hash and recomputed all 90 trial AUC
means/intervals and disjoint profile/target splits. The focused replication and
timing tests passed 12/12 before collection; both release examples built.
Collection used separate CPUs for driver/service, but the shared host load rose
from 6.46 to 7.52 (one-minute load average) during the 88-second run. See the
[preregistration](ORAM_ZIPF16_MARKOV_REPLICATION_PREREG_20261028.md),
[result report](ORAM_ZIPF16_MARKOV_REPLICATION_20261028.md), and raw
[verification record](../experiments/results/oram-isolated-zipf16-markov-replication-20261028/verification.json).

## 2026-10-28: persistent SSE journal benchmark implementation

Added `sse-journal-benchmark`, a reproducible benchmark for the existing
`PersistentClient` using the actual Unix SQLite anchor service. It builds
distinct-keyword indexes at configured sizes, measures each durable journal
record at creation (including later-pruned checkpoint records), separates
server insertion from persistent-client update calls, and performs repeated
recovery attempts in fresh child processes. The client key travels over a
private child stdin pipe and is not written to the result bundle. The machine
configuration and method are frozen in
[the preregistration](SSE_JOURNAL_BENCHMARK_20261028.md) and
[the config](../experiments/configs/sse-persistent-journal-benchmark-20261028.json).

The full 30-trial collection completed in about 2 h 54 min. It produced 120
index-build trials, five fresh-process recovery opens per trial (600 distinct
child PIDs), raw per-operation timings, summary statistics, and an SVG. The
report's source revision is the frozen runner commit above, with a clean
tracked source tree. The independent verifier rechecked all configured trial
and size pairs, generation/update counts, byte ratios, checkpoint schedules,
recovery process counts, and descriptive means/quantiles from the raw rows.
Its eight unit tests pass. It checks the 5,000-resample interval metadata and
ordering but does not duplicate the runner's exact Rust `StdRng` stream.

The mean application journal-byte amplification ranged from 84.037× at 64
postings to 244.754× at 4,093 postings; mean index-build time ranged from
3.316 s to 242.889 s. The 4,093-posting recovery-open mean of trial medians was
25.963 ms. These are host-specific measurements, not SQLite/WAL or physical
device write amplification. Recovery launches a fresh process but does not
flush the operating-system page cache. The report, raw JSON, SVG, checksums,
method, and reproduction commands are in
[SSE_JOURNAL_BENCHMARK_20261028_RESULT.md](SSE_JOURNAL_BENCHMARK_20261028_RESULT.md).

Verification for the implementation: the new real-anchor/fresh-process smoke
test passes; all 21 tests in `cargo test --locked -p oblivion-sse --
--test-threads=1` pass; `cargo fmt --all --check` and workspace Clippy pass. A
fresh serial `cargo test --locked --workspace -- --test-threads=1` exited 0
with every enabled workspace test passing; the million-operation ORAM stress
test is intentionally ignored by that default command. An earlier serial run
stopped on the timing-sensitive `sse_metadata_discovery_precedes_real_mixed_invocation`
100 ms timeout; its isolated rerun passed without code or deadline changes.
The benchmark runner's code predates this result and its push/PR CI passed. The
independent verifier and plot renderer were added in commit `1e5a3b75`; their
focused Python tests and actual-report verification pass. The full test command
does not include the separately invoked million-operation stress tier.

Fresh result-bundle validation (2026-10-28): the independent verifier checked
120 samples across 30 trials and four index sizes; all three retained artifact
checksums match `SHA256SUMS`. The venv Python research suite passed 240 tests
with four skips.

## 2026-10-28: independent mTLS witness for standalone SSE and catalog clients

Added `oblivion-anchor-remote`, a separate synchronous TLS service backed by
the existing SQLite journal-head CAS, and `TlsSseJournalAnchor`, the matching
client adapter. Mutual TLS authenticates both endpoints. Each connection
carries one versioned JSON request and response, each limited to 512 KiB;
there is a five-second TCP connect timeout and an absolute five-second
TLS/frame I/O deadline shared by reads and writes after connect/accept. Byte
trickling cannot reset the I/O deadline. The CLI
requires a 32-byte master key in a regular restricted file and rejects
symlink/special-file key paths. The service listener is serial and suitable
for low-rate research anchoring, not a production availability target.
The service and CLI are in commit `7db12546`; the `PersistentClient` adapter
and application-journal rollback negative control are in `b758d0d4`.

`TlsSseJournalAnchor` is available to standalone `PersistentClient` SSE, and
`TlsRegistryCatalogAnchor` implements standalone signed catalog activation
using version/digest CAS. At this point in the implementation history, the
runtime worker was not yet configured to use the remote catalog adapter.
Remote ORAM
checkpoint and invocation-receipt contracts remain unimplemented. If the
separate witness operator retains the current database, it detects restoration
of an older application-side journal or catalog state. A witness rollback,
compromise, credential theft, or outage defeats availability or freshness;
there is no quorum, hardware monotonic counter, automatic retry after an
uncertain commit, or local fallback. The witness sees the stable slot, SSE
index identifier/generation/digest or catalog version/digest, and operation
time. The network sees peer addresses, timing, and approximate TLS record
sizes.
Every certificate chaining to the configured client CA can address any valid
slot; there are no per-client ACLs, quotas, or rate limits. Certificate
issuance and network policy are the authorization controls in this version.

The focused anchor and SSE package suites passed, including wrong-CA/client
certificate rejection, service restart, outage fail-closed behavior, a
slow-drip deadline regression, and the end-to-end application-journal rollback
negative control. The mTLS integration test also runs a real signed catalog
through `VerifiedRegistry::activate_catalog`, rejects stale catalog CAS, and
recovers its version/digest after witness restart. A catalog CAS against an
unavailable witness returns `AnchorCommitUnknown` for caller reconciliation.
The fresh serial
`cargo test --locked --workspace -- --test-threads=1` run exited 0 with every
enabled workspace test passing; the million-operation ORAM stress test remains
intentionally ignored. Workspace warning-denied Clippy, formatting, and
whitespace checks passed. Hosted CI passed on complete source commit
`38efb2a3` (runs `40742102781` and `40742122501`); an earlier intermediate
service-only push failed because its lockfile included the SSE test dependency
before that manifest change was pushed. This is not cryptographic review.

## 2026-10-29: remote registry catalog adapter

`TlsRegistryCatalogAnchor` now implements `RegistryCatalogAnchor` over the
existing mutually authenticated witness protocol. A standalone caller can load
and compare-and-swap a catalog version and 32-byte digest, then call
`VerifiedRegistry::activate_catalog`; the witness persists the state in its
SQLite-backed slot. Stale CAS is rejected, an unavailable or ambiguous CAS is
reported as `AnchorCommitUnknown`, and an exact catalog activation remains
idempotent after witness restart. At this adapter-only stage, the runtime
worker had not yet been wired to the remote catalog; startup integration is
recorded in the following entry. This increment does not add remote ORAM checkpoints, remote
invocation receipts, witness replication, per-certificate slot ACLs, or
hardware anti-rollback.

Fresh local verification on this source: `cargo test --locked --workspace --
--test-threads=1` exited 0 with all enabled workspace tests passing; the
million-operation ORAM stress test remains intentionally ignored by that
command. The four mTLS integration tests passed, including real signed catalog
activation, stale-writer rejection, witness restart, and unavailable-witness
uncertainty. `cargo clippy --locked --workspace --all-targets -- -D warnings`,
`cargo fmt --all --check`, and `git diff --check` passed. A relative-link check
resolved 308 links across 11 changed Markdown files. Hosted Rust quality gates
for source commit `a2f1281f77c065311fe3e8f78202187e56df25c2` passed in Actions
run [40745540050](https://github.com/dumbly-smart/Oblivion/actions/runs/40745540050):
Rust quality, million-operation ORAM stress, and analysis all succeeded.

## 2026-10-29: remote mTLS Path ORAM checkpoint adapter

Commit `a3201105` adds `TlsCheckpointAnchor`, an implementation of the existing
`oblivion_store::CheckpointAnchor` trait over the versioned mTLS witness
protocol. Checkpoint load returns the persisted snapshot ID and secret handle;
compare-and-swap delegates generation validation and atomic persistence to the
existing SQLite checkpoint slot. Definite stale generations map to
`AnchorConflict`. A response lost or malformed after request transmission, or
an explicit uncertain SQLite commit, maps to `AnchorCommitUnknown`. A failed
TCP connection before sending is a definite backend error. There is no retry
or local fallback.

The protocol transmits the 88-byte `TrustedCheckpoint` handle inside the TLS
channel. That handle contains the snapshot decryption key, so the witness is
trusted with snapshot confidentiality and can decrypt snapshots it can
access. The database encrypts handles at rest, but this does not conceal them
from the witness process/operator. Application-owned wire fields and serialized
frames are zeroized on drop as best effort; TLS-library, allocator, kernel and
crash-dump copies are outside that guarantee. Existing mTLS authorization is
global to the configured client CA: there is no per-certificate slot ACL.
Witness database rollback, compromise and outage remain outside the freshness
guarantee.

The integration test uses real Path ORAM state and a real encrypted snapshot:
it publishes through `TlsCheckpointAnchor`, stops and restarts the witness,
loads and restores the persisted handle, advances to a new snapshot, verifies
restored values, and confirms that a stale restored controller gets
`AnchorConflict`. The unavailable-witness test also checks that a failed
pre-send connection is a definite backend error for both load and CAS.

Verification on source commit `a3201105753bc14a220f1d4acddbcd301efc3578`:
`cargo fmt --all --check` passed; the anchor package's all-targets suite passed
42 tests; `cargo clippy --locked --workspace --all-targets -- -D warnings`
passed; and `git diff --check` passed. The pinned serial
`taskset -c 21 cargo test --locked --workspace -- --test-threads=1` run
completed with every enabled workspace test passing. The million-operation
stress test remains intentionally ignored by the default test suite, but the
dedicated hosted stress job passed. Hosted run
[40809388355](https://github.com/dumbly-smart/Oblivion/actions/runs/40809388355)
passed Rust quality, the million-operation ORAM stress oracle, and research
analysis on this exact source SHA. Concurrent run
[40809398937](https://github.com/dumbly-smart/Oblivion/actions/runs/40809398937)
also passed Rust quality and analysis; its stress job was skipped due workflow
concurrency. No performance benchmark was collected for this adapter.

This adapter is not wired into the runtime worker's durable checkpoint/receipt
configuration. Remote invocation receipts, multi-host writer fencing,
per-slot client authorization, replicated rollback resistance and
hardware-backed freshness remain open.

## 2026-10-29: fixed-width checkpoint handle encoding

Follow-up commit `2b79f0e4` removes a size side channel found during wire review:
JSON decimal byte arrays had different serialized lengths for different
secret-handle values. Protocol version 2 encodes the logical 88-byte handle as
exactly 176 lowercase hexadecimal characters. This keeps frame length
independent of snapshot-key/digest byte values. The parser validates exact
length and hex digits, decodes into a zeroizing fixed-size array, then rebuilds
the validated `CheckpointAnchorRecord`. The exported
`TRUSTED_CHECKPOINT_HANDLE_BYTES` constant keeps that wire adapter aligned with
the store's handle size. Version-1 remote anchor peers are rejected; both ends
must use version 2 for remote operations.

Two unit tests verify equal serialized lengths for different handle byte
values and reject malformed length/hex input. Verification on code commit
`2b79f0e4d4bfc3f7806636d5d32bc6ac841869fe`: the anchor all-targets suite passed
44 tests, workspace warning-denied Clippy passed, formatting passed, and
`git diff --check` passed. Full workspace tests and hosted CI are pending for
this follow-up commit; the preceding source commit's full workspace and hosted
stress evidence is recorded above. No performance benchmark was collected.

## 2026-10-29: mTLS certificate-to-slot authorization

Source commit `cfd1a04d` adds a version-1 witness authorization policy. It maps
an exact lowercase SHA-256 fingerprint of the complete DER leaf certificate to
one or more exact anchor slots. The witness first completes normal mTLS chain
validation, decodes the bounded request, and checks the authenticated leaf and
requested slot before dispatching an anchor operation. There are no wildcard
slots. The strict JSON parser rejects unknown fields, duplicate clients or
slots, malformed fingerprints, unsupported versions, empty grants and files
over 1 MiB. On Unix the policy file must be a regular non-symlink file and
must not be group- or world-writable. The policy is loaded once when the
witness starts; updates and certificate revocation require a restart. The
remote witness CLI now requires the policy file as its final argument.

Integration tests prove that a CA-valid certificate without a grant and a
granted certificate requesting another slot are both denied. Existing remote
SSE, signed-catalog and ORAM checkpoint tests now provision explicit grants.
This policy limits certificate-to-slot access only: it adds no per-slot quota,
rate limit, automated revocation, hot reload, witness replication, or
multi-host runtime checkpoint/receipt integration.

Verification on `cfd1a04d`: `cargo test --locked --workspace --
--test-threads=1` exited 0; the million-operation ORAM test remains
intentionally ignored by the default suite. `cargo clippy --locked --workspace
--all-targets -- -D warnings`, `cargo fmt --all --check`, `git diff --check`,
and the updated remote CLI help check passed. A changed-Markdown link check
resolved 328 relative links across 12 files. Hosted checks were pending when
this entry was written. No performance benchmark was collected for the policy.

## 2026-10-29: runtime remote mTLS invocation anchoring

Code commit `7bee2666` wires the runtime worker to choose either the existing
local Unix invocation anchor or `TlsInvocationAnchor`. Remote mode requires all
six `OBLIVION_INVOCATION_ANCHOR_MTLS_*` settings plus
`OBLIVION_ANCHOR_STATE_DIR`; partial configuration, a missing state directory,
and combining local and remote settings fail before readiness. Existing PEM
loading and permission checks are used, and there is no local fallback. The
wire exchange uses protocol v3 and an 80-byte fixed response capacity.

Both receipt hits and misses follow the same `load` then `finish` action
sequence. A hit reuses the current checkpoint and secret handle, writes no
snapshot, and returns the original saved response. This also handles an older
receipt after a later checkpoint without rolling the checkpoint backward. A
new invocation writes the encrypted snapshot locally and asks the witness to
atomically commit its pointer with the exact receipt. Only an ambiguous finish
uses exact-response confirmation. Remote mode has no distributed writer
lease: the witness CAS rejects a stale checkpoint publication but does not
fence concurrent execution or provide multi-host recovery.

The public storage schedule now reads the eight-block staged set at 5% of
the class deadline and commits it at 65%, leaving more time for real ORAM work
before the write phase. The former 25%/50% boundaries caused deadline failures
in two mixed stateful-function pipeline cases; the full serial pipeline suite
passes with the updated schedule. These targets do not force exact wall-clock
completion on a contended host.

The process integration test starts a real mTLS witness with a certificate-
to-slot grant, invokes an actual stateful WASM function using a signed
invocation, restarts the witness, verifies exact replay and restored ORAM
state, makes a later state transition, and replays the older receipt while
confirming that the newer checkpoint and state remain intact. Configuration
tests check partial credentials, missing state-directory configuration, and
local/remote conflicts. The witness receives the plaintext checkpoint handle,
which contains the snapshot key, and can distinguish receipt hits from misses.
Snapshot files remain on the worker host. There is no multi-host fencing,
witness replication, witness rollback protection, snapshot file replication,
or arbitrary external-side-effect atomicity.

Verification on code commit `7bee2666`: the serial whole-workspace command
`cargo test --locked --workspace -- --test-threads=1` passed 187 tests with one
intentionally ignored million-operation ORAM stress test. The separate
`cargo test --locked --release -p oblivion-store million_operation_oracle --
--ignored --exact` command passed that million-operation test in 88.76 seconds.
Workspace Clippy with `-D warnings`, formatting, and whitespace checks passed.
The dedicated server pipeline suite passed all 24 tests. Hosted run
[40824696959](https://github.com/dumbly-smart/Oblivion/actions/runs/40824696959)
passed Rust quality and analysis (including the research Python suite and
reference workspace); its million-operation stress job was skipped. No
performance benchmark or local Python suite was run for this Rust-only
increment. At the time of `7bee2666`, the remote ambiguous-finish transport
test dropped the connection after reading the request and did not simulate a
database commit followed by loss of that commit's reply. Source commit
`4e66221d` adds the handler-level commit-then-drop reconciliation test below.

### Remote invocation lost-reply fault coverage (source commit `4e66221d`)

Added `dropped_finish_reply_after_database_commit_is_reconciled_from_persisted_receipt`.
It uses a real mTLS client and test TLS listener, then exercises the production
protocol decoder, certificate-to-slot authorization, and `serve_request`
against a temporary SQLite `AnchorDatabase`. The first finish commits both
the checkpoint and receipt before the test drops the stream without writing a
response. The client observes `CommitIndeterminate`; a second TLS connection
confirms the exact invocation receipt and response, and the test reads back
the committed checkpoint generation and snapshot ID. The existing
process-level lost-reply test remains useful for the earlier failure point
where the peer reads the request and disconnects before dispatch.

`cargo test --locked --workspace -- --test-threads=1` passed 188 tests with
one intentionally ignored million-operation ORAM stress test. The dedicated
stress test was not rerun for this test-only increment; its previous measured
pass was on code commit `7bee2666`. Workspace Clippy with `-D warnings`,
formatting, and `git diff --check` passed. No benchmark, local Python suite,
or hosted CI run was performed for this increment. The TLS fault harness
suppresses the response after the production request handler returns; it does
not kill the `serve_mtls` process inside the real server write path. That
process/socket failure schedule remains future fault-injection work.

### Remote SSE stale-writer reservation coverage (source commit `12c2dd03`)

Added `remote_witness_reserves_pending_update_against_stale_writer` to
`crates/oblivion-sse/tests/remote_anchor.rs`. Two independent
`PersistentClient` instances open the same encrypted journal at one remote
anchor generation. The first client persists its pending update through the
mTLS SQLite witness. The stale client's competing `prepare_add` fails with
`AnchorConflict` before returning a request and poisons that stale instance.
A fresh instance reopens from the witness head, recovers the exact winning
request, submits it to the actual SSE server, persists the acknowledgement,
and verifies that only the winning keyword is searchable.

The full serial workspace suite passed 189 tests, with one intentionally
ignored million-operation ORAM stress test. Workspace Clippy with `-D
warnings`, formatting, and whitespace checks passed. The ORAM stress test was
not rerun; its last measured pass remains attached to code commit `7bee2666`.
No benchmark, Python suite, or hosted CI run was performed for this test-only
increment. This validates stale-generation reservation/recovery, not
simultaneous independent-host scheduling or a transaction spanning the witness
and SSE server. The witness can still be rolled back by its operator, so S11
remains partial.

### Concurrent remote SSE writer reservation (source commit `dc2c7201`)

Added `remote_witness_allows_one_simultaneous_pending_update_from_a_generation`.
Two `PersistentClient` instances load the same remote journal head, wait at a
barrier, and concurrently attempt different `prepare_add` operations. Exactly
one call returns a request; the other receives `AnchorConflict`. A newly
opened client recovers the winner's exact pending request, submits it to the
SSE server, persists the acknowledgement, and verifies that only the winning
keyword is searchable. The focused race passed 10 consecutive executions.

The serial workspace suite passed 190 tests with one intentionally ignored
million-operation ORAM stress test. Workspace Clippy with `-D warnings`,
formatting, and whitespace checks passed. The stress test was not rerun; its
last measured pass remains attached to code commit `7bee2666`. No benchmark,
Python suite, or hosted CI run was performed. The clients raced on one host
against one witness; this does not establish cross-host operation, witness
rollback resistance, or an atomic transaction with the SSE server. S11 remains
partial.
