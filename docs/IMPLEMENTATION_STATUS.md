# Implementation status

Updated 2026-10-22. The actual multi-process pipeline, bounded attack suite, A–G/disabled-layer experiments, required figure artifacts and local demo recording exist. The complete research roadmap is **not** declared finished: [REQUIREMENTS_MATRIX.md](REQUIREMENTS_MATRIX.md) retains mandatory evaluation gaps and separate optional extensions. The model is TrustedExecutor simulated with ordinary processes; no hardware TEE, attestation or production-security claim applies.

## Implemented system

Seven Rust crates implement encrypted Path ORAM, two-server XOR PIR, Wasmtime execution, authenticated epoch batching, process orchestration, trace generation and constrained GGM SSE. The current path supports one to four clients, all five actual functions, disjoint user/dummy state, genuine SSE metadata discovery, encrypted PIR, independent output/counter oracles and fixed 164-byte invocation/response envelopes.

Protected execution reads eight blocks at the public 25 ms phase and commits eight at 50 ms. Guest failure discards staged mutations; uncertain physical backend failure can poison partially written state. With eight logical blocks, an invocation emits 128 actual bucket events of 316 bytes and costs O(M log N) bandwidth for public working-set size M. The executor's private `prepare_scheduled` result allows trusted drivers to encrypt the response and log instrumentation before waiting for the 100 ms public response deadline; `execute_scheduled` remains a standalone padded API. Public slot starts are anchored to epoch arrival plus slot index × 100 ms. Trusted clients prepare encrypted frames before emitting them at their public epoch, reducing workload-dependent arrival coupling. OS scheduling can still introduce lateness.

The memory-backed demo remains ephemeral. A separate bounded file/checkpoint API authenticates complete snapshots, validates restore and rotates bucket keys. Application durability requires externally protected latest-handle publication, which this pipeline does not implement. Invocation endpoint restore, exactly-once acknowledgments and SSE persistence/backward privacy are unsupported. See [ARCHITECTURE.md](ARCHITECTURE.md), [STORAGE_RECOVERY.md](STORAGE_RECOVERY.md) and [SECURITY_ASSUMPTIONS.md](SECURITY_ASSUMPTIONS.md).

## Accepted bounded measurements

| Evidence | What ran | Result and boundary |
| --- | --- | --- |
| [Final joint system campaign](SYSTEM_EXPERIMENTS.md) | 30 fitted-model trials of actual A–G library paths and disabled-layer variants; 1,920 observations/mode | G three-class balanced accuracy 33.40% [32.29,34.51], chance 33.33%; real/dummy accuracy 50.83% [47.81,53.54]; conditional real-function accuracy 48.96% [45.83,52.29], chance 50%. Declared summary-feature attacker, not every host observation |
| [Execution/error campaign](EXECUTION_EVALUATION.md) | Five successful functions and three actual failures, 30 trials; visible-selector control first | Protected eight-class accuracy 11.67% [9.38,13.75] versus 12.5% chance; all 960 protected outputs/statuses verified, 164-byte frames and 128 bucket events each. Saved earlier binary/version |
| [Trace validation](TRACE_VALIDATION.md) | 100,000 actual ORAM accesses each for repeated/uniform workloads; 30 fresh encrypted PIR capture sessions | 1.4M bucket events/workload; 3,000 oracle-verified PIR retrievals, 6,000 complete streams, 61,363 packets, zero reported drops. Packet evidence is structural; unvalidated classifier removed and excluded |
| [SSE count/frequency](SSE_ATTACKS.md), [offline inference](ADVANCED_ATTACKS.md), [chosen updates](UPDATE_LINKABILITY.md) | Real encrypted SSE exports and chosen updates, independent profiles and 30 trial clusters | Six bounded SSE-facing methods with leaky controls. Likelihood recovery 80.52% ordinary and 33.80% padded; equality remains useful. These are not faithful Cash/SAP/IHOP/file-injection reproductions |
| [Attack API](ATTACK_INTERFACE.md) | Nine adapters, common predictions/confidence/metadata, bounded JSON CLI | Eleven adapter checks compare original implementations; uncalibrated scores stay labeled. Adapter presence does not add experimental evidence |
| [Runtime benchmarks](RUNTIME_BENCHMARKS.md) | 60 offered-load process trials and 270 epoch/real-ratio component trials | Underload/overload, admitted latency, drops, goodput, coarse CPU/RSS, E/2 queue-delay and 69,120 actual AEAD frames; short tails and shared-host limits retained |
| ORAM size, `oram-size-30-20261021/` | 30 fresh controllers each at 16/64/256/1,024 blocks | Actual latency/payload/stash figure; observed maxima are not stash-failure bounds |
| [SimplePIR reference](SIMPLEPIR_REFERENCE.md) | Genuine pinned Go/C algorithm and actual XOR; 30 processes/scheme, 10,000 eight-byte records | 960 complete oracle checks; real offline hint and separate setup/online costs. Not runtime replacement or wire-speed comparison |
| [Autoscaler](AUTOSCALER.md) | Five policies, four synthetic workloads, two 30-trial simulation campaigns | Cost/privacy/SLO figures; failed burst objectives retained. Hypothetical costs, no runtime provisioning or DP |
| [Demo](DEMO.md) | Actual three-client mixed `demo-sse` process run | 24 calls, 12 real, all five functions, 24 metadata queries and 3,072 storage events; MP4/terminalcast/raw records retained. Rendered data visualization, not screen recording or privacy test |

The final G campaign's per-real API p95/p99 are 100.159/100.200 ms. Mean opportunity wall time is 116.268 ms; real goodput is 4.3004/s, including initial epoch wait and oracle/logging overhead. Accounted payload is 82,484 bytes/real request at 50% dummy load. Full three-axis mean-point Pareto membership is A/E/G under explicitly hypothetical executor-wall and response-egress prices. These are measurement scopes, not deployment capacity, current cloud prices or statistical dominance claims.

## Chronology and negative outcomes

The stopped `system-30-20261021/` pilot has 18 trials and an incorrect measurement/oracle boundary; it remains excluded. The later `system-30-corrected-20261021/` campaign is genuine earlier-version evidence, including conditional G function accuracy 54.58% [50.21,59.17], suggesting possible arrival coupling. It is retained as a negative outcome. Final `system-fixed-publication-30-20261022/` uses encrypted preparation before emission and driver response preparation before the public publication wait; favorable final scores do not erase the earlier result or prove general timing privacy.

Historical `validation-20261020`, component demo and leakage records retain their original source/configuration meanings. In particular, old demos made two logical ORAM accesses per invocation at a 10 ms class; current protected invocations have sixteen at 100 ms. Saved source fingerprints and immutable measured executable hashes take precedence over a later recorded Git HEAD. Postmeasurement source snapshots are labeled as such; none is silently promoted into hermetic build provenance.

## Validation and delivery

[Frozen-source commands](../experiments/results/validation-20261022-frozen/commands.json) have five zero exits for formatting, warning-denied workspace Clippy, workspace tests, Python discovery and separate release stress. The Python log records 53 checks with one explicit optional Rust smoke skip; the million-operation stress command took 41.46 seconds. The before/after source fingerprints match (`c6102bec936a3419766040e628852e3fb530206d533de8ed1a63934c5b298476`). This validates that frozen revision, not subsequent corpus/presence/geometry additions. Hosted Actions success has not yet been observed.

The user authorized small component commits and pushes. Work is being delivered on `codex/oblivion-research-platform`; it is not merged into main. CI configuration and a pushed branch do not establish a successful hosted run.

## Mandatory work still open

Realistic licensed corpus and auxiliary-knowledge sensitivity, presence/intersection inference, broad load/parameter/fault sweeps, detailed warm/cold/resource accounting, full PIR database-size/timing curves, broader stash/geometry analysis and calibrated three-axis/SLO frontier interpretation remain incomplete. New source additions require fresh checks; hosted CI and final public delivery acceptance remain gates. The matrix names exact rows rather than treating the entire roadmap as complete because its main pipeline runs.

Hardware TEE/attestation, formal DP, recursive/Circuit ORAM, DPF/√n or native single-server PIR, persistent/backward-private SSE and durable invocation semantics remain separately identified extensions or deployment obligations. Cache/page faults, exposed billing/resources, presence, scheduling, active failures and independent-operator assumptions remain outside favorable empirical claims.
