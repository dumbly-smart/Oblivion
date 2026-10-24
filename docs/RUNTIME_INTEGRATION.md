# Runtime integration and failure policy

The runnable process simulation composes authenticated fixed-size invocation envelopes, epoch batching, two encrypted XOR-PIR worker connections, precompiled Wasmtime modules and actual Path ORAM state operations. It runs one to four trusted clients in the driver process, one executor process, and two PIR processes on one host. These are simulated trust boundaries: there is no hardware TEE, attestation or independently operated non-colluding deployment. A host operator can inspect all process memory. PIR privacy requires the two servers not to collude.

## Commands

Run from the repository root; each output directory must be new:

```sh
cargo run -p oblivion-server -- demo /tmp/oblivion-basic 50 1
cargo run -p oblivion-server -- demo-sse /tmp/oblivion-discovery 100 2 mixed
cargo run -p oblivion-server -- demo-sse /tmp/oblivion-four-idle 0 4 mixed
cargo run -p oblivion-server -- demo-sse /tmp/oblivion-four-half 50 4 mixed
cargo run -p oblivion-server -- demo-sse /tmp/oblivion-four-full 100 4 mixed
```

Both commands accept `NEW_OUTPUT_DIRECTORY [0|50|100] [1..4 PARTICIPANTS] [mixed]`. Each run has eight epochs; `mixed` cycles the five function metadata names. The original `demo` command retains its direct selection behavior. Real results are checked against an independent client oracle: echo, sum, Fibonacci, FNV hash and per-client stateful counters. Dummy invocations use a separate reserved state namespace. Every admitted invocation, including invalid authentication or PIR failure, attempts eight actual ORAM reads and eight actual ORAM writes around genuine WASM execution. Storage failure can interrupt that schedule; the code does not promise a complete trace after backend failure or process termination.

The `demo-sse` command first uses `oblivion-sse::Client` and `Server` to construct an ephemeral, constrained-GGM encrypted keyword index over the five function names. Before constructing each invocation payload, each trusted client calls `prepare_search`, `Server::search` and `finish_search`, compares authenticated document IDs against a plaintext metadata oracle and selects the returned function ID. That selected ID drives the same encrypted invocation, actual two-process PIR lookup, WASM execution and ORAM path. Search state and keys stay in the trusted driver. The SSE map is an untrusted logical component in that same process; there is no separate SSE service or deployment isolation claim. No SSE operation occurs inside the executor's padded class.

SSE setup/search protocol objects are recorded in `metadata-discovery-observer.jsonl` after a successful run. This transcript includes exactly the requests/responses visible to the SSE map, including index identity, constrained capabilities, posting addresses and encrypted IDs. It excludes client keys, search snapshots, plaintext names and oracle results. It reveals per-index setup size, search equality, posting history and result volume. The transcript groups operations by client slot, retaining each index's protocol order; it has no cross-client wall-clock ordering. Metadata discovery timing and variable search sizes are outside the fixed-envelope claim. This bounded integration does not establish Diana's theorem or backward privacy.

## Registry integrity and version policy

`REGISTRY_VERSION = 1` identifies the immutable deployment. Each fixed 128-byte record contains the SHA-256 digest of the exact embedded WAT source, function ID, deployment version and canonical padding. The trusted executor pins every byte of all five records from its compiled binary, then compares each recovered PIR record against the selected pinned record before dispatch. A domain-separated SHA-256 digest over the version and ordered records identifies the whole deployment in `client-summary.json`.

A stale version, substituted function, modified module digest, changed padding or truncated record fails comparison. Encrypted PIR session sequencing also rejects replayed transport frames. Replaying an identical current immutable record is harmless and accepted: the session has no registry update API. This is trusted local provisioning, not registry signing. Installing a new binary starts a new deployment/session; there is no durable cross-restart monotonic-version authority and no claim to resist an operator replacing the trusted binary with an old one. Supporting mutable deployments would require a separately authenticated update and rollback policy.

## Lifecycle and faults

| Event | Behavior |
| --- | --- |
| Executor bootstrap absent or partial | Two-second worker bootstrap deadline; process exits with error. Driver readiness deadline is ten seconds. |
| PIR bootstrap/address absent, oversized or child exits | Two-second adapter startup bound, 128-byte address bound; kill and reap the failed child. |
| Missing request, partial frame, or client goes silent | Two-second executor input deadline; fail the session. No automatic epoch catch-up or hidden retry. |
| Correctly ordered request arrives before timeout | Process it; OS delivery delays remain observable. |
| Late frame after timeout | Session has exited; it cannot resume. |
| Duplicate, wrong-slot or skipped epoch | Reject public ordering before PIR/WASM/ORAM work for that frame; terminate the session. |
| Frame has valid public ordering but fails AEAD | Execute cover through PIR, dummy WASM and reserved ORAM state; return authenticated fixed-size zero error; subsequent ordered traffic may continue. |
| Invalid function or reserved real-state address | Same cover/error path; real client state is unchanged. |
| Either PIR worker is lost or recovered record differs from the deployment pin | Execute reserved-state cover, return authenticated zero error and never return the dummy result as user output. The driver aborts on this error; no availability or automatic recovery claim. |
| Driver stops reading responses | One frame outstanding, bounded response-writer acknowledgment; executor exits after two seconds blocked on output. |
| EOF between complete epochs | Graceful executor shutdown and successful exit. EOF midway through an epoch or frame is an error. |
| Driver shuts down executor | Two-second exit wait; the process guard kills and reaps it if needed. |
| Normal executor teardown | PIR session guards kill and reap their workers. |
| Abrupt parent termination | An idle PIR listener exits after five seconds without a connection; an accepted connection separately has two-second protocol I/O bounds. Active attacker connections can extend the listener lifetime. |

The input queues hold at most four complete frames. The response pipe has one outstanding fixed frame. The driver sends at most four request frames before awaiting responses; its fixed bootstrap/request writes fit the local OS pipe buffer. Blocking stdin/stdout readers and writers run in threads; a timed-out main process exits to release those threads. These are local Linux process/pipe bounds, not an asynchronous network service or a guarantee against a malicious kernel. Backend I/O and host scheduling can overrun the execution deadline. The executor records private status, actual timing and deadline misses and flushes those records before releasing a response.

Active dropping, delaying, malformed public headers, endpoint loss and overload can terminate sessions or disrupt the fixed trace. The mechanism provides rejection and bounded cleanup for the tested faults; availability and indistinguishability under active denial of service remain outside its claims. Runtime class parameters remain the existing public 100 ms small class; they are not increased to conceal failed runs.

## Verification (21 October 2026)

Commands executed:

```sh
cargo test -p oblivion-server -- --test-threads=1
cargo clippy -p oblivion-server --all-targets -- -D warnings
```

The final scoped suite passed 4 unit tests and 14 integration tests (26.74 seconds for the integration suite), including actual subprocesses, mixed-function oracle checks, separate client/dummy state, incomplete bootstrap/frame/epoch, idle timeout and late request, duplicate/skipped epochs, ciphertext tamper, killed PIR child, bounded response backpressure and idle orphan cleanup. The backpressure test uses safe `rustix` to reduce the Linux response pipe to 4096 bytes. The lost-child test uses Linux `/proc` and `kill`; that test is explicitly Linux-only. Clippy passed with warnings denied.

TDD failures were observed before implementation for the new discovery CLI, bounded bootstrap/frame input, response backpressure, orphan timeout and incomplete-epoch rejection. Killing a PIR child also exposed an error-path bug: the encrypted error previously included the dummy result. Its regression test now verifies a zero-filled error and 16 actual ORAM operations.

An initial parallel suite run failed the discovery invocation under contention; the serial suite passed. An initial four-client 50% run also failed. Polling delay in the newly bounded PIR listener was reduced from 5 ms to 1 ms, and private records are now flushed before the response to preserve diagnostics on abort. The final scoped tests and clippy results are reported above; these passes are correctness/failure smoke evidence, not latency or leakage confidence bounds.

The final manual four-client matrix used `target/debug/oblivion-server demo-sse OUTPUT LOAD 4 mixed` for each `LOAD` in `0`, `50`, `100`, sequentially. All three exited successfully. Artifacts were written under `/tmp/oblivion-runtime-validation-txlc0y4w/{0,50,100}`:

| Real load | Real/dummy invocations | Verified SSE searches | Distinct real functions |
| --- | --- | --- | --- |
| 0% | 0 / 32 | 32 | 0 |
| 50% | 16 / 16 | 32 | 5 |
| 100% | 32 / 0 | 32 | 5 |

All three summaries report registry version 1 and deployment digest `de0d3a483eee0609030ee60cce3f8de2cef5731decb9475387af8bae777dedc5`. These are single-run integration observations on a shared host. They provide no TEE evidence, independent-operator evidence, proof of forward privacy, active-attack availability result or statistical indistinguishability conclusion.

## Open-loop offered-load experiment

The separate benchmark command accepts an independently timed offered stream:

```sh
cargo run -p oblivion-server -- open-loop /tmp/oblivion-open-low 150 8 2
cargo run -p oblivion-server -- open-loop /tmp/oblivion-open-high 10 8 2
```

Arguments are `NEW_OUTPUT_DIRECTORY INTERVAL_MS COUNT [QUEUE_CAPACITY]`, with interval 1–1000 ms, count 1–100000 and capacity 1–1024 (default 4). A producer thread schedules arrivals against one monotonic start time and uses `try_send` into a bounded queue. It records an offered request even when the queue is full; arrivals never wait for executor responses. Logging and OS scheduling can delay the producer, so every row records actual offered time, scheduled time and arrival lateness. The consumer drains accepted jobs, assigns contiguous authenticated epochs and invokes the real stateful WASM module through the same executor worker, encrypted envelopes, both encrypted PIR processes and actual 16-operation ORAM schedule. Offered IDs can have gaps; accepted epochs cannot. An independent accepted-success counter checks actual stateful outputs. Authenticated invocation errors are counted with zero result bodies; transport failure aborts the run.

This command measures offered-load behavior rather than using the demo's fixed epoch batcher. It intentionally exposes offered timing, admission, queue occupancy effects, drops, accepted invocation count and overload. It does not claim the fixed-cover metadata protection of `demo`. No acknowledgment is a durable state commit: worker state and the workload queue are ephemeral.

Artifacts:

- `offered-arrivals.jsonl`: every offered ID, scheduled/actual time, producer lateness, admission/drop and public queue capacity.
- `open-loop-latencies.jsonl`: admitted ID/epoch, offered/dequeue/completion timestamps, queue wait, actual service time, end-to-end latency, success/error and the public 250 ms SLO outcome.
- `open-loop-summary.json`: admitted/dropped/completed/success/error counts, admitted latency p50/p95/p99, maximum queue wait, SLO violations, failures including errors/drops, observed CPU ticks/seconds and sampled aggregate RSS.
- `metadata.json`: source digest, software/compiler/host provenance and exact offered-load configuration.
- The worker's actual `storage-observer.jsonl` and `executor-private.jsonl`, including deadline misses and private statuses.

CPU ticks and RSS are Linux `/proc` snapshots for the driver, executor and its two PIR children, sampled after readiness and at completions. CPU excludes process startup and teardown; RSS is a sampled sum of resident memory and may count shared pages multiple times or miss peaks. Unsupported resource accounting is represented as null. This is measured process resource use with explicit limits, not a billing model. Latency percentiles describe admitted requests; dropped jobs are excluded from their denominator and explicitly included in failure counts. A success that completes after 250 ms is an SLO miss. An error is an SLO failure even if it completes quickly.

The overload regression uses 2 ms × 12 offers with queue capacity 1. It verifies that arrivals continue before the first invocation response, some offers are dropped, admitted plus dropped equals offered, completed jobs equal admission, and actual ORAM events equal admitted × 16 × 8. The underload regression uses 150 ms × 4 offers with capacity 2 and checks every offered stateful request succeeds and Linux CPU/RSS counters are present. Both targeted tests passed. The final serial suite passed all 4 unit and 14 integration tests, and scoped clippy passed with warnings denied. Repeated trials and statistical conclusions belong to the experiment report; this command does not manufacture confidence bounds from one trial.
