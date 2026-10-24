# Joint A–G execution laboratory

The laboratory invokes real Wasmtime code, authenticated padded channels, the actual XOR PIR API (including two independently keyed server endpoints), actual epoch queues and either an address-revealing store or Path ORAM. It complements the multi-process `oblivion-server demo-sse`; this experiment runs components in one process. Its observations are API payloads and storage calls, **not captured TCP packets**, a TEE deployment or a complete model of resource side channels.

## Modes

| Mode | Invocation/data encryption | ORAM | PIR | Fixed-rate cover | Staged/padded executor |
| --- | --- | --- | --- | --- | --- |
| A | No | No | No | No | No |
| B | Yes | No | No | No | No |
| C | Yes | Yes | No | No | No |
| D | Yes | No | Yes | No | No |
| E | Yes | No | No | Yes | No |
| F | Yes | No | No | No | Yes |
| G | Yes | Yes | Yes | Yes | Yes |

The direct encrypted store uses fresh OS-generated per-session keys and unique counter nonces with address AAD. It deliberately reveals addresses. PIR scans all five 128-byte records at both servers; directional AEAD independently protects their links from the joint network observer. Every reconstructed record is checked against trusted deployment metadata. Servers must not collude. All modes execute actual echo or stateful WASM and compare real results to an independent client oracle. Dummy work targets a separate namespace. F and G stage eight blocks, execute guest accesses in trusted memory, and write all eight blocks back; this is a bandwidth-for-shape trade-off, not automatic data-oblivious WASM.

The shuffled workload is exactly half dummy opportunities, one quarter real echo and one quarter real stateful, with fresh sessions and deterministic workload seeds. Without batching no message is sent at dummy opportunities; E/G emit cover at each opportunity. Thus absence and participation are legitimately visible baseline features. The 100 ms execution class and 110 ms epoch are public. Serial scheduling, overdue emissions and OS jitter are measured, not assumed away.

## Reproduction

```sh
.venv/bin/python scripts/evaluate_system.py experiments/configs/system-30.json experiments/results/system-NEW
.venv/bin/python -m research.analysis.system experiments/results/system-NEW
cargo test -p oblivion-harness --test system
.venv/bin/python -m unittest research.tests.test_system
```

The runner refuses existing outputs, builds a release executable and copies it into a private temporary directory. Its SHA-256 is captured **before launch**. Configuration, seeds, trial/session counts, Rust/Python versions, hardware, process counters, source/analysis hashes, exact invocation and output directory are recorded. Concurrent source changes are visible in before/after hashes; the executable remains fixed. Crypto entropy comes from the OS and is not replayed from the workload seed.

Observer, ground-truth, private and benchmark records are distinct files. Full encrypted frames and physical storage sequences are retained. Private data must not be made available to the attacker merely because the experiment writes it to disk. The current attack uses twelve explicitly listed size/timing/address/count/startup summary features from public observer records. It does **not** exhaust the full recorded sequences, all cross-request correlations, billing counters or an individual PIR server's plaintext view. A future stronger attack may succeed.

Each independent trial fits a new bounded bootstrap forest on two complete profiling sessions and evaluates on two separate target sessions. No underlying session is split across training and testing. Target labels enter scoring only. Results include three-class accuracy and balanced accuracy, majority baseline, top-2, real/dummy accuracy/AUC and conditional function accuracy. Confidence intervals resample fitted-model trial means. The plaintext positive control must exceed balanced chance by 0.1 before comparison is accepted. Chance-like results are not a security proof.

## Timing and resource boundaries

The response timestamp is taken after authenticated response construction and **before** plaintext result validation, response trace serialization, client decryption and storage trace serialization. Result visibility uses a full-length byte mask in the protected mode. Baseline absence is recorded as zero API latency; report real-invocation and opportunity distributions separately when comparing service performance. Overall opportunity wall occupation and coarse process CPU ticks/RSS additionally include harness work. Linux tick/page sizes are in metadata. RSS includes shared engines and baseline state; it is not isolated component memory.

Initialization/precompilation is measured separately as public cold-start instrumentation and excluded from steady invocation response latency. Registered modules are warm for the session. Compiler/host memory is not bounded by guest fuel/memory limits. Latency here is serialized component-boundary latency; the independent process open-loop benchmark measures offered-load queues and drops.

## Superseded pilot

`experiments/results/system-30-20261021/` is an explicitly stopped 18-trial pilot. Review found that plaintext oracle work preceded its response timestamp and trace serialization inflated its reported latency. Its raw data and live executable-inode hash are preserved for diagnosis; it is not accepted final evidence. `PILOT_NOT_ACCEPTED.md` and its nonzero run return code document this. The corrected experiment uses a new output directory and the boundaries above.

Accepted measurements and figures will be linked after the corrected run finishes; an in-progress configuration is not a result. The ORAM-size study is independently recorded in `experiments/results/oram-size-30-20261021/`: 30 fresh controllers per size, 16/64/256/1024 blocks of 256 bytes, actual reads/writes, raw compressed traces and regenerable `oram-size.png`. Its latency statistic is the mean of per-trial read/write p95 values, not a pooled p95 or network latency.

## Accepted publication-scheduled run

`experiments/results/system-fixed-publication-30-20261022/` contains 30 completed trials, four independently initialized sessions/trial, 16 observations/session and all seven variants: **13,440 actual opportunities**. The plaintext control completed with 100% balanced accuracy. G reached **33.40% [32.29%,34.51%]** balanced accuracy against 33.33% chance; raw accuracy 48.96% against 50% majority. Real/dummy accuracy was 50.83% [47.81%,53.54%], and conditional real-function accuracy 48.96% [45.83%,52.29%]. These finite, feature-limited scores do not prove privacy. Individual variants A–D remained perfectly recoverable to this classifier, E reached 97.36% and F 98.89% balanced accuracy.

The accepted run precomputes client frames and releases them to the queue at the public epoch boundary. `prepare_scheduled` performs the fixed read/commit phases but returns a **private** result before the class deadline, permitting trusted response masking/encryption before publication at that deadline. The process worker also flushes its trace instrumentation before waiting, and fixes sequential slot origins relative to the batch origin. This avoids letting postvalidation work set the next client release or response construction follow the padding target. If a workload or host overruns its reserved phase, lateness remains visible; this is an operational requirement, not constant-time execution.

G's real-invocation response p95/p99 were **100.159/100.200 ms**. Mean measured opportunity wall occupation was **116.268 ms**, including scheduled idle, validation and serialization; useful finite-session throughput was **4.300 real invocations/s** at 50% dummy traffic. Those wall quantities must not be calculated by summing response latencies alone. Payload traffic was **82,484 bytes/real invocation**, including cover, both PIR links and actual bucket messages. This is API payload accounting, not TCP egress billing. The report separates real/opportunity quantiles, mean trial p95 uncertainty, driver readiness overruns and measured publication lateness.

Figures `latency-privacy.png`, `bandwidth-privacy.png`, `cost-attack.png`, `ablation-attacks.png` and `pareto-three-axis-slo.png` regenerate from raw data. Pareto membership uses measured point estimates, with explicit 100/110 ms operational p95 filters; it is not statistically established dominance. The illustrative cost model uses 0.00001 cost units per executor wall second and 0.1 units per GiB of client response payload; these are declared hypothetical inputs, not provider prices.

The preceding `system-30-corrected-20261021` run is retained as a composition investigation: its conditional real-function accuracy was 54.58% [50.21%,59.17%] under the prior release/publication behavior. This is weak evidence of a possible residual amid multiple exploratory metrics, not a proven causal leak. The implementation was strengthened and the full experiment rerun; the earlier result was not erased or relabeled as security. The final report records the exact analysis/attacker source hashes and immutable executable hash. Git HEAD in older runner metadata is the metadata-writing-time revision; launch-time source/executable hashes are authoritative when commits advanced during a long run.
