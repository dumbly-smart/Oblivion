# Eight-class execution timing and error evaluation

21 October 2026. This scoped experiment evaluates five actual successful WASM functions and three actual failure paths under the existing 100 ms `Class::small` budget. It uses genuine directional authenticated envelopes and actual Path ORAM, with no claim of TEE protection or constant-time execution. The completed 30-trial campaign is recorded below.

## Mechanism and timing boundary

The Rust `timing_measure` example registers the bundled echo, sum, Fibonacci, checksum and stateful functions plus modules that actually trap, exhaust fuel or exceed the memory resource limit. Each fresh process has a new executor, ORAM controller and OS-random invocation endpoint keys. One independently shuffled invocation of each class makes eight observations/session. All functions receive the same 64-byte input. Independent client checks verify complete expected output/status after the response timestamp; failures have encrypted zero output.

The measurement starts when the server receives an already constructed encrypted request and ends immediately after its authenticated encrypted response exists. It includes request authentication, actual execution/storage work, padding where enabled and response encryption. It excludes client-side request construction, client response decryption, plaintext oracle checking, trace extraction and JSON serialization. Registration/precompilation and store/key setup are recorded separately as startup; no cold-compilation hiding is claimed. Guest instantiation remains inside invocation execution. Output/status/label checking never determines the recorded response timestamp.

Protected execution uses the normal staged schedule: eight actual ORAM reads and eight actual ORAM writes, fixed class response body, public read/commit phases and deadline. Every observed request/response is a genuine 164-byte directional AEAD frame. Complete ciphertexts and physical bucket traces are retained. Each successful-function or failure class has one observation per session, with statuses saved only in separate ground truth. The class parameters are not enlarged for this experiment. Host jitter and late storage can still overrun the target.

## Attacker and control

Before running protected evaluation, the campaign executes a deliberately leaky positive control through the actual unpadded executor. That control additionally publishes the function/error selector, which is explicit auxiliary observation, and may expose guest-dependent physical storage counts. It validates the numerical classifier and class mapping; it does not establish that timing alone separates all eight paths. Response transport remains encrypted and fixed-size in both modes.

The same fixed-unit nearest-centroid algorithm trains separately for each mode/trial. Its six public summary features are response latency in seconds, request length, response length, storage event count, summed bucket bytes and the deliberately public selector. In protected mode the selector is absent (`null`) and maps to a constant. Request/response ciphertexts and full physical traces are saved, but this attacker does not exploit their contents/sequences or broader temporal correlations. Source knowledge, budgets and feature units are public. Target workload seeds and process launch commands are evaluator provenance, excluded from attacker auxiliary knowledge because they reproduce synthetic target ordering. Labels/status/work counters cannot enter the strict observer schema. The inferred privacy claim is restricted to the declared observer features, not an observer granted these target seeds.

Each of 30 trials trains on two complete profiling sessions and evaluates two other target sessions, with no session split across training/testing. Every session contains all eight classes once, so both chance and majority are 1/8. Scores include accuracy, balanced accuracy, top-three and success/error-subset top-one accuracy; the subset metrics still predict among all eight labels, rather than retraining a five-way or binary classifier. The 5,000-resample percentile intervals use whole fitted-model trial means. Queries sharing an estimated model are not independent samples.

A successful visible-selector control does not prove that the protected attacker is powerful. In particular, a fixed centroid can miss nonlinear timing/multimodal signals, physical leaf correlations, ciphertext implementation errors and stronger inference. Any observed advantage or failure is reported honestly; chance-like accuracy does not prove indistinguishability.

## Reproduce

```sh
cargo build --locked --release -p oblivion-exec --example timing_measure
cargo clippy --locked -p oblivion-exec --example timing_measure -- -D warnings
EXEC_TIMING_BINARY=target/release/examples/timing_measure \
  .venv/bin/python -m unittest research.tests.test_execution_timing -v
.venv/bin/python -m research.analysis.execution_timing \
  experiments/results/execution-timing-NEW --trials 30
```

The runner refuses an existing directory, copies the executable into the campaign's `bin/`, hashes it before launch and verifies the same hash after all trials. It records source/script hashes, Cargo.lock, compiler/Python/NumPy, hardware, command, seeds, counts, startup and per-session process launch records. Each mode has 120 fresh processes and 960 invocations; protected time is approximately 96 seconds plus startup. Cryptographic randomness is not seeded by workload RNG. Measurements use a shared host with no CPU affinity or resource isolation.

Ordinary Python discovery runs two cheap classifier/schema tests and explicitly skips the actual Rust smoke unless `EXEC_TIMING_BINARY` is provided. The documented scoped command enables it and verifies real eight-class outputs, all 128 bucket events/invocation, fixed envelopes and actual minimum protected elapsed time. These are scoped checks, not a substitute for workspace validation or hosted CI.

## Recorded evidence

The campaign output is `experiments/results/execution-timing-30-20261021/`. `provenance.json` records the immutable binary/source/environment; `report.json` records per-trial scores and trial-cluster intervals; per-session observer/truth/metadata/launch records retain actual measurements. The plot is generated only after both modes finish and the positive control has passed. A configuration or running process is not a completed result.

## Completed results

The leaky selector control completed first and reached **100% accuracy/balanced accuracy/top-three**, with [100%,100%] finite trial-bootstrap intervals. Only then did the protected campaign execute. This positive control deliberately grants the selector; it is not evidence that timing alone distinguishes all classes.

| Protected score | Mean | 95% fitted-trial interval | Relevant chance |
| --- | --- | --- | --- |
| Eight-class accuracy / balanced accuracy | 11.67% | 9.38–13.75% | 12.5% |
| Top-three | 38.54% | 34.38–42.50% | 37.5% |
| Top-one, five-success subset | 13.33% | 10.00–16.33% | 12.5% among eight predictions |
| Top-one, three-error subset | 8.89% | 5.00–13.33% | 12.5% among eight predictions |

[Full report](../experiments/results/execution-timing-30-20261021/report.json), [figure](../experiments/results/execution-timing-30-20261021/execution-timing.png), [shape audit](../experiments/results/execution-timing-30-20261021/shape-audit.json) and [provenance](../experiments/results/execution-timing-30-20261021/provenance.json).

All **960 protected observations** passed their independent expected-status/output oracle. Every one has 164-byte requests/responses and exactly 128 actual physical bucket events of 316 bytes, totaling **122,880 protected bucket events**. All selectors are absent in protected observer data. No executor `deadline_missed` flag was recorded; that flag measures executor work against the budget, not an assertion of a perfectly timed response boundary. Mean observed response boundary was **100.124 ms**, including padding and response AEAD. Class means ranged from 100.113 to 100.149 ms. These small observed differences are retained rather than rounded into an equal-time assertion.

The copied executable SHA-256 was unchanged before/after all 240 fresh processes: `5b56a61f98187865f2390ebf050c73be8622f6a7c9e654a6f1dfbe0a2f15f5ab`. Scoped release build, warning-denied example Clippy and all three Python tests (including real Rust smoke) exited zero. The initial build exposed a fixed-array serialization error, corrected by serializing byte slices before the accepted run; the successful campaign used the corrected copied binary. Hosted CI and unrelated workspace checks are not claimed here.

The chosen centroid did not demonstrate an advantage over the relevant baseline. Its limited features, short sessions and simple decision rule may miss exploitable residual timing or full-trace correlations. Neither the finite intervals nor the passing fixed-shape oracle prove indistinguishability of success, traps and resource failures to every attacker.
