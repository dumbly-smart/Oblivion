# Joint observer test across 0%, 50% and 100% real load

This component experiment runs the actual `EpochBatcher`, monotonic timer and authenticated `Endpoint` implementation. It asks a bounded supervised attacker to classify the real-load fraction from joint arrival timing, emission timing, fixed wire shape, public slot/destination identities and public wire bytes. It measures local queue submission/emission events; it does not capture sockets or execute the downstream PIR/WASM/ORAM path.

## Workload and observation boundary

Each complete process has eight enrolled participants and 32 epochs of 10 ms. Every slot sends one fixed-size request every epoch. All 0%, 50% and 100% classes therefore produce 256 arrivals, 32 batches, eight frames per batch and 164 bytes per frame. At 50%, a fresh seeded permutation chooses exactly four real requests per epoch. Arrival phases are independently sampled within the epoch. Scheduling uses real sleeps and `Instant`; actual arrival and emission timestamps are exported without replacing OS jitter with ideal times.

Protected requests use fresh OS-generated endpoint keys in each process and actual AEAD send/receive calls. Both real and dummy requests are authenticated, fixed-size client envelopes. Trusted endpoints verify every full decrypted body. The observer sees the actual complete frame bytes, their public epoch/slot headers, arrival timestamps, emitted batch frames and emission timestamps. Its logical destinations are the batcher and executor endpoints; slots are public enrollment identities. No separate `real`, dummy count, load class, workload seed or planned-arrival field is present in an observer event. A separate private truth file records workload classes and per-request real/dummy flags.

The unprotected control uses genuine serialized plaintext request bodies at the same 164-byte shape. Body byte 20 is the public real/dummy opcode; the tag area is zero. These control frames are deliberately unauthenticated. The batcher queues their opaque bytes, and a trusted plaintext oracle checks their full contents. They are never presented as accepted AEAD ciphertexts. Thus the control exposes load through actual public wire bytes, rather than handing the attacker a private oracle field.

Each of 30 fitted-model trials uses two complete labeled profile processes per class and two complete held-out target processes per class. All twelve processes have separate seeded workload schedules and fresh endpoints; profile and target process IDs are disjoint. Their launch order is shuffled independently in each trial across roles/classes. The first campaign stage completes all plaintext-control trials and requires mean accuracy at least 80%, with the lower 95% whole-trial interval above one-third, before generating any protected process.

## Attacker and strict API

`BatchLoadAttack.fit(profiles, seed=...)` consumes authorized records with exactly `process_id`, `label` and `observations`. `run(trace, aux)` returns the common `PredictionResult`, with one class prediction for the complete target process, `confidence=None`, and feature/model metadata. Alternatively, `aux` can contain explicit profiles for an inline fit. The target process ID must be absent from the profiling IDs. Unknown/private fields, invalid labels, duplicate profiles, malformed frame headers, inconsistent batches and invalid timestamps are rejected.

The same 22-feature whitelist and deterministic nearest-class-centroid rule apply to both modes. It combines actual arrival/interarrival, emission and derived queue-wait statistics; frame and batch sizes; public slot/destination counts; and the fraction of actual body-byte-20 values equal to one. In the plaintext control, the last feature observes its public opcode; in protected requests the same byte is ciphertext. The classifier never receives target labels, truth files, launch plans or workload seeds as training/feature inputs. Process IDs are used only to enforce separation and are not features. This is a joint wire/metadata attacker, not a claim that timing alone achieves the reported accuracy.

The final rule averages the two authorized profile vectors for each class and chooses the closest class mean by squared Euclidean distance. Every feature participates. The metric uses fixed public units: arrival count / 4096; epoch count / 64; frame-length mean/std / 164; slot count / 64; destination count / 2; slot entropy / 6; all 12 timing statistics / 10,000,000 ns (the declared 10 ms cadence); batch-size mean/std / 64; and body-byte fraction unchanged. Equivalently, each raw feature receives weight `1 / scale²` in the squared distance. No standard deviation, target label, target-derived variance or protected result selects these weights. The JSON report retains fitted class means, rather than calling metric weights learned feature importance. Six training process vectors per trial are a small auxiliary sample. The result does not cover stronger attackers, alternative feature selection, long-term observations, real application traffic or changing enrollment/cadence.

## Preserved failed control and correction

The [initial control campaign](../experiments/results/batch-load-20261023/failed-control-report.json) used the forest's default square-root feature subsampling. It achieved 50.00% accuracy (95% whole-trial interval 43.33–56.11%) over 30 trials and 180 held-out control processes. The 80% gate failed, and no protected processes were generated. All raw control traces, private plans, original source snapshots and [retrospective failure provenance](../experiments/results/batch-load-20261023/failed-control-provenance.json) are preserved. The gate exited before terminal provenance was written; the retrospective file explicitly does not assert a start-time executable hash.

A regression then generated six actual plaintext profile exports and six independent target exports with unrelated timer jitter. It failed at four correct targets out of six with the original model. Allowing all features at each split made that small regression pass, but the [new 30-trial all-feature forest control](../experiments/results/batch-load-allfeatures-20261023/failed-control-report.json) still recovered only 55.00% (46.67–63.33%), so its gate also stopped before any protected process. Its source snapshots and raw evidence are preserved separately.

A replay regression from that second campaign, where the forest got zero of six control targets correct, first failed and then passed with the fixed-unit class-centroid rule. Replaying all 30 control trials with that rule recovered all control targets. These investigations used only plaintext-control evidence; no protected traces or labels existed. The final campaign uses a new seed, independent new processes and a new output directory. These failed controls show why successful controls are necessary even when a public signal seems obvious, and why the final result remains conditional on the disclosed classifier capacity.

## Reproduce and validation

With the locked research dependencies installed:

```sh
cargo test -p oblivion-batcher --example load_trace
cargo clippy -p oblivion-batcher --example load_trace -- -D warnings
.venv/bin/python -m unittest research.tests.test_batch_load -v
.venv/bin/python scripts/evaluate_batch_load.py --config experiments/configs/batch-load-centroid-20261023.json --output experiments/results/batch-load-new
```

Two Rust tests cover genuine plaintext-control wire, actual timer emissions and authenticated fixed batches for all three load classes. Seven Python tests cover strict observer schemas, truth-field rejection, profile/target separation, common result shape with absent calibrated confidence, actual protected exports and the noisy-control regression and replay of the preserved hard control. The new tests failed before implementation or before the model correction, then passed. Scoped Clippy passes. Full workspace gates are coordinated separately by the parent task.

The driver copies the release exporter into ignored output `bin/`, hashes it before any process launch, uses that private executable for the entire campaign, and verifies its hash afterward. Before the first measured process, it writes durable `provenance-before.json` containing binary/config/source hashes and tool/hardware details, and snapshots those exact sources. It also freezes config bytes and verifies source hashes afterward, including the registry dependency. Each original JSONL observer stream is gzip-compressed; truth stays in separate files. The profile labels are authorized auxiliary knowledge; private workload seeds exist solely for reproducibility and are not attacker inputs.

## Final campaign

The [final report](../experiments/results/batch-load-centroid-20261023/report.json), [predictions](../experiments/results/batch-load-centroid-20261023/predictions.json), [figure](../experiments/results/batch-load-centroid-20261023/batch-load.png), [durable prelaunch provenance](../experiments/results/batch-load-centroid-20261023/provenance-before.json) and [terminal provenance](../experiments/results/batch-load-centroid-20261023/provenance.json) record the completed fresh-seed campaign. It used 720 complete independent processes, 60 fitted models (30 per mode), 184,320 arrival records and 23,040 emission records. All 720 process IDs and workload seeds are unique. Every successful exporter authenticated and checked every protected full body, or checked the deliberately plaintext control body, before writing its trace; a failed oracle would terminate that process and abort the campaign.

| Mode | Fitted model trials | Held-out target processes | Accuracy / balanced accuracy | 95% whole-trial interval |
| --- | --- | --- | --- | --- |
| Actual unauthenticated plaintext control | 30 | 180 | 100.00% | 100.00–100.00% |
| Actual AEAD fixed batching | 30 | 180 | 28.33% | 22.78–33.89% |

Balanced three-class chance and the independently profiled majority baseline are both 33.33%. The protected interval includes chance. This specific attacker did not demonstrate a positive recovery advantage on these protected component traces. The point estimate below chance is not evidence of stronger privacy, and the result is not an equivalence test, timing-independence theorem or upper bound on stronger attackers.

Every process across all three classes and both modes has the same observed shape: 256 arrivals, 32 emissions, eight 164-byte frames per batch, slots 0–7 and the two public logical destinations. The attack also used the actual timing and public-byte features jointly; equal shape alone was not substituted for a fitted classifier evaluation. The two earlier failed forest controls are preserved methodological evidence and are excluded from this final positive-control/protected comparison.

Uncertainty uses 5,000 percentile bootstrap resamples of 30 whole fitted-model trial means. All six held-out target predictions stay within their trial; individual packets or epochs are not independent model trials. The control stage precedes the protected stage, so changes in host load between stages remain a limitation even though class/role launch order is shuffled within each trial. The metric weights were selected from public units while investigating controls, before protected data existed; its small class-centroid model may miss nonlinear leakage.

All 1,513 final artifact hashes, seven source snapshots/current-source hashes and the frozen binary's before/after hash were verified after completion. The final campaign took about 265 seconds locally. The source and binary remained unchanged throughout it. Both failed control campaigns were also checked against their retrospective artifact/source-snapshot hashes, with their stated start-time-provenance limitation preserved. Fixed shape and this classifier result do not establish cryptographic or full-system security.
