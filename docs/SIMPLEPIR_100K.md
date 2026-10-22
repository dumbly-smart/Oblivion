# Genuine SimplePIR 100k correctness campaign

This campaign addresses the roadmap's Layer 3 requirement to check LWE recovery over at least 100,000 queries at the tested parameters. `experiments/results/simplepir-100k-20261023/` retains 100,020 full-record oracle checks for genuine pinned SimplePIR and another 100,020 checks for the matched naive two-server XOR baseline, each across 30 fresh process/setup trials. The implementation is the existing unmodified Go/C reference, rather than a substitute LWE construction.

The reference remains pinned to `e9020b03bf2872c75b8954e749e32408b5db87ed`. The [pin metadata](../research/pir_reference/pin.json) records its repository, MIT license and [primary SimplePIR paper](https://www.usenix.org/conference/usenixsecurity23/presentation/henzinger). Algorithm details and randomness can be inspected in the [pinned upstream source](https://github.com/ahenzinger/simplepir/tree/e9020b03bf2872c75b8954e749e32408b5db87ed/pir). This campaign makes no new paper-performance comparison.

## Reproduce and provenance

```sh
.venv/bin/python -m unittest research.tests.test_simplepir_campaign
.venv/bin/python scripts/simplepir_reference.py \
  --config experiments/configs/simplepir-reference-100k.json \
  --output experiments/results/simplepir-100k-new
```

The original default configuration and invocation remain compatible. The 100k configuration requests 30 trials × 3,334 queries, compressed per-trial raw files and no duplicate aggregate raw copy. Fresh output directories are required; earlier 30×16 results remain unchanged.

The runner builds the genuine Go adapter and Rust XOR adapter, checks adapter/dependency source hashes remained stable across compilation, then copies both executables into the result directory's ignored `bin/`. It writes `metadata-before.json` containing source, configuration and frozen executable hashes before the first measured process starts. Every process runs a frozen executable; hashes are checked before each launch and after completion. `metadata.json` adds after-run executable/source hashes, commands, toolchain, CPU/memory information and result hashes. A later source change is distinguishable from the executable that produced the samples. Original reference code is checked against the pinned pristine checkout.

Every setup uses a newly started process. The reference initializes its AES-CTR pseudorandom generator with a key from Go's `crypto/rand`; LWE secrets/errors and setup randomness use the reference's normal cryptographic generator. The public seed controls the target-index schedule only. No cryptographic key/noise seed is fixed for reproducibility.

## Measurement and correctness scope

Both schemes use the same 10,000 records of eight bytes, with the full 64-bit record value `index × 0x9e3779b97f4a7c15 + 17` modulo 2^64. Every recovered output is compared with that complete value. One query per process warms the real online path and is excluded from the reported sample count and latency. Each trial then runs 3,334 measured target queries; the stride schedule traverses all 10,000 targets across the campaign. Each scheme therefore has 30 setup records and 100,020 measured query records. Analysis rejects missing, duplicate or out-of-range setup/query identifiers and nonboolean oracle results. The adapters abort on an oracle mismatch; a partial run cannot produce a successful complete campaign summary.

Database construction, shared-matrix initialization and hint preprocessing are timed separately. Online latency separately records query generation, server answer(s) and recovery. Timings exclude output validation, raw serialization, compilation, process launch, network transfer and authentication. Scheme order is shuffled per trial using the recorded public order seed. SimplePIR uses the existing adapter's `PickParams(10000, 64, 1024, 32)` and records the actual selected matrix/noise parameters in every setup row. The shared matrix is uncompressed and its upload is included in offline communication. Database distribution/replication is excluded for both schemes.

Online query/answer payloads, shared-matrix upload and offline hint download remain separate in `summary.json`; amortized communication is a stated formula over 1/16/1,000/1,000,000 queries, rather than an observed network cost. Query/answer times are local single-thread algorithm wall times, with the XOR servers executed serially. Cached execution, the different Go/C and Rust implementations, allocation and shared-host scheduling affect timings. This is not a production or remote-server benchmark.

## Observed results

Both schemes completed all **100,020 measured oracle checks with zero mismatches**, across 30 independent process/setup trials each. No setup's configured workload produced an observed failure. Both frozen executable hashes matched before/after measurement, and adapter/dependency source hashes remained unchanged across compilation and through completion. The run started at 2026-10-22 20:32:52 UTC and finished at 20:33:48 UTC (2026-10-23 local date).

Actual SimplePIR parameters were L=266, M=264, LWE dimension 1,024, log₂(q)=32, plaintext modulus p=991 and sigma=6.4. The logical database was 80,000 bytes; the packed server matrix scan was 93,632 bytes/query. These are the adapter's chosen small-database parameters, without an independent cryptographic parameter audit.

| Metric | Genuine SimplePIR mean [95% trial-bootstrap CI] | Naive XOR mean [95% trial-bootstrap CI] |
|---|---:|---:|
| Query generation (µs) | 327.77 [326.32, 329.47] | 2.69 [2.66, 2.75] |
| Server total, serial (µs) | 5.96 [5.90, 6.02] | 103.59 [102.67, 105.01] |
| Recovery (µs) | 24.65 [24.26, 25.03] | 0.037 [0.036, 0.039] |
| Online algorithm total (µs) | 358.38 [356.81, 360.18] | 106.32 [105.37, 107.80] |
| Database construction (ms/setup) | 1.30 [1.17, 1.43] | 0.70 [0.63, 0.77] |
| Shared matrix initialization (ms/setup) | 21.38 [20.40, 22.57] | 0 |
| Hint preprocessing (ms/setup) | 5.12 [4.96, 5.39] | 0 |

SimplePIR used 1,056 query bytes, 1,064 answer bytes, a 1,081,344-byte uncompressed shared matrix upload and a 1,089,536-byte offline hint download. XOR used 2,500 combined query-share bytes and 16 combined answer bytes, with zero scheme-specific offline exchange. At 1,000 queries per setup the stated communication formula is 4,290.88 bytes/query for SimplePIR and 2,516 bytes/query for XOR; these exclude database replication, network headers and authentication. At 1,000,000 queries the formula gives 2,122.17 versus 2,516 bytes/query. The experiment actually uses 3,334 measured queries per setup; it does not claim a million-query measured run.

The zero-failure query-level Wilson 95% interval is [0, 3.84054×10⁻⁵], and the exact zero-failure one-sided 95% upper reference is 2.99509×10⁻⁵ **only under the IID query model**. At the setup-event level the corresponding values are [0, 0.11351] and 0.09503 for 30 trials, **only under the IID setup-event model**. These numerical reference calculations do not convert dependent query observations into an LWE failure guarantee.

The retained compressed raw samples plus configuration/log/metadata/summary files total about 2.94 MB, excluding ignored binaries. Each raw trial file is the adapter's original output and carries local trial identifier zero, since each process runs one setup; the final summary assigns the campaign trial from the filename/command. Both identifiers and every query index are validated before aggregation.

## Statistical interpretation

The summary gives observed failure counts and fractions, together with a Wilson 95% interval and an exact zero-failure one-sided 95% upper reference under an **IID homogeneous Bernoulli query model**. Queries reuse the same setup/shared matrix/hint within each trial; 100,020 observations must not be treated as 100,020 independent setup trials. Those query-level intervals are conditional reference calculations, not calibrated setup-dependent bounds or cryptographic guarantees.

A second reference calculation uses 30 setup events, where failure means any oracle mismatch in that setup's finite configured workload. Its IID assumption is separately stated. This event does not cover every possible target/noise vector or an unbounded lifetime. No tested event failure implies no theorem about worst-case LWE failure probability. Fresh cryptographic randomness improves experimental coverage without proving either IID model.

Latency intervals bootstrap the mean of 30 trial means with 10,000 resamples. Queries within a trial are not counted as independent latency replicas. The retained per-trial setup and raw query records allow independent inspection and alternate analysis. The original small comparison and this longer correctness run answer different experimental questions; historical values are preserved.
