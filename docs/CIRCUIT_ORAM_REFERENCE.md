# Matched Path/Circuit ORAM reference benchmark

This O12 evaluation uses the genuine existing MobileCoin `mc-oblivious-ram` Path and Circuit ORAM implementations, version **2.3.0**, as an external algorithm benchmark. It compares both vendor implementations with the same unencrypted heap storage, logical block size, bucket capacity, stash capacity and workload. It does not replace Oblivion's encrypted Path ORAM implementation or compare these timings directly against that implementation.

The separate `research/oram_reference/` Cargo workspace and executable are GPL-3.0; upstream sources are Copyright (c) 2018–2023 The MobileCoin Foundation. The exact package versions and registry checksums are retained in its independent `Cargo.lock`, with the upstream GPL license text in `LICENSE`. Oblivion's workspace has no dependency on this program. Sources: [mc-oblivious-ram 2.3.0](https://crates.io/crates/mc-oblivious-ram/2.3.0), its [versioned API](https://docs.rs/mc-oblivious-ram/2.3.0/mc_oblivious_ram/), and the [upstream repository](https://github.com/mobilecoinfoundation/mc-oblivious).

## Reproduction and provenance

```sh
cargo build --locked --release --manifest-path research/oram_reference/Cargo.toml
cargo test --locked --manifest-path research/oram_reference/Cargo.toml
cargo fmt --manifest-path research/oram_reference/Cargo.toml -- --check
cargo clippy --locked --manifest-path research/oram_reference/Cargo.toml --all-targets -- -D warnings
.venv/bin/python -m unittest research.tests.test_oram_reference
.venv/bin/python scripts/evaluate_oram_reference.py \
  --config experiments/configs/circuit-reference-30.json \
  --output experiments/results/circuit-reference-new
```

The runner checks adapter source stability across compilation, copies the executable into the fresh result directory's ignored `bin/`, snapshots adapter/lock/license sources, and writes `provenance-before.json` before the first measurement. It records compiler, CPU/platform, configuration, Git state, feature assumptions, registry package metadata/source hashes and frozen executable hash. Each launch checks the frozen binary, and `provenance-after.json` records its final hash and adapter source hashes. Per-process logs, original raw samples compressed after each successful run, trial summaries, bootstrap report, plot and artifact hashes are retained in `experiments/results/circuit-reference-20261023/`. A failed upstream process leaves its log and any partial raw output rather than yielding a successful summary.

The adapter validates algorithm, power-of-two record count, operations and warm-up bounds before constructing an ORAM or opening the output file. Unit/integration tests cover these bounds and genuine full-record runs of **both** algorithms. The program uses the upstream default assembly implementation on Linux x86-64; `no_asm_insecure` is not enabled. This does not establish resistance to all hardware side channels.

## Matched method

The four cells are Path/Circuit × 64/1,024 logical records. Each record is 1,024 bytes, each storage bucket holds Z=4 records (4,096 payload bytes plus metadata), and stash capacity is 128. Each cell has 30 fresh process/controller trials. Both algorithms use the vendor `HeapORAMStorageCreator`, which copies data in trusted heap memory and **does not encrypt storage**. No enclave, remote server or untrusted backend is involved. At these sizes the vendor position-map creator selects its `TrivialPositionMap` path (the upstream threshold is 4,096), so this experiment does not benchmark recursive position-map levels.

The program calls the unmodified `PathORAM4096Z4Creator` or `CircuitORAM4096Z4Creator` API. Both instantiate the vendor's shared ORAM framework with different eviction strategies. The Circuit creator selects the upstream Circuit eviction strategy with two additional deterministic branch evictions; Path uses its own dense eviction strategy with zero additional branches. Their performance difference is an observation about these two implementations/configurations, not a general asymptotic or cryptographic comparison.

Each controller RNG requested by the upstream maker is a fresh `ChaCha20Rng::from_entropy`, seeded through the OS. A separate seeded RNG selects logical data, addresses and 50/50 read/write decisions. Every logical record is materialized before measurement. Sixteen checked warm-up reads are excluded, followed by 512 measured uniformly addressed operations. Every measured read and the **old value returned by every measured write** is compared against a `HashMap` oracle of complete 1,024-byte values, after stopping the operation timer. A final untimed full-dataset read audit checks every record, including writes not selected again during measurement.

Creator/allocation time is recorded separately as `setup_ns`; initialization writes, warm-up, final audit, oracle comparison and JSON output are excluded from measured operation latency. In-memory upstream work and its own allocations remain included. Scheme order is shuffled within each trial using a recorded order seed. Shared-host scheduling, CPU/cache state and compiler optimization remain uncontrolled.

There are **61,440 measured operations** and **193,920 complete-record oracle comparisons**, including initialization returns, warm-up, measured API outputs and final audits. Private post-access stash occupancy is recorded after every measured access. It is a diagnostic, not a server observable or a rare-overflow probability estimate. Backend bytes and network bandwidth were not instrumented; the report makes no fabricated byte-count or network-throughput claim.

## Observed results

Every trial completed with its oracle checks passing. The frozen executable and adapter source hashes matched before/after measurement. The campaign ran from 2026-10-23 08:04:34 to 08:05:14 UTC.

| Logical records | Reference algorithm | Mean trial p50 / p95 / p99 (µs) | 95% trial CI for mean p95 (µs) | Maximum measured stash |
|---:|---|---:|---:|---:|
| 64 | Path | 204.99 / 259.11 / 302.10 | 239.63–281.39 | 3 |
| 64 | Circuit | 49.91 / 56.73 / 68.95 | 53.18–60.47 | 0 |
| 1,024 | Path | 368.39 / 410.86 / 451.51 | 393.95–433.38 | 6 |
| 1,024 | Circuit | 60.49 / 65.00 / 70.26 | 63.71–66.62 | 0 |

The Circuit reference was faster and retained fewer post-access stash blocks in this bounded heap-backed experiment. Zero observed post-access stash occupancy does not imply zero temporary occupancy, zero failure probability or a universal performance ordering. Creator-only mean times were approximately 133.87/121.55 µs for Path/Circuit at N=64 and 445.98/443.79 µs at N=1,024; these exclude materializing the logical dataset.

`summary.json` retains separate read/write/all-operation p50/p95/p99 summaries and stash histograms; `trial-results.json` retains every trial estimate. Intervals are percentile bootstraps of 30 trial quantile estimates, with 5,000 resamples. Operations within a controller are not counted as independent controller trials. `circuit-reference.png` plots mean trial p95 and observed stash maxima. The retained data/log/source/report artifacts total about 0.93 MB, excluding ignored binaries.

This supplies a reproducible external Circuit ORAM reference point for O12. Larger databases, recursive position maps, different bucket sizes, network/storage encryption, TEE execution, formal stash bounds and a storage-adversary security evaluation remain outside its scope.
