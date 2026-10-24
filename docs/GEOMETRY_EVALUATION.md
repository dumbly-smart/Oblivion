# Bounded ORAM and PIR geometry evaluation

The campaign in `experiments/results/geometry-20261022/` supplies measured geometry evidence for O04/O07/P04 and the ORAM/PIR portion of M05. It contains 36 ORAM cells and six PIR cells, with 30 fresh independent controller or server-state trials per cell. It does not establish stash failure bounds, network performance, production throughput, or cryptographic security.

## Reproduce and inspect

From the repository root, using the research environment with NumPy and Matplotlib installed:

```sh
.venv/bin/python -m unittest research.tests.test_geometry
.venv/bin/python scripts/sweep_geometry.py experiments/results/geometry-new
.venv/bin/python scripts/sweep_geometry.py experiments/results/geometry-20261022 --plot-only
```

The first measurement command builds the two release examples, copies frozen executables into the result directory's ignored `bin/`, and writes `provenance.json` **before** measurement. The provenance records compiler, hardware, dirty Git status, source file hashes, executable hashes, configuration and seeds. Raw output is never overwritten. Each completed cell's raw traces are compressed immediately. `sha256.json` covers retained result artifacts, excluding itself and ignored binaries; executable hashes remain in provenance. The archival full grid is `experiments/configs/geometry-30.json`; the runner generates the same bounded grid.

Reanalysis requires the existing `sha256.json` baseline and verifies every recorded file, including derived reports and plots, before overwriting anything. Changed, missing or unexpected raw/derived artifacts stop regeneration; no manifest is silently rebuilt from altered raw data. Only the four declared derived report/plot hashes may change after successful regeneration. Raw/configuration/provenance hashes remain copied from the accepted baseline and are checked again after analysis. Direct creation of a new manifest also refuses to replace an existing baseline. `analysis_revisions_sha256` records successive analysis sources and `measurement_provenance_sha256` anchors the original measurement provenance; original campaign source/executable fingerprints stay unchanged.

The collected runs started at 2026-10-22 20:15:40 UTC (2026-10-23 local time), using an Intel Core i7-14650HX, Linux x86-64, Rust 1.99.1, and LLVM 23.1.3. The directory date is the campaign identifier. The initial plotting command used a system Python without Matplotlib and stopped after collecting all raw data. Analysis and figures were then regenerated with `.venv/bin/python`; no measurements were substituted. The premeasurement runner hash and current analysis hash are both retained, since analysis subsequently added observer consistency validation, p50/p99 and a width figure. Measurement executable sources and binary hashes match provenance.

## ORAM method and findings

The grid crosses logical block counts 64/256, block widths 64/256/1024 bytes, Z=3/4/5 and same-address/uniform workloads. Each trial creates a fresh OS-random encrypted Path ORAM, materializes every logical record, excludes 16 warm-up accesses, then measures 128 operations with a seeded 50/50 read/write workload: 138,240 measured operations overall. The workload seed controls logical addresses and data only. A full-record plaintext oracle checks every measured read. Timing excludes oracle validation and trace serialization. Core API/backend timing and in-memory trace collection remain included. Initialization and warm-up are excluded from latency.

Each genuine private trace records the post-eviction stash after every measured access. Analysis reconstructs its histogram, compares it with the Rust trial histogram and checks completeness. Observer trace event counts, total bytes and fixed bucket sizes are checked against the public geometry for every trial. The stash maximum below means the largest observed **post-eviction** measured stash, across the cell's 3,840 accesses. `private_state.max_stash_blocks` is a separate implementation diagnostic that may include initialization/warm-up; it is not substituted for the measured trace histogram.

At N=256 and 256-byte blocks, uniform accesses yielded:

| Z | Mean trial p50 / p95 / p99 (µs) | 95% trial CI for mean p95 (µs) | Measured stash maximum | Encrypted bytes/access | Encrypted storage bytes |
|---|---:|---:|---:|---:|---:|
| 3 | 41.25 / 43.07 / 44.18 | 42.93–43.21 | 5 | 14,760 | 419,020 |
| 4 | 46.39 / 48.95 / 50.74 | 48.05–50.22 | 3 | 19,512 | 553,924 |
| 5 | 50.61 / 53.33 / 55.61 | 52.66–54.54 | 1 | 24,264 | 688,828 |

The trusted metadata diagnostic for these cells is 6,136 bytes, plus a configured stash payload allowance of 32,768 bytes. This is implementation payload accounting, excluding allocator overhead, temporary buffers, oracle memory and process/library memory. Across all 36 cells the largest measured stash was seven blocks. These finite runs describe observed stash occupancy; they do not estimate rare overflow probabilities or prove a recommended Z. The core stash limit is 128 for this experiment.

`oram-geometry.png` shows Z, latency and observed stash at 256-byte blocks. `oram-width.png` shows the measured width tradeoff for uniform N=256: per-access encrypted bytes divided by logical block bytes and latency. All sizes, trials, p50/p95/p99, histograms, storage expansion and trusted memory diagnostics remain available in `summary.json`.

## PIR method and findings

The PIR grid crosses 64/1,024/10,000 records with 64/1,024-byte record widths. Each trial creates two independently owned database states, warms one query, then measures 16 seeded target queries using fresh OS-random XOR shares. There are 2,880 measured queries. Every recovered record is checked byte for byte against a nontrivial full-record oracle, outside the timed recovery interval. Query generation, each serial server answer, and recovery have separate wall-clock measurements. State construction is excluded.

| Records/server | Record bytes | Mean serial total (µs), 95% trial CI | In-process two-server full-scan rate (decimal GB/s), 95% trial CI |
|---:|---:|---:|---:|
| 64 | 64 | 1.065 [1.034, 1.099] | 11.10 [10.77, 11.47] |
| 64 | 1,024 | 2.518 [2.487, 2.552] | 60.42 [59.63, 61.20] |
| 1,024 | 64 | 11.559 [10.947, 12.212] | 12.27 [11.65, 12.88] |
| 1,024 | 1,024 | 45.310 [38.619, 52.943] | 54.14 [48.21, 59.61] |
| 10,000 | 64 | 114.462 [113.061, 116.512] | 11.49 [11.31, 11.61] |
| 10,000 | 1,024 | 519.996 [507.850, 533.852] | 39.83 [38.83, 40.75] |

The scan rate is `2 × count × width / (server1_ns + server2_ns)` within each trial, aggregating all 16 queries before division. Decimal bytes/ns numerically equal GB/s. Both servers execute serially in the same process. Small databases can reside in CPU caches; these rates are an algorithm microbenchmark, with no claim of DRAM bandwidth, encrypted transport throughput, network capacity or production GB/s. Serial total adds generation, both server answers and recovery and excludes validation, initialization and scheduling between queries.

The two query shares together occupy 16/256/2,500 payload bytes at N=64/1,024/10,000, independent of target index. Two answers occupy 128 or 2,048 payload bytes, depending only on record width. Database payload memory is `2 × count × width` for the two owned states, reaching 20,480,000 bytes for the largest cell. Allocator/object overhead and temporary query/result buffers are excluded. These are plaintext protocol payload formulas; this example does not measure authenticated transport framing. Generation/server/recovery means, CIs and per-trial raw timing samples are retained, and `pir-geometry.png` plots total latency and scan rate.

## Statistical scope and remaining work

All intervals resample 30 trial estimates, using 5,000 percentile bootstrap resamples. ORAM quantiles are computed separately within each trial using NumPy linear interpolation; the report summarizes their means rather than claiming a pooled population p99. PIR means aggregate 16 queries within each trial; queries within a trial are not treated as independent replicas. Workload seeds intentionally match across geometry cells; comparisons are descriptive. No multiple-comparison significance tests or host-noise controls were applied.

O04/O07 now have a bounded Z/width/N/workload sweep with genuine stash samples, latency quantiles and payload diagnostics. P04 now has a bounded full-scan throughput curve and fixed payload accounting. M05 has additional measured ORAM/PIR axes. Larger N, longer same-address runs, rare stash overflow analysis, full process memory, remote servers, cache controls, concurrent/open-loop load and network measurements remain outside this evidence. Other M05 axes require their own evidence. Two-server privacy still assumes non-collusion, and none of these measurements is a privacy proof.
