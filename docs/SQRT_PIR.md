# Square matrix two-server PIR

The crate now provides a working square-root communication variant beside its basic two-server XOR scheme. [The implementation](../crates/oblivion-pir/src/sqrt.rs) reuses the existing masked full scan and CSPRNG query-share generator. [The measured sweep](../experiments/results/sqrt-pir-20261023/report.json) compares actual calls to both constructions; [raw samples](../experiments/results/sqrt-pir-20261023/measurement/private-samples.jsonl), [query-bit diagnostics](../experiments/results/sqrt-pir-20261023/measurement/query-bit-diagnostics.jsonl), [figure](../experiments/results/sqrt-pir-20261023/sqrt-pir.png) and [provenance](../experiments/results/sqrt-pir-20261023/provenance.json) are retained.

## Primary source and construction

Chor, Goldreich, Kushilevitz and Sudan, *Private Information Retrieval*, Journal of the ACM 45(6), 1998, [primary paper, §3.1 and §3.4 / Corollary 3.4.1](https://www.cs.umd.edu/~gasarch/TOPICS/pir/first.pdf), describes uniform-subset XOR queries and the matrix transformation yielding two-server square-root communication. Section 4.1 discusses fixed-size records. The [author's publication page](https://www.wisdom.weizmann.ac.il/~/oded/p_pir.html) provides the publication history and versions. This implementation adapts that generic transformation to byte records, transposing its matrix orientation so the privately retrieved vector is called a row. It does not implement the paper's more elaborate cubic-root construction.

For public record count `N` and fixed record width `B` bytes, let `r = c = ceil(sqrt(N))`. Lay out records in row order in a public `r × c` matrix and zero-pad unused cells. Each packed row is `cB` bytes. The client calls `QueryPair::generate(r, target / c)` to produce shares `q1` and `q2` with `q1 XOR q2 = unit_vector(target_row)`. Each server applies the existing `Database::answer` to its own independently owned packed rows and returns the entire masked row. The client XORs the responses and extracts its private column `target % c`.

`Geometry::new(N, B)` validates public dimensions; `Geometry::server(records)` creates one server state; `Geometry::query(target)` returns the transport query shares and separate `Recovery` state. The column is private inside `Recovery`, which has no `Debug` or serialization implementation. Neither the query payload nor the server state contains that private column. The client receives the selected full row, so this is not symmetric PIR: it may learn other records in that row.

A single share is uniform and its translation by a fixed unit vector is also uniform. Consequently each individual query distribution is independent of row; column is absent entirely. This argument assumes secure independent randomness and non-colluding servers. Joint shares reveal the row, violating full target privacy even though they do not identify the column. No claim covers malicious answers, authentication, side channels, network metadata or a compromised client. The module does not introduce a transport wrapper or change the runtime registry's current basic-PIR selection.

## Communication, work and bounds

Per complete retrieval across both servers:

| Quantity | Basic XOR PIR | Square matrix variant |
| --- | --- | --- |
| Query payload | `2 ceil(N/8)` bytes | `2 ceil(r/8)` bytes |
| Response payload | `2B` bytes | `2cB` bytes |
| Bytes scanned per server | `NB` | `rcB` |

For fixed `B`, total communication is `O(sqrt(N))`. Each server still scans every padded database byte, `Theta(NB)`; packing changes constants and response size. These are payload bytes, without framing, authentication, packets or TCP overhead.

The public square layout balances record dimensions. It is not the byte-optimal rectangle for multi-byte records, because selecting a row costs approximately `r/4 + 2NB/r` bytes across both servers. Ignoring integer rounding and bounds, that expression is minimized near `r = sqrt(8NB)`, with `c = N/r`. The implementation deliberately uses the roadmap's square variant; choosing a public rectangle based on record width is separate work. In particular, lower query bytes need not mean lower total communication.

Checked integer arithmetic and existing typed `Error` variants reject invalid dimensions before row allocation. Original dimensions obey the crate's existing limits; additionally, the entire padded payload per server is at most 64 MiB and each packed row/response at most 1 MiB. The padded cap can reject a database whose unpadded payload would fit. These are payload bounds, not a claim that setup peak memory is 64 MiB: packing temporarily owns input records and packed rows, and a deployment stores two independent copies. Invalid target indices, wrong input counts/widths, malformed query lengths and non-row-sized responses return typed errors. Responses remain unauthenticated.

## Reproduce and validation

With the research Python dependencies installed:

```sh
cargo test -p oblivion-pir --test sqrt
cargo clippy -p oblivion-pir --lib --test sqrt --example sqrt_measure -- -D warnings
.venv/bin/python -m unittest research.tests.test_sqrt_pir -v
.venv/bin/python scripts/evaluate_sqrt_pir.py --output experiments/results/sqrt-pir-new
```

The driver builds only the release example, copies it into ignored output `bin/`, hashes that private copy before any measurement and verifies it after the complete campaign. All measurement subprocess work uses that copy. Source hashes before/after and an immutable config copy identify the run; raw-file, report and plot hashes are in provenance. The Python test executes a private copy successfully after replacing the original executable path with a failing program. A separate full-record integration test exercises the actual Rust matrix implementation, rather than a Python simulation.

Five Rust tests pass: all-index/full-record retrieval on square and non-square databases, independent server states, zero-padded final-row recovery, maximum/overflow and padded-cap rejection, malformed dimensions/messages, and the row revealed by joint shares. Three Python tests pass for trial clustering and paired analysis, missing/duplicate-sample rejection and executable isolation. Both suites first failed for their missing new feature/API before implementation; scoped Clippy with warnings denied passes. Full workspace integration gates are coordinated separately by the parent task.

## Measured comparison

The campaign uses `N = 64, 1024, 10000`, `B = 8, 1024`, with 30 fresh independently owned server-state pairs per mode/geometry and 16 complete retrievals per trial: 5,760 verified full-record retrievals. Each paired trial uses the same seeded uniformly sampled workload indices, with randomized mode order. CSPRNG query shares come from production `OsRng`, never the workload RNG. Setup is excluded; one warm query precedes each mode. Times are sequential local generation + server 1 + server 2 + recovery, not network latency. Both servers perform full scans.

| N | B | Basic query + answer bytes | Matrix query + answer bytes | Basic mean local time, µs (95% trial interval) | Matrix mean local time, µs (95% trial interval) |
| --- | --- | --- | --- | --- | --- |
| 64 | 8 | 16 + 16 = 32 | 2 + 128 = 130 | 1.059 (1.024–1.098) | 0.523 (0.501–0.551) |
| 1024 | 8 | 256 + 16 = 272 | 8 + 512 = 520 | 9.515 (9.332–9.731) | 0.855 (0.845–0.865) |
| 10000 | 8 | 2500 + 16 = 2516 | 26 + 1600 = 1626 | 123.096 (119.195–126.831) | 5.230 (3.565–8.309) |
| 64 | 1024 | 16 + 2048 = 2064 | 2 + 16384 = 16386 | 2.202 (2.169–2.241) | 2.075 (2.014–2.147) |
| 1024 | 1024 | 256 + 2048 = 2304 | 8 + 65536 = 65544 | 49.936 (40.407–63.015) | 54.912 (41.400–71.743) |
| 10000 | 1024 | 2500 + 2048 = 4548 | 26 + 204800 = 204826 | 634.448 (554.740–723.649) | 522.887 (467.806–588.139) |

At 10,000 eight-byte records, square packing reduces total payload from 2,516 to 1,626 bytes. For 1,024-byte records it increases payload at every measured size, by about 45× at 10,000 records. Local timing improvements for short records reflect fewer query bytes and fewer, wider records in the same full-scan loop, including different allocation/vectorization overhead; they do not imply sublinear server computation or network speedup. Host load, compiler and cache effects limit timing generalization. The fixed database contents are reused across fresh states, rather than representing independently collected data.

Intervals use 5,000 percentile bootstrap resamples of 30 whole trial means. Both modes' workloads are paired; the report also gives paired differences. Query samples within a trial are not treated as independent trials. The sweep's sizes happen to be perfect squares; non-square zero-padding and retrieval are covered by Rust tests.

For each mode/size/trial and four target positions, an additional 256 fresh production shares yield first-bit and final-byte high-bit balance diagnostics for each server separately. Across 192 summaries, observed one-fractions range from 0.4861 to 0.5132. Six unadjusted 95% intervals exclude 0.5; no multiple-comparison correction is applied. These diagnostics test two marginal bits, not the full distribution, correlations, timings or target recovery. The privacy rationale is the uniform-share argument above, with the stated threat model, rather than a claim that these diagnostics prove privacy.
