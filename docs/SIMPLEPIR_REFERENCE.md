# Genuine SimplePIR reference comparison

This adapter imports the authors' unmodified Go/C implementation of SimplePIR.
It implements no replacement PIR cryptography. The pinned commit is
[`e9020b03bf2872c75b8954e749e32408b5db87ed`](https://github.com/ahenzinger/simplepir/tree/e9020b03bf2872c75b8954e749e32408b5db87ed),
which matched the official repository HEAD when checked on 2026-10-20. Its commit
date is 2023-01-13. Upstream uses the MIT license; a copy is retained in
[UPSTREAM_LICENSE](../research/pir_reference/UPSTREAM_LICENSE). The reference's
`rand.go` also retains its original Henry Corrigan-Gibbs permission notice in
source. Fetching preserves that file unchanged.

The primary paper is Henzinger, Hong, Corrigan-Gibbs, Meiklejohn and
Vaikuntanathan, [*One Server for the Price of Two: Simple and Fast Single-Server
Private Information Retrieval*, USENIX Security 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/henzinger).
Its security is based on learning with errors. This differs from the project's
two-server XOR PIR, which requires the servers not to collude. Both answer
methods still perform work linear in their encoded database representation.
This local benchmark does not establish either implementation's deployment
security or reproduce the paper's large-database throughput claims.

## Reproduce

Requirements: Git, Python 3, Rust/Cargo, Go with cgo enabled, and a C compiler.
Upstream was originally tested with Go 1.19.1 and GCC 11.2.0. This recorded run
used Go 1.27.2 and GCC 16.2.1 on Linux/amd64; it passed both the adapter oracle
and the original upstream `TestSimplePir` correctness test. The upstream C
flags include `-O3 -march=native`, so executable compatibility and performance
are host dependent. No upstream files or compiler flags are patched.

From the repository root:

```sh
python3 scripts/simplepir_reference.py --fetch-only
python3 scripts/simplepir_reference.py \
  --config experiments/configs/simplepir-reference-small.json \
  --output experiments/results/simplepir-reference-NEW
```

The fetch step clones the official repository into an ignored local cache,
checks out exactly the pinned commit, and rejects a modified or differently
pinned checkout. The run builds the Go adapter and a release Rust adapter that
calls the project's actual `Database`, `QueryPair`, and `recover` APIs. It
requires a new output directory and records build logs, exact invocation
arguments, source hashes, compiler versions, CPU/memory information, repository
state, per-process raw samples, merged raw samples, and summary statistics.
The local source cache and executables are ignored; no vendored replacement is
silently selected. The Rust adapter has its own small manifest and lockfile.

To rerun the original upstream correctness check:

```sh
cd research/pir_reference/upstream
go test ./pir -run '^TestSimplePir$' -count=1 -v
```

The recorded check and output are preserved in `upstream-correctness.log` and
its command is in `metadata.json` in the result directory.

## Scope and measurement

The matched workload has **10,000 records of 8 bytes**, not 1 KiB records. The
reference's public `MakeDB` and `Recover` APIs accept/return `uint64`; see the
pinned [database implementation](https://github.com/ahenzinger/simplepir/blob/e9020b03bf2872c75b8954e749e32408b5db87ed/pir/database.go)
and [recovery implementation](https://github.com/ahenzinger/simplepir/blob/e9020b03bf2872c75b8954e749e32408b5db87ed/pir/simple_pir.go).
Using its long-record dimension argument and checking only a returned 64 bit
value would not verify arbitrary 1 KiB output. Accordingly this comparison
checks every bit of each 64 bit result against known, varying record values.
The project's existing 10,000 × 1 KiB naive measurements remain a separate
experiment; these results cannot be substituted into that comparison.

Each scheme runs in **30 fresh processes**, each with a new database/setup,
one excluded warm-up, and 16 measured queries: 480 measurements per scheme.
Their order within each trial is randomized with a recorded seed. Targets and
record values are deterministic and identical across schemes; cryptographic
randomness uses each implementation's normal OS-seeded source. Every measured
result is checked against the oracle. SimplePIR calls real `Init`, `Setup`,
`Query`, `Answer`, and `Recover`; it never calls `FakeSetup` or uses a random
substitute for the hint. Parameter selection uses the upstream table with
LWE dimension 1024 and ciphertext modulus 2^32; this geometry selects
`L=266, M=264, p=991, sigma=6.4`.

Timings cover the individual in-process algorithm calls. Their sum is labelled
`total_algorithm_ns`; it excludes transport, serialization, authentication,
process startup, compilation, warm-up and the separately measured setup. The
two XOR servers are independent database objects measured sequentially; their
summed time is aggregate serial work, not a claim about parallel network
latency. The upstream kernels are single threaded, and Go uses GOMAXPROCS=1.
The host is a shared Intel Core i7-14650HX with no CPU affinity or resource
isolation. Go/cgo optimized packed matrices and Rust's Vec-of-records full scan
have different memory layouts and runtime overheads. Ratios therefore describe
these implementations and this small cached workload, not an algorithmic lower
bound or production comparison.

Summaries report mean, median, p95 and sample standard deviation. Confidence
intervals resample the **30 trial means**, preserving all 16 within-process
queries as one cluster, with 10,000 seeded bootstrap resamples and percentile
95% bounds. This estimates variation across these runs; it does not account
for every source of shared-host measurement bias.

## Recorded results

Raw output: [simplepir-reference-small-20261020](../experiments/results/simplepir-reference-small-20261020/summary.json).
All 960 measured queries passed their full output oracle checks.

| Mean online component | Genuine SimplePIR | Naive XOR, two serial servers |
| --- | ---: | ---: |
| Query generation | 560.30 µs | 5.84 µs |
| Server work | 11.57 µs | 201.97 µs |
| Recovery | 41.33 µs | 0.11 µs |
| Sum of algorithm calls | 613.20 µs | 207.92 µs |
| 95% CI for that sum's mean | 600.48–626.50 µs | 202.73–213.20 µs |
| Median sum | 582.51 µs | 207.22 µs |
| p95 sum | 824.01 µs | 235.46 µs |

SimplePIR's server computation is faster in this local run, while its client
query generation makes the sum of online calls larger. Preprocessing is an
additional cost:

| Mean setup component, per fresh process | Genuine SimplePIR | Naive XOR |
| --- | ---: | ---: |
| Database construction | 2.23 ms | 1.21 ms for both copies |
| Shared matrix generation | 36.81 ms | 0 |
| Real database-dependent hint/preprocessing | 9.27 ms | 0 |

The one-server SimplePIR scan input occupies 93,632 bytes after reference
packing/padding, versus 80,000 payload bytes at each XOR server, 160,000 summed.
These are nominal full-scan input footprints, **not measured DRAM traffic**;
query reads, pointers, metadata, allocator overhead and caches are additional.
The SimplePIR server still reads its whole packed matrix for every query;
preprocessing does not make this a sublinear server retrieval.

## Communication and setup accounting

These are protocol matrix/share payload sizes computed from the actual message
objects, not captured packets. No framing, AEAD, TCP or transport compression is
included for either scheme. Database provisioning is excluded for both: logical
input is 80,000 bytes for one SimplePIR server and two copies totaling 160,000
bytes for XOR, before their representation and object overheads.

The experiment uses upstream's **uncompressed shared matrix**. Conceptually the
client generates and uploads A during setup, and downloads the database-dependent
hint H. It accounts for both matrix sizes. A deployment using shared public
parameters or the compressed-seed API would have different offline traffic;
that optimization is not measured here. The hint can be reused for queries to
a static database. Updates and hint refreshes are not measured.

| Payload | Genuine SimplePIR | Naive XOR, total across both servers |
| --- | ---: | ---: |
| Offline shared-matrix upload | 1,081,344 bytes | 0 |
| Offline hint download | 1,089,536 bytes | 0 |
| Online query upload | 1,056 bytes | 2,500 bytes |
| Online answer download | 1,064 bytes | 16 bytes |
| Online total | 2,120 bytes | 2,516 bytes |

Including offline setup, SimplePIR's protocol traffic per query is
`2,120 + 2,170,880 / Q` bytes over Q queries to that static setup. This is
137,800 bytes/query at Q=16 and 4,290.88 bytes/query at Q=1,000; it becomes lower
than XOR's 2,516 bytes/query after 5,483 queries under this accounting. The
summary also includes Q=1 and Q=1,000,000. Counting only online bytes would hide
the larger setup cost in this small experiment.

This adds a reproducible genuine reference experiment, not a server replacement
in the invocation pipeline. No conclusion about end-to-end traffic privacy,
malicious-server answer correctness, TEE isolation, database updates, larger
records or network service performance follows from these measurements.
