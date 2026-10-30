# Actual ORAM leaf traces and PIR packet capture

The retained runs exercise actual Rust ORAM accesses and actual encrypted two-server PIR requests. They provide correctness and bounded trace diagnostics. They do not establish indistinguishability, independence, or end-to-end privacy.

## Retained evidence

| Run | Actual workload | Accepted observation |
| --- | --- | --- |
| `experiments/results/leaf-100k-current` | One fresh crypto session each for repeated address zero and uniform logical addresses; 100,000 measured accesses per workload, 64 blocks of 64 bytes | 100,000 observed leaf reads and 1,400,000 physical bucket events per workload; every bucket event is 316 bytes |
| `experiments/results/pir-capture-current` | 30 fresh process sessions, 100 shuffled balanced requests each; five 128-byte records | 3,000 complete oracle-verified retrievals; 6,000 server TCP streams; 61,363 genuine captured packets |

ORAM materialization and 1,000 warmup accesses precede each measured workload. `same/observer-0.jsonl.gz` and `uniform/observer-0.jsonl.gz` contain physical events; `private-0.jsonl.gz` contains evaluator truth. These are compressed real records, not samples synthesized from a distribution. The compression sidecars preserve the uncompressed SHA-256 and size. `integrity-recheck.json` records a later streaming verification of all four compressed files, without rewriting their bytes.

PIR's two worker processes receive fresh endpoint keys through inherited private pipes before capture. Each trial announces its two dynamically allocated owned loopback listener ports before the parent starts capture, and waits for the parent to continue. The captured transport carries encrypted queries and answers. The client recovers each result from both server answers and compares it with the expected record. The processes share one OS and host; they are two process address spaces, not TEEs or independent server operators.

## Scope and structural checks

Each retained `trial-NNN/capture-launch.json` records the actual executable command, port allocation, capture command, exit status, and complete dumpcap log. The capture filter is exactly:

```text
tcp and host 127.0.0.1 and (port OWNED_PORT_0 or port OWNED_PORT_1)
```

Capture uses the existing dumpcap capability on `lo`. No unrelated traffic, privilege changes, broad interface capture, or key provisioning is part of these captures. Raw `capture.pcapng` files are genuine packet evidence; `application-frames.jsonl` is separate application evidence. `packet-observer.jsonl` contains tshark's decoded timestamps, frame sizes, IP addresses, ports, stream identifiers, TCP payload sizes, flags, and retransmission indicators; the exact decoder command is retained per trial.

The current analyzer requires both IP endpoints to be `127.0.0.1` and at least one port to belong to the trial's two listeners. Every one of the 30 retained capture logs reports explicit zero drops, including the `pcap`, `dumpcap`, `flushed`, and `ps_ifdrop` component counters. The reported received count equals the decoded packet count in every trial. Missing, malformed, duplicate, nonzero, or inconsistent drop summaries fail analysis rather than silently implying complete capture.

Across these captures, TCP frame lengths are 66, 74, 119, and 246 bytes; TCP payload lengths are 0, 53, and 180 bytes. Each server stream has exactly 53 query payload bytes and 180 answer payload bytes after excluding marked retransmissions. These are complete encrypted application frames, including transport framing overhead. TCP handshakes, acknowledgments, connection closure, kernel scheduling, segmentation, and capture behavior account for packet overhead; a packet's frame length is not the application's frame length.

For completeness accounting only, each stream's first query data timestamp must fall inside exactly one private client query interval. Each trial must have exactly one stream per server per client step. `structural-streams.jsonl` records these assignments and size/timing summaries without target labels. Shared-host wall clocks provide this evaluator alignment, not an attacker capability. `structural-diagnostics.json` is the current accepted report.

## Statistical leaf diagnostics

The retained `diagnostics.json` contains full counts, discrete distribution comparisons, mutual information estimates with permutation null references, and numeric leaf autocorrelations. Selected observed values are:

| Diagnostic | Repeated address | Uniform addresses |
| --- | --- | --- |
| Uniformity chi-square p | 0.7080 | 0.3561 |
| Discrete KS p against uniform reference | 0.9296 | 0.2795 |
| Consecutive equal leaf fraction | 0.016110 | 0.015490 |
| Uniform equal-leaf reference | 0.015625 | 0.015625 |
| Adjacent leaf mutual information, bits | 0.029862 | 0.028869 |
| Adjacent leaf mutual information permutation p | 0.068 | 0.490 |

Between workloads, leaf-count homogeneity has chi-square statistic 71.8156 and unadjusted p 0.2089; discrete KS distance is 0.00389 with permutation p 0.320. The analysis reports a Holm correction over its stated family of 11 diagnostic p values; the minimum adjusted p is 0.748. This family is defined in the analysis script, with no claim of independent preregistration. The table's p values are unadjusted. Discrete uniform KS references use 5,000 multinomial simulations; two-workload KS and mutual information references use 499 permutations, with finite Monte Carlo resolution.

The positive plug-in mutual information estimates have finite-sample bias; their permutation baselines are retained for that reason. Repeated-address logical-address dependence is unidentifiable because the address has zero entropy. Numeric autocorrelation depends on arbitrary leaf numbering and remains exploratory. One session per workload cannot establish robustness across sessions, and failure to reject a modeled null is not proof of it. These structural distribution checks are not implemented inference attacks or successful privacy acceptance tests.

## Inference attack acceptance

The former packet nearest-centroid classifier had no validated positive control. Its near-chance results are **excluded from acceptance and from privacy evidence**. The classifier implementation has been removed from `scripts/capture_pir.py`; the current analyzer performs structural diagnostics only. No successful packet attack resistance test is claimed.

Original `analysis.json` and `evaluator-packet-features.jsonl` remain unchanged as historical exploratory artifacts; they are superseded for acceptance by `structural-diagnostics.json`. They must not be cited as evidence of privacy. A future packet inference attack must first recover a legitimate leaky implementation using the same observer inputs and feature extraction, then be evaluated on fresh secure sessions with whole sessions separated between profiling and evaluation. Ground-truth-derived synthetic features cannot serve as that control. These packet and leaf runs support no claims about active attacks, cache or page observations, external networks, full runtime composition, or cryptographic security proofs.

## Reproduction and provenance

From the repository root, use a Python environment containing the research dependencies for the leaf script (the retained environment is `.venv`; plain system Python lacks SciPy):

```sh
.venv/bin/python scripts/leaf_stress.py experiments/results/leaf-100k-NEW
python scripts/capture_pir.py experiments/results/pir-capture-NEW --trials 30 --queries 100
python scripts/capture_pir.py experiments/results/pir-capture-current --analyze-only
python -m unittest research.tests.test_capture_pir -v
```

Generation requires a new output directory. Both generation scripts build with `cargo build --locked --release`, copy the measured executable into the run's `bin/` directory, and record its SHA-256 before launching any workload and again after completion. Existing launch JSON records are authoritative for the retained actual commands. Workload seeds are reproducible; cryptographic keys, nonces, query shares, and ORAM random choices intentionally use fresh OS randomness.

The retained ORAM executable SHA-256 is `8fa0ad58dc632fe860fb1a3a56cb96385fc698ffc9baafaed4fb6001a95a50ad`; the retained PIR executable SHA-256 is `c733beafe2221c324869763b610d4eb3076bce9e87a5809a5ceea54c0f408a73`. These identify the executable bytes actually run even if a concurrent build replaces `target/` outputs. `metadata.json` records launch-time script and generator hashes, geometry, workload counts, seeds, platform, and timestamps. Per-workload configuration and launch JSON record exact arguments. The retained platform is Linux 7.2.11 on an Intel Core i7-14650HX; the recorded Rust compiler is 1.99.1 and capture/decode tools are Wireshark 4.7.4.

`source-provenance-after.json` is explicitly a source fingerprint captured **after** measurement; it is not a hermetic build-time source snapshot. Its full dependency source hashes, current revision, and tool versions supplement the immutable executable evidence. Future PIR runs additionally record all PIR source, manifest, and lockfile hashes after build but before launch, plus script invocation and tool versions; these remain observational fingerprints, not a hermetic build guarantee. Existing metadata is preserved rather than retroactively attributing current source to old launches.

The PIR `integrity-recheck.json` hashes the retained raw captures, decoded packets, truth, launch records, executable, historical reports, and current structural reports at audit time. Its timestamps distinguish that later integrity audit from launch provenance. All 30 raw pcap hashes and the measured PIR executable were compared with their previously recorded hashes. ORAM's four gzip records were checked against both compressed and uncompressed hashes. The three capture unit checks cover all drop counter components and missing summaries, exact loopback/port boundaries, and retained real-capture accounting. The current structural analyzer also completed against all 30 sessions with 3,000 verified queries and 6,000 verified streams.
