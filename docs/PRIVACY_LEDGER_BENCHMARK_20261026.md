# Persistent privacy-ledger microbenchmark (2026-10-26)

This is a local SQLite microbenchmark for the opt-in autoscaler composition
ledger. It measures the `PersistentUserPrivacyLedger.record` transaction; it
does not measure the scheduler, network, identity verifier, or a deployed
service.

## Method

The committed benchmark at `c78f54f8` ran 30 releases for each of four
principal-set sizes: 1, 16, 64, and 256 synthetic IDs per release. Each
case used a fresh temporary SQLite database and a fresh 32-byte OS-CSPRNG
ledger key. The deterministic synthetic principal set was reused across all
30 releases in its case. Every release charged epsilon `0.01` and delta
`0.000001`; the configured lifetime ceilings were epsilon `100` and delta
`0.9`. Thus each principal in a case was charged 30 releases, totaling
epsilon `0.3` and delta `0.00003`.

The timed region includes ID validation, keyed pseudonym generation, duplicate
and budget checks, SQLite reads/writes, and a `synchronous=FULL` commit. It
excludes workload generation, identity verification, report writing, and
plotting. The driver was pinned to logical CPU 2. The host was an Intel
i7-14650HX with 24 logical CPUs; load averages were about 19.8, 18.8, and
18.7 before and after the short run. This is a shared-host measurement.

The report gives empirical p50/p95/p99 and mean over the 30 per-release
latencies; these percentiles are not confidence intervals. Every raw latency
is retained. SQLite file sizes were read after the 30 commits and before the
temporary database was deleted.

## Results

| Principals per release | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Throughput (releases/s) | DB bytes after 30 releases |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0.154 | 0.236 | 0.270 | 0.165 | 6,046 | 49,152 |
| 16 | 0.521 | 0.561 | 0.605 | 0.511 | 1,956 | 172,032 |
| 64 | 1.713 | 1.780 | 1.798 | 1.643 | 609 | 659,456 |
| 256 | 5.196 | 6.265 | 6.336 | 5.135 | 195 | 2,498,560 |

Latency and the retained database size rise with the number of principals
charged in one transaction. The implementation checks each principal before
writing and updates each principal row inside the transaction, so the observed
growth is consistent with the current per-principal SQL work. These values
describe this machine, local filesystem, Python/SQLite versions, and workload;
they are not a general throughput promise or provider-cost estimate.

## Integrity and reproduction

The retained
[`raw benchmark artifact`](../experiments/results/privacy-ledger-benchmark-20261026/)
contains machine-readable config and 120 raw latency values, collection
provenance and hashes, independent verification, a plot, and a derived-file
manifest. The verifier checked the collection manifest, recomputed all four
percentile/mean/throughput summaries and release-composition totals, and
confirmed the current benchmark and ledger source hashes match the collection
hashes. The run used source commit `c78f54f8`; its only initially dirty path
was the pre-existing untracked `.ignore` file.

From the repository root, use the project virtual environment for the plotting
dependency and choose a new result directory:

```sh
taskset -c 2 python3 scripts/benchmark_privacy_ledger.py \
  --output experiments/results/privacy-ledger-benchmark-rerun \
  --seed 20261026 --trials 30 --users-per-release 1 16 64 256
.venv/bin/python -m research.analysis.privacy_ledger_benchmark \
  experiments/results/privacy-ledger-benchmark-rerun
```

The benchmark key and database live only in private temporary directories and
are removed after each case. The summary retains the key fingerprint, not the
key. This microbenchmark does not test cross-host coordination, backup
rollback, database tampering, or remote storage performance.
