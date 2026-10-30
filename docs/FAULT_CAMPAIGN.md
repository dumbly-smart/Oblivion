# Repeated process fault campaign

[Accepted report](../experiments/results/fault-campaign-30-20261023-retry/report.json) records 30 launches of each of seven real integration tests, 210 assertion-bearing subprocesses overall. Every launch passed. [Metadata](../experiments/results/fault-campaign-30-20261023-retry/metadata.json) confirms identical before/after test executable, server executable and relevant source hashes. Raw stdout/stderr, exact commands, exit codes, measured harness wall time and one independent record per launch are retained.

The runner rejects zero-test launches and timeouts, preserves nonzero exits, shuffles launch order with a recorded seed, and validates the exact scenario/trial set. A timed-out process group is killed and reaped. Aggregate records use same-directory temporary files and atomic replacement; every trial also has its own record. These evidence writes are not an application durability or power-loss protocol.

| Actual fault fixture | Assertions checked | Median whole-test wall ms |
| --- | --- | ---: |
| Missing bootstrap and partial request | Both incomplete inputs cause bounded worker exit | 4,076.75 |
| Duplicate and skipped epochs | Fail closed without a second storage execution | 364.72 |
| Lost PIR child | Authenticated fixed error response, user state untouched | 264.52 |
| Abandoned response pipe | Output backpressure cannot hold the worker forever | 4,575.04 |
| Late frame after idle bound | An expired session cannot resume | 2,069.04 |
| Tampered AEAD frame | Cover path runs; next valid stateful call remains correct | 264.89 |
| EOF halfway through two-client epoch | Incomplete multi-client epoch rejected | 164.30 |

Times include worker startup, readiness, fault waits, assertions, cleanup and the test harness polling interval. They are not response latency or publication timing distributions. Each named integration test may launch more than one actual session. Seeded launch order does not randomize all fault payloads or times. The conditional Wilson 95% interval for trial assertion failure is [0,11.35%] for each 30-launch scenario; zero observed failures is not a proof of general robustness. Host interference and repeated fixed fixtures limit generalization.

The accepted campaign concerns bounded availability and the exact state/shape checks implemented by those tests. It does not hide active failures, prevent denial of service, establish exactly-once delivery, or guarantee atomic application storage commits. Physical ORAM commit failures can poison the controller; separate recovery tests cover authenticated snapshots and documented external-anchor assumptions.

## Failed first attempt preserved

The first campaign stopped at launch 107 when the host filesystem filled. Its aggregate trials file was truncated by the older non-atomic writer. [Incomplete evidence](../experiments/results/fault-campaign-30-20261023/INCOMPLETE.md) remains excluded from accepted aggregate results. After the writer regression test and disk recovery, all 210 launches were repeated in a new directory; failed evidence was not silently substituted or removed.

## Reproduce

```sh
.venv/bin/python -m unittest research.tests.test_fault_campaign
.venv/bin/python scripts/evaluate_faults.py experiments/results/fault-campaign-new
```

The default runs 30 trials/scenario on Linux and refuses an existing output directory. Five focused tests cover Cargo artifact selection, zero-matching-test rejection, exact trial sets, real nonzero/timeout subprocess retention and preservation of previously published records under an injected atomic-publication failure. Current-source runs can differ from this frozen historical campaign; compare fingerprints before attributing results.
