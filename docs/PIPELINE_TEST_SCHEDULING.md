# Pipeline correctness-test scheduling

Rust correctness gates run with `--test-threads=1`. The process-pipeline fixtures launch actual WASM/PIR/storage workers with the unchanged 100 ms public class and a 50 ms guest commit boundary. Concurrent fixtures compete for CPU and can legitimately reach a masked Timeout before a correctness test's expected successful call. Serial test scheduling reduces competition introduced by the harness; it does not guarantee success under arbitrary external host load or alter runtime deadlines.

The hosted push run `39969711451` at commit `565d2f4e` failed `multiple_clients_execute_mixed_functions_with_isolated_state_and_fixed_traces` with the strict client's generic authenticated invocation error. Its private cause is unknown. Local reproduction supports scheduler contention as a possible mechanism; it does not establish the hosted failure's cause.

The [bounded diagnostic](../experiments/results/pipeline-ci-diagnosis-20261023/diagnosis.json) predeclared exactly three attempts and retained every result:

| Attempt | CPU allocation | Result |
| --- | --- | --- |
| All fourteen pipeline tests, fourteen harness threads | Same two logical CPUs | 12 passed, two failed; retained private traces show Timeout on expected successful calls |
| Same fourteen tests, one harness thread | Same two logical CPUs | All fourteen passed |
| One strict three-participant mixed demo, sixteen explicit busy competitors | One logical CPU | Nonzero generic invocation error; first real echo has private Timeout, valid authenticated request/registry, two completed PIR queries and 128 storage events |

The direct contended call recorded 218.319 ms preparation. Other Timeout records completed preparation within 100 ms but after the 50 ms commit boundary; `deadline_missed=false` therefore does not imply guest success. The settings, exact reproduction script, complete exits/stdout/stderr, actual synthetic private traces and artifact hashes are retained in the diagnostic directory. There were no retries, budget changes or source edits during diagnosis. This three-attempt exercise is a causal stress diagnostic, not a statistical failure-rate estimate.

Strict demo and manual protocol assertions remain strict. On failure only, pipeline tests attach the retained synthetic fixture path and bounded tails of `executor-private.jsonl` and `publication-private.jsonl` (at most 1,024 bytes and four rows from each file). Missing diagnostic files are reported without replacing the original assertion. These private fixture records never enter runtime responses or observer streams. A regression verifies tail retention, size bounds and missing-file handling. The test suite now contains fifteen tests, including that diagnostic regression.

Serial correctness gates do not replace the explicit concurrency, queue-pressure or overload scenarios inside individual tests. They do not select successful runs, suppress errors or change published measurement campaigns. Research `demo-sweep` separately retains and accounts masked runtime failures under its documented policy; strict correctness demos continue to reject them.
