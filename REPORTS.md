# Reports and evidence index

This index points to technical reports and retained outputs. Read [docs/EXPERIMENTS.md](docs/EXPERIMENTS.md) for the current command catalog and [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) for chronology and source-validation status. Each report defines its own workload, attacker view, executable/source identity, and limits. A result is not automatically evidence about current source or a different threat model.

## Project status, design, and assumptions

| Topic | Report |
| --- | --- |
| Whole supplied roadmap mapped to selected work and remaining requirements | [Completion audit](docs/COMPLETION_AUDIT.md), [requirements matrix](docs/REQUIREMENTS_MATRIX.md) |
| System flow and components | [Architecture](ARCHITECTURE.md), [detailed architecture](docs/ARCHITECTURE.md), [full explanation](EXPLANATION.md) |
| Assets, adversary, leakage, non-goals | [Threat model](docs/THREAT_MODEL.md), [security assumptions](docs/SECURITY_ASSUMPTIONS.md) |
| Implementation chronology and verified status | [Implementation status](docs/IMPLEMENTATION_STATUS.md), [progress snapshot](PROGRESS.md) |
| Remaining engineering and research actions | [Next steps](docs/NEXT_STEPS.md) |
| Research references, decisions, and qualifications | [Research notes](docs/RESEARCH_NOTES.md), [related work](docs/RELATED_WORK.md) |
| How to run experiments and interpret old artifacts | [Experiments](docs/EXPERIMENTS.md), [figure reproduction audit](docs/FIGURE_REPRODUCTION.md) |

## Runtime, protocols, and core components

| Area | Design / results |
| --- | --- |
| End-to-end demo and current process path | [Recorded integration demo](docs/DEMO.md), [runtime integration](docs/RUNTIME_INTEGRATION.md), [runtime registry/PIR](docs/REGISTRY_RUNTIME.md) |
| Versioned envelope, registry bootstrap, ORAM event and trace schemas | [Protocols and trace schemas](docs/PROTOCOL.md) |
| Path ORAM construction and attack diagnostics | [ORAM leaf/timing](docs/ORAM_LEAF_TIMING.md), [trace validation](docs/TRACE_VALIDATION.md), [geometry/stash](docs/GEOMETRY_EVALUATION.md) |
| Checkpoint API, crash ordering, cryptographic and freshness limits | [Storage recovery](docs/STORAGE_RECOVERY.md), [anchor service and remote checkpoint adapter](docs/ANCHOR_SERVICE.md) |
| Local SQLite anchor and socket interface | [Anchor service](docs/ANCHOR_SERVICE.md) |
| Independent mTLS witness scope and freshness limits | [Witness design](docs/ANCHOR_FRESHNESS_DESIGN.md), [anchor service](docs/ANCHOR_SERVICE.md), [threat model](docs/THREAT_MODEL.md) |
| Durable invocation, local/remote anchor selection, and receipt replay | [Invocation durability and remote mTLS operation](docs/INVOCATION_DURABILITY.md), [runtime anchor design](docs/ANCHOR_SERVICE.md), [runtime integration test](docs/IMPLEMENTATION_STATUS.md) |
| Signed catalog wire and offline provisioning | [Registry records](docs/REGISTRY.md), [external registry](docs/EXTERNAL_REGISTRY.md), [registry activation](docs/REGISTRY_ACTIVATION.md) |
| Two-server XOR PIR and authenticated transport | [PIR transport](docs/PIR_TRANSPORT.md), [SimplePIR comparison](docs/SIMPLEPIR_REFERENCE.md), [100k correctness](docs/SIMPLEPIR_100K.md), [square-root PIR](docs/SQRT_PIR.md) |
| Fixed-shape executor and error inference | [Execution evaluation](docs/EXECUTION_EVALUATION.md), [executor resource/CPU costs](docs/EXECUTOR_RESOURCES.md) |
| SSE construction and integration boundary | [SSE design](docs/SSE_DESIGN.md), [SSE implementation](docs/SSE_IMPLEMENTATION.md) |
| Persistent SSE journal size/recovery performance (30 trials; local anchor) | [Result and limits](docs/SSE_JOURNAL_BENCHMARK_20261028_RESULT.md), [method](docs/SSE_JOURNAL_BENCHMARK_20261028.md), [raw report, SVG, and hashes](experiments/results/sse-persistent-journal-benchmark-20261028/), [verifier](research/analysis/verify_sse_journal_benchmark.py) |

## Leakage, attacks, and traffic experiments

| Question | Report |
| --- | --- |
| Which inputs an attack may consume and how adapters are registered | [Attack interface](docs/ATTACK_INTERFACE.md) |
| Main A–G ablation and system-level controls | [System experiments](docs/SYSTEM_EXPERIMENTS.md) |
| Search-volume, inference, and update-linkage attacks | [SSE attacks](docs/SSE_ATTACKS.md), [advanced attacks](docs/ADVANCED_ATTACKS.md), [update linkability](docs/UPDATE_LINKABILITY.md) |
| Real query text and auxiliary-information drift | [Corpus evaluation](docs/CORPUS_EVALUATION.md), [human-query evaluation](docs/HUMAN_QUERY_EVALUATION.md) |
| Presence/intersection leakage under virtual epochs | [Presence evaluation](docs/PRESENCE_EVALUATION.md), [sensitivity](docs/PRESENCE_SENSITIVITY.md) |
| Batcher and integrated epoch load | [Population sweep](docs/POPULATION_SWEEP.md), [batch-load inference](docs/BATCH_LOAD_EVALUATION.md), [epoch system](docs/EPOCH_SYSTEM_EVALUATION.md) |
| Offered load, drops, and bounded local CPU sensitivity | [Runtime benchmarks](docs/RUNTIME_BENCHMARKS.md), [population runtime](docs/RUNTIME_POPULATION.md), [extended population](docs/RUNTIME_POPULATION_EXTENDED.md), [cost sensitivity](docs/COST_SENSITIVITY.md) |
| Fault campaign and correctness scheduling | [Fault campaign](docs/FAULT_CAMPAIGN.md), [test scheduling](docs/PIPELINE_TEST_SCHEDULING.md) |

## ORAM timing replication series

The newest run is the preregistered [Zipf-16/Markov replication from 2026-10-28](docs/ORAM_ZIPF16_MARKOV_REPLICATION_20261028.md). Its complete machine-readable bundle is in [experiments/results/oram-isolated-zipf16-markov-replication-20261028](experiments/results/oram-isolated-zipf16-markov-replication-20261028), and its frozen configuration is [here](experiments/configs/oram-isolated-zipf16-markov-replication-20261028.json). Controls passed; ORAM AUC was 0.4968 with a 95% trial-bootstrap interval [0.4864, 0.5072]. This is a bounded inconclusive classifier result, not a security proof.

Earlier studies are retained as separate experiments; do not pool them without a declared analysis:

- [Initial isolated timing](docs/ORAM_TIMING_REPLICATION.md) and [two-address replication](docs/ORAM_TWO_ADDRESS_REPLICATION_20261026.md), with their preregistration in [ORAM_TWO_ADDRESS_REPLICATION_PREREG_20261026.md](docs/ORAM_TWO_ADDRESS_REPLICATION_PREREG_20261026.md).
- [2026-10-25 signal replication](docs/ORAM_SIGNAL_REPLICATION_20261025.md) and [frozen protocol](docs/ORAM_SIGNAL_REPLICATION_20261025_PREREG.md).
- [Markov workload B](docs/ORAM_MARKOV_REPLICATION_20261026.md) and [protocol](docs/ORAM_MARKOV_REPLICATION_20261026_PREREG.md); [Markov transition attack](docs/ORAM_MARKOV_TRANSITION_REPLICATION_20261026.md) and [protocol](docs/ORAM_MARKOV_TRANSITION_REPLICATION_PREREG_20261026.md).
- [Pinned service](docs/ORAM_PINNED_REPLICATION_20261026.md) and [protocol](docs/ORAM_PINNED_REPLICATION_20261026_PREREG.md); [paired affinity crossover](docs/ORAM_AFFINITY_CROSSOVER_20261026.md) and [protocol](docs/ORAM_AFFINITY_CROSSOVER_PREREG_20261026.md).
- [Zipf-32](docs/ORAM_ZIPF32_REPLICATION_20261026.md), [monitored Zipf-32](docs/ORAM_ZIPF32_MONITORED_REPLICATION_20261026.md), [uniform-32](docs/ORAM_UNIFORM32_REPLICATION_20261026.md), and [higher-skew Zipf-32](docs/ORAM_ZIPF32_ALPHA15_REPLICATION_20261026.md). Each report links its own preregistration and output bundle.
- Workload/attacker follow-ups: [uniform access](docs/ORAM_UNIFORM.md), [eight-address timing](docs/ORAM_EIGHT_ADDRESS.md), [frequency attacker](docs/ORAM_ATTACK_FAMILIES.md), [read-heavy](docs/ORAM_READ_HEAVY.md), [write-heavy](docs/ORAM_WRITE_HEAVY.md), [frequency orientation](docs/ORAM_FREQUENCY_ORIENTATION.md), and [isolated timing design](docs/ORAM_ISOLATED_TIMING.md).
- Reference and geometry comparisons: [matched Circuit ORAM](docs/CIRCUIT_ORAM_REFERENCE.md), [geometry evaluation](docs/GEOMETRY_EVALUATION.md), [PIR target timing](docs/PIR_TARGET_TIMING.md).

The [implementation status](docs/IMPLEMENTATION_STATUS.md) explains which earlier runs have positive controls, which include possible weak signals, which had provenance limits, and which raw records were superseded. Read each preregistration and result together.

## Autoscaling reports

- [Autoscaler simulation](docs/AUTOSCALER.md) describes the policy/workload model and default comparisons.
- [DP mechanism and attacks](docs/AUTOSCALER_DP.md) describes conditional mechanism arguments, bounded sampler studies, attacks, and limits.
- [Likelihood attacker](docs/AUTOSCALER_LIKELIHOOD.md), [interval attacker](docs/AUTOSCALER_INTERVAL_ATTACK.md), [privacy ledger](docs/PRIVACY_LEDGER.md), and [ledger overhead](docs/PRIVACY_LEDGER_BENCHMARK_20261026.md) cover individual follow-ups.

These reports describe simulators and bounded observers. They are not a deployed autoscaler or a general privacy proof. In particular, public deterministic seeds and privileged rollback of the local ledger are explicit limitations.

## Latest ORAM study reproduction

The preregistration was committed before building and collecting. The completed runner and independent verifier used the Python environment pinned for this repository. To repeat with a new, empty output directory, first build the release measurement tools, then run:

    cargo build --locked --release -p oblivion-store --example oram-measure
    cargo build --locked --release -p oblivion-store --example oram-control
    taskset -c 2 .venv/bin/python -m research.analysis.oram_isolated_replication --config experiments/configs/oram-isolated-zipf16-markov-replication-20261028.json --output experiments/results/oram-isolated-zipf16-markov-replication-NEW

The collected 2026-10-28 run used output name `oram-isolated-zipf16-markov-replication-20261028`; the command above is for a fresh repeat and must not overwrite that directory. The exact frozen command and statistical method are in the [preregistration](docs/ORAM_ZIPF16_MARKOV_REPLICATION_PREREG_20261028.md). The report and raw manifest are the source for the displayed result.
