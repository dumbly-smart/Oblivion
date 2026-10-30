# Reports and evidence index

Updated 2026-10-30. This index points to technical reports and retained outputs. Read [docs/EXPERIMENTS.md](docs/EXPERIMENTS.md) for the current command catalog and [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) for chronology and source-validation status. Each report defines its own workload, attacker view, executable/source identity, and limits. A result is not automatically evidence about current source or a different threat model.

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
| Invocation-boundary function identity from frame sizes and timing | [Preregistration](docs/INVOCATION_BOUNDARY_ATTACK_PREREG_20261030.md), [control-gate result](docs/INVOCATION_BOUNDARY_ATTACK_20261030.md), [raw bundle and independent receipt](experiments/results/invocation-boundary-attack-20261030/) |

## ORAM timing replication series

The newest run is the preregistered [rank-64 Zipf/Markov replication from 2026-10-30](docs/ORAM_RANK64_MARKOV_REPLICATION_20261030.md). Its frozen configuration is [here](experiments/configs/oram-isolated-rank64-markov-replication-20261030.json), and its raw bundle, host observations, figure, predictions, and independent verification are retained in [the result directory](experiments/results/oram-isolated-rank64-markov-replication-20261030/). Both controls scored AUC 1.000; Path ORAM scored 0.502474 with a 95% trial-bootstrap interval [0.496502, 0.508492]. The interval includes chance and is inconclusive for this attacker and measurement boundary, not a security proof.

The [frequency-only tag attack follow-up](docs/ORAM_RANK64_FREQUENCY_ORIENTATION_SECONDARY_20261030.md)
reuses those same sessions and is explicitly post-hoc, not independent
replication evidence. Both positive controls scored AUC 1.000; the ORAM
frequency scorer measured 0.496447 [0.491316, 0.501515]. The output and
independent verification receipt are retained in
[`oram-rank64-frequency-orientation-secondary-20261030/`](experiments/results/oram-rank64-frequency-orientation-secondary-20261030/).

A fresh-seed, preregistered replication increased address persistence to 0.60
and collected new sessions. Its frequency-only controls again scored AUC
1.000; Path ORAM scored 0.502248 [0.498132, 0.506253]. This is independent
session evidence for that changed workload, but the protocol was informed by
the earlier result and is not blind. See the [replication report](docs/ORAM_RANK64_FREQUENCY_REPLICATION_20261030.md),
[preregistration](docs/ORAM_RANK64_FREQUENCY_REPLICATION_PREREG_20261030.md),
and [raw/analysis bundles](experiments/results/oram-isolated-rank64-frequency-replication-20261030/).

A fresh-seed preregistered one-step transition attack then used address
persistence 0.80. Its plaintext/encrypt-only controls passed at AUC 0.898148
[0.895392, 0.900593]; ORAM scored 0.502017 [0.497459, 0.506447], inconclusive
for the single-previous-tag lookup. The protocol is a secondary analysis of
the new collector sessions, not an independent sample from that collection's
temporal classifier. The [frozen protocol](docs/ORAM_RANK64_TRANSITION_REPLICATION_PREREG_20261030.md),
[result and limits](docs/ORAM_RANK64_TRANSITION_REPLICATION_20261030.md),
[configuration](experiments/configs/oram-isolated-rank64-transition-replication-20261030.json),
raw bundle, prediction artifacts, and final independent verifier receipt are
retained separately.

Earlier studies are retained as separate experiments; do not pool them without a declared analysis:

- [Initial isolated timing](docs/ORAM_TIMING_REPLICATION.md) and [two-address replication](docs/ORAM_TWO_ADDRESS_REPLICATION_20261026.md), with their preregistration in [ORAM_TWO_ADDRESS_REPLICATION_PREREG_20261026.md](docs/ORAM_TWO_ADDRESS_REPLICATION_PREREG_20261026.md).
- [2026-10-25 signal replication](docs/ORAM_SIGNAL_REPLICATION_20261025.md) and [frozen protocol](docs/ORAM_SIGNAL_REPLICATION_20261025_PREREG.md).
- [Markov workload B](docs/ORAM_MARKOV_REPLICATION_20261026.md) and [protocol](docs/ORAM_MARKOV_REPLICATION_20261026_PREREG.md); [Markov transition attack](docs/ORAM_MARKOV_TRANSITION_REPLICATION_20261026.md) and [protocol](docs/ORAM_MARKOV_TRANSITION_REPLICATION_PREREG_20261026.md).
- [Pinned service](docs/ORAM_PINNED_REPLICATION_20261026.md) and [protocol](docs/ORAM_PINNED_REPLICATION_20261026_PREREG.md); [paired affinity crossover](docs/ORAM_AFFINITY_CROSSOVER_20261026.md) and [protocol](docs/ORAM_AFFINITY_CROSSOVER_PREREG_20261026.md).
- [Zipf-32](docs/ORAM_ZIPF32_REPLICATION_20261026.md), [monitored Zipf-32](docs/ORAM_ZIPF32_MONITORED_REPLICATION_20261026.md), [uniform-32](docs/ORAM_UNIFORM32_REPLICATION_20261026.md), and [higher-skew Zipf-32](docs/ORAM_ZIPF32_ALPHA15_REPLICATION_20261026.md). Each report links its own preregistration and output bundle.
- [Zipf-16/Markov replication from 2026-10-28](docs/ORAM_ZIPF16_MARKOV_REPLICATION_20261028.md), followed by the independent [rank-64 Zipf/Markov result](docs/ORAM_RANK64_MARKOV_REPLICATION_20261030.md). The latter reuses the attacker unchanged and changes the workload and logical address space; the two runs are not pooled.
- Workload/attacker follow-ups: [uniform access](docs/ORAM_UNIFORM.md), [eight-address timing](docs/ORAM_EIGHT_ADDRESS.md), [frequency attacker](docs/ORAM_ATTACK_FAMILIES.md), [read-heavy](docs/ORAM_READ_HEAVY.md), [write-heavy](docs/ORAM_WRITE_HEAVY.md), [frequency orientation](docs/ORAM_FREQUENCY_ORIENTATION.md), and [isolated timing design](docs/ORAM_ISOLATED_TIMING.md).
- Reference and geometry comparisons: [matched Circuit ORAM](docs/CIRCUIT_ORAM_REFERENCE.md), [geometry evaluation](docs/GEOMETRY_EVALUATION.md), [PIR target timing](docs/PIR_TARGET_TIMING.md).

The [implementation status](docs/IMPLEMENTATION_STATUS.md) explains which earlier runs have positive controls, which include possible weak signals, which had provenance limits, and which raw records were superseded. Read each preregistration and result together.

## Autoscaling reports

- [Autoscaler simulation](docs/AUTOSCALER.md) describes the policy/workload model and default comparisons.
- [DP mechanism and attacks](docs/AUTOSCALER_DP.md) describes conditional mechanism arguments, bounded sampler studies, attacks, and limits.
- [Likelihood attacker](docs/AUTOSCALER_LIKELIHOOD.md), [interval attacker](docs/AUTOSCALER_INTERVAL_ATTACK.md), [privacy ledger](docs/PRIVACY_LEDGER.md), and [ledger overhead](docs/PRIVACY_LEDGER_BENCHMARK_20261026.md) cover individual follow-ups.

These reports describe simulators and bounded observers. They are not a deployed autoscaler or a general privacy proof. In particular, public deterministic seeds and privileged rollback of the local ledger are explicit limitations.

## How to read an experiment record

Read the preregistration before the result. It fixes the workload, attacker
view, train/test split, primary metric, positive-control gate, uncertainty
method, seed, and output path. The result report records deviations and
interpretation. Raw observations, labels, predictions, checksums, and
environment metadata are retained under the referenced `experiments/results/`
directory when the experiment collects them.

A failed positive control invalidates that attack comparison. A successful
control shows that the selected attacker can detect the intended signal in
the leaky baseline; it does not prove the attacker is optimal. A confidence
interval that includes chance means the study did not distinguish the tested
conditions at that resolution. It does not prove indistinguishability or
cryptographic security. Compare only studies with compatible workloads,
attacker features, measurement boundaries, source/binary identity, and
independent sampling units. Never overwrite a captured output directory; use a
new path for a reproduction and document exclusions or superseding analyses.

## Completed rank-64 ORAM replication

The preregistration and configuration were frozen and pushed in `d5847766`
before study-specific tests, release builds, or collection. The study later
passed both positive controls and retained its result and raw evidence in
`experiments/results/oram-isolated-rank64-markov-replication-20261030/`.
The detailed [result report](docs/ORAM_RANK64_MARKOV_REPLICATION_20261030.md)
and [independent verifier](research/analysis/verify_oram_isolated_bundle.py)
describe integrity checks and limits.

## Latest completed ORAM study reproduction

The latest preregistration was committed before building and collecting. The completed runner and independent verifier used the repository's pinned Python environment. To repeat with a new, empty output directory, first build the release measurement tools, then run:

    cargo build --locked --release -p oblivion-store --example oram-measure --example oram-control
    taskset -c 2 .venv/bin/python -m research.analysis.oram_isolated_replication --config experiments/configs/oram-isolated-rank64-markov-replication-20261030.json --output experiments/results/oram-isolated-rank64-markov-replication-NEW --oram-binary target/release/examples/oram-measure --control-binary target/release/examples/oram-control
    .venv/bin/python -m research.analysis.verify_oram_isolated_bundle --bundle experiments/results/oram-isolated-rank64-markov-replication-NEW --output experiments/results/oram-isolated-rank64-markov-replication-NEW/independent-verification.json

The command is for a fresh repeat and must not overwrite the retained
2026-10-30 or 2026-10-28 output directories. Frozen parameters and statistical
methods are in the [2026-10-30 preregistration](docs/ORAM_RANK64_MARKOV_REPLICATION_PREREG_20261030.md).
The raw report and independent verification are the sources for the displayed
result.
