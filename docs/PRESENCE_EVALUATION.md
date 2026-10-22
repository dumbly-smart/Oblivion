# Presence and intersection evaluation

This experiment addresses roadmap L5's online/offline intersection test. It is a bounded synthetic component model using the actual `oblivion-batcher` endpoints and epoch queue. A virtual monotonic clock drives emission. It is not a network capture, an OS timing measurement, a full pipeline evaluation, or a reproduction of a published attack.

Eight enrolled endpoint slots have independent OS-generated channel keys. Each trial samples a hidden owner uniformly from eight slots. Independent Bernoulli online schedules use probability 0.35 or 0.70 per slot per epoch. A synthetic owner function fires with probability 0.25 conditional on the owner being online. An explicitly separate public semantic beacon identifies those event epochs without identifying the owner. This is strong owner-conditioned auxiliary knowledge: it might model externally recognizable application events, but no real source is collected here. The exact same beacon and latent workload are used across configurations. No private owner, real/dummy label, plaintext or endpoint key is supplied to the attack.

The positive control submits one authenticated fixed frame for every online client, containing a synthetic work/dummy indicator inside its encrypted body. Fixed-rate-online uses the same actual queue and online schedule; all online clients emit one authenticated frame per epoch. These two modes deliberately have the same presence visibility. Padding batches cannot hide missing upstream clients. Always-participating additionally sends valid encrypted dummies from enrolled clients whose latent application schedule is offline; this assumes their agents remain connected. It cannot conceal physically disconnected clients without some distinct trusted sender.

Observers record actual incoming slot sets, the actual emitted batch's `missing_slots`, frame sizes and outgoing byte count. The attack intersects incoming participant sets at beacon epochs. A second observer derives participant sets from missing slots and must give identical candidates. A downstream-only set sees eight slots each epoch and demonstrates the narrower observer's limitation. Candidate scores are uniform 1/n compatibility scores, explicitly uncalibrated. Ties use a public constant permutation seed (90000), independent of latent workload seeds and truth. Knowledge sensitivity takes the first 1, 2, 4 and all beacon events. With no events it retains all eight owners.

Whole independent trials are the units for accuracy, top-3 and candidate-size bootstrap intervals. Uniform chance and population-majority baselines are reported; each trial contains one owner, with no profile/target session mixing or learned profiling. Synthetic workload parameters, seed, private owner and latent online/work schedules are retained separately from observer JSONL. Incoming authenticated bytes, batch cover bytes, authenticated dummy bytes and fixed downstream bytes expose the additional cover cost.

The retained evidence and results appear below. No formal DP or zero-leakage claim is made.

## Retained campaign and reproducibility

The campaign completed on 2026-10-22 before the session interruption. The 2026-10-23 audit confirmed all 60 export commands exited zero, all 180 compressed raw streams exist, all 197 hashes in the original artifact manifest match, and the frozen binary and source hashes match. No trial was replaced. Artifacts occupy approximately 2.9 MiB.

[Configuration](../experiments/configs/presence-30.json), [provenance recorded before launch](../experiments/results/presence-30-20261022/provenance.json), [command exits](../experiments/results/presence-30-20261022/commands.json), [artifact hashes](../experiments/results/presence-30-20261022/artifact-sha256.json), [corrected summary](../experiments/results/presence-independent-ties-wilson-20261023/summary.json), [corrected whole-trial predictions](../experiments/results/presence-independent-ties-wilson-20261023/trial-metrics.json), [costs](../experiments/results/presence-30-20261022/costs.jsonl), and [resume audit](../experiments/results/presence-30-20261022/audit-20261023.json) preserve the evidence. The original artifact manifest predates the resume audit, so it does not list that additional audit file. The original scores use a tie seed derived from each latent workload seed. That derived seed was unnecessary auxiliary information, so those scores are **superseded**. The [corrected analysis provenance](../experiments/results/presence-independent-ties-wilson-20261023/provenance.json) identifies an analysis-only correction using fixed seed 90000, with the original raw streams unchanged. An intermediate independent-tie analysis without Wilson intervals is retained separately under `presence-independent-ties-20261023`. The tables below use the final independent-tie/Wilson analysis. Reproducibility seeds and truth are evaluator artifacts, excluded from the attack knowledge contract; they are published for scientific inspection and must not be mistaken for public metadata of a real target. The binary is retained under `bin/presence`; snapshots under `sources/` preserve exact measured source. Raw names identify public online-probability configuration and trial seed; `.observer.jsonl.gz`, `.beacon.jsonl.gz` and `.truth.jsonl.gz` are physically separate files. The attacker consumes only the first two.

```sh
cargo build -p oblivion-batcher --example presence --release
PRESENCE_BINARY="$PWD/target/release/examples/presence" \
  .venv/bin/python -m unittest research.tests.test_presence -v
.venv/bin/python -m research.analysis.presence \
  --binary target/release/examples/presence \
  --config experiments/configs/presence-30.json \
  --out experiments/results/presence-new-run

# Reanalyze the retained raw streams with independent ties and Wilson intervals:
.venv/bin/python -m research.analysis.presence \
  --raw-source experiments/results/presence-30-20261022 \
  --out experiments/results/presence-new-analysis
```

The output path must be new to preserve prior evidence. The runner copies and hashes the binary, source, lockfile and configuration and records Python/Rust/Cargo and host information before starting exports. Public stdout is compressed as it is produced. Each bounded private/auxiliary export is compressed immediately after its process exits. No full encrypted-frame intermediate is retained. Epoch time is simulated; these bytes count library envelopes and exclude TCP/IP framing, replies, PIR, execution and storage traffic.

## Results and limits

The actual configuration uses 128 epochs and **two** independent Bernoulli online probabilities, 0.35 and 0.70, with seeds 1001–1030 per probability. Modes share each trial's latent workload and owner; different probabilities reuse trial seeds and are paired sensitivity configurations, not 60 independent owners. The random owner prior is uniform, but the realized 30-owner sample is imbalanced: the fixed label-zero predictor succeeds in 7/30 trials (23.3%). It is the deterministic tie winner under the known uniform prior, not a majority selected using target labels. Uniform guessing has expected accuracy 12.5% and top-3 accuracy 37.5%.

With all observed beacon events, both online probabilities give:

| Configuration | Owner accuracy, 30 trials | 95% Wilson interval | Mean candidates | Top-3 accuracy |
| --- | ---: | ---: | ---: | ---: |
| Deliberately intermittent positive control | 100% | 88.6–100% | 1 | 100% |
| Fixed rate per online client | 100% | 88.6–100% | 1 | 100% |
| All eight endpoint agents participate | 10% | 3.5–25.6% | 8 | 33.3% |

The analyzer verifies the positive control before interpreting defended predictions. Incoming and public missing-slot observers give identical predictions. The resume audit checked all 7,680 paired control/online rows for exact equality apart from their mode name, and all 720 mode/knowledge/observer prediction comparisons for incoming versus missing-slot equality. Downstream-only observation retains all eight candidates in every trial and has the same tie-based scores as always participation. Missing-client random batch cover fails the matching endpoint's authentication oracle; it is not a valid dummy sent by that endpoint.

The 10% tie-based result has an interval containing 12.5%; it does not establish a security guarantee. The algorithm retains eight equally compatible owners, irrespective of sampled tie accuracy. The two always-participating probability rows share the same owners and tie permutations, explaining identical accuracy. Perfect observed controls also do not establish population-perfect inference. The machine summary retains 2,000-replicate whole-trial percentile bootstrap intervals, including degenerate [1,1] intervals for 30/30 observed successes. The corrected analyzer adds Wilson binomial intervals based on one owner prediction per independent trial; the table uses those intervals. Top-3 bootstrap intervals are [16.7%,50.0%] for always participation and [100%,100%] for the perfect controls.

Knowledge sensitivity for the intermittent control and fixed-rate-online modes is identical:

| Online probability | Known beacon events | Mean candidates (bootstrap 95% CI) | Accuracy (bootstrap 95% CI) |
| --- | --- | --- | --- |
| 0.35 | 1 | 3.10 [2.67,3.50] | 40.0% [23.3%,56.7%] |
| 0.35 | 2 | 1.60 [1.40,1.80] | 63.3% [46.7%,80.0%] |
| 0.35 | 4 | 1.03 [1.00,1.10] | 100% [100%,100%] |
| 0.70 | 1 | 5.77 [5.27,6.27] | 26.7% [13.3%,43.3%] |
| 0.70 | 2 | 4.10 [3.63,4.57] | 36.7% [20.0%,53.3%] |
| 0.70 | 4 | 2.43 [2.10,2.80] | 53.3% [36.7%,70.0%] |

All-event inference reaches one candidate in these trials. This depends on the strong conditional semantic beacon, independent synthetic schedules and a single persistent owner. With no beacon events, the attack returns all eight owners. No learned profile or target/profile session reuse is involved. Realistic correlated availability, owner changes, imperfect/noisy beacon knowledge, active traffic shaping and real network users remain outside this experiment.

## Envelope cost

Mean bytes per 128-epoch trial are measured from actual submitted and emitted envelopes, each 164 bytes:

| Online probability | Mode | Incoming authenticated bytes | Outgoing bytes | Missing-slot cover bytes | Authenticated dummy bytes |
| --- | --- | ---: | ---: | ---: | ---: |
| 0.35 | Intermittent / fixed-rate-online | 59,488.3 | 167,936 | 108,447.7 | 44,449.5 |
| 0.35 | Always participating | 167,936 | 167,936 | 0 | 152,897.2 |
| 0.70 | Intermittent / fixed-rate-online | 118,375.2 | 167,936 | 49,560.8 | 88,554.5 |
| 0.70 | Always participating | 167,936 | 167,936 | 0 | 138,115.3 |

The latent workloads contain mean 91.7 and 181.8 real frames per trial at probabilities 0.35 and 0.70. Valid always-participating traffic adds upstream cover cost while keeping downstream envelope volume fixed. These are component byte counts, not deployment cost or full-pipeline goodput.

Four focused Python tests pass, including actual-batcher export/oracle integration against the retained executable, schema/private-field rejection, invalid configuration bounds, known intersections, knowledge sensitivity, no-beacon/all-participant behavior, Wilson reporting, and repeated analysis producing exactly the same three cost rows without appending duplicates. The Rust example passed `cargo clippy -p oblivion-batcher --example presence -- -D warnings` before the campaign. Endpoint receive checks authenticate all incoming frames and verify their private expected payloads; random cover authentication is rejected for missing slots. These checks do not claim that an untrusted batcher can keep disconnected clients present.

A subsequent provenance review added a guard to `--raw-source`: it verifies every recorded artifact digest and requires manifest entries for every configured observer/truth/beacon stream before creating the output directory. A tampered valid-gzip input is rejected without creating output paths or changing source artifacts. The added regression test failed against the previous implementation and passes after the guard; all five focused tests pass against the retained binary. The new verifier also checked all 197 original recorded artifacts successfully. Existing campaign and corrected-analysis provenance remain historical records and were preserved.
