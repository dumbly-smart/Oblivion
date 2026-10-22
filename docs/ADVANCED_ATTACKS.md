# Offline likelihood inference over encrypted SSE observations

This work adds numerical inference over the existing local synthetic SSE experiment. It executes no index mutation, chosen-file experiment, or external target interaction. It reads the full Rust-generated encrypted-index exports described in [SSE_ATTACKS.md](SSE_ATTACKS.md), extracts actual observed query equality and posting counts, and compares three mathematically specified inference methods. These additions are not faithful reproductions of SAP, IKK, or IHOP.

## Source basis and scope

[Oya and Kerschbaum, USENIX Security 2021](https://www.usenix.org/conference/usenixsecurity21/presentation/oya), motivate query recovery from search-pattern leakage and statistical auxiliary knowledge. Their paper page describes a maximum-likelihood attack using access and search patterns. The large PDF could not be retrieved through the browsing service in this session; no claim of a line-by-line reconstruction is made.

[Their IHOP paper, USENIX Security 2022](https://www.usenix.org/system/files/sec22-oya.pdf), §4.2 and Algorithms 1–2, fixes part of an assignment and repeatedly solves linear assignments for the remaining tokens; quadratic terms between two free tokens are omitted from each linear subproblem. Its official [author artifact](https://github.com/simon-oya/USENIX22-ihop-code) exists. We inspected the primary description and artifact landing page, without importing, copying or translating artifact code. Our implementation differs in objective, smoothing, initialization, acceptance rule, vocabulary, data, and evaluation.

The implementation uses SciPy's [optimal rectangular linear assignment solver](https://docs.scipy.org/doc/scipy/reference/generated/scipy.optimize.linear_sum_assignment.html). Although the experiment calls the refinement “iterative Hungarian,” SciPy implements a modified Jonker–Volgenant assignment algorithm. The term describes repeated exact linear assignment subproblems, not an independently implemented Hungarian solver.

## Inputs and knowledge

The source is `experiments/results/sse-attacks`, comprising 30 independent trial seeds, three modes, and two target sessions per trial. Each trial provides an independently sampled public corpus and a complete separate labeled public query profiling session. Both target sessions share this auxiliary information; neither is used to fit it. Each target session contains 64 queries. The candidate vocabulary has eight keywords, although an individual target session can omit some of them.

For a query tag `t`, the observation contains its opaque equality tag and observed encrypted posting count `v[t]`. No plaintext document IDs or cross-keyword document intersections are supplied. Different keywords use separate GGM leaf addresses and client-only encrypted IDs, so intersecting their posting addresses would not give document co-occurrence. We deliberately use observed query transition counts instead of inventing such a feature.

The auxiliary corpus contains `N = 256` document incidences per keyword. Let `c[w]` be its keyword counts. The independent labeled public query profile has length `L = 2048`, keyword counts `u[w]`, and transition counts `a[w,z]`. The attacker is given the candidate universe and public corpus size, and computes:

```text
p[w]   = (c[w] + 0.5) / (N + 1)
q[w]   = (u[w] + 1) / (L + K)
P[w,z] = (a[w,z] + 1) / (sum_z a[w,z] + K)
```

The first expression applies Jeffreys smoothing to a Bernoulli incidence probability; the others apply Laplace smoothing. These are plug-in estimates, not integrated Bayesian posterior prediction. The public and target corpora are independently sampled from the same latent incidence probabilities except in the expressly exact-count positive control. Query profiles and target sessions are independently sampled from the same query distribution.

The attack accepts only observations and auxiliary knowledge. The evaluator loads target labels after all predictions for that session have been computed. Target labels enter only scoring and consistency checks. It does not use the published synthetic workload seed to reconstruct a label schedule.

## Numerical objectives

An injective mapping `pi` assigns each of the `m <= K` observed tags to a different candidate keyword. For each observed tag, define its count log likelihood:

```text
B[t,w] = v[t] log p[w] + (N - v[t]) log (1 - p[w])
```

The binomial coefficient can be omitted because it depends on `v[t]`, not its assigned label. Each count contributes **once per distinct tag**, not once per repeated query. This assumes a static corpus and a binomial marginal model. In the known fixed-padding mode, set `B = 0`; the attacker knows that 96 stored encrypted postings reveal no real keyword count.

**Separable likelihood assignment.** Let `f[t]` be the number of queries bearing tag `t`. The method maximizes:

```text
S_IID(pi) = sum_t (B[t, pi(t)] + f[t] log q[pi(t)])
```

This is the plug-in joint likelihood of the keyword volumes and an IID query sequence, under the stated independence model. It is a rectangular linear assignment problem solved globally. The implementation additionally enumerates feasible mappings and confirms that the linear solver attains the enumerated optimum. The one-to-one constraint uses more information than independently choosing the closest count for each query.

**Approximate iterative assignment under a Markov model.** Let `T[t,s]` count consecutive target query tags and let `t0` be the first tag. The alternative model maximizes:

```text
S_Markov(pi) = sum_t B[t, pi(t)] + log q[pi(t0)]
              + sum_t,s T[t,s] log P[pi(t), pi(s)]
```

This is a first-order Markov query likelihood plus marginal volume likelihood. It replaces the IID frequency term; it does not add both terms and double-count a query sequence. Each target session is evaluated separately, so no transition is fabricated across session boundaries.

Refinement starts from the separable likelihood assignment. For 200 seeded iterations, choose up to three free tokens, retain the other assignments, and solve the linear assignment of free tokens to available keywords. The subproblem includes unary terms, token self-transitions, and both incoming and outgoing transitions involving fixed tokens. It omits transitions between distinct free tokens. A candidate is accepted only when the **full** Markov objective improves. This monotone acceptance rule is an additional approximation choice, not a reproduction of IHOP's update rule. The saved prediction records include every accepted objective value.

**Exact bounded comparator.** With at most eight keywords, the evaluator can enumerate all injective mappings: at most `8! = 40320`. It computes the exact Markov objective optimum. This supplies an upper bound on that numerical objective, not on attainable recovery accuracy. A better objective can produce worse true labels when the statistical model is imperfect. Exhaustive enumeration is not a scalable substitute for a published attack on a large vocabulary.

For top-three rankings, each optimizer's assigned MAP label is first; remaining labels follow exact posterior marginals obtained by normalizing the corresponding model scores over all feasible mappings with a uniform mapping prior. Thus top-three results for the iterative method use additional exhaustive computation. They must not be presented as an efficient iterative method's standalone confidence scores. These plug-in model marginals are not calibrated real-world probabilities.

## Results and uncertainty

All methods first pass the actual encrypted exact-count positive control: ordinary recovery accuracy must exceed the public-profile majority baseline by 0.2. The query profiles remain independent even in this deliberately favorable count control.

The checked run produced:

| Method | Exact-count control | Independently sampled SSE | Padded SSE |
| --- | --- | --- | --- |
| Likelihood assignment | 94.43% (91.02–97.50%) | 80.52% (72.45–87.53%) | 33.80% (28.15–39.17%) |
| Iterative Markov assignment | 90.96% (87.32–94.56%) | 75.55% (68.72–81.85%) | 30.96% (25.88–36.20%) |
| Exact Markov objective optimum | 91.09% (87.53–94.53%) | 75.81% (69.50–81.77%) | 28.57% (22.92–34.45%) |

Entries are ordinary query recovery accuracy with 95% percentile bootstrap intervals over 30 independent trial means. The profile-majority baseline is 21.69%; uniform eight-way chance is 12.5%. Two target sessions sharing one profile and corpus remain in the same resampled trial cluster. There are 540 method/session score records, not 540 independent trials. Source modes share workload samples and are paired, although the figure displays each mode's marginal interval separately.

The [report](../experiments/results/inference-sse/report.json) also records balanced accuracy, distinct-token recovery, top-three recovery, majority and hindsight-majority references, advantage over profile majority, and optimizer objective gaps. Balanced accuracy averages recall over classes present in each target session. This is a multiclass permutation inference task, so a binary ROC/AUC is not supplied.

The iterative method's mean objective gap from the exact Markov optimum is about 0.028 log units for SSE and 0.363 for padded SSE. Its recovery can nevertheless exceed the exact optimum's recovery, as the padded result illustrates. Optimization quality and statistical identification quality are separate measurements.

These target queries were generated IID, so the independently estimated transition matrix mainly adds finite-profile noise. No transition-model improvement was assumed or forced. The stronger separable likelihood assignment raises SSE recovery relative to the earlier nearest-count baseline by combining count and query-frequency evidence under a global injective assignment. Fixed-count padding removes its volume evidence, while search equality and frequency information remain.

## Reproduce and audit

This command only reads existing local inputs and performs numerical analysis:

```sh
.venv/bin/python -m unittest research.tests.test_inference -v
.venv/bin/python -m research.analysis.inference experiments/results/sse-attacks experiments/results/inference-sse
```

Use a new output directory when regenerating; preserve an existing result directory first. The analysis writes:

- `report.json`: full configuration, summary intervals, and per-session metrics.
- `predictions.json`: rankings, mappings, model posterior marginals, objective values, and accepted refinement histories.
- `inference-attacks.png`: reproducible comparison figure.
- `provenance.json`: input hashes, analysis/test/dependency source hashes before and after execution, Python executable hash, package versions, platform, output hashes, and the original SSE generation provenance.

No Rust trace-generation executable is launched by this analysis. The preserved original generation provenance identifies the real encrypted-index exporter, original binary, hardware and workload; the new provenance identifies the numerical analysis separately. Six tests cover a numerical positive control, exact linear optimum versus enumeration, monotone refinement and its exact objective bound, known-padding behavior, missing tokens, and rejection of changing counts in the static-corpus model.

The vocabulary is tiny, distributions synthetic and stable, and corpus/query independence unusually favorable to modeling. Neither chance-like recovery nor a high exact-objective score is a cryptographic result. No claim covers hidden query equality, realistic distribution drift, active adversaries, executor leakage, or full-system composition.
