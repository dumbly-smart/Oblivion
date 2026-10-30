# SSE count, volume, and search-pattern evaluation

This experiment executes the actual append-only bounded GGM SSE crate independently of the runtime. Its observable data come from `Client::prepare_add`, `Server::insert`, `Client::prepare_search`, and `Server::search`, followed by actual AEAD verification with `Client::finish_search`. It does not construct defended traces from a plaintext index. See [the construction](SSE_DESIGN.md) and [component implementation](SSE_IMPLEMENTATION.md).

## Reproduce

From the repository root, install `research/requirements.txt` in `.venv` if needed, then run:

```sh
cargo build --release -p oblivion-sse --example leakage
cargo clippy -p oblivion-sse --example leakage -- -D warnings
.venv/bin/python -m unittest research.tests.test_sse_attacks -v
.venv/bin/python -m research.analysis.sse generate experiments/configs/sse-attacks.json experiments/results/sse-attacks --binary target/release/examples/leakage
```

Generation requires a new output directory; rename an existing result directory to preserve it. To score existing raw traces and regenerate the figure:

```sh
.venv/bin/python -m research.analysis.sse evaluate experiments/results/sse-attacks
```

The committed [raw results and report](../experiments/results/sse-attacks/report.json) use 30 independent trial seeds starting at 20261021. Each trial has a fresh public corpus, target corpus, independently sampled labeled public profiling session, and two complete held-out target sessions. Each mode creates a fresh client/master key/index. Workload samples reproduce from seeds; cryptographic ciphertexts, index identities and local timings vary because keys come from `OsRng`. The compressed JSONL files contain the actual full server wire messages, including constrained seeds, addresses, ciphertexts and stable search tags. They are research fixtures, not client secrets.

`provenance.json` records hardware, Python/NumPy/Rust versions, git HEAD, source and binary hashes, workload command and raw artifact hashes. `analysis-provenance.json` records the analysis source, attack source, final report and plot hashes. The git HEAD alone is insufficient to identify these additions; the source hashes cover them. Durations are local prepare-plus-server-search measurements, excluding client verification and transcript serialization. JSON byte lengths reflect this exporter, not a specified binary network framing or TCP packets.

## Knowledge boundary

The vocabulary is eight keywords. Each trial randomly assigns document probabilities from 1/32 through 8/32 to keywords. A public auxiliary corpus and a target corpus each contain 256 independent Bernoulli document incidences per keyword. They share a latent distribution but have independently sampled actual counts. The experiment synthesizes keyword posting lists rather than a realistic email corpus or correlated keyword document sets.

Independently of document popularity, keyword query weights are a shuffled permutation of 1 through 8. One labeled public profiling session contains 2048 draws from that distribution. Two target sessions contain 64 queries each from the same distribution; none of their labels is authorized profiling knowledge. Public profile labels and counts live in `auxiliary.json`; target counts and query labels live in `ground-truth.json`. Attacks receive only auxiliary knowledge and server-derived observations. The scoring function reads target labels after the rankings exist. No individual query from a target session is put in profiling data.

The count/volume attacker ranks candidate labels by distance between observed encrypted posting count and public-corpus count. It uses the independent public query prior to break ties, with seeded randomness only for equal priors. All encrypted IDs have the same length, so posting count and cryptographic response volume carry the same signal here. This is a transparent count baseline inspired by leakage-abuse evaluation; it is not a faithful reproduction of Cash et al.'s complete algorithm.

The stronger extension groups the stable search tags observed during a whole target session and assigns public keyword labels by query-frequency rank. It uses all unlabeled queries in that session offline. It does not use target labels or map tags through a known plaintext index. Equal frequency ties are seeded. The extension is a simple search-pattern frequency attack; it does not implement co-occurrence estimation, transition correlations, quadratic assignment, file injection, IKK, published MLE, or IHOP. Top-three rankings for this extension retain the assigned label first and put the remaining labels in public-prior order; they are heuristic rankings, not calibrated posteriors.

Search-pattern attacks are motivated by [Oya and Kerschbaum's 2021 primary paper page](https://www.usenix.org/conference/usenixsecurity21/presentation/oya), which explains why query equality survives access-pattern defenses. [Their 2022 IHOP paper](https://www.usenix.org/conference/usenixsecurity22/presentation/oya) instead solves quadratic optimization through repeated assignment problems and exploits richer statistical information. A public [author IHOP artifact](https://github.com/simon-oya/USENIX22-ihop-code) was surfaced during this work, correcting the roadmap's earlier unverified-artifact note; none of its code was imported or translated. This experiment must not be called an IHOP reproduction.

## Positive control and genuine padding

Modes execute in this order for every trial:

1. **Exact-count control:** real SSE posting counts intentionally match the auxiliary corpus exactly. This deliberately grants unusually accurate count knowledge and validates the attack using the same encrypted implementation. The control is leaky in its count relation, not because keyword labels were inserted into the observer data. Duplicate public counts can still prevent perfect recovery.
2. **SSE:** real target posting counts are independently sampled. Search exposes their exact count even though updates use constrained GGM addresses. Forward privacy does not promise result-volume privacy.
3. **Padded SSE:** the trusted workload builder inserts real AEAD-encrypted dummy postings under the actual keyword until every keyword has 96 postings. Server search expands and returns all 96 actual ciphertexts. The high bit of the decrypted eight-byte ID marks dummies; only the trusted client filters them after authenticating and checks the full expected real result list. Dummy markers and real counts do not appear in the observer export. Updates are randomly interleaved across keywords, preserving each keyword's posting order.

The padding bound is public and the attacker knows it. For this mode, count distance contains no keyword evidence, so the count attacker uses its public prior, attaining the profile-majority baseline rather than forcing uniform guesses. The frequency attacker still sees stable query tags. A test demonstrates that the frequency method recovers labels from deliberately separated tag frequencies even when every count is equal; the evaluation additionally requires its exact-control mean accuracy to exceed profile majority by 0.1. The count control must exceed profile majority by 0.2 before the report is accepted.

This is a static index-build padding mechanism supplied by the experiment wrapper. It costs 768 stored postings per padded trial. It is not a general dynamic volume-hiding SSE protocol: future growth, repadding, epochs, changes to the bound, update correlations, timings and persistent state need additional design. Padding only the network response would leave the exact request covers and server lookup count visible and would not justify this result. Here the covers, actual stored postings and server lookup count are all padded.

## Measurement and interpretation

[The figure](../experiments/results/sse-attacks/sse-attacks.png) compares the attacks, positive control and defense. The report includes ordinary accuracy, balanced accuracy (mean recall over classes present in each target session), top-three accuracy, public-profile majority accuracy, hindsight target-majority accuracy, uniform chance (1/8; top-three 3/8), and accuracy advantage over profile majority. Hindsight majority is a scoring reference; its target labels never train an attacker.

Confidence intervals use 5000 percentile bootstrap resamples of the 30 independent trial means. Both target sessions sharing one public profile and corpus remain inside the same trial cluster. The report includes intervals for balanced/top-three/baseline/cost metrics as well as ordinary accuracy. Queries are not treated as independent trials. The independent-trial count is 30 for each attack/mode, not 3840. Modes share workload samples and can be compared as paired trials, although the plotted error bars describe each mode separately.

The checked run produced:

| Attacker | Mode | Accuracy (95% trial-cluster interval) | Balanced accuracy | Top-three |
| --- | --- | --- | --- | --- |
| Count/volume | Exact-count control | 98.88% (97.81–99.77%) | 97.41% | 100.00% |
| Count/volume | SSE | 51.67% (43.07–60.00%) | 48.14% | 93.78% |
| Count/volume | Padded SSE | 21.69% (20.42–22.97%) | 12.99% | 57.58% |
| Search-pattern frequency | Each of the three modes | 32.24% (26.93–37.37%) | 35.23% | 64.43% |

The public-profile majority baseline is 21.69%; uniform eight-way chance is 12.5%. Identical query sequences across paired modes explain identical frequency recovery: padding retains the same equality groups. Mean observed postings rise from 36.81 to 96 per search (2.61×); mean JSON response length rises from 9286 to 24082 bytes (2.59×). These figures exclude update transport and container overhead. Full source-dependent cost and uncertainty values are in the report.

The experiment shows result counts can support query recovery after forward-private updates, and that genuine fixed-count dummy postings remove this particular count signal. Stable-tag frequency recovery survives this padding. Neither a chance-like result nor equality to a majority baseline proves security. The candidate space is small, the corpora synthetic, auxiliary distributions unusually stable, and the attacks deliberately transparent. Timing and byte encodings are exported for audit but are not trained into these attackers; no claim covers those channels, active attackers, keyword intersections, real workload drift, unknown vocabulary, executor leakage, or composition with the runtime.

The scoped verification is a release build, example-only Clippy with warnings denied, and eight Python unit tests. Tests include real Rust AEAD updates/search, actual dummy padding with trusted-client result verification, equal-count search-pattern leakage, independent corpus sampling, prior-aware ties, cluster uncertainty, and refusal to truncate an under-sized padding bound. They do not establish a cryptographic security theorem.
