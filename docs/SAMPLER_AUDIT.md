# Exact finite-distribution check for scaler noise

The autoscaler roadmap marks independent sampler review as open. This adds
exact-rational regression checks for narrow parts of that review:
one-function request-level adjacency and one two-function bounded-user
adjacency, each for a single release. They complement the seeded Monte Carlo
marginal test with deterministic calculations over the full finite support
of the implemented capped sampler.

## Calculation

For configured rational `q`, cap `K`, and a capped geometric draw `G`, the
test constructs

`P(G=j) = (1-q) q^j` for `0 <= j < K`, and `P(G=K) = q^K`.

It convolves two such independent draws to obtain the exact rational
distribution of `D = G1 - G2`. For neighboring one-count inputs, it computes
the hockey-stick divergence in both directions using
`exp(epsilon_effective) = 1/q`, then compares the larger exact value to the
sampler's declared per-release delta bound. This enumerates every output,
including the capped support boundaries; it does not use random samples.

## Results

| Total epsilon | Configured total delta | Releases | Cap | Exact one-release delta | Declared one-release bound | Composed bound |
|---:|---:|---:|---:|---:|---:|---:|
| 2.0 | 1e-3 | 1 | 4 | 2.9006269814e-4 | 7.6172511533e-4 | 7.6172511533e-4 |
| 2.0 | 1e-6 | 2 | 16 | 7.1135797531e-8 | 3.0786910381e-7 | 6.1573820763e-7 |
| 0.5 | 1e-4 | 3 | 70 | 1.3164700544e-6 | 3.1666936690e-5 | 9.5000810071e-5 |

All exact one-release divergences are below the declared per-release bounds;
the reported basic-composition bounds are below the configured total delta
for these cases. The independent exact check is in
`test_exact_capped_noise_hockey_stick_is_below_declared_delta` in
[`test_scaler.py`](../research/tests/test_scaler.py). Existing tests separately
check parameter composition, the fixed entropy draw shape, malformed entropy
rejection, and empirical sampler marginals.

The cap-2 bounded-user check uses two pools, one release, total epsilon 2,
and the declared one-release delta bound 5.6044601951e-4. It enumerates both
possible placements of two added requests across pools: `(2, 0)` and `(1, 1)`.
Exact divergences are 8.8567362761e-5 and 5.7395634356e-5, respectively, in
both neighboring directions.

## Scope limits

This is not an independent source-code or cryptographic audit. The tests use
the production parameter generator's `q` and cap, then independently
reconstruct the finite probability law and its one-coordinate or two-pool
divergence for the listed settings. They do not prove the coupling bound for
every cap and epsilon, arbitrary pool counts or bounded-user shifts, the full
composition theorem, any identity-authentication assumption, OS-CSPRNG
behavior, runtime timing leakage, or the end-to-end autoscaler transcript.
The public-seed experiment artifacts still have no differential-privacy
guarantee. The bounded-user guarantee remains conditional on stable,
non-spoofable identities and per-user clipping over the stated horizon.

Run the exact check with:

```sh
.venv/bin/python -m unittest \
  research.tests.test_scaler.ScalerTests.test_exact_capped_noise_hockey_stick_is_below_declared_delta
.venv/bin/python -m unittest \
  research.tests.test_scaler.ScalerTests.test_exact_bounded_user_two_pool_hockey_stick_is_below_declared_delta
```
