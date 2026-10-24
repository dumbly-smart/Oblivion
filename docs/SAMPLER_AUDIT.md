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

The bounded-user check enumerates every nonzero nonnegative pool-count shift
whose L1 norm is at most the configured cap, in both neighboring directions.
For two pools, cap 2, epsilon 2, and delta 1e-3, the worst exact divergence
is 8.8567362761e-5 against a declared bound of 5.6044601951e-4. Two further
parameter sets were checked: three pools/cap 2/epsilon 1.5/delta 1e-2 had
worst divergence 7.5564400386e-4 against 5.7285527124e-3; two pools/cap
3/epsilon 3/delta 1e-2 had worst divergence 6.6498670041e-4 against
3.8291275813e-3. These are finite exact checks for the tested configurations,
not a proof for arbitrary dimensions or caps.

A source-level review also checked that each capped geometric stream consumes
a fixed-size random word, that the cap absorbs the entire remaining tail, and
that the per-release sensitivity and union-bound dimensions match the stated
request and bounded-user adjacency. It found a malformed-input defect in
`Config.validate`: Python booleans passed its numeric check. Boolean values for
numeric configuration fields are now rejected before calibration. This
correctness fix does not authenticate user IDs or extend the privacy claim.

## Scope limits

This is not an external source-code or cryptographic audit. The tests use the
production parameter generator's `q` and cap, then independently reconstruct
the finite probability law and divergence for the listed settings. They do
not prove the coupling bound for every cap and epsilon, arbitrary pool counts
or bounded-user shifts, the full composition theorem, any identity-
authentication assumption, OS-CSPRNG behavior, runtime timing leakage, or
the end-to-end autoscaler transcript.
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
