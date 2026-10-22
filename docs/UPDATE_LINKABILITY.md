# Controlled update association experiment

This local synthetic experiment compares a deliberately non-forward-private encrypted stable-tag index with the actual bounded GGM SSE crate. Both perform genuine AEAD encryption. The control attaches a stable keyword HMAC tag to every update; it is clearly labeled and is not called Diana. No external service or real user dataset is involved.

```sh
.venv/bin/python -m unittest research.tests.test_linkability
.venv/bin/python -m research.analysis.linkability experiments/results/update-linkability-NEW
```

Thirty independent ephemeral setups each initialize eight opaque keyword classes with four postings, observe all eight past searches, add one chosen document posting to each class in shuffled order, then observe the next searches in a separately shuffled order. The exporter uses actual `Client::prepare_add`, `Server::insert`, `finish_add`, constrained search and authenticated client recovery. Its oracle verifies all original and chosen document IDs. Server-visible requests/responses are saved as compressed JSONL; the shuffled association truth is a separate file. The numerical attacker takes only server records and a guessing seed, never target labels.

The attacker first tries stable update tags and already-authorized posting addresses to associate each chosen update with a prior opaque search event. With no match it makes a seeded random permutation guess. After the next searches, it matches chosen addresses in the returned posting lists and links repeated search tags. The retained GGM capabilities cover exactly the earlier four counters; their inability to authorize the fifth counter is separately tested exhaustively by the SSE crate. This experiment's before-stage attacker checks the known authorized address set; it is not a general cryptanalysis or a proof of forward privacy.

Actual results are in `experiments/results/update-linkability-30-20261021/report.json`, with full raw records, source/executable hashes and a figure:

| Index | Before next search | After next search |
| --- | ---: | ---: |
| Stable-tag encrypted control | 100% | 100% |
| Bounded GGM SSE | 15.83% [10.42%, 21.25%] | 100% |

Uniform chance is 12.5%. Intervals resample the 30 complete trial means. Before authorization, the control provided 240/240 direct matches; GGM provided 0/240 direct matches. After authorization, both provided 240/240. The chance-like guessing result is a narrow regression check, not evidence of a general security theorem.

The result exposes the intended limit: forward privacy delays the association of a fresh update with a past query; it does not hide the membership of an adversarially known document after the next authorized search. This is a simplified controlled chosen-update experiment, not a reproduction of a published file-injection attack or a guarantee against every active attacker. Timing, update grouping and auxiliary workload knowledge may expose more. There is no backward privacy or malicious-server availability claim.
