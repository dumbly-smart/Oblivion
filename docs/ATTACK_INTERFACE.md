# Offline attack interface

`research.attacks.registry` adds a common adapter interface over the existing
algorithms. Existing analysis scripts continue calling their original code.
The adapters do not change those algorithms or supply new experimental results.
All implementations are simple approximations, **not faithful reproductions of
published attacks**. In particular, the iterative assignment model is not IHOP,
and chosen-update association is not a general forward-privacy attack or proof.

```python
from research.attacks.registry import create_attack

attack = create_attack('count')
result = attack.run([{'count': 7}], {'counts': [19, 7]})
assert result.predictions == [1]
assert result.confidence is None
payload = result.to_dict()  # JSON-compatible predictions, confidence, metadata
```

Every plugin implements `Attack.run(trace, aux) -> PredictionResult`.
`predictions` contains one top label per observation, except association, which
returns one opaque past-search slot per injected update. Presence returns one client identity for the entire observed trace (or `None` for an empty candidate set). All built-in adapters
return `confidence=None`: binary class indicators, leaf proportions, rankings,
and plug-in posterior marginals are not calibrated success probabilities.
Metadata labels these outputs `UNCALIBRATED` and retains the original scores,
rankings, or function result for inspection. It does not invent predictions or
silently reinterpret scores as confidence.

## Registered implementations

| Name | Actual implementation called | Observations | Auxiliary knowledge |
| --- | --- | --- | --- |
| `frequency` | `simple.FrequencyAttack.run` | `tag` | `ranked_labels`, `majority` |
| `traffic` | `simple.TrafficAttack.fit/run` | `bytes`, `latency_ns` | Fit labels and separate session IDs; target session IDs at run |
| `joint` | `joint.JointAttack.fit/run` | All twelve joint fields below | Fit labels and separate session IDs; target session IDs at run |
| `count` | `sse.CountVolumeAttack.run` | `count`, optional `tag` | `counts`, optional `query_counts`, `seed`, `pad_to` |
| `searchpattern` | `sse.SearchPatternFrequencyAttack.run` | `tag`, `count` | `counts`, `query_counts`, optional `seed`, `pad_to` |
| `likelihood` | `inference.infer` → `likelihood_assignment` | `tag`, `count` | `counts`, `corpus_documents`, independent `profile_labels`; optional `padded`, `seed` |
| `iterativeLAP` | `inference.infer` → `iterative_hungarian_markov` | Same | Same |
| `exactboundedcomparison` | `inference.infer` → `exact_markov_bound` | Same | Same |
| `presence` | `presence.intersect` | Declared epoch/participation/byte fields | Public semantic `beacon`; optional `knowledge_events`, `observer`, independent tie `seed` |
| `chosenupdateassociation` | `linkability.recover_links` | Local observation records below | `mode`, optional `seed` |

The six roadmap-facing names are `count`, `searchpattern`, `likelihood`,
`iterativeLAP`, `exactboundedcomparison`, and `chosenupdateassociation`.
They identify the limited models implemented here, not additional claims about
named published attacks. The original `infer` function computes all three
comparisons, including exact enumeration, even when selecting only one output.
The adapter preserves that behavior and its cost; at most eight labels are allowed.

Joint fields are `request_bytes`, `response_bytes`, `registry_bytes`,
`registry_index`, `storage_events`, `storage_bytes`, `last_bucket`,
`storage_span_ns`, `latency_ns`, `late_by_ns`, `instance_count`, `cold_start_ns`.

## Independent profiling

```python
attack = create_attack('traffic')
attack.fit(
    [{'bytes': 4, 'latency_ns': 9}, {'bytes': 64, 'latency_ns': 7}],
    {'profile_labels': [1, 0], 'profile_session_ids': ['profile-session']},
)
result = attack.run(
    [{'bytes': 4, 'latency_ns': 100}],
    {'target_session_ids': ['held-out-session']},
)
```

`fit` requires one label per profiling row and a nonempty list of profile session
IDs. `run` requires nonempty target session IDs disjoint from those provided at
fit. IDs name the complete sessions represented by each input. This checks the
caller's declared separation; it cannot authenticate the provenance of a trace.
The caller must supply genuinely independent profiling data and assign IDs
honestly. Binary traffic labels are 0/1; joint profiles must cover 0/1/2, as the
original model requires. Labels occur only in explicit auxiliary profiling data,
never inside observer rows. Inference's `profile_labels` similarly identifies
an independent public query profile, never target-session labels.

## Input bounds and observer schemas

Built-in adapters reject unknown observation and auxiliary fields. Thus `label`,
`truth`, `target_labels`, `real`, `function`, and similar private fields cannot
be included in observer records. This is schema enforcement, not protection
against a caller disguising truth as an allowed feature.

Inputs contain 1–10,000 records. Numeric values must be finite, nonnegative, at
most 10^15; count values and labels must be integers (booleans are rejected).
Tags are uniformly typed nonnegative integers or strings of 1–256 characters.
Count/frequency vocabularies contain 1–256 labels; inference vocabularies contain
1–8 labels and cannot contain more observed tags than labels. Query priors must
match vocabulary size. Inference preserves the original static-count-per-tag
and public corpus checks. Seeds are integers in [0, 2^32−1]. Known fixed padding
is passed to the existing implementation and suppresses count evidence there.

Association records allow only `mode`, `phase`, `slot`, `injection`, `request`,
and `response`. Search phases (`past_search`, `fresh_search`) require an opaque
request `tag`, a `slot`, and response `entries` with an `address` and optional
`ciphertext`. Update phase (`injected_update`) requires request `address` and
optional `stable_tag`. Tags, addresses, and ciphertext here are lists of 1–256
byte values. There are at most 10,000 total response entries. Past `slot` values
are **opaque observer-assigned event identifiers**, never plaintext word labels.
Association checks apply within the selected mode; unknown nested fields are
rejected across every record. Before-search predictions are the primary output;
`metadata.original_result.after_predictions` preserves predictions after the
known posting is authorized by a fresh search. These stages have different
knowledge, so the adapter does not combine their scores.

## JSON CLI

```sh
.venv/bin/python -m research.attacks --list
printf '%s\n' '{"trace":[{"count":7}],"aux":{"counts":[19,7]}}' |
  .venv/bin/python -m research.attacks --attack count
.venv/bin/python -m research.attacks --attack count --input /path/to/input.json
```

`--list` returns a sorted JSON array of stable descriptions, observation fields,
auxiliary fields, fit support, and limitations. It does not need NumPy or SciPy;
execution imports the dependencies of the selected existing algorithm lazily.
Run input is an object with `trace`, `aux`, and optional `profile`, where
`profile` contains its own `trace` and `aux` passed to `fit`. Input is bounded to
8 MiB. Successful stdout is a single JSON document; invalid input returns exit
status 2 and a diagnostic on stderr. JSON NaN/Infinity are rejected.

## Adding a plugin

```python
from research.attacks.registry import AttackSpec, register_attack

register_attack(
    AttackSpec('my_attack', 'Specific offline model', ('tag',), ('public_prior',)),
    MyAttack,  # zero-argument factory implementing run(trace, aux)
)
```

Names must be unique. New plugins own their declared schema validation, bounds,
truth separation, and confidence semantics; registration does not enforce their
implementation. Register a custom plugin in the running process before using
`create_attack` or `list_attacks`; the standalone CLI ships the built-ins only.
Do not add dependencies or target interaction through this registry.

Verification: `.venv/bin/python -m unittest research.tests.test_attack_registry -v`
compares all nine adapters against actual original implementations on numerical
and local observer fixtures, checks separation and malformed inputs, exercises
registration, and round-trips the CLI JSON.
