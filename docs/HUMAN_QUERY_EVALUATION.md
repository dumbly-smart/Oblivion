# Human search query workload evaluation

This experiment feeds filtered Bing query text from MIMICS-Click into the existing constrained-GGM SSE evaluation. It evaluates whether query-content priors help an attacker infer which known vocabulary terms appear in a user's search. It does not measure a real user's full search history, population-level risk, or query arrival rates.

## Dataset and terms

MIMICS-Click contains 414,362 unique query-clarification rows sampled from Bing's en-US market in September 2019. The paper says the released queries had appeared at least 40 times from distinct users in the prior year; released query-clarification pairs had at least 10 impressions; session and personalized information was excluded; additional proprietary filtering was applied; and sensitive or inappropriate content was automatically removed. See the [MIMICS paper](https://www.microsoft.com/en-us/research/uploads/prod/2020/06/CIKM_2020___Clarification_Data-7.pdf) and the [archived Microsoft repository](https://github.com/microsoft/MIMICS).

The repository advertises an MIT license but its README also includes a terms paragraph for ORCAS that describes noncommercial research use. This experiment is confined to noncommercial research and preserves that ambiguity in `provenance.json`; it does not interpret the terms as unrestricted reuse. The cited materials do not establish individual consent or guarantee anonymity. A 40-user threshold and filtering are privacy measures, not proof that query text is harmless.

The pinned input is the official `MIMICS-Click.tsv` at repository commit `6450e8143bd380505bbf047822e41a2a3a2b474f`. The config records the URL, exact byte size, and SHA-256. The source TSV is downloaded to a temporary directory during a normal run; a private predownloaded input may be passed with `--source`. The downloaded source used for the recorded run is kept outside the repository in `/tmp` and must not be copied into results or committed.

## Workload construction

The script reads only the `query` column. It lowercases text, extracts distinct ASCII alphabetic tokens of length 3–16 in their original order, and discards the original query string immediately. Each source query is one target session. The session's in-vocabulary tokens are sent as sequential single-keyword SSE accesses. This uses observed query terms and does not invent query labels. It is a token-level workload derived from multiword searches; the SSE interface does not reproduce web-search ranking or multi-term result semantics.

For each of 30 seeded trials, the script randomly partitions whole query rows. It chooses eight vocabulary terms from 2,048 auxiliary query rows based only on auxiliary query-document frequency, requiring distinct count values. It selects eight target query rows from the disjoint remainder that contain at least one selected term. The auxiliary rows provide public posting lists and the empirical term prior; target query rows supply the hidden session labels. Each target row is one session. The current exporter accepts at most two sessions per invocation, so the eight target sessions are exported in four batches. The report gives the fraction of target-pool queries with at least one in-vocabulary term. Terms outside the selected vocabulary are omitted, so interpret metrics only alongside this coverage.

The exact-count positive control is run and required to exceed the profile-majority baseline by 0.2 mean accuracy before unpadded or padded SSE results are evaluated. Both SSE modes use the existing real constrained-GGM executable with fresh client keys. Summary intervals bootstrap whole-trial means; source rows recur across trials, so these intervals do not represent independent collections of search users.

## Recorded result

The 2026-10-24 run processed 414,362 source rows; 411,616 had at least one searchable token. Mean target-pool query coverage by the auxiliary-selected vocabulary was 12.2% (trial range 10.2%–12.6%). There were 240 target sessions across the 30 split/workload trials. The exact-count control passed before defenses were scored; its mean token-label accuracy was 1.00 against a 0.225 profile-majority baseline. Unpadded SSE also scored 1.00, consistent with exact response counts exposing the distinct auxiliary frequency bins. With public-bound padding, the four attacks scored between 0.217 and 0.225 mean accuracy; for the count-volume attack the 95% split-trial bootstrap interval was 0.175–0.277, around the 0.225 profile-majority baseline. These results are conditional on the small eight-term vocabulary workload and the 12.2% coverage subset; they do not estimate risk over all Bing queries.

Aggregate report and provenance are in [`experiments/results/human-query-20261024`](../experiments/results/human-query-20261024/).

MIMICS publishes unique queries and interaction signals, not per-query search frequency or query timestamps. Accordingly, this workload treats sampled query rows uniformly and makes no claim about query popularity, temporal behavior, or representative arrival-weighted privacy risk. The older AOL query-log disclosure is not used as a data source; random identifiers did not prevent re-identification from linked histories.

## Output and privacy boundary

The raw source, tokenized records, vocabulary, query-to-term incidence, target labels, SSE wire traces, and per-session attack predictions remain in a temporary directory and are deleted when the run ends. Committed results are limited to aggregate metrics, query-coverage statistics, source hashes/size, software provenance, and the stated methodological limits. Do not add raw queries, vocabularies, token incidence, low-count string subsets, per-query output, or wire traces to the results directory.

Run with:

```sh
cargo build --release -p oblivion-sse --example corpus
.venv/bin/python -m research.analysis.human_queries \
  --config experiments/configs/human-query.json \
  --output experiments/results/human-query-20261024 \
  --binary target/release/examples/corpus
```
