# Licensed text corpus and auxiliary drift evaluation

The completed [report](../experiments/results/corpus-real-frozen-20261023/report.json), [figure](../experiments/results/corpus-real-frozen-20261023/corpus-drift.png), [positive-control gate](../experiments/results/corpus-real-frozen-20261023/positive-controls.json) and [provenance](../experiments/results/corpus-real-frozen-20261023/provenance.json) record the final 30-trial campaign using a private executable snapshot. The earlier [campaign](../experiments/results/corpus-real/report.json) is preserved: its exporter path was shared with the build directory and its executable hash was recorded only at the end, so it lacks the final campaign's executable freeze evidence.

The bounded experiment uses document/keyword associations derived from real public text. Query sequences remain synthetic IID samples; they are not measured human search behavior. The target is the local `oblivion-sse` implementation, with fresh CSPRNG client keys and actual AEAD encrypted document IDs.

## Dataset and attribution

Almeida, T. & Hidalgo, J. (2011). **SMS Spam Collection** [Dataset]. UCI Machine Learning Repository. [DOI 10.24432/C5CC84](https://doi.org/10.24432/C5CC84). The [official dataset page](https://archive.ics.uci.edu/dataset/228/sms+spam+collection), checked 22 October 2026, explicitly lists [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The download is the official [compressed archive](https://archive.ics.uci.edu/static/public/228/sms%2Bspam%2Bcollection.zip). This work adapts the collection by normalization, deduplication, partitioning, tokenization and extraction of bounded aggregate postings. UCI's authors and dataset are credited; no endorsement is implied.

The source archive remains only in an ignored `bin/` cache beneath the output directory. It is not redistributed. Archive/member SHA256 digests and source URLs are recorded. Raw messages are processed a line at a time without creating an extracted plaintext file; retained in-memory records contain only normalized tokens, class and digest. Committed derived artifacts contain counts, integer document IDs/postings and source digests, without SMS message text or phone numbers. The source contains personal text; this experiment does not need to republish it. CC BY 4.0 grants copyright/database permissions and does not itself grant privacy or publicity rights.

## Knowledge and splits

Thirty seeded trial resamples each partition deduplicated documents into three disjoint pools: public auxiliary, target, and held-out drift auxiliary. Exact normalized duplicates are removed before splitting. The same underlying source collection is reused across trials: the intervals describe random split/workload variability conditional on this corpus, not thirty independently collected real-world corpora.

Choose exactly eight vocabulary items using public auxiliary documents only. Tokenization is lowercase ASCII alphabetic words, length 3–16; document incidence counts each word once per document. Among frequent auxiliary words, retain eight distinct auxiliary document-frequency bins, breaking equal-count candidate-word ties lexically. This optimistic auxiliary-only selection makes the exact-count control unambiguous; its vocabulary is not a random sample of SMS vocabulary. Stop words are retained. No target counts or labels select the vocabulary. All views and target use the same public document bound. The baseline auxiliary sample is random; held-out auxiliary samples enrich the spam proportion to model substantial distribution mismatch. The target remains unchanged across these attacker knowledge views. Report both requested and observed class mixtures; do not describe these mixtures as chronological drift (UCI says messages are not chronologically ordered).

A labeled public query profile is sampled independently from target query sessions. The synthetic public and target query priors are shared and fixed within a trial; the sensitivity sweep changes document knowledge alone. Two target sessions are held out in full. Attacks receive the auxiliary vocabulary counts, corpus size, public profile and server observations; target document incidence and query labels enter only the trusted workload driver and final scorer. The observer export contains server wire messages, never target keyword IDs or plaintext doc IDs.

## Execution and attacks

First execute an intentionally leaky exact-count positive control through real SSE, with counts equal to the auxiliary base sample. Require count and numerical inference accuracy advantages over public-profile majority before executing defended target modes. Then build real target postings and a second index padded to the public document bound with genuine AEAD encrypted dummy IDs. Trusted clients authenticate and verify every result against the expected real IDs after filtering authenticated dummy markers. All modes use the crate APIs; defended wire messages are never synthesized from plaintext statistics.

Score the existing count baseline and existing eight-keyword likelihood, repeated Hungarian Markov refinement and exhaustive Markov comparator under each auxiliary view. All auxiliary views are disjoint from the target documents. The baseline and held-out drift pools are also disjoint. The two drift views may share held-out documents with each other and are compared within each trial; they do not reveal target word/tag correspondence. The inference routines are transparent plug-in models, not faithful SAP/IHOP reproductions. The query workload is IID, so Markov fitting may overfit profile noise. Known fixed padding removes the count contribution in the model; stable search tags and query frequencies remain visible.

## Bounds and uncertainty

At most eight keywords, at most 100,000 stored postings and the crate's existing bounded result policy apply. The per-view sample is 128 documents, so fixed padding costs 1,024 postings. Source download and member sizes are bounded before decoding. Wire exports are streamed directly into gzip. Cryptographic randomness uses `Client::new`/`OsRng`; seeded Python randomness controls only reproducible corpus splits, update interleaving, vocabulary ties and synthetic workloads.

Report accuracy, balanced accuracy, top-three accuracy, profile-majority/chance baselines, objective gaps, observed posting/response byte costs, class-mixture shift and document-frequency shift. Bootstrap whole trial means, retaining both sessions and all knowledge views within a trial; compare drift views with paired trial differences. Intervals describe these conditional seeded resamples, not uncertainty over all SMS traffic. Corpus realism alone does not establish security, real query realism, dynamic volume privacy, unknown vocabulary resilience or full-system composition.

The original archive README additionally credits copyright to Tiago Agostinho de Almeida and José María Gómez Hidalgo, requests citation of the collection/paper, and supplies an AS IS / no warranty / limitation of liability notice. Those original notices remain in the ignored source archive. The source is made available without warranties of accuracy, merchantability, fitness or non-infringement; users bear the risk of their use. The current UCI CC BY 4.0 designation is recorded alongside this original notice rather than implying the old README itself contained that license label. The data adaptation here does not redistribute original SMS examples.

Initial official download: archive SHA256 `1587ea43e58e82b14ff1f5425c88e17f8496bfcdb67a583dbff9eefaf9963ce3`; uncompressed `SMSSpamCollection` member SHA256 `7d039a24a6083ed9ef0f806ebad56bbb976e3aeb8de05669173bfdc4996c239d`, 477,907 bytes. These are content pins, not an assertion of an external cryptographic signature.


## Reproduce and validation

From the repository root with `research/requirements.txt` installed:

```sh
.venv/bin/python scripts/evaluate_corpus.py --output experiments/results/corpus-real-new
```

The command builds the release example, copies that executable into the ignored output `bin/` cache with read-only permissions, hashes the copy before any export, and launches every control/target subprocess from that private copy. It verifies the copy hash again after the run. The command fetches only the pinned official dataset archive into the same ignored cache. Outputs must be new apart from that cache; the command refuses to overwrite prior results. Eight unit/integration checks cover auxiliary-only vocabulary, strict partitions and reproducible mixture shifts, archive digest rejection, failing controls, trial-paired uncertainty, genuine shared document IDs with authenticated dummy postings, fresh client instances, rejection of undersized padding/duplicate real IDs, and successful real SSE execution from the snapshot after replacing the original executable path with a failing program. Run them with:

```sh
cargo clippy -p oblivion-sse --example corpus -- -D warnings
.venv/bin/python -m unittest research.tests.test_corpus -v
```

The release build, example Clippy and eight checks passed. The campaign completed successfully, with source hashes and the private executable hash unchanged from start to finish. The regression test first failed before the snapshot helper existed, then passed after the fix. The old campaign's source and data remain preserved; the final campaign supplies the stronger executable provenance. Its archive contains 5,574 raw records; normalization removes 415 duplicate messages, leaving 5,159 distinct messages. The committed derived data and wire/prediction gzip files use about 54 MB; the ignored original archive is about 199 KB. No original SMS plaintext file is extracted or committed.

## Measured results

The table gives query recovery accuracy, with 95% bootstrap intervals over the 30 conditional split/workload resamples. All views use the same target within each trial. `matched` means independently sampled auxiliary documents from the same population, not the exact target documents. Spam enrichment changes auxiliary document frequencies, while the synthetic public query prior stays fixed.

| Attacker | Exact-count control | SSE, matched | SSE, 50% spam auxiliary | SSE, 90% spam auxiliary | Padded SSE, all views |
| --- | --- | --- | --- | --- | --- |
| Count/volume | 100% (100–100) | 32.68% (27.58–37.58) | 30.05% (25.91–34.04) | 25.73% (19.74–31.87) | 22.63% (21.30–23.91) |
| IID likelihood assignment | 80.42% (74.11–86.20) | 64.35% (55.91–72.50) | 52.84% (46.04–59.38) | 36.35% (29.04–43.44) | 38.88% (32.58–45.70) |
| Repeated Hungarian Markov refinement | 71.72% (64.90–78.00) | 61.09% (52.86–68.80) | 49.97% (43.13–56.61) | 32.45% (25.55–39.48) | 35.36% (28.65–42.32) |
| Exact bounded Markov comparator | 70.76% (64.22–76.85) | 61.72% (53.80–68.93) | 50.18% (43.75–56.69) | 32.60% (25.65–39.79) | 33.62% (27.42–39.51) |

All four exact-count controls passed the required mean advantage of 20 percentage points above the independent-profile majority baseline before any target or padded mode ran. Their unequal accuracy reflects the different specified scoring models: exact optimization of a noisy plug-in likelihood does not guarantee the correct labels. The known public query majority baseline is 22.63%; uniform eight-way chance is 12.5%.

The likelihood assignment loses 27.99 percentage points under the strongest document shift, with a paired interval of −37.29 to −18.49 points relative to the matched auxiliary view. Count recovery loses 6.95 points, with a paired interval of −14.19 to +0.26 points, so this particular contrast is not resolved away from zero by these resamples. The full report includes balanced and top-three recovery plus all paired differences. A weak attack under mismatched knowledge should not be interpreted as low protocol leakage.

Padding raises observed results from 15.85 to 128 encrypted postings per search, approximately 8.08×, and mean JSON response bytes from 4,048 to 32,105, approximately 7.93×. These serializer lengths do not measure packets, total transport or client memory. Padding removes document-count evidence, so all auxiliary document-shift views produce identical padded predictions; stable query tags and the fixed public query profile still permit likelihood recovery above majority. This is static build-time padding with actual encrypted dummy postings, not a general dynamically volume-hiding SSE protocol.
