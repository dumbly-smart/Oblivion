"""Aggregate-only SSE evaluation using filtered Bing query text from MIMICS."""
from collections import Counter
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

import numpy as np
import scipy

from research.analysis import corpus
from research.analysis.sse import dump, metrics, read_observations
from research.attacks.inference import infer
from research.attacks.sse import CountVolumeAttack

ROOT = Path(__file__).resolve().parents[2]
MIMICS_COMMIT = "6450e8143bd380505bbf047822e41a2a3a2b474f"
MIMICS_URL = ("https://raw.githubusercontent.com/microsoft/MIMICS/" + MIMICS_COMMIT +
              "/data/MIMICS-Click.tsv")
MAX_SOURCE_BYTES = 60_000_000


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def tokenize_query(query):
    """Return distinct searchable ASCII terms in source order; never retain the query."""
    terms = re.findall(r"[a-z]{3,16}", query.lower())
    return tuple(dict.fromkeys(terms))


def load_records(path):
    """Read MIMICS query cells into token tuples; never return source strings or labels."""
    if path.stat().st_size > MAX_SOURCE_BYTES:
        raise ValueError("MIMICS source size limit")
    records = []
    token_total = 0
    total_rows = 0
    with path.open("r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        if not reader.fieldnames or "query" not in reader.fieldnames:
            raise ValueError("MIMICS TSV must include a query column")
        for row in reader:
            total_rows += 1
            query = row.get("query")
            if query is None or len(query) > 1000:
                raise ValueError("invalid MIMICS query cell")
            tokens = tokenize_query(query)
            if tokens:
                records.append({"record_id": total_rows - 1, "tokens": tokens})
                token_total += len(tokens)
    return records, {"query_rows": total_rows,
                     "source_rows_with_searchable_terms": len(records),
                     "source_rows_without_searchable_terms": total_rows - len(records),
                     "mean_distinct_searchable_terms_per_query": token_total / max(len(records), 1),
                     "raw_query_text_retained": False}


def select_vocabulary(records, keywords):
    """Choose frequent auxiliary-only terms with distinct query-document counts."""
    counts = Counter(term for record in records for term in set(record["tokens"]))
    vocabulary, used_counts = [], set()
    for term, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        if count not in used_counts:
            vocabulary.append(term)
            used_counts.add(count)
        if len(vocabulary) == keywords:
            return vocabulary
    raise ValueError("insufficient distinct auxiliary query counts")


def make_trial(records, config, trial):
    """Split whole query rows; map each target query to its observed in-vocabulary terms."""
    rng = random.Random(config["seed"] + trial)
    order = list(range(len(records)))
    rng.shuffle(order)
    auxiliary_ids = order[:config["auxiliary_queries"]]
    target_pool = order[config["auxiliary_queries"]:]
    auxiliary_records = [records[index] for index in auxiliary_ids]
    vocabulary = select_vocabulary(auxiliary_records, config["keywords"])
    term_to_label = {term: label for label, term in enumerate(vocabulary)}
    candidate_sessions = []
    candidate_ids = []
    for index in target_pool:
        session = [term_to_label[t] for t in records[index]["tokens"] if t in term_to_label]
        if session:
            candidate_sessions.append(session)
            candidate_ids.append(records[index].get("record_id", index))
    take = min(config["target_sessions"], len(candidate_sessions))
    if take < config["target_sessions"]:
        raise ValueError("not enough target queries containing auxiliary vocabulary")
    selected = rng.sample(range(len(candidate_sessions)), take)
    sessions = [candidate_sessions[i] for i in selected]
    selected_ids = [candidate_ids[i] for i in selected]
    matched_postings = [[i for i, record in enumerate(auxiliary_records)
                         if term in record["tokens"]] for term in vocabulary]
    counts = [len(posting) for posting in matched_postings]
    profile = [label for record in auxiliary_records for label, term in enumerate(vocabulary)
               if term in record["tokens"]]
    auxiliary = {"matched": {"counts": counts, "public_postings": matched_postings,
                              "corpus_documents": len(auxiliary_records),
                              "vocabulary": vocabulary,
                              "query_counts": [profile.count(i) for i in range(len(vocabulary))],
                              "profile_labels": profile,
                              "profiling_session": f"mimics-auxiliary-{trial}",
                              "record_ids": [records[i].get("record_id", i) for i in auxiliary_ids],
                              "spam_fraction": 0.0}}
    truth = {"postings": matched_postings, "target_sessions": sessions,
             "record_ids": selected_ids, "spam_fraction": 0.0}
    return auxiliary, truth, {"candidate_target_queries_with_vocabulary": len(candidate_sessions),
                              "candidate_target_queries": len(target_pool),
                              "query_coverage": len(candidate_sessions) / max(len(target_pool), 1),
                              "target_sessions_used": len(sessions)}


def score(directory, mode, auxiliary, config, trial, session_offset=0):
    sessions, updates = read_observations(directory / f"{mode}.jsonl.gz")
    results = []
    for view, knowledge in auxiliary.items():
        if mode == "exact_count_control" and view != "matched":
            continue
        for session_id, observations in sessions.items():
            started = time.perf_counter()
            padded = mode == "padded_sse"
            rankings = CountVolumeAttack().run(
                observations, knowledge, seed=trial * 100 + session_id,
                pad_to=config["pad_to"] if padded else None)
            predictions = {"count_volume": {"rankings": rankings}}
            predictions.update(infer(observations, knowledge, padded=padded,
                                     seed=config["seed"] + trial * 100 + session_id))
            elapsed = time.perf_counter() - started
            labels = json.loads((directory / "ground-truth.json").read_text())["target_sessions"][session_id]
            majority = int(np.argmax(knowledge["query_counts"]))
            for attack, prediction in predictions.items():
                row = metrics(prediction["rankings"], labels, config["keywords"], majority)
                row.update(trial=trial, session=session_offset + session_id, mode=mode, view=view, attack=attack,
                           updates=updates,
                           mean_postings=float(np.mean([o["count"] for o in observations])),
                           mean_response_json_bytes=float(np.mean([o["response_json_bytes"] for o in observations])),
                           objective_gap=prediction.get("exact_objective", 0) - prediction.get("objective", 0),
                           all_attacks_seconds=elapsed)
                results.append(row)
    return results


def download_source(destination):
    request = urllib.request.Request(MIMICS_URL, headers={"User-Agent": "oblivion-research/1"})
    digest = hashlib.sha256()
    size = 0
    with urllib.request.urlopen(request, timeout=90) as response, destination.open("xb") as output:
        while True:
            block = response.read(65536)
            if not block:
                break
            size += len(block)
            if size > MAX_SOURCE_BYTES:
                raise ValueError("MIMICS source size limit")
            output.write(block)
            digest.update(block)
    return size, digest.hexdigest()


def run(config_path, output, binary, source_path=None):
    started = time.time()
    config = json.loads(config_path.read_text())
    if config["trials"] != 30 or config["keywords"] != 8:
        raise ValueError("recorded human-query experiment requires 30 trials and 8 keywords")
    if config["source_url"] != MIMICS_URL:
        raise ValueError("only the pinned official MIMICS release is accepted")
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("output directory must be empty")

    with tempfile.TemporaryDirectory(prefix="oblivion-mimics-") as private_dir:
        private = Path(private_dir)
        raw = Path(source_path) if source_path else private / "MIMICS-Click.tsv"
        if source_path is None:
            source_size, source_hash = download_source(raw)
        else:
            source_size, source_hash = raw.stat().st_size, sha(raw)
        if source_hash != config["source_sha256"]:
            raise ValueError("MIMICS source checksum mismatch")
        records, data_summary = load_records(raw)
        frozen_binary, binary_hash = corpus.snapshot_binary(binary, private / "corpus")

        # Build every split before running controls so no protected-mode result is
        # inspected until the leakage control has been scored and passed.
        trials = []
        for trial in range(config["trials"]):
            auxiliary, truth, coverage = make_trial(records, config, trial)
            trials.append((auxiliary, truth, coverage))
        rows = []
        for trial, (auxiliary, truth, _) in enumerate(trials):
            for offset in range(0, config["target_sessions"], 2):
                directory = private / f"trial-{trial:02}-batch-{offset:02}"
                directory.mkdir()
                batch_truth = dict(truth, target_sessions=truth["target_sessions"][offset:offset + 2])
                dump(directory / "ground-truth.json", batch_truth)
                corpus.export(frozen_binary, directory / "exact_count_control.jsonl.gz",
                              auxiliary["matched"]["public_postings"], batch_truth["target_sessions"],
                              None, config["seed"] + trial)
                rows.extend(score(directory, "exact_count_control", auxiliary, config, trial, offset))
        corpus.require_controls(rows)
        control_count = len(rows)

        for trial, (auxiliary, truth, _) in enumerate(trials):
            for offset in range(0, config["target_sessions"], 2):
                directory = private / f"trial-{trial:02}-batch-{offset:02}"
                batch_truth = dict(truth, target_sessions=truth["target_sessions"][offset:offset + 2])
                dump(directory / "ground-truth.json", batch_truth)
                for mode in ("sse", "padded_sse"):
                    corpus.export(frozen_binary, directory / f"{mode}.jsonl.gz", truth["postings"],
                                  batch_truth["target_sessions"], config["pad_to"] if mode == "padded_sse" else None,
                                  config["seed"] + trial)
                    rows.extend(score(directory, mode, auxiliary, config, trial, offset))

        summary, paired = corpus.summarize(rows, config["trials"])
        coverage = [coverage for _, _, coverage in trials]
        report = {"summary": summary, "paired_auxiliary_differences": paired,
                  "query_coverage": {"mean": float(np.mean([r["query_coverage"] for r in coverage])),
                                     "min": float(np.min([r["query_coverage"] for r in coverage])),
                                     "max": float(np.max([r["query_coverage"] for r in coverage])),
                                     "sessions_per_trial": config["target_sessions"]},
                  "source_summary": data_summary,
                  "scope": "Filtered real Bing query text is used as a token workload; each source query is one session, and only its distinct in-vocabulary terms become sequential single-keyword SSE accesses. No synthetic labels or query text are retained in output.",
                  "limitations": "MIMICS-Click contains unique query-clarification rows, not query arrivals or session history; no frequency or temporal weighting is available. The token workload models single-keyword accesses derived from a multiword search string, not a full web-search engine. Terms absent from each trial's auxiliary-selected vocabulary are omitted; coverage is reported. This is not representative-arrival or population privacy measurement.",
                  "controls": {"passed": True, "scored_before_defenses": True,
                               "control_session_metrics": control_count,
                               "threshold_advantage_over_profile_majority": 0.2},
                  "uncertainty": "95% bootstrap intervals resample 30 seeded whole-query split/workload trial means; source records recur across independent trial resamples, so trials are not independent corpus collections."}
        dump(output / "report.json", report)
        dump(output / "config.json", config)
        dump(output / "provenance.json", {
            "dataset": "MIMICS-Click",
            "source_url": MIMICS_URL,
            "repository_commit": MIMICS_COMMIT,
            "source_bytes": source_size,
            "source_sha256": source_hash,
            "raw_query_text_retained": False,
            "dataset_rows_read": data_summary["source_rows_with_searchable_terms"] + data_summary["source_rows_without_searchable_terms"],
            "license_note": "Repository advertises MIT but README also contains ORCAS research-only terms; use confined to noncommercial research and terms remain ambiguous.",
            "privacy_note": "Source paper reports >=40 users in prior year, >=10 impressions, proprietary additional privacy filtering, and automatic sensitive/inappropriate-content removal. This does not establish consent or guarantee anonymity.",
            "binary_sha256": binary_hash,
            "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
            "python": sys.version,
            "numpy": np.__version__,
            "scipy": scipy.__version__,
            "platform": platform.platform(),
            "elapsed_seconds": time.time() - started,
            "output_policy": "Aggregate statistics only; query text, query-token incidence, session labels, SSE traces, and attack predictions remained in a temporary directory and were deleted."})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "experiments/configs/human-query.json")
    parser.add_argument("--output", type=Path, default=ROOT / "experiments/results/human-query-20261024")
    parser.add_argument("--binary", type=Path, default=ROOT / "target/release/examples/corpus")
    parser.add_argument("--source", type=Path, help="Use a private predownloaded source file")
    args = parser.parse_args()
    run(args.config, args.output, args.binary, args.source)


if __name__ == "__main__":
    main()
