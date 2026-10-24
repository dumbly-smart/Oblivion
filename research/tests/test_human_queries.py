"""Privacy boundaries for the MIMICS human-query workload builder."""
import csv
from pathlib import Path
import tempfile
import unittest

from research.analysis import human_queries


class HumanQueryCorpus(unittest.TestCase):
    def test_query_tokenization_keeps_ordered_known_words_without_text(self):
        self.assertEqual(human_queries.tokenize_query("Best BEST cafés near me!"),
                         ("best", "caf", "near"))

    def test_loader_returns_token_records_not_source_query_strings(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "queries.tsv"
            source.write_text("query\tquestion\n" +
                              "private phrase alpha\tquestion one\n" +
                              "private phrase beta\tquestion two\n", encoding="utf-8")
            records, info = human_queries.load_records(source)
        self.assertEqual(records[0]["tokens"], ("private", "phrase", "alpha"))
        self.assertNotIn("query", records[0])
        self.assertNotIn("private phrase", repr(records))
        self.assertEqual(info["query_rows"], 2)

    def test_trial_uses_whole_query_split_and_real_query_token_sequences(self):
        records = [{"tokens": ("alpha", "beta", "common") if i % 3 else ("beta", "common")}
                   for i in range(240)]
        config = {"seed": 41, "keywords": 2, "auxiliary_queries": 64,
                  "target_sessions": 16}
        auxiliary, truth, coverage = human_queries.make_trial(records, config, 0)
        self.assertEqual((auxiliary, truth, coverage), human_queries.make_trial(records, config, 0))
        self.assertEqual(len(truth["target_sessions"]), 16)
        self.assertTrue(all(row for row in truth["target_sessions"]))
        self.assertTrue(all(set(row) <= {0, 1} for row in truth["target_sessions"]))
        self.assertTrue(set(auxiliary["matched"]["record_ids"]).isdisjoint(truth["record_ids"]))
        self.assertNotIn("vocabulary", repr({"truth": truth}))


if __name__ == "__main__":
    unittest.main()
