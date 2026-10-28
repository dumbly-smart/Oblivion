import unittest

from research.analysis.verify_sse_journal_benchmark import (
    VerificationError,
    summarize_samples,
    verify_report,
)
from research.analysis.plot_sse_journal_benchmark import render_svg


def _fixture_report():
    config = {
        "schema_version": 1,
        "index_sizes": [2, 3],
        "trials": 2,
        "recovery_repetitions": 5,
        "schedule_seed": 7,
    }
    samples = []
    child_pid = 4000
    for trial in range(config["trials"]):
        for index_size in config["index_sizes"]:
            generation = 2 * index_size
            recovery = [1000 + trial * 10 + repetition for repetition in range(5)]
            samples.append(
                {
                    "trial": trial,
                    "index_size": index_size,
                    "generation": generation,
                    "logical_input_bytes": 34 * index_size,
                    "journal_record_bytes_written": 34 * (generation + 1),
                    "journal_byte_amplification": 34 * (generation + 1) / (34 * index_size),
                    "retained_journal_bytes": 34 * index_size,
                    "journal_records_written": generation + 1,
                    "retained_journal_records": index_size,
                    "anchor_compare_and_swap_calls": generation + 1,
                    "anchor_load_calls_during_recovery": 5,
                    "checkpoint_generations": list(range(0, generation, 256)),
                    "initialization_ns": 10,
                    "index_build_ns": 100 + trial + index_size,
                    "prepare_add_ns": [10 + trial] * index_size,
                    "server_insert_ns": [2] * index_size,
                    "finish_add_ns": [5 + trial] * index_size,
                    "recovery_open_ns": recovery,
                    "recovery_process_total_ns": [value + 100 for value in recovery],
                    "recovery_child_pids": list(range(child_pid, child_pid + 5)),
                }
            )
            child_pid += 5
    summary = summarize_samples(samples, config["index_sizes"])
    bootstrap_offsets = {
        "journal_record_bytes_written": 0,
        "journal_byte_amplification": 1,
        "index_build_ns": 2,
        "recovery_open_trial_median_ns": 3,
    }
    for row in summary:
        for metric, offset in bootstrap_offsets.items():
            mean = row[metric]["mean"]
            row[metric].update(
                {
                    "mean_bootstrap_ci95": [mean, mean],
                    "bootstrap_replicates": 5000,
                    "bootstrap_seed": 202_610_280_001 + row["index_size"] + offset,
                }
            )
    return {
        "schema_version": 1,
        "software_version": "0.1.0",
        "source_revision": "a" * 40,
        "tracked_source_dirty": False,
        "environment": {
            "architecture": "x86_64",
            "cpu_model": "test CPU",
            "logical_cpus": 2,
            "os": "linux",
            "rustc": "rustc test",
        },
        "configuration": config,
        "samples": samples,
        "summary": summary,
    }, config


class SseJournalBenchmarkVerifierTests(unittest.TestCase):
    def test_accepts_complete_structurally_valid_report(self):
        report, config = _fixture_report()

        result = verify_report(report, config, expected_revision="a" * 40)

        self.assertEqual(result["sample_count"], 4)
        self.assertEqual(result["summary_count"], 2)

    def test_rejects_missing_trial_size_pair(self):
        report, config = _fixture_report()
        report["samples"].pop()

        with self.assertRaisesRegex(VerificationError, "sample coverage"):
            verify_report(report, config)

    def test_rejects_wrong_generation_and_update_count(self):
        report, config = _fixture_report()
        report["samples"][0]["generation"] += 1

        with self.assertRaisesRegex(VerificationError, "generation"):
            verify_report(report, config)

    def test_rejects_inconsistent_journal_byte_amplification(self):
        report, config = _fixture_report()
        report["samples"][0]["journal_byte_amplification"] += 1

        with self.assertRaisesRegex(VerificationError, "amplification"):
            verify_report(report, config)

    def test_rejects_reused_recovery_child_pid(self):
        report, config = _fixture_report()
        report["samples"][1]["recovery_child_pids"][0] = report["samples"][0]["recovery_child_pids"][0]

        with self.assertRaisesRegex(VerificationError, "PID"):
            verify_report(report, config)

    def test_rejects_corrupted_summary(self):
        report, config = _fixture_report()
        report["summary"] = [{"index_size": 2, "trial_count": 999}]

        with self.assertRaisesRegex(VerificationError, "summary"):
            verify_report(report, config)

    def test_rejects_dirty_or_wrong_source_revision(self):
        report, config = _fixture_report()
        report["tracked_source_dirty"] = True

        with self.assertRaisesRegex(VerificationError, "dirty"):
            verify_report(report, config)

        report["tracked_source_dirty"] = False
        with self.assertRaisesRegex(VerificationError, "source revision"):
            verify_report(report, config, expected_revision="b" * 40)

    def test_renders_three_measurements_as_standalone_svg(self):
        report, config = _fixture_report()
        verify_report(report, config)

        svg = render_svg(report)

        self.assertIn("<svg", svg)
        self.assertIn("Journal byte amplification", svg)
        self.assertIn("Index build time", svg)
        self.assertIn("Fresh-process recovery", svg)
        self.assertIn("95% bootstrap CI", svg)


if __name__ == "__main__":
    unittest.main()
