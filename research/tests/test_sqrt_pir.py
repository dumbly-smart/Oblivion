"""Analysis invariants for the actual two-server matrix PIR measurement."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.evaluate_sqrt_pir import freeze_binary, summarize


class SqrtPirAnalysis(unittest.TestCase):
    def rows(self):
        rows = []
        for trial in range(30):
            for mode in ('xor', 'sqrt'):
                for step in range(2):
                    rows.append(dict(count=64, record_bytes=8, trial=trial, step=step, mode=mode,
                                     generation_ns=10, server1_ns=100, server2_ns=100, recovery_ns=10,
                                     query_payload_bytes=16 if mode == 'xor' else 2,
                                     response_payload_bytes=16 if mode == 'xor' else 128,
                                     scan_payload_bytes_per_server=512))
        return rows

    def test_summarizes_actual_payloads_and_thirty_whole_trial_means(self):
        summary, paired = summarize(self.rows(), 30, 2)
        self.assertEqual(len(summary), 2)
        indexed = {r['mode']: r for r in summary}
        self.assertEqual(indexed['xor']['total_payload_bytes'], 32)
        self.assertEqual(indexed['sqrt']['total_payload_bytes'], 130)
        self.assertEqual(indexed['sqrt']['protocol_ns_trial_bootstrap_95'], [220, 220])
        self.assertEqual(paired[0]['sqrt_minus_xor_protocol_ns'], 0)
        self.assertEqual(indexed['sqrt']['fresh_state_trials'], 30)

    def test_rejects_missing_trial_and_duplicate_sample(self):
        rows = self.rows()
        with self.assertRaises(ValueError):
            summarize(rows[1:], 30, 2)
        with self.assertRaises(ValueError):
            summarize(rows+[rows[0]], 30, 2)

    def test_private_copy_executes_after_original_path_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory/'mutable'
            source.write_text("#!/bin/sh\nprintf '%s' original\n")
            source.chmod(0o755)
            frozen, before = freeze_binary(source, directory/'bin'/'measure')
            source.unlink()
            source.write_text('#!/bin/sh\nexit 97\n')
            source.chmod(0o755)
            self.assertEqual(subprocess.check_output([str(frozen)]), b'original')
            self.assertEqual(len(before), 64)
            self.assertNotEqual(frozen.stat().st_ino, source.stat().st_ino)


if __name__ == '__main__':
    unittest.main()
