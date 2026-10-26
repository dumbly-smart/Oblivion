"""Durability, atomicity, and local filesystem boundaries for the DP ledger."""
import json
import os
from pathlib import Path
import threading
import unittest
import tempfile

from research.simulation.privacy_ledger import PersistentUserPrivacyLedger


class PersistentUserPrivacyLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.key = self.root / "ledger.key"
        self.key.write_bytes(bytes(range(32)))
        self.key.chmod(0o600)
        self.database = self.root / "ledger.sqlite3"

    def tearDown(self):
        self.temp.cleanup()

    def test_composition_survives_reopen_without_persisting_raw_ids(self):
        ledger = PersistentUserPrivacyLedger(self.database, self.key)
        ledger.record("run-a:horizon-1", ["alice", "bob"], .5, .01)
        ledger.record("run-a:horizon-2", ["alice"], .25, .02)

        summary = PersistentUserPrivacyLedger(self.database, self.key).summary()
        self.assertEqual(summary["release_count"], 2)
        self.assertEqual(summary["max_user_release_count"], 2)
        self.assertEqual(summary["max_user_epsilon"], .75)
        self.assertAlmostEqual(summary["max_user_delta"], .03)
        self.assertFalse(summary["principal_identifiers_emitted"])
        self.assertNotIn("alice", json.dumps(summary))
        self.assertNotIn(b"alice", self.database.read_bytes())

    def test_duplicate_and_budget_rejection_are_persistent_and_atomic(self):
        ledger = PersistentUserPrivacyLedger(
            self.database, self.key, max_epsilon=.75, max_delta=.05)
        ledger.record("release-1", ["alice"], .5, .01)
        with self.assertRaisesRegex(ValueError, "budget exceeded"):
            ledger.record("release-2", ["alice", "bob"], .5, .01)

        reopened = PersistentUserPrivacyLedger(
            self.database, self.key, max_epsilon=.75, max_delta=.05)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            reopened.record("release-1", ["alice"], .1, .001)
        reopened.record("release-3", ["bob"], .25, .01)
        summary = reopened.summary()
        self.assertEqual(summary["release_count"], 2)
        self.assertEqual(summary["max_user_release_count"], 1)
        self.assertEqual(summary["max_user_epsilon"], .5)

    def test_wrong_key_cannot_open_existing_ledger(self):
        PersistentUserPrivacyLedger(self.database, self.key)
        wrong_key = self.root / "wrong.key"
        wrong_key.write_bytes(b"x" * 32)
        wrong_key.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "key fingerprint mismatch"):
            PersistentUserPrivacyLedger(self.database, wrong_key)

    def test_existing_ledger_rejects_changed_persistent_budget_limits(self):
        PersistentUserPrivacyLedger(self.database, self.key, max_epsilon=1.0)
        with self.assertRaisesRegex(ValueError, "budget configuration mismatch"):
            PersistentUserPrivacyLedger(self.database, self.key, max_epsilon=2.0)

    def test_existing_ledger_rejects_identity_registry_change(self):
        fingerprint = "1" * 64
        PersistentUserPrivacyLedger(
            self.database, self.key, identity_registry_sha256=fingerprint)
        with self.assertRaisesRegex(ValueError, "identity registry fingerprint mismatch"):
            PersistentUserPrivacyLedger(
                self.database, self.key, identity_registry_sha256="2" * 64)

    def test_invalid_unicode_inputs_are_rejected_without_charging(self):
        ledger = PersistentUserPrivacyLedger(self.database, self.key)
        with self.assertRaisesRegex(ValueError, "valid UTF-8"):
            ledger.record("release-\ud800", ["alice"], .1, .001)
        with self.assertRaisesRegex(ValueError, "valid UTF-8"):
            ledger.record("release-1", ["user-\ud800"], .1, .001)
        self.assertEqual(ledger.summary()["release_count"], 0)

    def test_recorded_command_redacts_ledger_database_and_key_paths(self):
        from research.simulation.run import recorded_command

        command = recorded_command([
            "oblivion-scaler", "config.json", "out",
            "--privacy-ledger", "/private/ledger.sqlite3",
            "--privacy-ledger-key=/private/ledger.key",
            "--privacy-ledger-max-epsilon", "4.0",
        ])
        self.assertEqual(command, [
            "oblivion-scaler", "config.json", "out",
            "--privacy-ledger", "[REDACTED]",
            "--privacy-ledger-key=[REDACTED]",
            "--privacy-ledger-max-epsilon", "4.0",
        ])

    def test_insecure_key_and_database_directory_are_rejected(self):
        self.key.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "private permissions"):
            PersistentUserPrivacyLedger(self.database, self.key)
        self.key.chmod(0o600)

        public_directory = self.root / "public"
        public_directory.mkdir(mode=0o755)
        public_directory.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "database directory permissions"):
            PersistentUserPrivacyLedger(public_directory / "ledger.sqlite3", self.key)

        self.database.write_bytes(b"")
        self.database.chmod(0o400)
        with self.assertRaisesRegex(ValueError, "owner-readable and writable only"):
            PersistentUserPrivacyLedger(self.database, self.key)

    def test_database_must_not_be_a_hardlink_to_key(self):
        os.link(self.key, self.database)
        with self.assertRaisesRegex(ValueError, "distinct files"):
            PersistentUserPrivacyLedger(self.database, self.key)

    def test_competing_writers_serialize_budget_checks(self):
        ledgers = [PersistentUserPrivacyLedger(
            self.database, self.key, max_epsilon=.5) for _ in range(2)]
        barrier = threading.Barrier(2)
        results = []

        def record(ledger, release):
            barrier.wait()
            try:
                ledger.record(release, ["alice"], .5, .01)
                results.append("committed")
            except ValueError as error:
                results.append(str(error))

        threads = [threading.Thread(target=record, args=(ledger, f"release-{index}"))
                   for index, ledger in enumerate(ledgers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertCountEqual(results, ["committed", "privacy budget exceeded"])
        self.assertEqual(ledgers[0].summary()["release_count"], 1)

    def test_batch_runs_compose_across_invocations_for_authenticated_ids(self):
        from research.simulation.run import run

        registry = self.root / "identity-keys.json"
        registry.write_text(json.dumps({
            f"synthetic-user-{index}": (bytes([index + 1]) * 32).hex()
            for index in range(64)
        }))
        registry.chmod(0o600)
        config = self.root / "config.json"
        config.write_text(json.dumps(dict(
            version=1,
            seed=29,
            trials=2,
            sessions=8,
            workloads=["uniform"],
            policies=["naive", "dp_laplace"],
            simulation=dict(duration=4, dp_epsilon=2,
                            dp_user_contribution_cap=2,
                            require_authenticated_user_ids=True),
        )))

        reports = []
        for index in range(2):
            reports.append(run(
                config, self.root / f"run-{index}",
                identity_registry_path=registry,
                privacy_ledger_path=self.database,
                privacy_ledger_key_path=self.key,
                privacy_ledger_max_epsilon=100,
                privacy_ledger_max_delta=.9,
            ))

        first, second = reports
        self.assertNotEqual(first["persistent_privacy_ledger"]["run_id"],
                            second["persistent_privacy_ledger"]["run_id"])
        ledger = PersistentUserPrivacyLedger(
            self.database, self.key, max_epsilon=100, max_delta=.9,
            identity_registry_sha256=(
                second["persistent_privacy_ledger"]["identity_registry_sha256"]))
        summary = ledger.summary()
        self.assertEqual(first["persistent_privacy_ledger"]["release_count"], 16)
        self.assertEqual(second["persistent_privacy_ledger"]["release_count"], 32)
        self.assertEqual(summary["release_count"], 32)
        self.assertEqual(first["privacy_composition"]["release_count"], 16)
        self.assertEqual(second["privacy_composition"]["release_count"], 16)
        self.assertNotIn("synthetic-user-", json.dumps(second["persistent_privacy_ledger"]))
        self.assertNotIn(b"synthetic-user-", self.database.read_bytes())
        recorded = json.loads((self.root / "run-1" / "config.json").read_text())
        self.assertNotIn(str(self.database), json.dumps(recorded))
        self.assertNotIn(str(self.key), json.dumps(recorded))

        from scripts.regenerate_scaler import regenerate
        rebuilt = regenerate(self.root / "run-1", self.root / "rebuilt", registry)
        self.assertEqual(rebuilt["privacy_composition"], second["privacy_composition"])
        self.assertEqual(rebuilt["persistent_privacy_ledger"]["release_count"], 32)
        self.assertEqual(rebuilt["persistent_privacy_ledger"]["snapshot_status"],
                         "copied_from_source_report_not_recomputed")

    def test_batch_runner_rejects_persistent_ledger_without_authenticated_ids(self):
        from research.simulation.run import run

        config = self.root / "config.json"
        config.write_text(json.dumps(dict(
            version=1, seed=1, trials=2, sessions=8,
            workloads=["uniform"], policies=["naive", "dp_laplace"],
            simulation=dict(duration=4, dp_epsilon=2, dp_user_contribution_cap=2),
        )))
        with self.assertRaisesRegex(ValueError, "authenticated user IDs"):
            run(config, self.root / "rejected-run",
                privacy_ledger_path=self.database,
                privacy_ledger_key_path=self.key)
        self.assertFalse((self.root / "rejected-run").exists())


if __name__ == "__main__":
    unittest.main()
