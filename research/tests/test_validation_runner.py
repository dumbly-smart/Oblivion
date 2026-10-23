"""Validation provenance includes guest programs and explicit real fixture gates."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('validation_runner', Path(__file__).resolve().parents[2]/'scripts/validate.py')
validation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validation)


class ValidationRunnerTests(unittest.TestCase):
    def test_digest_covers_wasm_and_independent_reference_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('crates/a/src/lib.rs', 'examples/wasm-functions/echo.wat', 'research/oram_reference/Cargo.lock', 'Cargo.toml', 'Cargo.lock', 'research/requirements.lock'):
                path = root/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('before')
            original = validation.digest(root)
            for name in ('examples/wasm-functions/echo.wat', 'research/oram_reference/Cargo.lock'):
                path = root/name; path.write_text('after')
                self.assertNotEqual(validation.digest(root), original)
                path.write_text('before')
            cache = root/'research/oram_reference/target/generated.rs'; cache.parent.mkdir(parents=True); cache.write_text('cache')
            self.assertEqual(validation.digest(root), original)

    def test_commands_build_real_fixtures_before_python(self):
        commands = validation.commands(with_reference=True)
        python = next(i for i,c in enumerate(commands) if 'unittest' in c)
        build = next(i for i,c in enumerate(commands) if c[:2] == ['cargo','build'] and '--workspace' in c)
        self.assertLess(build, python)
        self.assertIn('--examples', commands[build])
        self.assertIn('--bins', commands[build])
        self.assertTrue(any('--manifest-path' in c and 'research/oram_reference/Cargo.toml' in c for c in commands[:python]))

    def test_default_validation_includes_required_reference_fixture(self):
        self.assertTrue(any('research/oram_reference/Cargo.toml' in command for command in validation.commands()))

    def test_correctness_suites_do_not_race_deadline_bound_process_trees(self):
        suites = [command for command in validation.commands()
                  if command[:2] == ['cargo', 'test'] and '--release' not in command]
        self.assertEqual(len(suites), 2)
        for command in suites:
            self.assertIn('--', command)
            self.assertIn('--test-threads=1', command[command.index('--')+1:])


if __name__ == '__main__':
    unittest.main()
