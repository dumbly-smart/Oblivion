#!/usr/bin/env python3
"""One-command actual SSE corpus evaluation (requires research Python dependencies)."""
import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, default=ROOT/'experiments/configs/corpus-real.json')
    parser.add_argument('--output', type=Path, default=ROOT/'experiments/results/corpus-real')
    args = parser.parse_args()
    subprocess.run(['cargo', 'build', '--release', '-p', 'oblivion-sse', '--example', 'corpus'], cwd=ROOT, check=True)
    subprocess.run([sys.executable, '-m', 'research.analysis.corpus', str(args.config), str(args.output),
                    '--binary', str(ROOT/'target/release/examples/corpus')], cwd=ROOT, check=True)


if __name__ == '__main__':
    main()
