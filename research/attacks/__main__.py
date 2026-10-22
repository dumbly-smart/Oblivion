"""JSON-only offline attack CLI; no target interaction."""
import argparse
import json
from pathlib import Path
import sys

from research.attacks.registry import create_attack, list_attacks

MAX_INPUT_BYTES = 8 * 1024 * 1024


def _reject_constant(value):
    raise ValueError(f'non-finite JSON constant: {value}')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--list', action='store_true', help='list stable JSON attack descriptions')
    action.add_argument('--attack', help='registered attack name')
    parser.add_argument('--input', type=Path, help='JSON input file; default stdin')
    args = parser.parse_args(argv)
    try:
        if args.list:
            output = list_attacks()
        else:
            if args.input:
                with args.input.open('rb') as stream:
                    raw = stream.read(MAX_INPUT_BYTES + 1)
            else:
                raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
            if len(raw) > MAX_INPUT_BYTES:
                raise ValueError('input exceeds 8 MiB limit')
            payload = json.loads(raw, parse_constant=_reject_constant)
            if not isinstance(payload, dict) or set(payload) - {'trace', 'aux', 'profile'} or not {'trace', 'aux'} <= set(payload):
                raise ValueError('expected trace, aux and optional profile')
            attack = create_attack(args.attack)
            if 'profile' in payload:
                profile = payload['profile']
                if not isinstance(profile, dict) or set(profile) != {'trace', 'aux'}:
                    raise ValueError('profile must contain trace and aux')
                attack.fit(profile['trace'], profile['aux'])
            output = attack.run(payload['trace'], payload['aux']).to_dict()
        print(json.dumps(output, sort_keys=True, allow_nan=False))
    except (ValueError, TypeError, OSError, ImportError, RecursionError) as error:
        print(f'attack input error: {error}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
