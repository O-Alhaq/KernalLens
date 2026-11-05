#!/usr/bin/env python3
"""Validate all security configuration using the same loaders as the receiver."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def validate(directory):
    try:
        from backend.rule_config import load_rules
        from backend.scoring import Scorer
        from backend.correlation_config import load_policy
    except ImportError as error:
        print(f'Configuration dependencies unavailable: {error}. Run ./scripts/setup.sh', file=sys.stderr)
        return 1
    results = {}
    failed = False
    for filename, loader in (('rules.yaml', load_rules), ('scoring.yaml', Scorer.from_file),
                             ('correlation.yaml', load_policy)):
        try:
            results[filename] = loader(directory/filename)
        except (OSError, ValueError) as error:
            failed = True
            cause = error.__cause__
            mark = getattr(cause, 'problem_mark', None)
            detail = (f'; {cause.problem} (line {mark.line+1}, column {mark.column+1})'
                      if mark is not None else '')
            print(f'✗ {directory/filename}: {error}{detail}', file=sys.stderr)
    if failed:
        print('Configuration rejected. Fix the reported files and run make validate-config again.', file=sys.stderr)
        return 1
    for filename in results:
        print(f'✓ {filename}')
    print('\nKernelLens configuration is valid.')
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config-dir', type=Path, default=ROOT/'config')
    return validate(parser.parse_args().config_dir)


if __name__ == '__main__':
    sys.exit(main())
