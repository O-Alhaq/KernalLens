#!/usr/bin/env bash
set -eu
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if ! command -v python3 >/dev/null 2>&1; then
    echo 'Python 3 is required to run setup. On Ubuntu: sudo apt-get install python3' >&2
    exit 1
fi
exec python3 -B scripts/setup_environment.py "$@"
