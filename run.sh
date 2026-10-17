#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [[ ! -x "venv/bin/python" ]]; then
    echo "MetaClean is not installed yet. Run ./install.sh first."
    exit 1
fi

exec ./venv/bin/python main.py "$@"
