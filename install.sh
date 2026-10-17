#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: Python 3 is required."
    exit 1
fi

if ! command -v exiftool >/dev/null 2>&1; then
    echo "ExifTool is missing. Installing it..."
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update
        sudo apt-get install -y libimage-exiftool-perl
    else
        echo "Please install ExifTool using your system package manager."
        exit 1
    fi
fi

python3 -m venv venv
./venv/bin/python -m pip install --upgrade pip
./venv/bin/python -m pip install -r requirements.txt

echo
echo "MetaClean installation completed."
echo "Run it with: ./run.sh"
