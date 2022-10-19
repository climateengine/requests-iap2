#!/usr/bin/env bash
set -eux -o pipefail

pip install build

python -m build --sdist --wheel
