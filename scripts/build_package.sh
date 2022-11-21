#!/usr/bin/env bash
set -eux -o pipefail

pip install build

rm -rf dist build *.egg-info

python -m build --sdist --wheel
