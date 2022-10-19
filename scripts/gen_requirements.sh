#!/usr/bin/env bash
set -eux -o pipefail

pip install pip-tools

pip-compile -o test-requirements.txt setup.cfg --extra test
pip-compile -o requirements.txt setup.cfg
