#!/usr/bin/env bash
set -eux -o pipefail

pip install pip-tools

pip-compile --extra=dev --output-file=requirements.txt setup.cfg
