#!/usr/bin/env bash
set -eux -o pipefail

pip install twine

twine upload dist/*
