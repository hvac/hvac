#!/usr/bin/env bash

# This script is used with the PR build workflow.
# We override SPHINXOPTS in order to not fail on warnings,
# because we want to publish the docs if we can anyway.
# A different job will fail on those warnings.

set -e

make -C "${BASH_SOURCE%/*}" SPHINXOPTS='-E -a' html
