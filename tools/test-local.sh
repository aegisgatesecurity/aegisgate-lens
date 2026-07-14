#!/bin/bash
# tools/test-local.sh - Local equivalent of the CI smoke.yml test step.
#
# Per the project ground rules:
#   - Zero external npm dependencies (no package.json required)
#   - Always rebuild the bundle before node --test, because the e2e tests
#     (test/e2e/manifest-validation.test.mjs) read test/headless-smoke/bundle.js
#     from disk, but bundle.js is in .gitignore (it is a build artifact).
#
# This script is the LOCAL mirror of the CI workflow step at
# .github/workflows/smoke.yml lines 80-95 (the "Run unit tests + e2e tests" step
# which runs AFTER the "Build the test bundle" step).
#
# Usage:
#   bash tools/test-local.sh
#
# Exits 0 on 500/500 pass, non-zero on any failure.
#
# Lesson #121 reminder: ALWAYS verify the test count with grep on the log
# after node --test runs, not with memory or assumptions.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Step 1: Rebuild the test bundle (mirrors CI step "Build the test bundle")
echo "[test-local] Step 1/2: Rebuild the test bundle"
python3 tools/ci/build-bundle.py

# Step 2: Run unit + e2e tests (mirrors CI step "Run unit tests + e2e tests")
# Per Lesson #118: redirect to a log file in .workingdirectory/, do NOT pipe
# the result through tail/head/grep in the same shell call (causes 120s
# stream-drain timeout).
echo "[test-local] Step 2/2: Run node --test (output to log per Lesson #118)"
LOG_DIR=".workingdirectory"
LOG_FILE="$LOG_DIR/test-local-node.log"
mkdir -p "$LOG_DIR"

node --test test/unit/*.test.mjs test/e2e/*.test.mjs > "$LOG_FILE" 2>&1
NODE_EXIT=$?

echo "[test-local] node --test exit: $NODE_EXIT"
echo "[test-local] log: $LOG_FILE"
echo "[test-local] summary (read in a SEPARATE shell call per Lesson #118):"
echo "[test-local]   grep "ℹ tests" "$LOG_FILE""
echo "[test-local]   grep "not ok" "$LOG_FILE""

exit $NODE_EXIT
