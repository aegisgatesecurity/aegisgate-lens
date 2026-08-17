#!/bin/bash
# tools/build-package.sh — Package AegisGate Lens for CWS/AMO upload.
#
# Creates a ZIP with extension files at the root (NOT nested in a directory).
# Both Chrome Web Store and Firefox AMO require manifest.json at the ZIP root.
#
# Usage:
#   bash tools/build-package.sh [version]
#
# If version is omitted, reads from manifest.json.
#
# Output: dist/aegisgate-lens-v{version}.zip
#
# The ZIP includes:
#   - manifest.json
#   - src/ (all JS, CSS, HTML, icons)
#   - icons/ (extension toolbar icons)
#   - models/ (ML weights, if present)
#   - welcome/ (welcome page, if present at root)
#   - LICENSE
#
# Apache 2.0. Copyright 2026 AegisGate Security, LLC.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Get version from manifest.json
VERSION=$(python3 -c "import json; print(json.load(open('manifest.json'))['version'])")
if [ -n "${1:-}" ]; then
    VERSION="$1"
fi

OUTPUT_DIR="dist"
OUTPUT="$OUTPUT_DIR/aegisgate-lens-v${VERSION}.zip"

# Clean and create output directory
mkdir -p "$OUTPUT_DIR"
rm -f "$OUTPUT"

# Create a temporary staging directory
STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

# Copy files to staging (these will be at the ZIP root)
cp manifest.json "$STAGING/"
cp -r src/ "$STAGING/src/"
cp -r icons/ "$STAGING/icons/"

# Copy welcome page if it exists at root level
if [ -d "welcome" ]; then
    cp -r welcome/ "$STAGING/welcome/"
fi

# Copy ML model weights if they exist (gitignored — must be present locally)
if [ -f "models/threat_cnn_bilstm_weights.bin.json" ]; then
    mkdir -p "$STAGING/models"
    cp models/threat_cnn_bilstm_weights.bin.json "$STAGING/models/"
else
    echo "WARNING: ML weights file not found. Extension will run regex-only (no ML facet)." >&2
fi

# Copy LICENSE
cp LICENSE "$STAGING/" 2>/dev/null || true

# Create the ZIP from inside the staging directory (files at root, no nesting)
cd "$STAGING"
zip -r -X "$REPO_ROOT/$OUTPUT" . -x ".*" "*/.*" "*.DS_Store"

cd "$REPO_ROOT"

# Verify manifest.json is at the root of the ZIP
if ! unzip -l "$OUTPUT" | grep -E "^\s+\S+\s+\S+\s+\S+\s+manifest\.json$" | grep -qv "src/"; then
    echo "ERROR: manifest.json not found at ZIP root!" >&2
    exit 1
fi

echo ""
echo "✅ Built: $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
echo "   Files at ZIP root:"
unzip -l "$OUTPUT" | head -5