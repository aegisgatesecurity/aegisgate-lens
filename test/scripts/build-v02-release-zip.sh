#!/bin/bash
# =========================================================================
# AegisGate Lens v0.2.0 - Production ZIP Builder
# =========================================================================
#
# Builds the final aegisgate-lens-v0.2.0.zip for Chrome Web Store
# submission. Includes:
#   - manifest.json (version 0.2.0)
#   - All content scripts
#   - INT8 ONNX bundle (147 MB)
#   - ORT runtime files (ort.min.js + WASM modules)
#   - AegisGate shield icons (16, 32, 48, 128)
#   - welcome.html + popup.html
#   - No external dependencies (per docs/NO-EXTERNAL-DEPS.md)
#
# Output: aegisgate-lens-v0.2.0.zip in repo root
# =========================================================================

set -e

REPO="/home/chaos/Desktop/AegisGate/lens-repo-bootstrap-v02"
DIST="$REPO/lens-final-dist"
OUT="$REPO/aegisgate-lens-v0.2.0.zip"

if [ ! -d "$DIST" ]; then
    echo "ERROR: dist directory missing. Run build-v02-dist.sh first."
    exit 2
fi

cd "$REPO"

# Verify manifest version is valid (strict semver, no suffixes)
MANIFEST_VERSION=$(python3 -c "import json; print(json.load(open('$DIST/manifest.json'))['version'])")
if [[ ! "$MANIFEST_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "ERROR: manifest version '$MANIFEST_VERSION' is not strict semver"
    echo "Chrome MV3 strict validator rejects suffixes like '-test' or '-rc'"
    exit 3
fi
echo "Manifest version: $MANIFEST_VERSION"

# Verify all manifest-referenced files exist
python3 << 'PYEOF'
import json, os
from pathlib import Path
DIST = Path('/home/chaos/Desktop/AegisGate/lens-repo-bootstrap-v02/lens-final-dist')
m = json.load(open(DIST / 'manifest.json'))
refs = set()
for cs in m.get('content_scripts', []): refs.update(cs.get('js', []))
sw = m.get('background', {}).get('service_worker')
if sw: refs.add(sw)
for war in m.get('web_accessible_resources', []): refs.update(war.get('resources', []))
for sz, p in m.get('icons', {}).items(): refs.add(p)
for sz, p in (m.get('action', {}).get('default_icon') or {}).items(): refs.add(p)
popup = m.get('action', {}).get('default_popup')
if popup: refs.add(popup)
missing = []
for r in sorted(refs):
    full = DIST / r
    if not full.exists(): missing.append(r)
if missing:
    print(f'MISSING: {missing}'); raise SystemExit(4)
print(f'All {len(refs)} referenced files present')
PYEOF

# Create the ZIP
echo "Building ZIP at $OUT..."
cd "$DIST"
rm -f "$OUT"
zip -r "$OUT" . -x "*.html" "test-page.html" "bundle-test.html" "banner-test.html" "day6-test.html" "onnx-test.html" 2>&1 | tail -3

# Generate SHA256SUMS
echo ""
echo "ZIP SHA256:"
sha256sum "$OUT"
echo ""
echo "ZIP size:"
ls -la "$OUT" | awk '{print $5}'
