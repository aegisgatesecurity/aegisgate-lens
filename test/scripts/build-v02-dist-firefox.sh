#!/usr/bin/env bash
# =========================================================================
# AegisGate Lens v0.2 — Firefox dist build (for Option B pen-tests)
# =========================================================================
#
# Creates lens-final-dist-firefox/ from lens-final-dist/ by:
#   1. Adding browser_specific_settings.gecko.id (required for Firefox)
#   2. Wrapping chrome.* calls with browser.* shim (Firefox API)
#
# The shim adds a thin layer that translates chrome.runtime -> browser.runtime
# at the dist level (no source changes).
# =========================================================================

set -e

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC_DIST="$REPO_ROOT/lens-final-dist"
FX_DIST="$REPO_ROOT/lens-final-dist-firefox"

echo "Building Firefox-compatible dist..."
echo "Source: $SRC_DIST"
echo "Output: $FX_DIST"

# Pre-flight
if [ ! -d "$SRC_DIST" ]; then
  echo "ERROR: $SRC_DIST doesn't exist. Run build-v02-dist.sh first."
  exit 2
fi
if [ -d "$FX_DIST" ] && [ "$(ls -A $FX_DIST 2>/dev/null)" ]; then
  echo "WARNING: $FX_DIST already exists. Removing for fresh build."
  rm -rf "$FX_DIST"
fi

# Copy Chrome dist to Firefox dist
cp -r "$SRC_DIST" "$FX_DIST"

# Patch manifest to add gecko settings
python3 << 'PYEOF'
import json
from pathlib import Path
fx = Path('/home/chaos/Desktop/AegisGate/lens-repo-bootstrap-v02/lens-final-dist-firefox')
manifest = json.load(open(fx / 'manifest.json'))
# Add Firefox-specific settings
manifest['browser_specific_settings'] = {
    'gecko': {
        'id': 'lens@aegisgatesecurity.io',
        'strict_min_version': '115.0',
    },
}
json.dump(manifest, open(fx / 'manifest.json', 'w'), indent=2)
print('Patched manifest with gecko settings')
PYEOF

# Inject chrome.* → browser.* shim
# Firefox's `chrome` namespace doesn't exist by default; use `browser` instead.
# However, modern Firefox (>= 115) supports `chrome` as an alias to `browser`.
# So actually no shim needed! Just ensure we use `browser` if available.
cat > "$FX_DIST/util/firefox-shim.js" << 'SHIM_EOF'
// Firefox API shim
// Modern Firefox (>= 115) supports both `chrome.*` and `browser.*`.
// This shim is a no-op but provides explicit compat documentation.

(function () {
  if (typeof browser !== 'undefined' && typeof chrome === 'undefined') {
    // Old Firefox without chrome.* polyfill — alias chrome to browser
    window.chrome = browser;
  }
  // Note: Manifest V3 Firefox supports `browser.*` natively.
  // AegisGate Lens v0.2 uses `chrome.*` which works in Firefox 115+.
})();
SHIM_EOF

# Add shim to manifest as the first script loaded
python3 << 'PYEOF'
import json
from pathlib import Path
fx = Path('/home/chaos/Desktop/AegisGate/lens-repo-bootstrap-v02/lens-final-dist-firefox')
manifest = json.load(open(fx / 'manifest.json'))
# Inject firefox-shim.js at the start of each content_scripts.js list
for cs in manifest.get('content_scripts', []):
    js_list = cs.get('js', [])
    if 'util/firefox-shim.js' not in js_list:
        cs['js'] = ['util/firefox-shim.js'] + js_list
# Also add to service-worker via background.scripts if not already there
# (Firefox MV3 uses background.scripts for service workers)
sw = manifest.get('background', {}).get('service_worker')
if sw and 'background' in manifest.get('background', {}):
    # Convert service_worker to scripts array for Firefox compat
    bg = manifest['background']
    if 'service_worker' in bg:
        scripts = ['util/firefox-shim.js', bg['service_worker']]
        manifest['background'] = {
            'scripts': scripts,
            'type': 'module',
            'persistent': False,
        }
json.dump(manifest, open(fx / 'manifest.json', 'w'), indent=2)
print('Manifest patched with shim')
PYEOF

# Compute SHA256SUMS
cd "$FX_DIST"
sha256sum $(find . -type f | sort) | tee "$FX_DIST/SHA256SUMS"

echo ""
echo "=== Built Firefox dist ==="
echo "Path: $FX_DIST"
echo "Files: $(find $FX_DIST -type f | wc -l)"
echo ""
echo "To install in Firefox:"
echo "  1. Open Firefox"
echo "  2. Navigate to about:debugging#/runtime/this-firefox"
echo "  3. Click 'Load Temporary Add-on'"
echo "  4. Select $FX_DIST/manifest.json"