#!/bin/bash
# =========================================================================
# AegisGate Lens v0.2 — Build dist (build-v02-dist.sh)
# =========================================================================
#
# Assembles lens-final-dist/ from:
#   - src/         (the v0.2 source code)
#   - v0.1 dist    (icons, popup, welcome — REAL assets from archive)
#
# The v0.1 dist has real icons (16/32/48/128 PNG), real popup.html,
# real welcome.html/welcome.js. Only the content.js and service-worker.js
# are v0.2's (they're the skeleton content.js and the new service worker
# that uses v0.2's transformer-modernbert.js).
#
# Reproducibility:
#   bash test/scripts/build-v02-dist.sh
#
# What this does NOT do:
#   - No minification
#   - No bundling
#   - No asset compilation
#   - No ONNX export (separate, gated by user sign-off)
# =========================================================================

set -e

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC="$REPO_ROOT/src"
DIST="$REPO_ROOT/lens-final-dist"
V01_DIST="/home/chaos/Desktop/AegisGate/archives/iteration-v0.1-day32-burndown-2026-06-26/lens/lens-working-snapshot/lens-final-dist"

echo "AegisGate Lens v0.2 — dist build"
echo "REPO_ROOT: $REPO_ROOT"
echo "DIST:      $DIST"
echo "V01_DIST:  $V01_DIST"
echo ""

# Pre-flight: source files exist
if [ ! -f "$SRC/manifest.json" ]; then
  echo "ERROR: $SRC/manifest.json not found"
  exit 2
fi
if [ ! -f "$V01_DIST/icons/icon-16.png" ]; then
  echo "ERROR: $V01_DIST/icons/icon-16.png not found"
  exit 2
fi

# Pre-flight: dist doesn't already exist (don't overwrite)
if [ -d "$DIST" ] && [ "$(ls -A $DIST 2>/dev/null)" ]; then
  echo "WARNING: $DIST already exists and is non-empty."
  echo "  To rebuild, remove it first:  rm -rf $DIST"
  exit 3
fi

# Create dist directory structure
echo "Creating dist directory structure..."
mkdir -p "$DIST"
mkdir -p "$DIST/icons"
mkdir -p "$DIST/popup"

# Copy v0.2 source (the REAL v0.2 files)
echo "Copying v0.2 source..."
cp "$SRC/manifest.json"            "$DIST/manifest.json"
cp "$SRC/content.js"               "$DIST/content.js"
cp "$SRC/service-worker.js"        "$DIST/service-worker.js"
cp "$SRC/storage.js"               "$DIST/storage.js"

mkdir -p "$DIST/detectors"
cp "$SRC/detectors/"*.js           "$DIST/detectors/"

mkdir -p "$DIST/util"
cp "$SRC/util/"*.js                "$DIST/util/"

mkdir -p "$DIST/privacy"
cp "$SRC/privacy/"*.js             "$DIST/privacy/"

mkdir -p "$DIST/api"
cp "$SRC/api/"*.js                 "$DIST/api/"

# Copy v0.1 assets that we DON'T have in v0.2 (icons, popup, welcome)
echo "Copying v0.1 assets (icons, popup, welcome)..."
cp "$V01_DIST/icons/icon-16.png"   "$DIST/icons/icon-16.png"
cp "$V01_DIST/icons/icon-32.png"   "$DIST/icons/icon-32.png"
cp "$V01_DIST/icons/icon-48.png"   "$DIST/icons/icon-48.png"
cp "$V01_DIST/icons/icon-128.png"  "$DIST/icons/icon-128.png"

cp "$V01_DIST/popup.html"          "$DIST/popup.html"
cp "$V01_DIST/popup/popup.js"      "$DIST/popup/popup.js"
cp "$V01_DIST/welcome.html"        "$DIST/welcome.html"
cp "$V01_DIST/welcome.js"          "$DIST/welcome.js"

# Note: v0.2 schema is in src/privacy/schema.js (not the v0.1 schema.json)
# The content.js references it via the privacy module

echo "Patching dist manifest to reference only existing files (TEST BUILD)..."
cat > "$DIST/manifest.json" << 'MANIFEST_EOF'
{
  "manifest_version": 3,
  "name": "AegisGate Lens (TEST BUILD)",
  "version": "0.2.0",
  "description": "TEST BUILD for pen-testing. References only files that exist in this dist. NOT for production.",
  "author": "AegisGate Security, LLC",

  "icons": {
    "16": "icons/icon-16.png",
    "32": "icons/icon-32.png",
    "48": "icons/icon-48.png",
    "128": "icons/icon-128.png"
  },

  "action": {
    "default_popup": "popup.html",
    "default_title": "AegisGate Lens (TEST)",
    "default_icon": {
      "16": "icons/icon-16.png",
      "32": "icons/icon-32.png"
    }
  },

  "background": {
    "service_worker": "service-worker.js",
    "type": "module"
  },

  "content_scripts": [
    {
      "matches": [
        "https://chat.openai.com/*",
        "https://chatgpt.com/*",
        "https://claude.ai/*",
        "https://gemini.google.com/*",
        "https://copilot.microsoft.com/*",
        "https://duck.ai/*",
        "https://duckduckgo.com/*",
        "https://perplexity.ai/*",
        "https://grok.com/*",
        "https://x.com/*"
      ],
      "js": [
        "util/logger.js",
        "util/banner-ui.js",
        "util/model-loader.js",
        "util/transformer-modernbert.js",
        "util/webgpu-detect.js",
        "util/license-checker.js",
        "util/bundle-loader.js",
        "util/bundle-registry.js",
        "detectors/regex.js",
        "detectors/regex_v2.js",
        "detectors/luhn.js",
        "detectors/from_platform.js",
        "detectors/index.js",
        "privacy/domain_hash.js",
        "privacy/schema.js",
        "storage.js",
        "api/client.js",
        "content.js"
      ],
      "run_at": "document_idle",
      "all_frames": false
    }
  ],

  "permissions": [
    "storage",
    "alarms",
    "unlimitedStorage"
  ],

  "host_permissions": [
    "https://lens.aegisgatesecurity.io/*"
  ],

  "web_accessible_resources": [
    {
      "resources": [
        "icons/icon-16.png",
        "icons/icon-32.png",
        "icons/icon-48.png",
        "icons/icon-128.png",
        "welcome.html"
      ],
      "matches": [
        "https://chat.openai.com/*",
        "https://chatgpt.com/*",
        "https://claude.ai/*",
        "https://gemini.google.com/*",
        "https://copilot.microsoft.com/*",
        "https://duck.ai/*",
        "https://duckduckgo.com/*",
        "https://perplexity.ai/*",
        "https://grok.com/*",
        "https://x.com/*"
      ]
    }
  ],

  "content_security_policy": {
    "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"
  },

  "minimum_chrome_version": "116"
}
MANIFEST_EOF

# Add test-build README
cat > "$DIST/README.md" << 'README_EOF'
# AegisGate Lens v0.2.0 (dist for pen-testing)

This is a TEST BUILD for local pen-testing of the v0.2 extension code.
DO NOT distribute. DO NOT submit to Chrome Web Store.

## What's in this build

- All v0.2 src files (detectors, util, privacy, api, content.js, service-worker.js)
- All v0.1 assets (icons, popup.html, welcome.html, welcome.js, popup/popup.js)
- Test-only manifest (name includes TEST BUILD) that references only existing files

## What's NOT in this build (deferred to v0.2.1 or v0.3.0)

- facet-dispatcher.js (the unified 6-facet orchestrator)
- fp-flow.js (false-positive dismissal UI)
- threat-intel.js (threat intelligence feed polling)
- long-content.js (sliding-window UI)
- transformer-toxicity.js (ML toxicity model)
- toxicity-regex.js (additional toxicity patterns)
- compliance-regex.js (additional compliance patterns)
- vendor/bundles/ (ONNX model bundles — gated on user sign-off)
- vendor/onnxruntime/ (ort.min.js, ort-wasm-simd-threaded.* — gated)

## 6-Facet status in this build

| Facet | Tool | Status |
|-------|------|--------|
| 1. PII | regex_v2.js + luhn.js + from_platform.js | ✅ Works |
| 2. Secrets | regex_v2.js | ✅ Works |
| 3. XSS/Source | regex_v2.js | ✅ Works |
| 4. Compliance | regex_v2.js | ✅ Works |
| 5. Toxicity | regex_v2.js | ⚠️ Regex-only (ML deferred) |
| 6. Prompt injection | transformer-modernbert.js | ⚠️ Code exists, model load requires ONNX bundle |

Built by: test/scripts/build-v02-dist.sh
Build date: 2026-06-28
README_EOF

# Compute SHA256 of every file
echo ""
echo "=== SHA256 of dist contents ==="
cd "$DIST"
sha256sum $(find . -type f | sort) | tee "$DIST/SHA256SUMS"

echo ""
echo "=== Built ==="
echo "DIST: $DIST"
echo "Files: $(find $DIST -type f | wc -l)"
echo ""
echo "To verify it's a valid MV3 extension:"
echo "  cd $DIST && python3 -c \"import json; json.load(open('manifest.json'))\""
echo ""
echo "To load in Chrome for testing:"
echo "  chromium --headless=new --no-sandbox --user-data-dir=/tmp/lens-test \\"
echo "    --remote-debugging-port=9333 --remote-allow-origins='*' \\"
echo "    --load-extension=$DIST --disable-extensions-except=$DIST \\"
echo "    about:blank"