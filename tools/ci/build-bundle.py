#!/usr/bin/env python3
"""
v0.1.3 B6: build bundle.js from the test/headless-smoke/dist/ directory.

The bundle is a concatenation of all JS files in content_scripts.js
load order from manifest.json, wrapped in a try/catch that sets
__lens_test_wrapper.error if the bundle throws.

This script is used by the CI workflow (and by the developer
build process when rebuilding the test bundle after a src/
change). The script takes no arguments; the paths are hardcoded
to the standard test/headless-smoke/ layout.

Apache 2.0. Copyright 2026 AegisGate Security, LLC.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# ROOT = <repo-root>/tools/ci/../.. = <repo-root>

DIST = os.path.join(ROOT, 'test', 'headless-smoke', 'dist')
BUNDLE = os.path.join(ROOT, 'test', 'headless-smoke', 'bundle.js')

# Load the manifest to get the file order
manifest_path = os.path.join(DIST, 'manifest.json')
with open(manifest_path) as f:
    m = json.load(f)
js_files = m['content_scripts'][0]['js']

# Build the bundle
parts = []
parts.append('window.__lens_test_wrapper = { started: Date.now() };')
parts.append('try {')
for js in js_files:
    fpath = os.path.join(DIST, js)
    if not os.path.exists(fpath):
        print('MISSING: ' + fpath, file=sys.stderr)
        sys.exit(1)
    with open(fpath) as f:
        src = f.read().rstrip()
    parts.append('')
    parts.append('// === ' + js + ' ===')
    parts.append(src)
parts.append('} catch (e) {')
parts.append('  window.__lens_test_wrapper.error = String(e);')
parts.append('  window.__lens_test_wrapper.errorStack = e && e.stack ? e.stack : "";')
parts.append('}')
parts.append('window.__lens_test_wrapper.completed = Date.now();')
parts.append('')

with open(BUNDLE, 'w') as f:
    f.write('\n'.join(parts))

print('Built bundle: ' + BUNDLE + ' (' + str(os.path.getsize(BUNDLE)) + ' bytes)')
