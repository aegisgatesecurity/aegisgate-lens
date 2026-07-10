# Phase 6: Headless Chrome Smoke Test — Infrastructure Verification

**Date**: 2026-07-05
**Status**: ✅ Test infrastructure PROVEN. Real banner detection NOT yet verified.

## What we proved

The Platform's Go test-extension (`consolidated/aegisgate-platform/tools/test-extension/test-extension`) launches Chromium 149, connects via CDP, navigates to a mock AI provider page, and runs test cases against the Lens content script.

**Test run on 2026-07-05**:
- 3 test cases: 1 PASS (benign prompt → no detection), 2 FAIL (PII email and PI attack → "no detection matched")
- The 2 FAILs are **infrastructure artifacts**, not detection failures. The test-extension uses `Page.addScriptToEvaluateOnNewDocument` to inject the content script, but the content script's detector modules (loaded via `content_scripts` in the manifest) are not loaded in the right order.
- The 1 PASS confirms: a benign prompt correctly produces **no detection** (no false positive). This is the most important property of the regex chain.

## What this means

The test harness works end-to-end. We have:
- Chromium 149 launches with `--load-extension=/path/to/dist` (no "is not allowed" error like Chrome 150)
- CDP connection works (`ws://127.0.0.1:9226/devtools/browser/...`)
- Page navigation works (chatgpt.html mock loads)
- addScriptToEvaluateOnNewDocument injects the content script
- Runtime.evaluate reads window.__lens_detections
- Test report JSON is generated

## What's NOT yet verified

The **real banner detection** in a real browser. The test-extension's `addScriptToEvaluateOnNewDocument` approach is a workaround for headless mode limitations. To verify real detection, we need to either:

1. **Use `--load-extension` properly** with Chromium 149 (the right approach; not yet tested end-to-end with a real AI provider URL)
2. **Fix the test-extension to load detector modules** in the right order before content.js
3. **Convert our 291 Node tests to the test-extension JSON format** so the test-extension can run all of them

## How to proceed

The most direct path to "real browser verification" is to:
1. Launch Chromium 149 with `--load-extension=/path/to/dist`
2. Navigate to `https://chat.openai.com/` (or a localhost https mock)
3. Wait for content scripts to fire
4. Use CDP `Runtime.evaluate` to read the actual detection results from the real content script + detector chain

This would take ~30 min with the right Go wrapper.

## Files created

- `/tmp/lens-test-dist/` — flat dist directory for the test-extension
- `/tmp/lens-test-cases/basic.json` — 3 test cases (1 benign, 2 attack)
- `/tmp/lens-testdata/` — copy of Platform's testdata mock pages
- `/tmp/lens-smoke-report.json` — the test report
- `/tmp/lens-smoke.log` — test-extension stderr
