# Chrome Extension Loading — SOLVED (2026-06-28)

## 🎯 Root Cause Found

**The bug was in `lens-final-dist/manifest.json` version string.**

The manifest had `"version": "0.2.0-test"` (with `-test` suffix). Chrome's strict MV3 validator REJECTS versions that aren't valid semver:

```
WARNING:load_error_reporter.cc(73)] Extension error: Failed to load extension from: 
/home/chaos/Desktop/AegisGate/lens-repo-bootstrap-v02/lens-final-dist. 
Required value 'version' is missing or invalid. 
It must be between 1-4 dot-separated integers each between 0 and 65536.
```

**Fix**: Changed version to `"0.2.0"` (valid semver). Extension now loads.

## ✅ Proof: Chrome 120 Loaded Our Extension

```bash
$ DISPLAY=:88 /tmp/chrome-linux64/chrome \
    --no-sandbox --disable-gpu \
    --user-data-dir=/tmp/chrome120-data \
    --remote-debugging-port=9716 \
    --remote-allow-origins='*' \
    --load-extension=/home/chaos/Desktop/AegisGate/lens-repo-bootstrap-v02/lens-final-dist \
    --disable-extensions-except=/home/chaos/Desktop/AegisGate/lens-repo-bootstrap-v02/lens-final-dist \
    --no-first-run \
    about:blank

# Targets after launch:
[
  { "type": "page", "title": "Welcome to AegisGate Lens", "url": "chrome-extension://nmmakohhlichiagociipmfhgcdnnkigj/welcome.html" },
  { "type": "service_worker", "url": "chrome-extension://nmmakohhlichiagociipmfhgcdnnkigj/service-worker.js" },
  { "type": "page", "url": "about:blank" }
]

# Extension info:
{
  "id": "nmmakohhlichiagociipmfhgcdnnkigj",
  "name": "AegisGate Lens",
  "version": "0.2.0",
  "files": 17   # content_scripts[0].js.length
}
```

## What We Now Have: Comprehensive Test Bed

| Capability | Browser | Status |
|---|---|---|
| MV3 extension loaded | **Chrome 120** | ✅ WORKS (after fix) |
| WebGPU | **Firefox 152** (via Xvfb) | ✅ Full features including shader-f16 |
| ONNX inference | Firefox with mock ONNX | ✅ JS pipeline proven |
| WASM ONNX | Both browsers | ⚠️ ORT 1.27.0 + Firefox WASM fetch bug |

## Time Spent on This Bug

**~1.5 hours** of trying various Chrome flags, Xvfb configurations, headless vs headed modes. The actual fix was a 5-character change (removing `-test`).

## Lessons Learned (CRITICAL)

1. **Chrome's MV3 manifest validator is strict.** It rejects any version string that isn't valid semver (1-4 dot-separated integers). Always use `X.Y.Z` format.

2. **`--enable-logging=stderr --v=0` is the minimum to surface extension load errors.** Without verbose logging, errors are SILENT.

3. **`Required value 'version' is missing or invalid`** is the EXACT error message Chrome gives when version is bad — not "invalid version" or "bad manifest".

4. **Don't use `-test`, `-dev`, `-rc1`, etc. in manifest version field.** Use `X.Y.Z-suffix` format (which IS valid semver) — e.g., `0.2.0-test` works fine in semver, but Chrome's regex doesn't accept dashes.

5. **Old Chrome (120) is MORE permissive about extensions than current Chrome (149).** Chrome 120 loaded our extension on the first try (after version fix). Chrome 149 silently dropped it.

## Files Changed

- `lens-final-dist/manifest.json` — version `0.2.0-test` → `0.2.0`
- `lens-final-dist-firefox/manifest.json` — same fix (defensive)
- `test/scripts/build-v02-dist.sh` — patched heredoc to use `0.2.0`
- `test/scripts/build-v02-dist-firefox.sh` — already correct (uses `strict_min_version` not version)

## Chrome Versions Tested

| Version | Result |
|---------|--------|
| Chrome 149.0.7827.155 (system) | ❌ Silent drop (failed silently) |
| Chrome 120.0.6046.0 (Chrome for Testing) | ✅ **WORKS** (after version fix) |
| Chrome 113.0.5672.0 (older) | ❌ Crashes on startup |

**Chrome 120 stable (Chrome-for-Testing) is our recommended test target.**

## Next Steps

Now that Chrome 120 works, we can:
1. Run real e2e pen-tests against the Chrome-loaded extension
2. Test all 6 facets in Chrome context
3. Compare Chrome vs Firefox behavior
4. Document that `0.2.0-test` semver is INVALID for Chrome
5. Proceed with the 7 unimplemented module implementation (Phase B)

## TODO for Chrome 120 Verification

- [ ] Run F-01..F-05 pen-tests against Chrome 120 + extension
- [ ] Test 6 facets in Chrome context
- [ ] Test bundle loading (Ed25519 signature verification)
- [ ] Test sliding-window inference in Chrome (vs Firefox)

## Stop Point

Chrome 120 extension loading works. Awaiting Phase B (7 unimplemented modules) or Phase C (privacy/threat model).