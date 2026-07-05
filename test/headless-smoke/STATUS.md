# Phase 6: Headless Chrome Smoke Test — STATUS

**Date**: 2026-07-05

## What works

1. **Chromium 149 launches** with `--load-extension` (no "is not allowed" error like Chrome 150)
2. **CDP connects** via gorilla/websocket (one third-party dep, mirrored from Platform)
3. **HTTPS mock server** starts with self-signed cert, accepts connections
4. **TLS handshake** works with `--ignore-certificate-errors` flag
5. **Page navigation** to `https://localhost:8443/` works
6. **Test infrastructure** is a Go stdlib program in `tools/headless-smoke/`

## What's still broken

**The content script does not fire on `https://localhost/`.** The page loads, the content script should inject per the manifest matches (`https://localhost/*` was added), but `window.__lens_cs` is never set within 10 seconds.

**Root cause hypothesis**: `selectors.js`'s `identifyProvider()` requires the hostname to match one of the 10 provider hostnames (`chat.openai.com`, `claude.ai`, etc.). On `https://localhost/`, no provider matches, so the content script's `window.__lens_cs` is not set.

**Fix options**:
1. Add a `localhost` provider in `selectors.js` for testing
2. Serve the mock page at a hostname that matches (e.g., `chat.openai.com` via /etc/hosts)
3. Make `__lens_cs` set regardless of provider match (for diagnostics)

## How to run

```bash
cd $LENS
pkill -9 -f "headless-smoke"  # NOT pkill chromium (would hang the MCPs)
$LENS/test/headless-smoke/headless-smoke-bin \
  --dist $LENS/test/headless-smoke/dist \
  --output $LENS/test/headless-smoke/reports/run.json \
  --verbose > $LENS/test/headless-smoke/logs/run.log 2>&1
```

## Test cases (built into the binary)

- `benign-python-factorial` (expected 0 detections)
- `pi-ignore-previous` (expected >=1 detection, category=pi_jailbreak)
- `pii-email` (expected >=1, category=pii_email)
- `secrets-aws-key` (expected >=1, category=secrets_aws_key)
- `xss-script-tag` (expected >=1, category=xss_script_tag)

## File locations (proper, per Lesson AA)

- `tools/headless-smoke/main.go` — orchestrator
- `tools/headless-smoke/chromium.go` — Chromium spawn
- `tools/headless-smoke/devtools.go` — CDP client (gorilla/websocket)
- `tools/headless-smoke/mock.go` — HTTPS mock server
- `tools/headless-smoke/runner.go` — test cases + assertions
- `tools/headless-smoke/go.mod` — module def
- `test/headless-smoke/dist/` — built bundle for testing
- `test/headless-smoke/cases/` — JSON test cases (basic.json)
- `test/headless-smoke/mock/platform-testdata/` — copy of Platform's mock pages
- `test/headless-smoke/headless-smoke-bin` — built binary (gitignored)
- `test/headless-smoke/logs/` — runtime logs (gitignored)
- `test/headless-smoke/reports/` — test reports (gitignored)
