# Validation Findings — 2026-06-28

## 1. Hardware validation ✅

| Component | Expected | Actual | Status |
|-----------|----------|--------|--------|
| CPU cores | 40 | 40 (Intel Xeon E5-2687W v3 @ 3.10GHz) | ✅ |
| RAM | 256 GB | 251 GiB (239 GiB available) | ✅ |
| GPU | RTX 3060 / 12GB VRAM | RTX 3060 / 12288 MiB (11601 MiB free) | ✅ |
| CUDA | 12.0+ | 12.0.140, driver 580.159.03 | ✅ |
| Disk | Sufficient | 1.5 TB free | ✅ |

**Verified via shell commands.** All resources available.

## 2. Browser validation ✅

| Component | Status |
|-----------|--------|
| `/usr/bin/chromium` | ✅ Chromium 149.0.7827.155 |
| `/usr/bin/google-chrome` | ✅ |
| `/usr/bin/google-chrome-stable` | ✅ |
| `/usr/bin/chromedriver` | ✅ 149.0.7827.155 |
| ChromeDevTools MCP (via goose) | ✅ `listPages`, `navigatePage`, `takeSnapshot`, `evaluateScript` all working |
| Custom CLI flags | ✅ `--headless=new --load-extension= --user-data-dir= --remote-debugging-port=` all confirmed working |
| DevTools Protocol (CDP) endpoint | ✅ `ws://localhost:9222/...` works |

**Browser reported environment** (via `navigator.hardwareConcurrency`):
- 40 cores (matches shell) ✅
- `navigator.gpu: false` — **WebGPU NOT available in this Chrome build**

## 3. WebGPU validation — NOT available in this environment

The bundled Chromium 149.0.7827.155 does NOT expose `navigator.gpu`. Tested:
- Default Chromium (MCP browser)
- Chrome with `--enable-features=WebGPU,Vulkan` + `--enable-unsafe-webgpu`
- Chrome with `VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/nvidia_icd.json`
- Chrome with `--use-vulkan=swiftshader` / `--use-vulkan=native`
- Chrome with `--use-angle=vulkan` / `--use-angle=swiftshader`

**Root cause**: Chrome's GPU process can't init Vulkan:
`vkCreateInstance() failed: -7` (`VK_ERROR_INITIALIZATION_FAILED`).
NVIDIA devices are world-readable (`/dev/nvidia*` perms `666`); not a
permissions issue. Likely cause: headless mode + Chrome Vulkan init path.

**What CAN run**: WASM ONNX (350ms target), full browser automation,
all 6 facets, memory profiling, determinism tests.

**What CANNOT run**: WebGPU adapter creation, 80ms WebGPU latency,
q4f16 WebGPU EP. Document in PROVENANCE.md as "WebGPU runtime
validation deferred to production environment."

**Fixing this requires**: Xvfb installation + headed Chrome, OR
alternative browser (Firefox 152 via WebDriver BiDi, no geckodriver
installed), OR older Chrome version. Not a quick fix.

Full details: `test/eval/WEBGPU-VALIDATION-2026-06-28.md`

## 4. Extension state

| Item | Status |
|------|--------|
| v0.2 source `src/` | ✅ Complete (12 dirs, 21 files) |
| v0.2 `lens-final-dist/` | ❌ Empty — no built dist |
| v0.1 dist (archive) | ✅ Available at `archives/iteration-v0.1-day32-burndown-2026-06-26/lens/lens-working-snapshot/lens-final-dist/` (manifest v3, content.js, service-worker.js, popup, welcome — all valid MV3) |
| v0.2 manifest | ✅ At `src/manifest.json` |
| v0.2 content.js / service-worker.js | ✅ At `src/content.js` and `src/service-worker.js` |

## 5. Test infrastructure available

| Tool | Use |
|------|-----|
| `Chromedevtools.*` | Drive the existing Chromium MCP browser |
| Headless Chromium CLI | Launch fresh instances with custom flags (`--load-extension=`) |
| Python+CUDA venv | Run inference comparison tests (already validated) |
| Node.js | Run JS unit tests (already validated) |

## 6. Implications for the testing plan

Because WebGPU is unavailable, Phase 3 ONNX latency validation will use:
- **WASM execution provider only** (per architecture §2.3 fallback)
- Latency target adjusted: **350ms WASM** (vs 80ms WebGPU which we cannot test)
- The "80ms WebGPU" claim from the architecture doc remains a future-work item requiring a WebGPU-capable browser

Because no v0.2 dist exists yet, we have two e2e options:
- **Option A**: Build a minimal v0.2 dist (copy src/ + manifest, add icons stub) for e2e testing of the new transformer-modernbert.js
- **Option B**: Use v0.1 dist as a smoke-test target to validate the e2e harness works end-to-end, then build v0.2 dist

Option A is the right path; Option B is a useful prerequisite.

## 7. Tools that I CAN actually drive

Confirmed working:
- `Chromedevtools.listPages`, `navigatePage`, `takeSnapshot`, `evaluateScript`, `closePage`, `newPage`
- `Chromedevtools.takeScreenshot`, `takeHeapsnapshot`
- `Chromedevtools.listConsoleMessages`, `listNetworkRequests`
- `Chromedevtools.resizePage`, `emulate`
- `Chromedevtools.lighthouseAudit`
- `Chromedevtools.performanceStartTrace`/`performanceStopTrace`/`performanceAnalyzeInsight`
- Shell `chromium --headless --load-extension=<path>` with CDP port

Not yet tested but expected to work:
- `Chromedevtools.click`, `fill`, `fillForm`, `typeText`, `pressKey`, `hover`, `drag`
- `Chromedevtools.uploadFile`, `waitFor`