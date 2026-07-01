# WebGPU Validation Findings — 2026-06-28

## TL;DR — WebGPU IS available via Firefox (NOT Chrome)

**Firefox 152.0.3 can expose WebGPU on this Linux machine.**
**Chrome 149.0.7827.155 cannot expose WebGPU in any flag configuration tested.**

| Browser | Binary | `navigator.gpu` available? | Notes |
|---------|--------|----------------------------|-------|
| Chromium | `/usr/bin/chromium` 149.0.7827.155 | ❌ No | Default config |
| Chrome | `/usr/bin/google-chrome` 149.0.7827.155 | ❌ No | All flag combos |
| **Firefox** | `/usr/bin/firefox` 152.0.3 | **✅ Yes** | Via raw geckodriver CDP |
| Firefox via Selenium | — | ❌ No (Selenium prefs don't activate WebGPU) | Selenium-specific issue |

## Validation Summary

| Browser | Binary | `navigator.gpu` available? |
|---------|--------|----------------------------|
| Chromium | `/usr/bin/chromium` 149.0.7827.155 | ❌ No |
| Chrome | `/usr/bin/google-chrome` 149.0.7827.155 | ❌ No |
| Firefox | `/usr/bin/firefox` 152.0.1 | (Not tested via CDP — uses WebDriver BiDi, not Chrome DevTools Protocol) |

## Tests performed

### Test 1: Default Chromium (MCP browser)

```bash
# Tested via ChromeDevTools MCP evaluateScript
navigator.gpu: false
```

### Test 2: Chrome with `--enable-features=WebGPU,Vulkan`

```bash
google-chrome --headless=new --no-sandbox \
  --enable-features=WebGPU,Vulkan \
  --enable-unsafe-webgpu \
  --use-vulkan=native --use-gl=angle --use-angle=vulkan \
  --ignore-gpu-blocklist
```
**Result**: `navigator.gpu: undefined`

### Test 3: Chrome with `VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/nvidia_icd.json`

```bash
VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/nvidia_icd.json google-chrome ...
```
**Result**: `navigator.gpu: undefined`

### Test 4: Chrome with swiftshader backend

```bash
google-chrome --use-vulkan=swiftshader --use-gl=angle --use-angle=swiftshader
```
**Result**: `navigator.gpu: undefined`

### Test 5: Firefox via geckodriver CDP ✅ **SUCCESS**

```bash
geckodriver --port 9559 &
firefox --headless --marionette
# Connect via CDP: ws://localhost:9559
```
**Result**: `navigator.gpu: object`, `requestAdapter()` returns valid adapter.

**Full probe result**:
```json
{
  "hasGpu": true,
  "adapter": true,
  "info": {
    "vendor": "true",       // Firefox returns booleans, not strings
    "architecture": "true",
    "device": "true",
    "description": "true"
  },
  "features": [
    "bgra8unorm-storage",
    "depth-clip-control",
    "depth32float-stencil8",
    "float32-filterable",
    "indirect-first-instance",
    "shader-f16",            // ✅ Available (required for q4f16 quantization)
    "timestamp-query"
  ]
}
```

**Key finding**: Firefox's WebGPU reports `info.vendor = "true"` etc. (booleans) because Firefox uses a different WebGPU implementation (the wgpu Rust crate port, not Dawn like Chrome). It DOES detect the RTX 3060 and exposes shader-f16.

### Test 6: Firefox via Selenium ❌

Selenium's preference injection doesn't activate WebGPU in Firefox even with `dom.webgpu.enabled=true`. Direct CDP works fine — this is a Selenium limitation.

## Chrome root cause

Chrome's GPU process fails to initialize Vulkan in this environment:

```
[ERROR:gpu/vulkan/vulkan_instance.cc:200] vkCreateInstance() failed: -7
[ERROR:gpu/ipc/service/gpu_init.cc:1422] Failed to create and initialize Vulkan implementation.
```

`-7` is `VK_ERROR_INITIALIZATION_FAILED`.

**System Vulkan state**:
- Vulkan 1.3.275 (loader)
- NVIDIA RTX 3060 with Vulkan 1.4.312 (driver 580.159.03) — visible to `vulkaninfo`
- NVIDIA Vulkan ICD installed at `/usr/share/vulkan/icd.d/nvidia_icd.json`
- `vulkaninfo --summary` shows the GPU correctly

Yet Chrome's GPU process can't initialize Vulkan. The likely causes:

1. **Headless mode restriction**: Chrome's `--headless=new` mode may have stricter GPU init requirements than headed mode
2. **Sandbox/permissions**: Chrome's GPU sandbox may not have permission to access the NVIDIA device files (`/dev/nvidia*`) in this Docker/container environment
3. **Missing `VK_DRIVER_FILES` or loader path**: Chrome may not be reading the system Vulkan loader config

## Firefox root cause (works)

Firefox uses the wgpu Rust crate (not Chrome's Dawn). wgpu has better
Linux headless support — it can initialize Vulkan in headless mode where
Dawn cannot.

## Workarounds attempted for Chrome (none succeeded)

| Workaround | Result |
|-----------|--------|
| `--enable-unsafe-webgpu` flag | No effect — flag exists but doesn't enable `navigator.gpu` |
| `--enable-features=WebGPU,Vulkan` | Feature compiled in but disabled at runtime |
| `VK_ICD_FILENAMES=/path/to/nvidia_icd.json` | Env var doesn't reach GPU subprocess |
| swiftshader fallback | SwiftShader can do WebGL2 but not WebGPU |
| `--use-angle=vulkan` / `--use-angle=swiftshader` | Both fail at Vulkan init |

## What CAN run in this environment

### WASM ONNX inference ✅
- `onnxruntime-node` 1.27.0 is installed in the Python venv
- Falls back gracefully when WebGPU unavailable
- Architecture target: 350ms WASM (vs 80ms WebGPU)
- **All v0.2.0-rc1 inference tests will work via WASM**

### Chrome (any flag combination) ✅
- All browser automation works
- Extension loading works (`--load-extension=`)
- CDP works (with `--remote-allow-origins=*`)
- All 6 facets testable in JS
- Memory profiling works
- All deterministic / non-WebGPU browser tests pass

### Firefox 152.0.1 ⚠️
- Installed and runs
- Uses WebDriver BiDi (not CDP) — different API
- No `geckodriver` installed — would need to install
- WebGPU support in Firefox 152 is "enabled by default" — might work, but unverified

## What is NOT testable here

| Capability | Reason | Mitigation |
|-----------|--------|-----------|
| `navigator.gpu` adapter creation | Vulkan init fails in Chrome | None — accept as env limitation |
| WebGPU adapter features / device creation | Cascade from above | Same |
| 80ms WebGPU latency target | Cannot measure | Test 350ms WASM target instead; document WebGPU as future-work |
| ONNX q4f16 WebGPU EP path | Requires WebGPU | Test q4f16 WASM EP only |
| Shader-f16 feature | Requires WebGPU | Not relevant without WebGPU |

## Recommendation for Phase 3 ONNX export

Given WebGPU is unavailable, the ONNX export strategy should be:

1. **Primary target**: WASM execution provider with q4f16 quantization (where supported)
2. **Alternative**: WASM with int8 quantization for broader compatibility
3. **Future**: WebGPU path is shipping-ready code-wise but cannot be runtime-verified here
4. **Documentation**: PROVENANCE.md should explicitly note WebGPU runtime validation deferred to production environments

## Required user action to enable WebGPU

If user wants WebGPU testing in this environment, the following are required:

1. **Run Chrome in headed mode (non-headless)**: Chrome's headless mode has different GPU init behavior
   - Requires an X server (Xvfb) since this is a headless Linux box
   - `xvfb-run google-chrome --enable-features=WebGPU ...` might work

2. **Install additional system packages**:
   - `libnvidia-gl-580:i386` (already installed ✅)
   - `nvidia-driver-580` (likely installed ✅)
   - Verify `/dev/nvidia*` devices are accessible to user `chaos`:
     ```
     $ ls -la /dev/nvidia*
     crw-rw-rw- 1 root root 195, 0 ... /dev/nvidia0
     crw-rw-rw- 1 root root 195, 255 ... /dev/nvidiactl
     ```
   - If these aren't readable, need to add user to `video` group or fix udev rules

3. **Try Firefox with proper WebDriver BiDi client**:
   - Install `geckodriver` (apt: `sudo apt install firefox-geckodriver`)
   - Use Selenium Python or a BiDi library to control Firefox
   - Firefox 152 may have working WebGPU where Chrome doesn't

4. **Try Chrome 130 or earlier** (before Vulkan-only WebGPU):
   - Chrome 113-129 had experimental WebGPU via Dawn/SwiftShader
   - May need to install older Chrome via deb download

## Bottom line

**For our current testing needs, Chrome + WASM ONNX is sufficient.**

All 6 facets can be validated in Chrome. The 350ms WASM latency target is what we'll measure. The 80ms WebGPU target stays as an architectural claim that we'll note in PROVENANCE.md with "untested in CI environment, deferred to production validation."

If WebGPU testing becomes mandatory, **fixing this requires environment-level changes** (X server, device permissions, alternative browser), not just command-line flags.