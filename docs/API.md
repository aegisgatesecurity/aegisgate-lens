# AegisGate Lens — Bundle API Reference

**Version**: v0.3.2
**Status**: Stable (within v0.3.x)
**Audience**: Developers integrating with the Lens content script, or
contributors who need to understand the module contracts.

The AegisGate Lens content script is a chain of CommonJS-style IIFE
modules, each one setting a global on `window` (and equivalents) at
the end of its IIFE. The contract is documented in
`src/bootstrap.js`; this document is the API surface of each global.

## Load order

The modules are loaded in the order declared in
`manifest.json`'s `content_scripts[0].js`. Subsequent modules may
read the globals set by earlier ones:

```
0  bootstrap.js
1  util/constants.js     → __lensConstants
2  util/typedefs.js
3  util/logger.js        → __lensLogger
4  detectors/luhn.js
5-8  pii-{us-core,us-extended,international-id,financial}.js
9  detectors/regex/pii.js
10 detectors/regex/secrets.js
11 detectors/regex/source_xss.js
12 detectors/regex/compliance.js
13 privacy/schema.js     → __lensSchema
14 privacy/domain_hash.js
15 detectors/index.js    → __lensDispatcher
16 util/selectors.js     → __lensSelectors
17-18 prompt-detect-{dom,lifecycle}.js
19 util/prompt-detect.js → __lensPromptDetect
20 util/banner-icons.js
21 util/dismiss.js      → __lensDismiss
22-24 banner-ui-{formatters,html,lifecycle}.js
25 util/banner-ui.js     → __lensBannerUI
26 content.js            → __lens_cs
```

## Globals

### `__lensConstants`

Set by: `src/util/constants.js` (loaded first, after bootstrap)

Brand and tuning constants. Frozen at module load.

| Key | Type | Purpose |
|---|---|---|
| `STORAGE_KEYS.OPT_IN` | `string` | `chrome.storage` key for the opt-in record |
| `STORAGE_KEYS.DISMISSALS` | `string` | `chrome.storage` key for the per-domain dismissal map |
| `STORAGE_KEYS.ONBOARDED` | `string` | `chrome.storage` key for the first-run onboarding flag |
| `STORAGE_KEYS.FP_QUEUE` | `string` | `chrome.storage` key for the opt-in FP report queue |
| `STORAGE_KEYS.EVENTS_RING` | `string` | `chrome.storage.session` key for the in-memory event ring buffer |
| `DEBOUNCE_MS` | `number` | Prompt-detect debounce (250 ms) |
| `BANNER_FADE_IN_MS` | `number` | Banner fade-in animation duration (200 ms) |
| `BANNER_Z_INDEX` | `number` | Banner z-index (max 32-bit signed int) |
| `DISMISS_TTL_MS` | `number` | Dismissal time-to-live (24 h) |
| `MAX_EVENTS_RING` | `number` | Max events in the ring buffer (1000) |
| `MAX_USER_ACTIONS` | `number` | Max user actions logged (100) |
| `FP_REASON_CODES` | `object` | The 3 FP dismissal reasons (test_data / own_data / legitimate_use_case) |
| `COLOR_TOKENS` | `object` | Banner CSS color tokens (matches the corporate site) |

### `__lensLogger`

Set by: `src/util/logger.js`

A minimal logger with `.info()`, `.warn()`, `.error()` methods.
Falls back to `console.log` if the real logger module isn't loaded
(e.g., in tests).

```js
window.__lensLogger.info("something happened");
window.__lensLogger.warn("non-fatal issue", errorObj);
window.__lensLogger.error("fatal", errorObj);
```

### `__lensSchema`

Set by: `src/privacy/schema.js`

Schema validator for the `lens_event` payload (the event sent to
the service worker when the user takes an action on a banner).

```js
const result = window.__lensSchema.validateEventMetadata(event);
// result.ok: boolean
// result.error: string (if !ok)
```

The schema is the single source of truth for what fields are
allowed in the SW payload. Any field not in the schema is
rejected — this is the privacy boundary (no prompt text, no URL,
no page content, no user identifiers).

### `__lensDispatcher`

Set by: `src/detectors/index.js`

The detector aggregator. Runs all 4 regex facets on a text string
and returns a structured `DetectionResult`.

```js
const result = window.__lensDispatcher.detect(text);
// {
//   text: string,
//   hasDetections: boolean,
//   count: number,
//   maxSeverity: 'critical' | 'high' | 'medium' | 'low' | null,
//   events: [DetectionEvent]  // sorted by severity (critical first)
// }
```

### `__lensSelectors`

Set by: `src/util/selectors.js`

Provider detection + DOM selectors for the 8 supported AI chat
tools (8 host patterns in the manifest, 1 localhost fallback for
the smoke test).

```js
const provider = window.__lensSelectors.identifyProvider();
// provider: { id: 'chatgpt', hostname: 'chat.openai.com', ... } or null

const input = window.__lensSelectors.findInput(provider);
// input: the prompt-textarea DOM element (or null)

window.__lensSelectors.setInputValue(input, "user typed text");
// Fires the 'input' event so prompt-detect's MutationObserver fires
```

### `__lensPromptDetect`

Set by: `src/util/prompt-detect.js`

The per-keystroke detector. Attaches a MutationObserver to the
input element and fires the `onDetect` callback when a PII/secret
is detected.

```js
window.__lensPromptDetect.init({
  onDetect: (events, text) => { /* show banner */ },
  onSendIntercept: (events, text) => ({ action: 'cancel' })
});

const state = window.__lensPromptDetect.getState();
// { input, attached, lastValue, lastValueAt, debounceTimer, ... }
```

The `onDetect` callback receives an array of `DetectionEvent` (the
same shape as `__lensDispatcher.detect().events`).

The `onSendIntercept` callback is called when the user attempts
to send a message. It must return a decision object:
`{ action: 'send' | 'redact' | 'cancel' }`.

### `__lensDismiss`

Set by: `src/util/dismiss.js`

Per-domain 24h dismissal map. `storage.session` is the
implementation; `storage.local` is the fallback for older Chrome.

```js
const isDismissed = await window.__lensDismiss.isDismissed(
  domainHash, 'pii_ssn', 'pii_ssn_v1'
);
// returns: null (not dismissed) or { expiresAt: timestamp }

await window.__lensDismiss.dismiss(
  domainHash, 'pii_ssn', 'pii_ssn_v1', 'private', null
);
// stores the dismissal for 24h

const report = window.__lensDismiss.buildFPReport(event, domainHash, reason);
// returns: { domain_hash, category, severity, reason, ... }
// NEVER includes prompt text, URL, page content, or user identifier
```

### `__lensBannerUI`

Set by: `src/util/banner-ui.js`

The banner UI. Owns the `state.el` (the banner DOM element) and
the `show()`, `hide()`, `isVisible()`, `getElement()`, `getState()`
public API.

```js
window.__lensBannerUI.show(events, opts);
// events: [DetectionEvent]
// opts: { input, domainHash, learnMoreUrl, onAction }
// onAction(action, payload) is called when the user clicks a button

window.__lensBannerUI.hide();
// Removes the banner from the DOM (with a 200ms fade-out animation)

const el = window.__lensBannerUI.getElement();
// The banner DOM element (or null if not yet shown)

const visible = window.__lensBannerUI.isVisible();
// true if show() was called and hide() hasn't been called
```

### `__lens_cs`

Set by: `src/content.js` (last, after all other modules)

The content script's public surface. Bridges the internal modules
and exposes the test/diagnostic state.

```js
window.__lens_cs = {
  hostname: 'chat.openai.com',
  domainHash: 'a1b2c3...',  // first 16 hex chars of SHA-256(hostname)
  lastDetections: [/* DetectionEvent */],
  lastText: 'the prompt that triggered the last detection',
  lastDetectedAt: 1234567890,  // Date.now()
  initError: null,  // or a string if init() failed
}
```

The test/diagnostic state (`lastDetections`, `lastText`,
`lastDetectedAt`) is updated on every `onDetect` callback. This is
how the headless smoke test verifies detection without parsing
the banner DOM.

## Deprecated globals

The following globals were planned but **not implemented** in
v0.2.x. They are reserved in `src/util/typedefs.js` but
should not be relied on:

| Name | Status | Replacement |
|---|---|---|
| `__lensMl` | Reserved for v0.2.0 TinyML | (future) |
| `__lensToxicity` | Reserved for v0.2.0 | (future) |
| `__lensPromptInjection` | Reserved (the facet name in schema.js) | Use `__lensDispatcher.detect()` and filter on `facet: 'compliance'` |

## How to add a new global (for contributors)

1. Add the global to the IIFE at the bottom of the new module:
   ```js
   if (typeof self !== 'undefined') self.__lensXxx = module;
   if (typeof window !== 'undefined') window.__lensXxx = module;
   if (typeof globalThis !== 'undefined') globalThis.__lensXxx = module;
   ```
2. Add the global name to `KNOWN_LENS_GLOBALS` in
   `test/helpers/load-module.js` (so `resetGlobals()` knows to clear it)
3. Add the global's API contract to this document
4. Add a unit test in `test/unit/` that uses the global
5. Add an entry to the load order in `src/bootstrap.js`

## See also

- `src/bootstrap.js` — the load-order contract
- `src/util/typedefs.js` — TypeScript-style JSDoc types
- `docs/ARCHITECTURE-v0.1.3.md` — the architecture diagram
- `docs/THREAT-MODEL.md` — what these globals could leak
