# AegisGate Lens — Architecture (v0.1.3)

**Version**: v0.1.3
**Last updated**: 2026-07-10
**Audience**: Contributors, security auditors, and technical evaluators.

> Pattern count: 131, test count: 405/405 unit
> + 3/3 Go + 16/16 smoke), and provider count (10 → 8 with localhost
> fallback for tests).

## System overview

Lens is a Chrome extension that injects a content script into
8 AI chat tool hostnames. As the user types, the content script
runs 4 regex facets against the prompt. On detection, a banner
appears at the top of the page with the category, severity, and
options (Cancel / Edit & Redact / Send Anyway / False Positive).

## Detection pipeline

```mermaid
graph TD
    A[User types in prompt-textarea] -->|input event| B[MutationObserver]
    B -->|250ms debounce| C[prompt-detect]
    C -->|text| D[__lensDispatcher.detect]
    D --> D1[pii-us-core.js<br/>43 patterns]
    D --> D2[pii-us-extended.js<br/>11 patterns]
    D --> D3[pii-international-id.js<br/>23 patterns]
    D --> D4[pii-financial.js<br/>9 patterns]
    D --> D5[pii.js aggregator]
    D --> D6[secrets.js<br/>41 patterns]
    D --> D7[source_xss.js<br/>12 patterns]
    D --> D8[compliance.js<br/>24 patterns]
    D5 --> E[DetectionResult]
    D6 --> E
    D7 --> E
    D8 --> E
    E -->|hasDetections| F[__lensBannerUI.show]
    E -->|!hasDetections| G[no-op]
    F --> H[Banner element in DOM]
    H -->|user click| I[__lensBannerUI.onAction]
    I -->|cancel| J[__lensDismiss.dismiss]
    I -->|false-positive| K[show dismiss form]
    I -->|send| L[allow send]
    J --> M[chrome.storage write]
```

## Banner show / hide flow

```mermaid
sequenceDiagram
    participant U as User
    participant PD as prompt-detect
    participant DS as dispatcher
    participant CS as content.js
    participant BU as __lensBannerUI
    participant SW as service worker

    U->>PD: types "My SSN is 123-45-6789"
    PD->>PD: 250ms debounce
    PD->>DS: detect(text)
    DS->>DS: 4 facets, 131 patterns
    DS-->>PD: [DetectionEvent(category: pii_ssn)]
    PD->>CS: onDetect(events, text)
    CS->>CS: __lens_cs.lastDetections = events
    CS->>BU: show(events, opts)
    BU->>BU: createBannerElement (if null)
    BU->>BU: innerHTML = buildBannerHTML(events)
    BU->>BU: remove('hidden') class
    BU->>BU: append to document.documentElement
    U->>BU: clicks [x] Dismiss
    BU->>BU: hide() -> add 'lens-hiding' class
    Note over BU: 200ms fade-out animation
    BU->>BU: add 'hidden' class, remove from DOM
    BU->>SW: onAction('dismiss', events)
    SW->>SW: recordDismissalForEvents
```

## Dismiss storage round-trip

```mermaid
graph LR
    A[User clicks Dismiss] --> B[__lensBannerUI.hide]
    B --> C[__lensDismiss.dismiss]
    C -->|domainHash + category| D[chrome.storage.session<br/>or .local fallback]
    D --> E[record: expiresAt = now + 24h]
    F[Next prompt: same domain, same category] --> G[__lensPromptDetect fires]
    G --> H[__lensDismiss.isDismissed]
    H --> D
    D -->|expiresAt less than now? remove| I[no entry: not dismissed]
    I --> J[show banner]
    D -->|expiresAt greater equal now? return entry| K[already dismissed: hide banner]
```

## Module load order

```mermaid
graph TD
    BO[bootstrap.js<br/>module registry] --> CO[util/constants.js]
    CO --> TD[util/typedefs.js]
    TD --> LO[util/logger.js]
    LO --> LU[detectors/luhn.js]
    LU --> PI[pii-us-core.js]
    PI --> PE[pii-us-extended.js]
    PE --> PII[pii-international-id.js]
    PII --> PF[pii-financial.js]
    PF --> PIA[pii.js aggregator]
    PIA --> SE[secrets.js]
    SE --> XS[source_xss.js]
    XS --> CP[compliance.js]
    CP --> SC[privacy/schema.js]
    SC --> DH[privacy/domain_hash.js]
    DH --> DI[detectors/index.js<br/>__lensDispatcher]
    DI --> SE2[util/selectors.js]
    SE2 --> PD1[util/prompt-detect-dom.js]
    PD1 --> PD2[util/prompt-detect-lifecycle.js]
    PD2 --> PD3[util/prompt-detect.js<br/>__lensPromptDetect]
    PD3 --> BI[util/banner-icons.js]
    BI --> DM[util/dismiss.js<br/>__lensDismiss]
    DM --> BF[util/banner-ui-formatters.js]
    BF --> BH[util/banner-ui-html.js]
    BH --> BL[util/banner-ui-lifecycle.js]
    BL --> BU[util/banner-ui.js<br/>__lensBannerUI]
    BU --> CT[content.js<br/>__lens_cs]
```

## Privacy boundary

```mermaid
graph LR
    subgraph "ON-DEVICE (Lens)"
        PS[prompt-detect]
        DI[dispatcher]
        BU[banner UI]
        DM[__lensDismiss]
    end

    subgraph "OPT-IN ONLY (Lens to Backend)"
        FR[FP report]
    end

    subgraph "NEVER (architectural)"
        PT[prompt text on wire]
        URL[URL on wire]
        PC[page content on wire]
        LOG[keystroke logging]
    end

    PS --> DI
    DI --> BU
    BU -->|user clicks False Positive| FR
    FR -->|domain-hashed, category-only| BACKEND[POST lens.aegisgatesecurity.io/lens/telemetry/fp-report]
    PS -.X.- PT
    PS -.X.- URL
    PS -.X.- PC
    PS -.X.- LOG
```

The "NEVER" column is enforced by the code, not by policy. There is
no `fetch()` call to any origin in the content script. The opt-in
FP report is the ONLY egress, and it's only invoked when the user
explicitly clicks "False Positive" on a banner.

## Provider detection

```mermaid
graph TD
    A[document loaded] --> B[content.js init]
    B --> C[identifyProvider]
    C -->|hostname matches<br/>chat.openai.com<br/>claude.ai<br/>gemini.google.com<br/>copilot.microsoft.com<br/>copilot.cloud.microsoft<br/>duck.ai<br/>perplexity.ai<br/>mistral.ai| D[return PROVIDERS i]
    C -->|hostname is<br/>localhost or 127.0.0.1| E[return PROVIDERS 0 for smoke test]
    C -->|no match| F[return null<br/>prompt-detect skips]
    D --> G[findInput]
    E --> G
    F --> H[no-op]
    G --> I[attach MutationObserver to textarea]
    I -->|user types| J[250ms debounce + detect]
```

## What this document does NOT cover

- **Bundle format**: see `docs/MODEL-CARD.md`
- **Permission justifications**: see the CWS listing at
- **Threat model**: see `docs/THREAT-MODEL.md`
- **Bundle globals**: see `docs/API.md`
