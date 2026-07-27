# AegisGate Lens v0.1.4 — Model Card

**Model name:** AegisGate Lens v0.1.4
**Model version:** 0.1.0-beta (released 2026-07-04)
**Model type:** Deterministic pattern-matching algorithm (no ML)
**Card format:** Google Model Cards v1 (extended for non-ML systems)
**Date:** 2026-07-09
**Authors:** AegisGate Security, LLC <security@aegisgatesecurity.io>

## 1. Intended Use

AegisGate Lens is a **Chrome browser extension** that
detects PII, secrets, source-code risks, and compliance-
relevant language in prompts the user is about to send to
consumer AI chat tools. Detection is performed 100% in the
browser. The extension NEVER sees prompt content; it sees
the pattern-match results, not the prompt.

**Primary use case:** warn the user (in real time, before
they hit send) when their prompt contains sensitive content.

**Out-of-scope use cases:**
- Server-side enforcement of prompt content policies
  (use AegisGate Platform)
- Network IDS/IPS for prompt content (the extension has
  no network egress by default)
- Multi-tenant audit log of prompts (the extension has no
  audit log by default; opt-in only)
- Enterprise SSO, custom patterns, automated redaction
  (all in AegisGate Platform)

## 2. Training Data

**None.** AegisGate Lens v0.1.4 is a deterministic
pattern-matching algorithm. There is no training data,
no model weights, no ONNX bundle, no TensorFlow Lite
artifact, no ML inference.

The detection patterns were **authored by AegisGate
Security, LLC** using the following sources:
- OWASP LLM Top 10 (2025) — for OWASP pattern names
- MITRE ATLAS — for adversarial robustness categories
- EU AI Act Articles 5, 15, 50 — for compliance patterns
- ANP (Brazil) — for `anp_personal_data`,
  `anp_special_category`
- Computer Use Guard (UK) — for `cu_consumer_rights`,
  `cu_minor_protection`
- NIST CSF, ISO 27001, CCPA, LGPD, PIPEDA, POPIA — for
  regional reference patterns
- Industry standard regex libraries (e.g., common
  credit-card Luhn validators, common IBAN formats)
- The 100K-prompt benchmark corpus (internal,
  not used for training, only for evaluation)

The patterns are **open source** under Apache 2.0 and
auditable at `src/detectors/regex/{pii,secrets,
source_xss,compliance}.js`.

## 3. Evaluation Data

The model was evaluated against:

1. **PII heldout corpus** (`corpora/v01beta-raw/`): 60,000+
   records from 5 public PII datasets (see `corpora/v01beta-raw/`
   for full source list). All records are labeled with
   `expected_label` and `expected_attack_position_token`.
2. **Benign baseline corpus**: 30,000 real user prompts
   from OASST1 (Apache 2.0) and HuggingFaceH4/ultrachat_200k
   (MIT).
3. **Headless smoke**: 6 in-browser flows on the 8
   supported providers, run in real Chromium 149 via
   the headless-smoke Go binary.

**Results (v0.1.4, locked 2026-07-08):**
- In-target PII recall: 98.99% (5,870 of 5,930 high-risk
  PII records caught)
- Mixed records recall: 99.73% (39,285 of 39,391)
- FPR on real user prompts: 7.40% (2,221 of 30,000)
- PII facet precision: 76.51%
- Latency p50: 0.156ms
- Latency p99: 0.847ms
- Unit tests: 328/328 passing
- Headless smoke: 6/6 PASS, SHIP GATE: PASS

**Out-of-scope for this evaluation:**
- Adversarial robustness against paraphrasing (Tier 3
  ML, which was burned down for ship-gate reasons). See
  `docs/THREAT-MODEL.md` F-15.
- Adversarial robustness against base64 / OCR / split-
  across-lines obfuscation. See F-20.
- The Secrets, XSS, and Compliance facets were not
  evaluated at scale (the PII benchmark corpus does not
  contain secrets/XSS/compliance data). Build a separate
  corpus in v0.2.0 to evaluate them.

## 4. Model Architecture (Technical Detail)

**Architecture: 4 regex facets, 132 patterns, deterministic.**

The detector is composed of 4 facets, each a list of
`{category, severity, re, postProcess}` tuples:

```
┌──────────────────────────────────────┐
│ User prompt (typed into a chat input) │
└──────────────────┬───────────────────┘
                   │ per keystroke, debounced 250ms
                   ▼
┌──────────────────────────────────────┐
│ src/detectors/index.js (dispatcher)  │
└─┬────────┬────────┬────────┬─────────┬─┘
  ▼        ▼        ▼        ▼         ▼
┌────┐  ┌────┐  ┌────┐  ┌────┐
│ PII│  │Secr│  │XSS │  │Comp│
│ 54 │  │ 41 │  │ 12 │  │ 24 │  patterns
└──┬┘  └────┘  └────┘  └────┘
   │  ▲
   │  │  Luhn postProcess (credit-card validation)
   │  │  BIP39 postProcess (seed-phrase validation)
   ▼  │
 events[]
   │
   ▼
┌──────────────────────────────────────┐
│ src/util/banner-ui.js (banner render) │
└──────────────────────────────────────┘
   │ top-of-screen banner
   ▼
   User sees the detection result
```

The dispatcher runs all 4 facets, aggregates the matches
by `category`, dedupes, sorts by severity, and returns
the events array. The banner renders the events.

**PostProcess pipeline (the closest thing to "ML" in
this version):**
- `pii_credit_card`: Luhn checksum validation
- `pii_phone_intl_loose`: digit-count + date-shape filter
  to reduce false positives on SSN-like patterns
- `pii_bip39_seed`: wordlist match (15 common words)
  to filter out English prose

These are not learned; they are hand-tuned heuristics.

## 5. Performance

### 5.1 Latency

- **p50:** 0.156ms (median per-detection, on the 100K
  benchmark corpus)
- **p95:** 0.459ms
- **p99:** 0.847ms
- **p99.9:** 0.886ms
- **Throughput:** 6,474 records/second on a single
  thread (Node 25.9.0, no GPU)

### 5.2 Memory

- **Per-pattern memory:** ~5KB (compiled regex + metadata)
- **Total detector memory:** ~1.4MB (132 patterns + index)
- **Per-detection allocation:** 0 (reuses the result
  arrays from the dispatcher)

### 5.3 Browser Impact

- **CPU:** <0.1% on a 2020 MacBook Pro M1 (measured
  during typing on ChatGPT)
- **Memory:** 0 (the regex is allocated once at extension
  load)
- **Network:** 0 bytes by default (the extension has no
  network egress). Opt-in telemetry: 1 POST per dismissed
  false-positive (rare)

## 6. Limitations

1. **Adversarial robustness:** the regex tier is bypassable
   by paraphrasing, base64-encoding, OCR-ing, or splitting
   PII across multiple lines. See `docs/THREAT-MODEL.md`
   F-15 and F-20.
2. **Secrets / XSS / Compliance coverage:** the v0.1.4
   benchmark does not include a large-scale secrets / XSS /
   compliance corpus. The detectors exist; their recall on
   real-world data has not been measured.
3. **International PII:** the international PII patterns
   cover the most common document types (US, UK, EU, CA,
   AU, DE, FR, ES, IT, JP, BR, IN). Patterns for less
   common jurisdictions (e.g., Chinese ID, Korean RRN,
   Singapore NRIC, Russian SNILS) are partial or absent.
4. **Severity assignment is heuristic:** the `severity`
   field is hand-assigned per pattern (e.g.,
   `pii_ssn.severity = "critical"`,
   `pii_email.severity = "medium"`). The banner renders
   different colors per severity, but the assignment is
   not data-driven.

## 7. Ethical Considerations

**The detection is opt-in for the user, not enforced on
behalf of the user.** The banner warns; it does not
block. The user can always press "Send Anyway" and the
prompt will be sent to the AI provider. This is a
deliberate design choice: the Lens is a "warn, never
block" tool, not a content filter.

**No prompt content ever leaves the device.** The
detection runs locally. The only outbound message is
opt-in, metadata-only, anonymized, domain-hashed telemetry
to the AegisGate backend (which is also opt-in).

**No demographic data is collected.** The detector
operates on string content, not on user demographics.
The hashed domain in the telemetry signal is the AI
provider's domain (e.g., `chatgpt.com`), not the user's
domain or any personal identifier.

**No content moderation, no censorship, no opinion.**
The Lens detects PII, secrets, XSS, and compliance
language. It does not detect political content,
controversial topics, or anything related to the
substance of what the user is asking the AI to do.

## 8. Caveats and Recommendations

- **For high-risk use cases** (HIPAA, PCI, EU AI Act
  Article 15 compliance), the Lens is necessary but not
  sufficient. Use the AegisGate Platform (server-side
  enforcement, audit logging, automated redaction) in
  addition to the Lens.
- **For adversarial robustness,** the regex tier is not
  sufficient. v0.2.0 introduces a TinyML tier that adds
  semantic-paraphrase detection.
- **For new AI providers,** the Lens needs a `selectors.js`
  entry (DOM selectors for the input field + send button).
  Adding a new provider takes ~1 hour of work; the
  detection is automatic.

## 9. License

AegisGate Lens v0.1.4 is licensed under Apache 2.0.
Copyright 2024-2026 AegisGate Security, LLC.

You may copy, modify, and redistribute. You may NOT
sell the Lens by itself. See `LICENSE` for the full text.

## 10. Citation

```
@software{aegisgate-lens-v0_1_0_beta,
  author = {AegisGate Security, LLC},
  title = {AegisGate Lens: a privacy-first browser
           extension for AI prompt safety},
  version = {0.1.0-beta},
  year = {2026},
  month = {7},
  url = {https://github.com/aegisgatesecurity/aegisgate-lens}
}
```

## 11. Changelog

- **v0.1.4** (2026-07-04): initial public release.
  4 regex facets, 132 patterns, 8 AI providers,
  Apache 2.0.
- (v0.2.0 will add the TinyML tier for adversarial
  robustness.)

---

**Signed-off-by:** AegisGate Security <security@aegisgatesecurity.io>
**Last updated:** 2026-07-09
**Version:** v0.1.4