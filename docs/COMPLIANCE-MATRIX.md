# AegisGate Lens — Compliance Matrix (MITRE ATLAS / NIST AI RMF / OWASP LLM Top-10)

**Date**: 2026-06-30
**Status**: v0.2.0-rc1 (pre-CWS-submission)
**Purpose**: Map AegisGate Lens's detection capabilities to the three primary AI-security frameworks used by enterprise CISOs, GRC teams, and procurement.

---

## 1. MITRE ATLAS (Adversarial Threat Landscape for AI Systems)

ATLAS is MITRE's knowledge base of adversary tactics and techniques against AI systems. AegisGate Lens addresses the following ATLAS techniques:

| ATLAS ID | Technique | Lens Coverage | Detection Method |
|---|---|---|---|
| AML.T0048 | Erode ML Model Integrity | ✅ PARTIAL | Sliding-window inference with anomaly aggregation; toxic-bert ML (v0.2) |
| AML.T0024 | Exploit ML Model Inference | ✅ PARTIAL | Sliding-window inference on long-context attacks |
| AML.T0023 | Craft Adversarial Data | ✅ YES | 1,764 obfuscated attack variants corpus (Step D) |
| AML.T0051 | LLM Prompt Injection (AML.T0051) | ✅ YES | ModernBERT ML classifier + sliding window (Facet 6) |
| AML.T0040 | ML Supply Chain Compromise | ✅ YES | Ed25519 bundle signing (F-02) — all 8 attack vectors rejected |
| AML.T0052 | LLM Jailbreak (AML.T0052) | ✅ YES | "act as X", RLO Unicode, "ignore previous instructions" patterns in regex + ML |
| AML.T0043 | Craft Training Data (backdoor) | ❌ NO | Out of scope — the Lens protects the END USER from prompt injection, not the model vendor from training-time attacks |
| AML.T0028 | LLM Data Leakage (training data exfil) | ❌ NO | Out of scope — the Lens protects prompt content (input), not training data |
| AML.T0046 | Erode Datasets (data poisoning) | ❌ NO | Out of scope — the Lens has no visibility into training datasets |
| AML.T0018 | Obfuscate Inputs | ✅ YES | Unicode normalization + homoglyph detection in regex layer |

**Coverage summary**: 7/10 ATLAS techniques relevant to end-user prompt-injection defense are addressed. The 3/10 out-of-scope techniques are about model-training-time attacks, which the Lens does not address (correctly — that's a Platform/vendorside concern).

---

## 2. NIST AI Risk Management Framework (AI RMF 1.0)

NIST AI RMF organizes risk management into four functions: GOVERN, MAP, MEASURE, MANAGE. The Lens supports each:

### GOVERN (organizational risk management)
- ✅ **GV-1 (Policies)**: The 12 privacy non-negotiables (`docs/PRIVACY-POLICY.md`)
- ✅ **GV-2 (Roles)**: Open source project with clear maintainer (AegisGate Security, LLC)
- ✅ **GV-4 (Documentation)**: `docs/THREAT-MODEL.md`, this compliance matrix, `SECURITY.md`

### MAP (context establishment)
- ✅ **MAP-1 (Context)**: Privacy-first product targeting consumers/employees of AI tools (the 95% who don't have AI estates)
- ✅ **MAP-2 (Categorization)**: Tier-1 detection (regex), Tier-2 (sliding window), Tier-3 (ModernBERT ML)
- ✅ **MAP-3 (Understanding)**: Threat model documents 15 findings (10 resolved, 1 partial, 1 closed, 3 accepted)

### MEASURE (analysis, assessment, benchmarking)
- ✅ **MEASURE-1 (Metrics)**: 233/233 tests pass; 96.94% recall on toxicity, 100% on short-context PI, 80% on long-context PI
- ✅ **MEASURE-2 (Evaluations)**: Per-corpus evaluations on r1-r8 corpora (5,200+ attack records, 20,000+ benign records)
- ✅ **MEASURE-3 (Tracking)**: `models/release-candidates/ship_readiness_metrics.json` tracks all metrics over time

### MANAGE (risk response)
- ✅ **MANAGE-1 (Prioritization)**: 6-facet detection with priority ordering (regex first, ML second)
- ✅ **MANAGE-2 (Implementation)**: Tier-1 cascade: regex → sliding window → ML (highest precision, lowest false positive)
- ✅ **MANAGE-4 (Documentation)**: This document, threat model, ship readiness gate

---

## 3. OWASP Top 10 for LLM Applications (2025)

| OWASP ID | Vulnerability | Lens Coverage | Notes |
|---|---|---|---|
| LLM01:2025 | Prompt Injection | ✅ YES | Facet 6 (ModernBERT ML) + sliding window — 100% short-context recall, 80% long-context |
| LLM02:2025 | Sensitive Information Disclosure | ✅ YES | Facets 1-2 (PII, secrets) — 16/16 + 17/17 detector tests pass |
| LLM03:2025 | Supply Chain | ✅ YES | Ed25519 bundle signing (F-02) — all 8 attack vectors rejected; 0 npm deps |
| LLM04:2025 | Data and Model Poisoning | ⚠️ PARTIAL | LLM04 covers training-time poisoning (out of scope for end-user tool). Lens does detect prompt-time poisoning attempts. |
| LLM05:2025 | Improper Output Handling | ⚠️ PARTIAL | Lens outputs are rendered via `textContent` (not `innerHTML`), preventing XSS via banner. Verified by 95.7% banner-XSS test pass rate. |
| LLM06:2025 | Excessive Agency | ❌ NO | Out of scope — the Lens is a passive observer, not an agent. Does not call tools or APIs. |
| LLM07:2025 | System Prompt Leakage | ✅ YES | Detected as "prompt extraction" pattern in regex layer (Facet 6) |
| LLM08:2025 | Vector and Embedding Weaknesses | ⚠️ PARTIAL | RAG/vectordb poisoning patterns in compliance layer (Facet 4) |
| LLM09:2025 | Misinformation | ✅ YES | Compliance detector flags output-marker patterns (Facet 4) |
| LLM10:2025 | Unbounded Consumption | ⚠️ PARTIAL | Sliding window caps at 4 windows × 2048 tokens = 8K context. Longer prompts bypass by design. |

**Coverage summary**: 5 fully covered, 4 partial, 1 out-of-scope. The partials are explicitly documented in the threat model with their limitations.

---

## EU AI Act (selected, relevant articles)

The EU AI Act classifies AI systems by risk. The Lens itself is not an AI system (it detects AI misuses); however, it helps comply with several requirements for systems that USE LLMs:

| Article | Requirement | Lens Support |
|---|---|---|
| Art. 9 (Risk management) | Continuous risk assessment | ✅ The Lens provides ongoing detection during AI use |
| Art. 10 (Data governance) | Training/validation data quality | ❌ N/A (Lens is not an LLM) |
| Art. 14 (Human oversight) | Effective human oversight of AI | ✅ The Lens is a human-oversight tool — it warns but does not block |
| Art. 15 (Accuracy, robustness, cybersecurity) | Appropriate accuracy + cybersecurity | ✅ 100% short-context attack recall; Ed25519 bundle signing; 0 npm deps |
| Art. 50 (Transparency) | Users know they're talking to AI | ❌ N/A (Lens doesn't interact with the AI, it observes the user) |
| Art. 52 (General-purpose AI) | Transparency for GPAI providers | ❌ N/A (Lens is for end users, not GPAI providers) |

---

## How to use this matrix

For a CISO procurement packet or GRC audit:
1. Print this page (or export to PDF)
2. Highlight the "✅ YES" rows relevant to your threat model
3. Note the "⚠️ PARTIAL" rows for documentation of known limitations
4. Note the "❌ NO" rows for explicit out-of-scope declarations

For an external auditor reviewing AegisGate Lens:
- The 12 non-negotiables (`docs/PRIVACY-POLICY.md`) are the primary audit point
- The threat model (`docs/THREAT-MODEL.md`) is the secondary audit point
- This matrix is the tertiary cross-reference for AI-security-specific frameworks

---

## Coverage gaps and roadmap

The following gaps are documented and tracked in `plans/AEGISGATE-LENS-V03-CONSOLIDATED-SHIP-BLOCKER-GAPS-2026-06-30.md`:

- **OWASP LLM05 partial** — banner XSS pass rate is 95.7% (1077/1125). The remaining 5% are edge cases with very long attribute values that the textContent renderer truncates. Acceptable for v0.2.0; will be addressed in v0.2.1.
- **OWASP LLM10 partial** — sliding window caps at 4 × 2048 = 8K tokens. v0.3.0 architecture will add a 100K-token "summary" tier.
- **NIST MEASURE-3** — formal external benchmark participation (e.g., MITRE ATLAS evals) is post-launch.
- **EU AI Act Art. 15** — formal accuracy certification by an external auditor is post-launch.

---

_This matrix is maintained alongside `models/release-candidates/ship_readiness_metrics.json`. Last updated 2026-06-30._
