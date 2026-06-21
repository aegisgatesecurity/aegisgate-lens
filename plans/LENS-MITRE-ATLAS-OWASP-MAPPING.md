# AegisGate Lens - MITRE ATLAS / OWASP LLM Top 10 Mapping

**Status**: Current  
**Version**: v0.1.0  
**Last Updated**: 2026-06-21  

## Purpose

This document maps AegisGate Lens detection categories to industry-standard
threat taxonomies:

- **MITRE ATLAS** (Adversarial Threat Landscape for AI Systems) — the AI/ML
  equivalent of the ATT&CK framework
- **OWASP LLM Top 10** (LLM01-LLM10) — the top risks for LLM applications
- **EU AI Act** — compliance categories from the EU AI Act

This is **not new detection logic** — the categories already exist. This
document provides a **mapping** for security teams to understand which
threats AegisGate Lens detects, and where the gaps are.

## 1. MITRE ATLAS Coverage

MITRE ATLAS (https://atlas.mitre.org) catalogs adversary tactics and
techniques against AI systems. AegisGate Lens currently maps to these
ATLAS techniques:

### 1.1 Reconnaissance
| ATLAS Technique | Lens Category | Notes |
|---|---|---|
| AML.T0048 - Discover LLM Applications | (not in user prompts) | Lens detects prompt-level threats, not reconnaissance |
| AML.T0049 - Discover LLM Prompts | `atlas_promptextraction`, `atlas_configexfiltration` | Direct extraction attempts |

### 1.2 Resource Development
| ATLAS Technique | Lens Category | Notes |
|---|---|---|
| (no user-prompt-level techniques) | — | Resource development is offline, not in prompts |

### 1.3 Initial Access
| ATLAS Technique | Lens Category | Notes |
|---|---|---|
| AML.T0043 - Craft Adversarial Data | (all prompt injection categories) | Adversarial inputs in the prompt |
| AML.T0051 - LLM Prompt Injection (Direct) | `atlas_promptinjection`, `owasp_prompt_injection`, `eu_ai_act_promptinject` | Direct injection via user prompt |
| AML.T0053 - LLM Prompt Injection (Indirect) | `atlas_indirectinjection`, `atlas_contentinjection` | Injection via third-party content |

### 1.4 ML Model Access
| ATLAS Technique | Lens Category | Notes |
|---|---|---|
| AML.T0048 - LLM Endpoint Abuse | (detected via anomaly patterns) | Unusual usage patterns |
| AML.T0045 - Exploit Public-Facing Application | (via OWASP coverage) | General web app exploitation |

### 1.5 Execution
| ATLAS Technique | Lens Category | Notes |
|---|---|---|
| AML.T0051 - Direct Prompt Injection | (same as Initial Access) | |
| AML.T0053 - Indirect Prompt Injection | (same as Initial Access) | |

### 1.6 Persistence
| ATLAS Technique | Lens Category | Notes |
|---|---|---|
| (not user-prompt-level) | — | Persistence is server-side |

### 1.7 Defense Evasion
| ATLAS Technique | Lens Category | Notes |
|---|---|---|
| AML.T0047 - Evade ML Model | (via ML ensemble detection of novel patterns) | Novel obfuscation attempts |
| AML.T0054 - LLM Jailbreak | `atlas_llmjailbreak`, `atlas_defenseevasion` | Explicit jailbreak attempts |

### 1.8 Discovery
| ATLAS Technique | Lens Category | Notes |
|---|---|---|
| AML.T0048 - Discover LLM Application | (via prompt extraction patterns) | |
| AML.T0049 - Discover LLM Prompts | (same) | |

### 1.9 Collection
| ATLAS Technique | Lens Category | Notes |
|---|---|---|
| AML.T0036 - Extract Data from ML Model | `atlas_dataextraction` | |
| AML.T0024 - Exfiltration via Cyber Means | (not prompt-level) | |

### 1.10 ML Attack Staging
| ATLAS Technique | Lens Category | Notes |
|---|---|---|
| AML.T0043 - Craft Adversarial Data | (via regex + ML) | |

### 1.11 Impact
| ATLAS Technique | Lens Category | Notes |
|---|---|---|
| AML.T0034 - Denial of ML Service | `atlas_denialofservice`, `atlas_resourceexhaustion`, `atlas_endpointdenial` | |
| AML.T0040 - Erode ML Model Integrity | (partial - via training data extraction attempts) | |
| AML.T0042 - External Harms | `harassment`, `violence`, `weapons`, `illegal`, `self_harm` | |
| AML.T0055 - LLM-enhanced Software Attack | (not prompt-level) | Code generation risks |

### 1.12 MITRE ATLAS Coverage Summary

| Status | Count | Techniques |
|---|---|---|
| **Fully covered** | 15 | atlas_promptextraction, atlas_configexfiltration, atlas_promptinjection, atlas_indirectinjection, atlas_contentinjection, atlas_dataextraction, atlas_llmjailbreak, atlas_defenseevasion, atlas_denialofservice, atlas_resourceexhaustion, atlas_endpointdenial, atlas_credentialforgery, atlas_mfabypass, atlas_pluginexploitation, atlas_vectordbpoisoning |
| **Partially covered** | 3 | atlas_elevationabuse (partial - low coverage), atlas_inhibitrecovery (partial), atlas_promptextraction (some variants) |
| **Not covered** | 8 | Reconnaissance, ML model access, persistence, command-and-control, exfiltration, ML attack staging, etc. (mostly server-side/offline) |

## 2. OWASP LLM Top 10 Coverage

OWASP LLM Top 10 (https://owasp.org/www-project-top-10-for-large-language-model-applications/):

| Risk | Lens Category | Status |
|---|---|---|
| **LLM01: Prompt Injection** | `owasp_prompt_injection`, `atlas_promptinjection`, `eu_ai_act_promptinject`, `prompt_injection_ml` | ✅ **Fully covered** (regex + ML) |
| **LLM02: Insecure Output Handling** | `owasp_insecure_output` | ✅ **Covered** (pattern detection) |
| **LLM03: Training Data Poisoning** | (not prompt-level) | ⚠️ **Partial** - via training data extraction patterns |
| **LLM04: Model DoS** | `owasp_model_dos`, `atlas_denialofservice`, `atlas_resourceexhaustion` | ✅ **Covered** |
| **LLM05: Supply Chain Vulnerabilities** | (not prompt-level) | ❌ **Not covered** (requires model file analysis) |
| **LLM06: Sensitive Information Disclosure** | All `pii_*` and `secret_*` categories | ✅ **Fully covered** (12 PII types, 16 secret types) |
| **LLM07: Insecure Plugin Design** | `owasp_insecure_plugin` | ✅ **Covered** (basic patterns) |
| **LLM08: Excessive Agency** | `owasp_excessive_agency` | ✅ **Covered** (pattern detection) |
| **LLM09: Overreliance** | (user behavior, not prompt-level) | ❌ **Not covered** (out of scope) |
| **LLM10: Model Theft** | (not prompt-level) | ❌ **Not covered** (server-side concern) |

## 3. EU AI Act Coverage

The EU AI Act (effective 2025) classifies AI risks. AegisGate Lens
maps to these compliance categories:

| EU AI Act Category | Lens Category | Risk Level |
|---|---|---|
| **Article 15 - Accuracy, Robustness, Cybersecurity** | All prompt injection | High |
| **Subliminal manipulation (Art 5)** | `eu_ai_act_subliminal` | Prohibited |
| **Manipulation of vulnerabilities (Art 5)** | `eu_ai_act_manipulation` | Prohibited |
| **Biometric identification (Art 5)** | (not user prompt) | Prohibited |
| **Prompt injection (Art 15)** | `eu_ai_act_promptinject` | High |
| **Data poisoning (Art 15)** | `eu_ai_act_datapoison` | High |
| **Adversarial example (Art 15)** | `eu_ai_act_adversarial` | High |

## 4. Coverage Gaps (Honest Assessment)

### 4.1 What AegisGate Lens Detects Well

- **PII** (email, phone, SSN, credit card, bank account, DOB, driver's license, health, IP)
- **Secrets** (API keys, tokens, passwords, private keys, JWT, OAuth)
- **Common prompt injection patterns** (via 18 regex patterns + ML)
- **Obfuscated attacks** (via ML ensemble with obfuscation training)
- **Multilingual attacks** (English, German, French, Spanish, Russian, Chinese, etc.)
- **Toxicity / harmful content** (harassment, violence, weapons, self-harm, illegal)

### 4.2 What AegisGate Lens Does NOT Detect

- **Server-side attacks** (model theft, training data extraction from model weights)
- **Out-of-band attacks** (poisoned training data, supply chain)
- **User behavior attacks** (overreliance, prompt leaking across sessions)
- **Adversarial images/audio** (we only process text)
- **Code execution risks** (LLM-generated malware, insecure code)
- **Subtle bias/discrimination** (requires semantic understanding beyond TF-IDF)
- **Long-context attacks** (attacks that require understanding conversation history)

### 4.3 Where the ML Ensemble Helps vs Where It Doesn't

| Attack Type | Regex | ML Ensemble |
|---|---|---|
| Known patterns (e.g., "ignore previous instructions") | ✅ Catches | ✅ Catches |
| Obfuscated ("1gn0r3 pr3v10us 1n5truct10n5") | ❌ Misses | ✅ Catches |
| Long-form (paragraph + attack) | ❌ Misses | ⚠️ Sometimes catches |
| Multilingual (German, French, etc.) | ⚠️ Some | ✅ Catches |
| Novel (zero-day patterns) | ❌ Misses | ⚠️ Catches if similar to training |
| Sophisticated (multi-turn) | ❌ Misses | ❌ Misses (single-prompt model) |

## 5. Use Cases for This Mapping

This mapping is useful for:

1. **Compliance reporting** - "Which OWASP/ATLAS risks does our LLM
   application have coverage for?"
2. **Threat modeling** - "What attacks should we worry about?"
3. **Sales conversations** - "Are you NIST/OWASP/ATLAS compliant?"
4. **Internal review** - "Where are our blind spots?"
5. **Roadmap planning** - "What should we add next?"

## 6. Roadmap (Future Coverage)

Based on the gap analysis, the v0.2 roadmap includes:

| Gap | Priority | Approach |
|---|---|---|
| Long-context / multi-turn attacks | High | DistilBERT tier (in plan) |
| Code execution risks | Medium | Add `code_injection` patterns |
| Subtle bias/discrimination | Medium | Larger transformer (v0.3) |
| Out-of-band attacks | Low | Out of scope for prompt-side detection |

## 7. References

- **MITRE ATLAS**: https://atlas.mitre.org/
- **OWASP LLM Top 10**: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- **EU AI Act**: https://artificialintelligenceact.eu/
- **NIST AI Risk Management Framework**: https://www.nist.gov/itl/ai-risk-management-framework

## 8. Updates

| Date | Author | Change |
|---|---|---|
| 2026-06-21 | AegisGate | Initial mapping |

---

**For questions or updates to this mapping**, see
`plans/LENS-MITRE-ATLAS-OWASP-MAPPING.md`.
