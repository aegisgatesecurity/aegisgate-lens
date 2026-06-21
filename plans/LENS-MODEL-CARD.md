# AegisGate Lens - Model Card

**Model version**: v0.1.0 (5-way ensemble, threshold 0.85)
**Last updated**: 2026-06-21
**License**: Apache 2.0

## 1. Model Details

### 1.1 Overview

AegisGate Lens is a Chrome extension that detects prompt injection
attacks and sensitive data in user prompts before they're sent to
AI providers. The extension uses a two-stage detection system:

1. **Regex stage**: 149 hand-curated patterns covering 65 categories
   (PII, secrets, MITRE ATLAS techniques, OWASP LLM Top 10 risks,
   EU AI Act compliance categories).
2. **ML ensemble stage**: A 5-way ensemble combining 1 Logistic
   Regression model and 4 Multi-Layer Perceptrons (MLPs), all trained
   on the same TF-IDF feature space.

### 1.2 Architecture

```
User Input Text
       │
       ▼
┌─────────────────────────────────────────────┐
│ Stage 1: Regex (always runs)               │
│  - 149 patterns, 65 categories               │
│  - <1ms latency, zero dependencies          │
│  - Catches: known PII/secrets, common       │
│    attack phrases                            │
└──────────────┬──────────────────────────────┘
               │ only if regex finds nothing
               ▼
┌─────────────────────────────────────────────┐
│ Stage 2: ML Ensemble (lazy loaded)          │
│  - 5 models: LR + 4× MLP small              │
│  - 5K-30K features per model                  │
│  - 64-32 hidden layers (MLPs)                │
│  - INT8 quantized for bundle size            │
│  - 0.6ms latency (after load)                │
│  - Total bundle: 8.35MB                      │
│  - ZERO network calls at inference           │
└─────────────────────────────────────────────┘
       │
       ▼
  Banner shown if score >= 0.85
  (threshold tunable per deployment)
```

### 1.3 Model Lineage

- **v0.1 (current)**: 5-way ensemble, 8.35MB bundle, 18/20 browser test
- Previous versions: see `ml-artifacts/` for full history

### 1.4 Owners

- **AegisGate Security, LLC**
- Contact: https://aegisgatesecurity.io/lens
- Privacy: see `legal/AEGISGATE-LENS-LEGAL-DEVELOPER-CONSTRAINTS.md`

## 2. Intended Use

### 2.1 Primary Use Cases

AegisGate Lens is designed for:

- **End users** browsing AI provider sites (ChatGPT, Claude, Gemini,
  etc.) who want a privacy-first warning when they accidentally type
  sensitive data or attempt a prompt injection.
- **Security teams** evaluating prompt injection risk in their
  organization's LLM usage.
- **Compliance officers** documenting LLM security controls for
  regulatory purposes (GDPR, EU AI Act, SOC2).

### 2.2 Out-of-Scope Use Cases

AegisGate Lens is **not** designed for:

- **Server-side attacks**: model theft, training data extraction from
  model weights, supply chain attacks.
- **Out-of-band attacks**: poisoned training data, compromised
  dependencies, malicious fine-tuning.
- **Multi-modal attacks**: image-based jailbreaks, audio injections.
- **Cross-session tracking**: detecting prompt leaking across multiple
  user sessions.
- **Network-level monitoring**: detecting exfiltration at the
  network layer.

If you need these capabilities, see the v0.2+ roadmap.

### 2.3 Users

- **Privacy-conscious individuals**: who use AI assistants for
  personal work and want a warning before sharing sensitive data.
- **SOC analysts**: who want to monitor their organization's LLM usage
  for prompt injection attempts.
- **Researchers**: studying prompt injection patterns and defenses.

## 3. Training Data

### 3.1 Attack Corpus Sources

All training data is from **publicly available, trusted sources**:

| Source | Type | Trust | Examples |
|---|---|---|---|
| JailbreakBench/JBB-Behaviors | Academic benchmark | High | 21K downloads, 106 likes |
| deepset/prompt-injections | Community standard | High | 7.9K downloads, 165 likes |
| JailbreakV-28K/JailBreakV-28k | Academic | High | 3.2K downloads, 67 likes |
| TrustAIRLab/in-the-wild-jailbreak-prompts | Academic | High | 3K downloads |
| Lakera/mosscap_prompt_injection | Industry leader | High | 769 downloads |
| walledai/JailbreakHub | Research | High | 843 downloads |
| nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection | Industry | High | 561 downloads |
| reshabhs/SPML_Chatbot_Prompt_Injection | Research | High | 1K downloads |
| xTRam1/safe-guard-prompt-injection | Community | High | 1.7K downloads |
| HuggingFaceH4/no_robots | Curated | High | Human-written prompts |
| OpenAssistant/oasst1 | Human conversations | High | Real conversations |

### 3.2 Synthetic Data

For diversity and target-pattern coverage, we used local LLM generation:

- **qwen3-coder:480b-cloud** (Alibaba) — for benign prompt variation
  and standard attack patterns. Code-focused model, fewer safety
  restrictions.
- **dolphin-mixtral** (Eric Hartford, Apache 2.0) — for uncensored
  attack generation including DAN personas, role-play scenarios,
  and developer-mode prompts.

### 3.3 Obfuscation Techniques

9 obfuscation techniques applied to expand training data:
1. Leetspeak (e.g., "1gn0r3" for "ignore")
2. Zero-width characters
3. Base64 encoding
4. ROT13
5. Case variation
6. Whitespace injection
7. Unicode homoglyphs
8. Synonym substitution
9. Template wrappers

### 3.4 Data Volumes

- v0.1 corpus: ~53,000 labeled examples
- Attack examples: ~45,000 (with 5x obfuscation multiplier)
- Benign examples: ~7,500 (WildChat) + ~1,000 generated
- Hard negatives: ~800 (AegisGate Platform test cases)
- Targeted fixes: ~450 (for known failure cases)

### 3.5 Data Preprocessing

- Lowercased
- Tokenized: word unigrams + bigrams, character 3-5 grams
- L2 normalized TF-IDF
- Deduplicated by text content
- 80/10/10 train/val/test split, stratified by label

## 4. Metrics

### 4.1 Offline Test Set Metrics

Tested on 6,500 WildChat normal + 45,883 attack examples:

| Model | TPR @ FPR≤0.5% | FPR @ default | F1 |
|---|---|---|---|
| Regex only | ~28% | 1.98% | ~40% |
| LR (v6) | 88.70% | 6.21% (default 0.5) | 93.98% |
| MLP small (v6) | ~80% | ~9% (default 0.5) | ~88% |
| **5-way ensemble (v7)** | **~95%** | **0.49%** (threshold 0.85) | **~99%** |

**5-way ensemble at threshold 0.85:**
- **TPR: 90-99%** (varies by test set composition)
- **FPR: 0.22-0.49%** (within target)
- **F1: 93-99%**
- **Latency: 0.6ms per prediction**
- **Bundle: 8.35MB**

### 4.2 Real-World Browser Test

Tested on real ChatGPT, Claude, Gemini, Copilot, and Duck.ai:

| Metric | Value | Notes |
|---|---|---|
| Test prompts | 20 hand-curated | 10 attacks, 10 benign |
| Accuracy | 90% (18/20) | 2 errors |
| TPR | 90% (9/10 attacks) | 1 FN: "developer mode" prompt |
| FPR | 10% (1/10 benign) | 1 FP: "cover letter" prompt |
| Latency | 0.6-5.5ms | Per detection |

### 4.3 Known Failure Modes

**False Negatives (attacks missed):**
- Long-form role-play attacks (e.g., "From now on, you will act as
  ChatGPT in developer mode")
- Multi-turn attacks that require conversation context
- Novel obfuscation techniques not in training data

**False Positives (benign flagged):**
- German/European language benign prompts containing attack-like
  keywords (e.g., "Passwort" / password)
- English prompts with "write a letter/resume" pattern

**Mitigation:** The dismiss banner feature allows users to suppress
false positives for 24 hours. This is the right user-facing solution
for the residual ~0.5% FPR.

### 4.4 Adversarial Robustness

AegisGate Lens has been tested against:
- 9 obfuscation techniques (leetspeak, base64, ROT13, etc.)
- Multilingual attacks (8 languages)
- Direct prompt injection
- Indirect prompt injection (in documents, tool outputs)
- DAN/persona jailbreaks
- Developer mode prompts
- Long-form academic framing attacks

**Not yet tested against:**
- Adversarial suffixes (GCG-style)
- Multi-modal attacks
- Real-time adaptive attacks
- Cross-session attacks

## 5. Ethical Considerations

### 5.1 Privacy

- **No prompt content is ever sent to a server** - all detection
  happens locally in the browser
- **Bundle is vendored** - no runtime model downloads
- **Telemetry is opt-in** - by default, no data leaves the browser
- **Domain hashing** - we can count detections by domain but cannot
  identify the domain
- **No user identification** - no cookies, no tracking, no fingerprinting

### 5.2 Bias

- Training data is predominantly English, with some European
  language coverage
- German/multilingual benign text may have higher FPR (mitigated
  by targeted training data)
- The model has not been audited for demographic bias (out of scope
  for prompt-level security)

### 5.3 Dual Use

This model is designed for **defensive** purposes (warning users
about prompt injection). It could potentially be used to:
- Test the robustness of other LLM systems
- Train adversarial examples against other defenses
- Develop new jailbreak techniques

We explicitly support the first two uses (responsible red-teaming)
but do not support using this model to develop more sophisticated
attacks against users without their knowledge.

### 5.4 Limitations

- **English-centric**: Multilingual performance is lower
- **Prompt-level only**: Cannot detect server-side attacks
- **Single-prompt**: Cannot reason about multi-turn context
- **Conservative on novel attacks**: May miss zero-day patterns
- **5-way ensemble bias**: All models share similar architecture
  limitations (TF-IDF + linear/MLP)

## 6. Caveats and Recommendations

### 6.1 Known Limitations

1. **TF-IDF + LR/MLP has limited semantic understanding**. The model
   learns surface patterns, not deep meaning. It cannot understand
   that "Can you help me write a cover letter?" is benign in a way
   that a human can.

2. **5-way ensemble is homogeneous** - all 5 models use the same
   feature space (TF-IDF) and similar architectures. They agree on
   most cases, which limits the ensemble's diversity gain.

3. **Long-context attacks are not well-handled** - the model sees
   one prompt at a time, not the conversation history.

4. **No online learning** - the model is fixed at training time and
   cannot adapt to new attack patterns.

5. **Real-world performance may differ from offline metrics** - the
   browser test (90%) is on 20 hand-curated prompts. Production
   performance across millions of users is unknown.

### 6.2 Recommendations for Deployment

1. **Set the threshold conservatively** (0.85-0.90) to keep FPR low.
   Users will tolerate a few missed attacks but not many false alarms.
2. **Enable the dismiss banner** - users will encounter false
   positives, especially in German/European languages. Give them
   a way to suppress them.
3. **Monitor real-world metrics** - the offline metrics are not
   representative of production. Collect anonymized telemetry from
   real dismissals to improve the model.
4. **Plan for model updates** - new attack patterns emerge weekly.
   Have a process for shipping model improvements safely.
5. **Combine with other defenses** - AegisGate Lens is one layer of
   defense. Combine with server-side validation, output filtering,
   and usage policies.

## 7. How to Use

### 7.1 Load the Extension

```bash
1. Open Chrome and navigate to chrome://extensions
2. Enable "Developer mode" (top right)
3. Click "Load unpacked" and select the lens_ml_build/ directory
4. The extension is now active on supported AI provider sites
```

### 7.2 Supported Sites

- chat.openai.com
- chatgpt.com
- claude.ai
- gemini.google.com
- copilot.microsoft.com
- duck.ai
- duckduckgo.com

### 7.3 Bundle Structure

```
lens_ml_build/
├── manifest.json (Chrome extension manifest v3)
├── content.js (content script - injects on AI provider sites)
├── service-worker.js (background worker)
├── detectors/ (regex pattern definitions)
├── util/
│   ├── lens-ml.js (5-way ensemble inference, 440 lines)
│   └── logger.js
├── ml_model/ (8.35MB ML bundle, lazy loaded)
│   ├── ensemble_config.json
│   ├── lr_*.json (LR artifacts)
│   └── mlp_*_*.json (4× MLP INT8 weights)
├── api/ (telemetry client, opt-in)
├── privacy/ (data sanitization)
└── icons/ (extension icons)
```

### 7.4 Customizing the Threshold

The detection threshold is in `ml_model/ensemble_config.json`:
```json
{
  "n_models": 5,
  "model_names": ["lr", "mlp_a", "mlp_b", "mlp_c", "mlp_d"],
  "threshold": 0.85,
  "strategy": "average",
  "version": "1.0.0"
}
```

- **Lower threshold (e.g., 0.70)**: catches more attacks but flags
  more benign prompts as suspicious
- **Higher threshold (e.g., 0.90)**: misses more attacks but fewer
  false positives
- **Default 0.85**: balances TPR and FPR based on offline metrics

## 8. Updates and Maintenance

### 8.1 Update Frequency

- Major version bumps: every 6 months (with model retraining)
- Minor version bumps: monthly (with new attack pattern coverage)
- Patch versions: as needed (bug fixes)

### 8.2 Update Process

1. New attack patterns identified (from research, CVE reports, or
   user reports)
2. Update training corpus with new attacks + hard negatives
3. Retrain 5-way ensemble
4. Validate on offline test set + browser test
5. Ship via Chrome Web Store update

### 8.3 Reporting Issues

- Security issues: security@aegisgatesecurity.io
- False positives: dismiss in the UI (logged for analysis if
  telemetry enabled)
- False negatives: report via the popup menu

## 9. Glossary

- **TPR** (True Positive Rate): % of attacks correctly detected
- **FPR** (False Positive Rate): % of benign prompts incorrectly flagged
- **F1**: Harmonic mean of precision and recall
- **PII**: Personally Identifiable Information
- **MITRE ATLAS**: Adversarial Threat Landscape for AI Systems
- **OWASP LLM Top 10**: Top 10 risks for LLM applications
- **DAN**: "Do Anything Now" - a common jailbreak persona
- **TF-IDF**: Term Frequency-Inverse Document Frequency
- **INT8**: 8-bit integer quantization (4x smaller than FP32)

## 10. References

- Mitchell, M., et al. (2019). "Model Cards for Model Reporting."
  Proceedings of FAT*.
- OWASP LLM Top 10: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- MITRE ATLAS: https://atlas.mitre.org/
- EU AI Act: https://artificialintelligenceact.eu/
- Chrome Extension Documentation: https://developer.chrome.com/docs/extensions/

---

**For the most up-to-date version of this model card, see:**
`plans/LENS-MODEL-CARD.md`

**License:** Apache 2.0
**Contact:** https://aegisgatesecurity.io/lens
