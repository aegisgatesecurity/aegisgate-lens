# AegisGate Lens - 30-Day Plan (2026-06-21)

**Status**: Approved by user. Zero budget. Self-attestation only.

**Strategic Context**: Lens is the funnel to AegisGate Platform sales. Solo founder, blue teamer (SOC expert), non-developer by trade. Apache 2.0 license. 7 AI providers supported. User wants to "compete with the big boys and win handily" via privacy + speed + open source moat.

---

## Tagline Adjustments (APPROVED 2026-06-21)

- **AegisGate Security Platform**: "Secure Every AI Interaction" (unchanged)
- **AegisGate Lens**: "Real-time prompt injection detection for AI chat platforms" (NEW)

---

## Current State (2026-06-21)

### What Works
- v0.2.1 with v8 models: TPR 69%, FPR 0% on original test set
- 3-tier cascade wired in content.js (Tier 1 regex, Tier 2 TF-IDF, Tier 3 transformer)
- Transformer (MiniLM-L12-H384, NOT L6) trained: validation TPR 99.11%, FPR 3.92%, F1 99.15%
- INT8 quantized: 66.8MB ONNX, 76.5MB signed bundle
- Ed25519 bundle signing working
- Dismiss banner with 24h local storage
- Multilingual training data (889 examples, 8 languages)
- CI/CD GitHub Actions workflow
- 187-prompt enterprise test harness

### What's Pending
- Bundle ONNX Runtime Web for production Tier 3 (~3-5MB)
- Test real AI provider pages
- Improve TPR to 95%+ (hard limit without multilingual Tier 3)
- Chrome Web Store launch
- Telemetry infrastructure
- Security hardening
- UX overhaul to match website

### Known Limitations
- CJK/Cyrillic: 0% TPR (TF-IDF limitation, scores 0.164 for all CJK attacks)
- TPR 83% with simulated Tier 3 (likely 88-92% with real Tier 3)
- 4 real FPs in current test: "write a short story about a cat", "Explain the French Revolution", "How do I update my direct deposit information", "Wie backe ich einen Kuchen?"
- 95%+ TPR not achievable without multilingual Tier 3 (1-2 week project)

---

## Day 1: UX Overhaul (APPROVED, STARTING TODAY)

### Goals
- Update welcome.html with website color scheme + logo
- Update banner CSS to match dark theme
- Use Chrome Web Store icons in banner
- Use full logo on welcome page

### Color Scheme (from /home/chaos/Desktop/AegisGate/websites/aegisgate-site/public/css/main.css)
- Background: `#0a0c10` (deep midnight black-blue)
- Primary: `#38bdf8` (sophisticated cyan)
- Success: `#10b981` (emerald green)
- Critical: `#f43f5e` (rose red)
- Text primary: `#f8fafc` (white-grey)
- Text secondary: `#94a3b8` (muted slate)
- Glass: `rgba(17, 20, 29, 0.7)` (semi-transparent backdrop)
- Border: `rgba(51, 65, 85, 0.5)` (transparent borders)

### Banner Color Mapping
- Critical warning (PII, prompt injection): `#f43f5e` (rose)
- High warning (prompt injection): `#f59e0b` (amber)
- Medium warning: `#38bdf8` (cyan)
- Safe/allowed: `#10b981` (emerald)

### Logo Assets
- Website logo: `/home/chaos/Desktop/AegisGate/websites/aegisgate-site/public/logo.png` (932x1092)
- Extension icons: `/home/chaos/Desktop/AegisGate/lens-repo-bootstrap/lens-final-dist/icons/icon-{16,32,48,128}.png`

---

## Days 2-5: Telemetry Phase 1 (APPROVED)

### Architecture
```
Lens Extension → TLS 1.3 + Certificate Pinning
   ↓
Telemetry Endpoint (aegisgatesecurity.io)
   - WAF (Cloudflare)
   - Rate limiting (100 events/user/day)
   - Input validation (schema)
   - Separate infrastructure
   ↓
Event Database (PostgreSQL, encrypted at rest)
   - Anonymized events only
   - Retention: 90 days
   ↓
Automated Analysis (daily cron)
   - Find new attack patterns
   - Identify false positives
   - Detect model drift
   ↓
Model Retraining (weekly)
   - New data from telemetry
   - Human review
   - Validation: must beat current
   - Canary 10% → auto-rollback
   ↓
New Bundle (signed, tested)
   ↓
Lens Extension (auto-update)
```

### What We Send (Safe Fields Only)
```json
{
  "event_type": "detection",
  "category": "prompt_injection",
  "severity": "high",
  "action": "dismissed",
  "model_version": "0.2.1",
  "tier": "tier3_transformer",
  "language": "en",
  "timestamp": "2026-06-21T19:00:00Z",
  "anonymous_token": "rotated_monthly_uuid"
}
```

### What We NEVER Send
- ❌ Prompt text (PII risk)
- ❌ Response text (PII risk)
- ❌ URLs (session token risk)
- ❌ User identifiers
- ❌ Cookies, localStorage values

### Opt-In Strategy
- OFF by default
- One-click opt-in after first dismiss FP
- Clear privacy guarantees upfront
- "Your contributions have improved detection by X%"
- Easy opt-out

### Cost Estimate
- $50-200/month (Vercel + PostgreSQL + Cloudflare)

---

## Week 1: Security Foundation (ZERO BUDGET, INTERNAL)

### Day 6-7: Threat Model (STRIDE-based)
- Output: `plans/LENS-THREAT-MODEL.md` (update existing 20938-byte file)
- Documents what we protect against and how
- Required for any enterprise sale

### Day 8: Vulnerability Disclosure Policy
- `security@aegisgatesecurity.io` email
- 90-day responsible disclosure
- Published at `/.well-known/security.txt`
- Output: `SECURITY.md`

### Day 9: Dependency Manifest
- SHA-256 hashes of every file
- Provenance tracking
- Output: `ml-artifacts/MANIFEST.json`

### Day 10: CSP Hardening
- No inline scripts in content.js
- No eval()
- Strict CSP header in manifest.json
- Output: Updated `src/manifest.json`

---

## Week 2: Security Testing (INTERNAL)

### Day 11-12: Penetration Testing
- Red team exercise against Lens
- Test: malicious prompts, bundle tampering, extension hijacking
- Output: `plans/LENS-PEN-TEST-REPORT.md`

### Day 13-14: Adversarial Robustness Testing
- Test against GCG, AutoPrompt, PAIR
- Measure: how easy is it to bypass Lens?
- Output: `plans/LENS-ADVERSARIAL-ROBUSTNESS.md`

### Day 15: Bug Bounty Setup
- HackerOne or Bugcrowd
- $500-5K bounties for critical vulnerabilities
- Output: Public bug bounty page

---

## Week 3: Process (ZERO BUDGET)

### Day 16-17: Secure SDLC
- Threat model per PR (lightweight)
- Security review checklist
- Output: `SECURITY-CHECKLIST.md`

### Day 18-19: Model Provenance Verification
- Verify model file hashes against HuggingFace
- Pin specific versions
- Document training data sources
- Output: `MODEL-PROVENANCE.md`

### Day 20: Privacy Policy + Terms of Service
- GDPR/CCPA compliant
- Clear data handling practices
- Output: `PRIVACY.md`, `TERMS.md`

---

## Week 4+: Return to Technical Work

### Tier 3 Activation in Production
- Bundle ONNX Runtime Web (~3-5MB)
- Wire into cascade in content.js
- Test in real browser

### TPR Improvement
- Real Tier 3 (not simulated): likely 88-92% TPR
- Multilingual Tier 3: potentially 95%+ (1-2 week project)
- Tune cascade uncertainty range

### Ship v0.2.1
- Lock-in metrics (no more constant changes)
- Chrome Web Store launch
- Community building (GitHub, Twitter, blog)

---

## Competitive Landscape (2026-06-21)

| Product | TPR | FPR | Latency | Local? | Open Source? |
|---|---|---|---|---|---|
| Lakera Guard | 92-95% | 2-3% | 50-200ms | ❌ Cloud | ❌ Closed |
| Microsoft Prompt Shields | 85-90% | 3-5% | 50-100ms | ❌ Cloud | ❌ Closed |
| Cisco AI Defense | 85-90% | 3-5% | 50-150ms | ❌ Cloud | ❌ Closed |
| **AegisGate Lens (v0.2.1)** | **83%** | **5.71%** | **5ms** | ✅ Local | ✅ Apache 2.0 |

**Our advantages**: 10-40x faster, 100% local, open source
**Our gap**: 7-12pp behind on TPR, CJK unsupported

---

## Key Files & Paths

### Source Code
- Extension: `/home/chaos/Desktop/AegisGate/lens-repo-bootstrap/src/`
- ML artifacts: `/home/chaos/Desktop/AegisGate/lens-repo-bootstrap/ml-artifacts/`
- Test harness: `/home/chaos/Desktop/AegisGate/lens-repo-bootstrap/harness/`
- Build output: `/home/chaos/Desktop/AegisGate/lens-repo-bootstrap/lens_ml_build/`

### Website Assets
- Website: `/home/chaos/Desktop/AegisGate/websites/aegisgate-site/public/`
- CSS: `/home/chaos/Desktop/AegisGate/websites/aegisgate-site/public/css/main.css`
- Logo: `/home/chaos/Desktop/AegisGate/websites/aegisgate-site/public/logo.png`

### Plans
- All Lens plans: `/home/chaos/Desktop/AegisGate/plans/`
- Threat model: `AEGISGATE-LENS-THREAT-MODEL.md` (exists, 20938 bytes)
- Architecture: `AEGISGATE-LENS-ARCHITECTURE-v1.md` (exists, 24322 bytes)
- Roadmap: `AEGISGATE-LENS-ROADMAP.md` (exists, 22081 bytes)

### Keys
- Ed25519 signing: `/home/chaos/Desktop/AegisGate/lens-repo-bootstrap/keys/lens-signing-private.pem`
- Public key: `68acee91c9b51258016433251bb2113b0d760b28cf1df92e2aff818fc23bd3e7`

---

## Lessons Learned (2026-06-21)

1. **"L6" was actually L12** - MiniLM-L6-H384-uncased doesn't exist on HuggingFace. The trained model is `microsoft/MiniLM-L12-H384-uncased` (12 layers, 384 hidden, 30K vocab).

2. **TfidfVectorizer 'analyzer=word'** does subword splitting that pollutes vocabulary with unprefixed features. Fix: use callable analyzer like `lambda x: x.split()`.

3. **JSON pretty-printing** causes whitespace inside magic bytes - search for magic value not exact opening brace.

4. **ONNX shape inference** fails for transformer models with external data files. Use optimum library for export+quantization.

5. **INT4 quantization** doesn't help when embeddings are stored as Gather not MatMul.

6. **Multilingual Latin training data** WITHOUT enough benign examples regresses FPR. The 11K ollama_benign corpus from v0.1.1 was lost in /tmp/ crash.

7. **Always work in `/home/chaos/Desktop/AegisGate/`** NOT `/tmp/`. Git commit important artifacts.

8. **DataLoader workers** are subprocesses of main training. Killing them kills the whole training.

9. **Tier 2 (TF-IDF + LR)** has limited capacity - multilingual improvement requires transformer.

10. **v0.1.1 0% FPR** was on a different/smaller test set - current 187-prompt test shows real FPs.

11. **The cascade is wired** but Tier 3 needs ONNX Runtime Web bundled to be production-ready.

12. **DataLoader workers**: When training in background, check `ps -ef | grep` to see parent process before killing.

13. **Multilingual v9 LR regressed FPR** from 0% to 8.57% because German "Passwort" examples in training caused FPs on similar benign German prompts.

14. **The "ollama_benign" 11K corpus** that was in v0.1.1 was lost. Without it, all retraining attempts (v9-v13) regressed FPR to 8-12%.

15. **TF-IDF char n-grams** need word boundary markers (`__` separator) to avoid splitting on whitespace.

---

## Resume Prompt

See `AEGISGATE-LENS-30-DAY-PLAN-RESUME-PROMPT.md` for the next-session resume prompt.
