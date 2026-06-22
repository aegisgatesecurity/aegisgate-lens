# AegisGate Lens - Session Resume Prompt

**Use this prompt to begin your next session. It contains all context needed to continue from where we left off on 2026-06-21.**

---

## Project Context

You are working on **AegisGate Lens**, a Chrome extension that detects prompt injection and sensitive data exposure in AI chat platforms (ChatGPT, Claude, Gemini, Copilot, Duck.ai, DuckDuckGo). The user is a **solo founder, blue teamer (SOC expert), non-developer by trade**. The project is a **passion project with zero budget** that serves as the funnel to AegisGate Security Platform sales.

**Strategic vision**: "Compete with the big boys and win handily" via privacy + speed + open source moat. The Platform keeps the tagline "Secure Every AI Interaction." Lens's new tagline (APPROVED 2026-06-21) is: **"Real-time prompt injection detection for AI chat platforms"**.

**Current production state**: v0.2.1 with v8 models (Tier 2 TF-IDF 5-way). 3-tier cascade wired in content.js. Tier 3 (transformer) trained but not bundled with ONNX Runtime Web yet.

---

## Required Reading (Before Starting)

Read these files in this order:

1. `/home/chaos/Desktop/AegisGate/lens-repo-bootstrap/plans/AEGISGATE-LENS-30-DAY-PLAN.md` (301 lines) — The complete 30-day plan with all decisions, metrics, and timeline.

2. `/home/chaos/Desktop/AegisGate/lens-repo-bootstrap/plans/AEGISGATE-LENS-NEXT-SESSION-PROMPT.md` (597 lines) — Previous session resume prompt with additional context.

3. `/home/chaos/Desktop/AegisGate/lens-repo-bootstrap/plans/AEGISGATE-LENS-V01-TEST-REPORT.md` (278 lines) — v0.1 test report with 10 sections.

4. `/home/chaos/Desktop/AegisGate/lens-repo-bootstrap/plans/AEGISGATE-LENS-MODEL-CARD.md` (420 lines) — Model card for v0.2.1.

5. `/home/chaos/Desktop/AegisGate/lens-repo-bootstrap/plans/AEGISGATE-LENS-DISMISS-BANNER-SPEC.md` (200 lines) — Dismiss banner specification.

6. `/home/chaos/Desktop/AegisGate/lens-repo-bootstrap/plans/AEGISGATE-LENS-MITRE-ATLAS-OWASP-MAPPING.md` (203 lines) — MITRE ATLAS / OWASP LLM Top 10 mapping.

7. `/home/chaos/Desktop/AegisGate/lens-repo-bootstrap/plans/AEGISGATE-LENS-THREAT-MODEL.md` (20938 bytes) — Existing threat model.

---

## Key Metrics (As of 2026-06-21)

| Metric | Value | Notes |
|---|---|---|
| **Tier 2 (TF-IDF 5-way) TPR** | 71% | Enterprise test (187 prompts) |
| **Tier 2 FPR** | 1.43% | |
| **3-tier cascade (simulated Tier 3) TPR** | 83% | Likely 88-92% with real Tier 3 |
| **3-tier cascade FPR** | 5.71% | |
| **Transformer validation TPR** | 99.11% | MiniLM-L12 (NOT L6) |
| **Transformer validation FPR** | 3.92% | |
| **Bundle size** | 8.76MB (Tier 2) + 76.5MB (Tier 3 signed) = ~85MB | Under 100MB Chrome limit |
| **CJK/Cyrillic TPR** | 0% | Hard limit without multilingual Tier 3 |

**4 Real FPs in current test**: "write a short story about a cat" (0.868), "Explain the French Revolution" (0.854), "How do I update my direct deposit information" (0.902), "Wie backe ich einen Kuchen?" (0.858).

**17 FNs include**: 6 CJK attacks (all score 0.164), 11 novel phrasing attacks.

**95%+ TPR is NOT achievable** on current architecture without multilingual Tier 3 (1-2 week project).

---

## Approved 30-Day Plan (Starting 2026-06-21)

### Day 1: UX Overhaul (IN PROGRESS)
- Update `welcome.html` with website color scheme + logo
- Update banner CSS to match dark theme
- Use Chrome Web Store icons in banner
- Use full logo on welcome page

**Color scheme** (from `/home/chaos/Desktop/AegisGate/websites/aegisgate-site/public/css/main.css`):
- Background: `#0a0c10` (deep midnight)
- Primary: `#38bdf8` (sophisticated cyan)
- Success: `#10b981` (emerald)
- Critical: `#f43f5e` (rose)
- Text: `#f8fafc` (white-grey)
- Glass: `rgba(17, 20, 29, 0.7)`
- Font: Inter

**Logo assets**:
- Website logo: `/home/chaos/Desktop/AegisGate/websites/aegisgate-site/public/logo.png` (932x1092)
- Extension icons: `/home/chaos/Desktop/AegisGate/lens-repo-bootstrap/lens-final-dist/icons/icon-{16,32,48,128}.png`

### Days 2-5: Telemetry Phase 1
- Sanitization function (no PII, no prompt text)
- Opt-in UI in settings
- Telemetry endpoint on aegisgatesecurity.io
- TLS 1.3, certificate pinning, rate limiting (100 events/user/day)
- End-to-end CI/CD loop: new data → retrain → canary 10% → auto-rollback

**Safe fields to send**:
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

**NEVER send**: prompt text, response text, URLs, user identifiers, cookies.

### Week 1: Security Foundation (Zero Budget)
- Day 6-7: Threat model (STRIDE-based) → `plans/LENS-THREAT-MODEL.md`
- Day 8: Vulnerability disclosure policy → `SECURITY.md` + `/.well-known/security.txt`
- Day 9: Dependency manifest (SHA-256) → `ml-artifacts/MANIFEST.json`
- Day 10: CSP hardening (no inline scripts, no eval) → updated `src/manifest.json`

### Week 2: Security Testing
- Day 11-12: Internal penetration testing → `plans/LENS-PEN-TEST-REPORT.md`
- Day 13-14: Adversarial robustness testing (GCG, AutoPrompt, PAIR) → `plans/LENS-ADVERSARIAL-ROBUSTNESS.md`
- Day 15: Bug bounty setup (HackerOne or Bugcrowd)

### Week 3: Process
- Day 16-17: Secure SDLC → `SECURITY-CHECKLIST.md`
- Day 18-19: Model provenance verification → `MODEL-PROVENANCE.md`
- Day 20: Privacy policy + Terms of Service → `PRIVACY.md`, `TERMS.md`

### Week 4+: Return to Technical Work
- Bundle ONNX Runtime Web for production Tier 3
- Wire Tier 3 into cascade
- Test real AI provider pages
- Improve TPR to 95%+ (multilingual Tier 3 if needed)
- Ship v0.2.1 with locked metrics
- Chrome Web Store launch

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

### Keys
- Ed25519 signing: `/home/chaos/Desktop/AegisGate/lens-repo-bootstrap/keys/lens-signing-private.pem`
- Public key: `68acee91c9b51258016433251bb2113b0d760b28cf1df92e2aff818fc23bd3e7`

### Test Corpus
- Enterprise test: `/home/chaos/Desktop/AegisGate/lens-repo-bootstrap/harness/test_prompts_enterprise.json` (187 prompts)
- Results: `/home/chaos/Desktop/AegisGate/lens-repo-bootstrap/harness/enterprise_results_v0_2_1.json`

---

## Critical Lessons Learned

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

12. **TF-IDF char n-grams** need word boundary markers (`__` separator) to avoid splitting on whitespace.

13. **CJK attacks all score 0.164** because the model doesn't see non-Latin features.

14. **The 4 real FPs** in current test are all close to 0.85 threshold (0.854-0.902) - they were caught because TF-IDF learned that "write a story", "Explain the Revolution", "update direct deposit", "Wie backe ich" are attack-like.

---

## User Communication Style

The user is:
- **Cybersecurity/SOC expert** (blue teamer) - use security terminology
- **Non-developer by trade** - explain technical concepts in plain English
- **Asks direct questions** - give direct answers
- **Wants honest assessments** - don't sugarcoat metrics or timelines
- **Has zero budget** - all work must be self-attestation
- **Wants to "win handily"** - aim for technical excellence
- **Pragmatic** - accepts trade-offs when explained clearly
- **Detail-oriented** - takes notes, tracks progress
- **Cares about UX** - wants consistent branding with website
- **Privacy-first** - 100% local, no telemetry by default

**Response style**:
- Use markdown formatting
- Tables for metrics comparison
- Code blocks for technical details
- Honest about limitations and trade-offs
- Propose options with clear recommendations
- Don't make promises you can't keep

---

## Immediate Next Step (Day 1)

**Start with the UX overhaul**. The user approved this and it's the first item on the 30-day plan.

**Tasks**:
1. Read `/home/chaos/Desktop/AegisGate/websites/aegisgate-site/public/css/main.css` for color scheme
2. Update `/home/chaos/Desktop/AegisGate/lens-repo-bootstrap/src/welcome.html` with website colors + logo
3. Update banner CSS in `/home/chaos/Desktop/AegisGate/lens-repo-bootstrap/src/content.js` to match
4. Use Chrome Web Store icons in banner, full logo on welcome page
5. Commit changes

**After Day 1**, proceed to Days 2-5 (Telemetry Phase 1).

---

## Questions to Ask the User First

1. "I've read the 30-day plan and the resume prompt. Should I proceed with Day 1 (UX overhaul) as planned, or do you want to discuss anything first?"

2. "Any updates or changes to the strategic decisions (taglines, telemetry, security priorities) since we last spoke?"

3. "Are there any new constraints or requirements I should be aware of?"

---

## Backup: How to Verify State

If anything is unclear, run these commands to verify current state:

```bash
# Check git status
cd /home/chaos/Desktop/AegisGate/lens-repo-bootstrap
git log --oneline | head -10

# Check bundle size
ls -la lens_ml_build/*.bundle

# Check test results
cat harness/enterprise_results_v0_2_1.json | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'TPR: {d[\"overall\"][\"TPR\"]*100:.2f}%, FPR: {d[\"overall\"][\"FPR\"]*100:.2f}%')"

# Check transformer model
ls -la ml-artifacts/models/minilm_l12_tier3/

# Check website color scheme
head -50 /home/chaos/Desktop/AegisGate/websites/aegisgate-site/public/css/main.css
```

---

## End of Resume Prompt

This prompt contains all context needed to continue AegisGate Lens development from 2026-06-21. Read the required files, then proceed with Day 1 (UX overhaul) unless the user provides different direction.
