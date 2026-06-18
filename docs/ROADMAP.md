# Roadmap

The canonical roadmap for AegisGate Lens lives in the [AegisGate Platform monorepo](https://github.com/aegisgatesecurity/aegisgate-platform):

**[AEGISGATE-LENS-ROADMAP.md](https://github.com/aegisgatesecurity/aegisgate-platform/blob/main/plans/AEGISGATE-LENS-ROADMAP.md)**

The roadmap is owned by the Platform monorepo because the phases span both the Lens extension and the Lens backend, and because the closed-loop threat intel requires the Gateway to pick up the Lens's IOCs.

## Quarter-by-quarter summary

| Quarter | Months | Ship | Success metric |
|---------|--------|------|----------------|
| Phase 1: Build | M1–3 | Lens v0.1 to Chrome Web Store + AegisGate Check | Functional + installable |
| Phase 2: Funnel | M4–9 | Lens for Teams + Check launch + Gateway wire-up | 10K installs + first paid |
| Phase 3: Moat | M9–12 | Threat intel marketplace + Check v2 + Cloud preview | 100K installs + first marketplace customer |
| Phase 4: Category | Y2 | Agent Guard + Cloud + reasoning-aware firewall | $1M ARR |

## Phase 1 detail (M1–3): Build

**Month 1:**
- ✅ AegisGate Lens repo created (this repo).
- ✅ Lens Privacy Policy drafted (in Platform monorepo at `plans/AEGISGATE-LENS-PRIVACY-POLICY-DRAFT.md`, 607 lines).
- ✅ Lens backend (`pkg/lensbackend/` in Platform monorepo, 2,830 LOC, 10 unit tests passing, 4 integration tests defined).
- ⏭️ Lens extension skeleton (TypeScript source files in this repo's `src/` directory).
- ⏭️ AegisGate Check landing page.

**Month 2:**
- Sensitive data detector (regex + Luhn for credit cards).
- Prompt injection detector (deferred to v0.2).
- Provider support (ChatGPT only in v0.1).
- Chrome Web Store submission.

**Month 3:**
- Telemetry pipeline end-to-end test in testlab.
- AegisGate Check v1 (the public threat-intel page).
- First 100 installs.

**Success metric for Phase 1:** The extension is installable from the Chrome Web Store, the backend is running, and the closed-loop threat-intel pipeline is end-to-end testable in the testlab.

## Out of v0.1 scope (deferred to v0.2+)

- **Lens for Teams UI** (the $9/seat/mo paid tier) — M4+.
- **Lens for Business bundling** (the $49/seat/mo tier) — M6+.
- **Reasoning-aware AI firewall** — Y2 (research spike in M11).
- **Threat intel marketplace** — M9+.
- **AegisGate Cloud managed SOC** — Y2.
- **Additional AI providers** (Claude, Gemini, Copilot) — v0.2; ChatGPT is the only provider in v0.1.
- **ML classifier** — v0.2; v0.1 is regex-only.
- **Firefox support** — v0.3; v0.1 is Chrome-only.

## Risks (top 3)

1. **Chrome Web Store rejection.** Mitigation: the Privacy Policy is published before submission; the no-deps constraint is enforced in CI; the manifest is reviewed by the founder before submission.
2. **A privacy violation discovered post-launch.** Mitigation: the §10 release gate in the Privacy Policy includes a "if a privacy violation is discovered, pull from Chrome Web Store" clause; the 12 non-negotiables are enforced in CI.
3. **Adoption is too low to gather meaningful telemetry.** Mitigation: the closed-loop threat intel is the strategic moat; even at 1K installs, the Lens can provide useful signal to the Gateway.
