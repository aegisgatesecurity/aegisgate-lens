# Privacy Policy

The published Privacy Policy for AegisGate Lens is hosted at:

**<https://aegisgatesecurity.io/lens/privacy>**

The source of truth for the policy lives in the [AegisGate Platform monorepo](https://github.com/aegisgatesecurity/aegisgate-platform):

- **Working draft:** [`AEGISGATE-LENS-PRIVACY-POLICY-DRAFT.md`](https://github.com/aegisgatesecurity/aegisgate-platform/blob/main/plans/AEGISGATE-LENS-PRIVACY-POLICY-DRAFT.md) (607 lines, awaiting founder legal review as of 2026-06-18).
- **Published version:** the source is extracted from the working draft after founder review and published to the URL above. Once published, this file (`docs/PRIVACY-POLICY.md`) will be a pointer to the published version.

## The 12 non-negotiables

The Privacy Policy commits to 12 non-negotiables. These are the design constraints, not nice-to-haves. Any violation pauses the build.

1. The Lens never sends prompt content to any server. Period.
2. The Lens never sends URLs to any server. Period.
3. The Lens never sends page content to any server. Period.
4. The Lens never collects a user ID, session ID, or cookie. Period.
5. The Lens's default is OFF. The user must explicitly opt in to telemetry.
6. The Lens is open source from day one. Apache 2.0.
7. The Lens's privacy policy is published before the Lens ships.
8. The Lens's third-party dependencies are audited. (There are none.)
9. The Lens's data retention is 90 days for events, indefinite for aggregated stats.
10. The Lens's API is rate-limited. 100 events/min per installation, 10K/min server.
11. The Lens's backend is TLS-only. HTTP is rejected. HSTS is enabled.
12. The Lens's threat model is updated whenever the architecture changes.

## ML detection disclosure (v0.3.0)

Starting in v0.3.0, the Lens includes an on-device ML threat detector
(Char CNN-BiLSTM with Attention, 1.58M parameters). This section
discloses how the ML model handles user data:

- **The ML model runs entirely on-device.** No prompt content, no
  ML inference scores, and no model outputs are sent to any server.
- **The model weights are bundled in the extension package** (3.7MB
  float16 JSON). They are not downloaded at runtime and cannot be
  updated remotely.
- **The model processes at most 128 characters** of the prompt
  (lowercase ASCII, truncated). Non-ASCII characters are mapped to
  an UNK token. The processing is a fixed forward pass — no
  learning, no fine-tuning, no gradient computation.
- **The model outputs a single score between 0 and 1** (threat
  probability). This score is used locally to determine whether to
  show the detection banner. The score is never sent to any server
  unless the user explicitly opts in to threat-intel reporting, in
  which case only the detection category (not the score, not the
  prompt text) is included.
- **The model is lazy-loaded.** The 3.7MB weight file is not fetched
  until the first `classify()` call. If the user never types a
  prompt, the model is never loaded.
- **The model is not a content moderator.** It detects adversarial
  prompt injection patterns (instruction override, roleplay injection,
  obfuscated commands). It does not detect political content,
  controversial topics, or the substance of what the user is asking
  the AI to do.
- **The model does not learn from user input.** It is a fixed,
  pre-trained model. There is no feedback loop, no reinforcement
  learning, no online training, no data collection for training
  purposes.

## Reporting privacy concerns

If you believe the Lens has violated any of these commitments, please email `privacy@aegisgatesecurity.io`. We treat privacy bugs as severity Critical and respond within 24 hours. See [`SECURITY.md`](../SECURITY.md) for the full disclosure process.

## Your rights

The full list of rights (GDPR Art. 15-22, CCPA/CPRA, LGPD, PIPEDA, APPI, PIPA) is in the published policy. The summary:

- **Right to access** your data: we have no user IDs, so we cannot look up "your" data. We can look up data by `domain_hash` (the 16-hex SHA-256 prefix of the AI provider's hostname).
- **Right to deletion**: 30-day SLA. See §9 of the published policy.
- **Right to opt out**: see §2.2 of the published policy.
- **Right to data portability**: events are exportable in JSON; aggregated stats are public.
- **Right to object**: opt out at any time; the detection still works locally.
- **Right to restrict processing**: opt out is the same as restrict.
- **Right to lodge a complaint**: with your local data protection authority.

The CCPA "Do Not Sell or Share My Personal Information" link is **not** displayed because we do not sell or share personal information. See §8.2 of the published policy for the analysis.