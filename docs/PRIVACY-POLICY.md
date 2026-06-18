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
