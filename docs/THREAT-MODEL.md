# Threat Model

The canonical threat model for AegisGate Lens lives in the [AegisGate Platform monorepo](https://github.com/aegisgatesecurity/aegisgate-platform):

**[AEGISGATE-LENS-THREAT-MODEL.md](https://github.com/aegisgatesecurity/aegisgate-platform/blob/main/plans/AEGISGATE-LENS-THREAT-MODEL.md)**

The document is a STRIDE analysis covering three trust boundaries:

1. **The Chrome extension** — the browser-side code, the Web Crypto API, the content script ↔ service worker boundary.
2. **The Go backend** — the HTTP server, the IOC aggregator, the rate limiter, the retention jobs.
3. **The threat-intel database** — the `pkg/ioc.Store`, the existing gossip protocol, the STIX/TAXII export.

The **core privacy boundary** is that **prompt content never leaves the browser**. The full set of 12 non-negotiables is in [`PRIVACY-POLICY.md`](PRIVACY-POLICY.md).

## Information disclosure is the most important risk to monitor

Of the six STRIDE categories, **Information Disclosure** is the highest-priority risk for the Lens. The threat model includes a specific table of threats and mitigations for this category, including:

- A malicious or buggy extension code path that sends prompt content over the wire. Mitigated by: the §1.1 schema validation (server-side `DisallowUnknownFields`), the audit logger's closed set of typed methods, the CI grep checks for `prompt|content|input|textarea` in log lines, and the 12 non-negotiables enforced in CI.
- A man-in-the-middle that tampers with the response. Mitigated by: TLS 1.2+ only, HSTS, the CORS allowlist.
- An insider with access to the IOC store reading the raw events. Mitigated by: the 90-day retention, the 24-hour `send_anyway` purge, the `domain_hash` truncation (the SNI is never stored).

## Residual risk

The threat model includes a summary table comparing the Lens's threat model to the Platform's (Gateway). The summary:

- The Lens has **fewer** attack surfaces than the Platform (no Postgres, no OIDC, no SAML, no MCP).
- The Lens has **more** privacy risk (the user is an individual, not an enterprise; the threat model treats a privacy violation as severity Critical).
- The mitigation cost per threat is **lower** for the Lens (the build is simpler, the CI is one Go job, the deps are zero).

The Platform's threat model (in the same monorepo) covers the Gateway's STRIDE analysis for comparison.

## Update cadence

Per the 12 non-negotiables (and the §10.3 release gate in the Privacy Policy), the threat model is updated whenever the architecture changes and reviewed at least every 90 days. Updates are tracked in the Platform monorepo's git history.
