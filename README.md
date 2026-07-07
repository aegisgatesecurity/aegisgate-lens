# AegisGate Lens

> Privacy-first browser extension that detects prompt injection, PII,
> secrets, and toxicity **before they reach AI tools**. No prompt content
> ever leaves your browser. Apache 2.0.

AegisGate Lens protects individuals and small teams (the 95% of AI users
without enterprise protection) from accidentally exposing sensitive data
to consumer AI tools and from being prompt-injected via pasted content.

It is the top of the funnel for the [AegisGate Security Platform][platform];
the AegisGate Gateway is the bottom. Both products share threat intel.
The Lens generates the data that makes the Gateway smarter.

[platform]: https://aegisgatesecurity.io

## Status

**v0.1.0-beta** — initial design complete, scaffold in progress, no
shippable code yet. See [`docs/ARCHITECTURE-v0.1.0-BETA.md`](docs/ARCHITECTURE-v0.1.0-BETA.md)
for the binding architectural specification.

## What it does

The Lens reads the content of the prompt textarea on 10 supported AI
chatbots and evaluates it through 6 detection facets:

1. **PII** — SSN, email, phone, credit card (Luhn-validated), etc.
2. **Secrets** — API keys, RSA private keys, OAuth tokens.
3. **Source / XSS** — accidental source-code leaks, XSS payloads.
4. **Compliance** — OWASP LLM Top 10, MITRE ATLAS, EU AI Act, etc.
5. **Toxicity** — regex first, then a lazy-loaded ML model.
a. **Prompt injection** — regex patterns for common injection attacks.
   a long-context model (Longformer-base) loaded on demand for prompts
   over 8K characters.

If any facet detects a problem, the Lens shows a warning banner with
three options: **send anyway**, **redact**, or **cancel**. The user
chooses.

## Privacy posture

- **No prompt content** ever leaves the browser. Not for debugging, not
  for support. The Lens is a privacy product; the default is OFF for
  telemetry.
- **No URLs** ever leave the browser. The page domain is hashed locally
  (SHA-256, truncated to 16 hex chars) before any opt-in event.
- **No page content** is read, only the prompt textarea.
- **No user ID, session ID, or cookie** is collected.
- **TLS 1.2+** for all backend traffic. HTTP is rejected.
- **Opt-in** for telemetry; **opt-out is sticky**.

Full privacy policy: [`docs/PRIVACY-POLICY.md`](docs/PRIVACY-POLICY.md).

## License

Apache 2.0. See [LICENSE](LICENSE).

Copyright 2026 AegisGate Security, LLC.

## Contributing

See [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) and
[`docs/NO-EXTERNAL-DEPS.md`](docs/NO-EXTERNAL-DEPS.md) before opening
a pull request.

## Repository layout

```
docs/        — architecture, threat model, privacy policy, model card
src/         — extension source (background.js, content.js, detectors/, etc.)
tools/build/ — Go build tool (stdlib only)
test/        — unit tests (node:test) and E2E tests (Go, chromedp)
```

## Contact

- Issues: GitHub issue tracker
- Security: security@aegisgatesecurity.io
- Privacy: privacy@aegisgatesecurity.io
