# AegisGate Lens

> Privacy-first browser extension that detects PII, secrets, XSS, and compliance
> violations before they reach AI tools. No prompt content
> ever leaves your browser. Apache 2.0.

AegisGate Lens protects individuals and small teams (the 95% of AI users
without enterprise protection) from accidentally exposing sensitive data
to consumer AI tools.

It is the top of the funnel for the [AegisGate Security Platform][platform];
the AegisGate Gateway is the bottom. Both products share threat intel.
The Lens generates the data that makes the Gateway smarter.

[platform]: https://aegisgatesecurity.io

## Status

**v0.1.0-beta** — production-ready regex detector, ready for Chrome Web Store submission. See [`docs/ARCHITECTURE-v0.1.0-BETA.md`](docs/ARCHITECTURE-v0.1.0-BETA.md)
for the binding architectural specification.

## What it does

The Lens reads the content of the prompt textarea on 10 supported AI
chatbots and evaluates it through 4 detection facets:

1. **PII** — SSN, email, phone, credit card (Luhn-validated), etc.
2. **Secrets** — API keys, RSA private keys, OAuth tokens, etc.
3. **XSS** — accidental source-code leaks, XSS payloads.
4. **Compliance** — OWASP LLM Top 10, MITRE ATLAS, EU AI Act, etc.
