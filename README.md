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
5. **Toxicity** — regex patterns for common toxic language.
