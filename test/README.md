# test/

This directory will hold test case files (JSON) for the AegisGate Lens detector.

**Status: empty in v0.1-pre-build. Populated in Step D of the build sequence.**

The test harness is a Go program in the Platform monorepo at `tools/test-extension/`. It:

1. Reads the JSON test cases from this directory.
2. Builds the extension.
3. Launches headless Chromium (via the Chrome DevTools Protocol, no third-party deps).
4. Loads the extension and the test cases.
5. Drives the test cases through the extension's detection logic.
6. Asserts the expected outputs.
7. Writes a JSON report.

The test cases are organized by detector category:

```
test/
├── pii_email.json
├── pii_phone.json
├── pii_ssn.json
├── pii_credit_card.json
├── api_key_aws.json
├── source_code.json
└── false_positives.json
```

Each file is a JSON array of `{input, expected_match, expected_category, expected_severity}` records. The `input` is the synthetic prompt text (redacted, never real PII), and the test harness checks that the detector's output matches `expected_*`.

**No real PII in the test cases.** All test inputs use synthetic data: `user@example.com`, `555-01-0123`, `4111-1111-1111-1111` (the canonical Stripe test card), `AKIAIOSFODNN7EXAMPLE` (the AWS documentation example key), etc. See the [Privacy Policy](../docs/PRIVACY-POLICY.md) for the data-handling commitments.
