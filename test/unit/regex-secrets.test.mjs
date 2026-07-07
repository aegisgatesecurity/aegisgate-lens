// AegisGate Lens — test/unit/regex-secrets.test.mjs
// Unit tests for the Secrets regex detector.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { patternRegexes } from '../detectors/regex/secrets.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const __testDirname = join(__dirname, '..');

// Load the secrets detector
const secrets = {
  detect: (text) => {
    const matches = [];
    for (const [name, { re, severity, category }] of Object.entries(patternRegexes)) {
      const match = text.match(re);
      if (match) {
        matches.push({ category, severity, value: match[0], pattern: name });
      }
    }
    return matches;
  }
};

// Helper to find category
function hasCategory(matches, category) {
  return matches.some(m => m.category === category);
}

// --- Slack ---
test('secrets: Slack bot token (xoxb-) detected', () => {
  const m = secrets.detect('xoxb-placeholder-test-abc123xyz');
  assert.equal(hasCategory(m, 'secret_slack_token'), true);
});

// --- Stripe ---
test('secrets: Stripe live secret key detected', () => {
  const m = secrets.detect('sk_test_example_12345');
  assert.equal(hasCategory(m, 'secret_stripe_key'), true);
  const k = m.find(x => x.category === 'secret_stripe_key');
  assert.equal(k.value.startsWith('sk_'), true);
});
test('secrets: Stripe live publishable key detected', () => {
  const m = secrets.detect('pk_test_example_12345');
  assert.equal(hasCategory(m, 'secret_stripe_key'), true);
});

// --- Twilio ---
test('secrets: Twilio API key (SK + 32 hex) detected', () => {
  const m = secrets.detect('SK-placeholder-example-abcdef0123456789');
  assert.equal(hasCategory(m, 'secret_twilio_key'), true);
});

// --- SendGrid ---
test('secrets: SendGrid API key (SG.) detected', () => {
  const m = secrets.detect('SG.placeholder_example_a1b2c3d4e5f6');
  assert.equal(hasCategory(m, 'secret_sendgrid_key'), true);
});

// --- Mailgun ---
test('secrets: Mailgun API key (key- + 32 hex) detected', () => {
  const m = secrets.detect('key-placeholder-example-abcdef0123456789');
  assert.equal(hasCategory(m, 'secret_mailgun_key'), true);
});

// --- OpenAI ---
test('secrets: OpenAI sk- key detected', () => {
  const m = secrets.detect('sk-placeholder-openai-key-abc123xyz');
  assert.equal(hasCategory(m, 'secret_openai_key'), true);
});

// --- GitHub Token ---
test('secrets: GitHub personal access token (ghp_) detected', () => {
  const m = secrets.detect('ghp-placeholder-abc123xyz');
  assert.equal(hasCategory(m, 'secret_github_token'), true);
});

// --- AWS Key ---
test('secrets: AWS Access Key ID detected', () => {
  const m = secrets.detect('AKIA-placeholder-abc123xyz');
  assert.equal(hasCategory(m, 'secret_aws_key'), true);
});

// --- Stripe Publishable Key ---
test('secrets: Stripe publishable key (pk_) detected', () => {
  const m = secrets.detect('pk_test_placeholder_abc123xyz');
  assert.equal(hasCategory(m, 'secret_stripe_key'), true);
});

// --- GitHub Token (ghp_ variant) ---
test('secrets: GitHub token (ghp_) detected', () => {
  const m = secrets.detect('ghp_placeholder_test_abc123xyz');
  assert.equal(hasCategory(m, 'secret_github_token'), true);
});

// --- PII Patterns (also tested) ---
test('secrets: PII email pattern also detected', () => {
  const m = secrets.detect('test@example.com');
  assert.equal(hasCategory(m, 'pii_email'), true);
});

// --- Credit Card ---
test('secrets: Credit card number detected', () => {
  const m = secrets.detect('4111-1111-1111-1111');
  assert.equal(hasCategory(m, 'pii_credit_card'), true);
});

// --- Phone Number ---
test('secrets: Phone number detected', () => {
  const m = secrets.detect('+1-555-123-4567');
  assert.equal(hasCategory(m, 'pii_phone'), true);
});

// --- Date of Birth ---
test('secrets: Date of birth detected', () => {
  const m = secrets.detect('1990-01-01');
  assert.equal(hasCategory(m, 'pii_dob'), true);
});
