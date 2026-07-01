#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Schema Validator Test Suite (Day 2)
// =========================================================================
//
// Runs the browser-side schema validator (src/privacy/schema.js) against
// a matrix of valid and invalid events. Exits 0 on success, 1 on failure.
//
// We load schema.js into a vm context with a stubbed window/self so the
// IIFE can run. The validator is pure (no chrome APIs) so the only stub
// needed is `window`.
//
// Usage:
//   node test/schema.test.mjs
//
// =========================================================================

'use strict';

import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import nodeFs from 'node:fs';
import path from 'node:path';
import url from 'node:url';
import vm from 'node:vm';

const here = path.dirname(url.fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');

// ----- Load the validator into a stubbed VM context -------------------------

const schemaSource = await fs.readFile(
  path.join(repoRoot, 'src/privacy/schema.js'),
  'utf8',
);

const sandbox = {
  window: {},
  self: {},
  console,
};
// Make window === self so the IIFE finds AegisGateLens on either path.
sandbox.window = sandbox.self;
vm.createContext(sandbox);
vm.runInContext(schemaSource, sandbox, { filename: 'privacy/schema.js' });

const schemaModule = sandbox.self.AegisGateLens.privacy.schema;
const { validate } = schemaModule;
// SCHEMA_VERSION / ACCEPTED_SCHEMA_VERSIONS were added on Day 2.
// Tolerate their absence so this test file can run against the v0.1
// baseline (before the schema cut-over is applied) AND the v1 schema
// (after the cut-over). The presence of either constant is informative,
// not a failure.
const SCHEMA_VERSION = schemaModule.SCHEMA_VERSION; // may be undefined
const ACCEPTED_SCHEMA_VERSIONS = schemaModule.ACCEPTED_SCHEMA_VERSIONS || [];

// ----- Helpers --------------------------------------------------------------

const NOW_MS = 1719000000 * 1000; // matches fixture timestamp (epoch seconds * 1000)
const NOW_S = 1719000000;

function loadFixture(name) {
  // fs/promises is async; loadFixture is sync (called from test bodies).
  // We use readFileSync from the built-in 'node:fs' module instead.
  // Lazy require so we don't fight the ESM loader.
  return JSON.parse(
    nodeFs.readFileSync(path.join(repoRoot, 'test/fixtures', name), 'utf8'),
  );
}

function clone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

/** Build a valid event, optionally overriding one field. */
function validEvent(overrides = {}) {
  const base = loadFixture('valid-event.json');
  // The fixture timestamp is fixed; compute "now" from it so delta=0.
  return Object.assign(base, overrides);
}

// ----- Test runner ----------------------------------------------------------

let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => {
      passed++;
      console.log(`  PASS  ${name}`);
    })
    .catch((err) => {
      failed++;
      failures.push({ name, err });
      console.log(`  FAIL  ${name}`);
      console.log(`        ${err.message}`);
    });
}

console.log('AegisGate Lens - Schema Validator Test Suite (Day 2)');
console.log('Schema version: ' + SCHEMA_VERSION);
console.log(
  'Accepted versions: ' + JSON.stringify(ACCEPTED_SCHEMA_VERSIONS),
);
console.log('');

// ----- Tests ---------------------------------------------------------------

await test('valid event from fixture passes', () => {
  const ev = validEvent();
  const r = validate(ev, NOW_MS);
  assert.equal(r.valid, true, 'expected valid=true');
  assert.equal(r.event.lens_event_version, 1);
  assert.equal(r.event.domain_hash, ev.domain_hash);
});

await test('missing lens_event_version is rejected', () => {
  const ev = validEvent();
  delete ev.lens_event_version;
  const r = validate(ev, NOW_MS);
  assert.equal(r.valid, false);
  assert.match(r.reason, /missing required field: lens_event_version/);
});

await test('lens_event_version=0 (legacy) is rejected', () => {
  const ev = validEvent({ lens_event_version: 0 });
  const r = validate(ev, NOW_MS);
  assert.equal(r.valid, false);
  assert.match(r.reason, /lens_event_version/);
});

await test('lens_event_version=2 (current v0.2) is accepted', () => {
  // v0.2 ships lens_event_version: 2. (v1 was the v0.1 cut-over; v2 is
  // the v0.2 cut-over with the new 'facet' field.)
  const ev = validEvent({ lens_event_version: 2 });
  const r = validate(ev, NOW_MS);
  assert.equal(r.valid, true);
});

await test('lens_event_version=3 (future) is rejected', () => {
  const ev = validEvent({ lens_event_version: 3 });
  const r = validate(ev, NOW_MS);
  assert.equal(r.valid, false);
  assert.match(r.reason, /not accepted/);
});

await test('lens_event_version as string is rejected', () => {
  const ev = validEvent({ lens_event_version: '1' });
  const r = validate(ev, NOW_MS);
  assert.equal(r.valid, false);
  assert.match(r.reason, /lens_event_version must be an integer/);
});

await test('each missing required field is rejected (8x)', () => {
  const required = [
    'domain_hash',
    'category',
    'severity',
    'user_action',
    'timestamp',
    'model_version',
    'lens_version',
    'confidence',
  ];
  for (const field of required) {
    const ev = validEvent();
    delete ev[field];
    const r = validate(ev, NOW_MS);
    assert.equal(r.valid, false, `should reject when ${field} is missing`);
    assert.match(
      r.reason,
      new RegExp('missing required field: ' + field),
      `wrong reason for missing ${field}: got "${r.reason}"`,
    );
  }
});

await test('unknown field (prompt_text) is rejected - privacy guardrail', () => {
  const ev = validEvent({ prompt_text: 'alice@example.com' });
  const r = validate(ev, NOW_MS);
  assert.equal(r.valid, false);
  assert.match(r.reason, /unknown field: prompt_text/);
});

await test('unknown field (url) is rejected - privacy guardrail', () => {
  const ev = validEvent({ url: 'https://chat.openai.com/' });
  const r = validate(ev, NOW_MS);
  assert.equal(r.valid, false);
  assert.match(r.reason, /unknown field: url/);
});

await test('invalid category is rejected', () => {
  const ev = validEvent({ category: 'super_secret' });
  const r = validate(ev, NOW_MS);
  assert.equal(r.valid, false);
  assert.match(r.reason, /category/);
});

await test('invalid severity is rejected', () => {
  const ev = validEvent({ severity: 'mega_critical' });
  const r = validate(ev, NOW_MS);
  assert.equal(r.valid, false);
  assert.match(r.reason, /severity/);
});

await test('invalid user_action is rejected', () => {
  const ev = validEvent({ user_action: 'panic' });
  const r = validate(ev, NOW_MS);
  assert.equal(r.valid, false);
  assert.match(r.reason, /user_action/);
});

// Phase 1.0 / fix-1: ensure dismiss_false_positive is in VALID_USER_ACTIONS
// (this is the action sent by sendFPTelemetry on FP dismissals).
await test('dismiss_false_positive user_action is accepted', () => {
  const ev = validEvent({ user_action: 'dismiss_false_positive', fp_reason: 'test_data' });
  const r = validate(ev, NOW_MS);
  assert.equal(r.valid, true);
});

await test('domain_hash wrong length is rejected', () => {
  const ev = validEvent({ domain_hash: 'abc' });
  const r = validate(ev, NOW_MS);
  assert.equal(r.valid, false);
  assert.match(r.reason, /domain_hash must be 16 hex chars/);
});

await test('domain_hash uppercase is rejected (must be lowercase)', () => {
  const ev = validEvent({ domain_hash: 'A1B2C3D4E5F60718' });
  const r = validate(ev, NOW_MS);
  assert.equal(r.valid, false);
  assert.match(r.reason, /lowercase hex/);
});

await test('timestamp too far in future is rejected', () => {
  const ev = validEvent({ timestamp: NOW_S + 48 * 3600 });
  const r = validate(ev, NOW_MS);
  assert.equal(r.valid, false);
  assert.match(r.reason, /within .*24h/);
});

await test('timestamp too far in past is rejected', () => {
  const ev = validEvent({ timestamp: NOW_S - 48 * 3600 });
  const r = validate(ev, NOW_MS);
  assert.equal(r.valid, false);
  assert.match(r.reason, /within .*24h/);
});

await test('confidence out of range is rejected (high)', () => {
  const ev = validEvent({ confidence: 1.5 });
  const r = validate(ev, NOW_MS);
  assert.equal(r.valid, false);
  assert.match(r.reason, /confidence/);
});

await test('confidence out of range is rejected (low)', () => {
  const ev = validEvent({ confidence: -0.1 });
  const r = validate(ev, NOW_MS);
  assert.equal(r.valid, false);
  assert.match(r.reason, /confidence/);
});

await test('non-object input is rejected (null)', () => {
  const r = validate(null, NOW_MS);
  assert.equal(r.valid, false);
  assert.match(r.reason, /must be an object/);
});

await test('non-object input is rejected (string)', () => {
  const r = validate('not an event', NOW_MS);
  assert.equal(r.valid, false);
  assert.match(r.reason, /must be an object/);
});

await test('normalized event preserves field order (for stable hashing)', () => {
  const ev = validEvent();
  const r = validate(ev, NOW_MS);
  const keys = Object.keys(r.event);
  assert.deepEqual(keys, [
    'lens_event_version',
    'domain_hash',
    'facet',
    'category',
    'severity',
    'user_action',
    'timestamp',
    'model_version',
    'lens_version',
    'confidence',
    'id',
  ]);
});

await test('id field is optional', () => {
  const ev = validEvent();
  delete ev.id;
  const r = validate(ev, NOW_MS);
  assert.equal(r.valid, true);
  assert.equal('id' in r.event, false);
});

await test('fp_reason field is allowed (string, optional)', () => {
  const ev = validEvent({ fp_reason: 'regex matched my own notes' });
  const r = validate(ev, NOW_MS);
  assert.equal(r.valid, true, 'fp_reason should be accepted: ' + (r.reason || ''));
  assert.equal(r.event.fp_reason, 'regex matched my own notes');
});

await test('fp_reason as non-string is rejected', () => {
  const ev = validEvent({ fp_reason: 42 });
  const r = validate(ev, NOW_MS);
  assert.equal(r.valid, false);
  assert.match(r.reason, /fp_reason/);
});

await test('fp_reason with a URL-looking value is rejected (privacy guardrail)', () => {
  // fp_reason is free-text metadata; URLs are forbidden elsewhere in the
  // schema so we keep this rule tight: no URL-shaped values.
  const ev = validEvent({ fp_reason: 'see https://example.com' });
  const r = validate(ev, NOW_MS);
  assert.equal(r.valid, false);
  assert.match(r.reason, /fp_reason/);
});

await test('fp_reason with a 1000-char value is rejected (length cap)', () => {
  const ev = validEvent({ fp_reason: 'x'.repeat(1000) });
  const r = validate(ev, NOW_MS);
  assert.equal(r.valid, false);
  assert.match(r.reason, /fp_reason/);
});

// ----- Summary -------------------------------------------------------------

console.log('');
console.log(`Passed: ${passed}    Failed: ${failed}`);

if (failed > 0) {
  console.log('');
  console.log('Failures:');
  for (const { name, err } of failures) {
    console.log(`  - ${name}: ${err.message}`);
  }
  process.exit(1);
}

process.exit(0);
