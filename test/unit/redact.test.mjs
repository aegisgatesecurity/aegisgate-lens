// AegisGate Lens — test/unit/redact.test.mjs
// Unit tests for the "Edit & redact" button behavior.
//
// The redact logic in content.js is: for each detection event (with
// .index, .value, .category), replace the value at the index with
// "[REDACTED:<category>]". Process from end to start so earlier
// indexes are not affected.
//
// This test validates the algorithm by running it against a real
// prompt + real detections from the regex detector. It mirrors
// what content.js does without loading the IIFE.
//
// The detector load order mirrors the production injection order
// (see src/background.js ~line 488): luhn.js is injected BEFORE
// pii.js, so __lensLuhn is available when __lensPII.detect runs.
// This is what makes the credit card postProcess work for
// dashed/spaced formats like 4111-1111-1111-1111.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const LENS_ROOT = join(__dirname, '..', '..');

// ============================================================
// Pure redact function (extracted from content.js redactInput)
// ============================================================
function redactText(current, events) {
  if (!events || events.length === 0) {
    return { text: current, count: 0 };
  }
  var sorted = events.slice().sort(function (a, b) {
    return (b.index || 0) - (a.index || 0);
  });
  var out = current;
  var count = 0;
  for (var i = 0; i < sorted.length; i++) {
    var ev = sorted[i];
    if (!ev || !ev.value) continue;
    var start = typeof ev.index === 'number' ? ev.index : -1;
    var len = ev.value.length;
    var rep = '[REDACTED:' + (ev.category || 'PII') + ']';
    if (start >= 0 && start + len <= out.length && out.substr(start, len) === ev.value) {
      out = out.slice(0, start) + rep + out.slice(start + len);
      count++;
    } else if (out.indexOf(ev.value) >= 0) {
      out = out.replace(ev.value, rep);
      count++;
    }
  }
  return { text: out, count: count };
}

// Load detectors in PRODUCTION order: luhn.js first, then pii.js
// (mirrors background.js dynamic injection order)
const luhn = (function() {
  const src = readFileSync(join(LENS_ROOT, 'src/detectors/luhn.js'), 'utf8');
  (0, eval)(src);
  return globalThis.__lensLuhn;
})();
assert.ok(luhn, 'luhn must load first (production order)');

const pii = (function() {
  const src = readFileSync(join(LENS_ROOT, 'src/detectors/regex/pii.js'), 'utf8');
  (0, eval)(src);
  return globalThis.__lensPII;
})();
assert.ok(pii, 'pii must load after luhn');

// ============================================================
// Redact algorithm tests
// ============================================================

test('redact: single SSN', () => {
  var text = 'My SSN is 123-45-6789 please help';
  var dets = pii.detect(text);
  var r = redactText(text, dets);
  assert.ok(r.count > 0, 'should detect at least one match');
  assert.ok(!r.text.includes('123-45-6789'), 'SSN should be removed');
  assert.ok(r.text.includes('[REDACTED:'), 'should contain [REDACTED:]');
  assert.ok(r.text.includes('My SSN is'), 'other text preserved');
  assert.ok(r.text.includes('please help'), 'trailing text preserved');
});

test('redact: multiple PII', () => {
  var text = 'Email jane@example.com and call 415-555-0100 and SSN 123-45-6789';
  var dets = pii.detect(text);
  var r = redactText(text, dets);
  assert.ok(r.count >= 2, 'should detect at least 2 PII');
  assert.ok(!r.text.includes('jane@example.com'));
  assert.ok(!r.text.includes('415-555-0100'));
  assert.ok(!r.text.includes('123-45-6789'));
  assert.ok(r.text.includes('[REDACTED:'));
});

test('redact: no detections = no change', () => {
  var text = 'Hello, this is a normal prompt';
  var dets = pii.detect(text);
  var r = redactText(text, dets);
  assert.equal(r.text, text, 'unchanged');
  assert.equal(r.count, 0);
});

test('redact: empty events = no change', () => {
  var text = 'My SSN is 123-45-6789';
  var r = redactText(text, []);
  assert.equal(r.text, text);
  assert.equal(r.count, 0);
});

test('redact: preserves order of surrounding text', () => {
  var text = 'Before X 123-45-6789 Y After';
  var dets = pii.detect(text);
  var r = redactText(text, dets);
  assert.ok(r.text.includes('Before X'));
  assert.ok(r.text.includes('Y After'));
  assert.ok(!r.text.includes('123-45-6789'));
});

test('redact: handles overlapping detection gracefully', () => {
  var text = 'Email jane@example.com here';
  var dets = [
    { index: 6, value: 'jane@example.com', category: 'pii_email' },
    { index: 6, value: 'jane@example.com', category: 'pii_digital_paypal' },
  ];
  var r = redactText(text, dets);
  assert.ok(r.count >= 1);
  assert.ok(!r.text.includes('jane@example.com'));
});

test('redact: invalid index falls back to string replace', () => {
  var text = 'jane@example.com is my email';
  var dets = [{ index: 999, value: 'jane@example.com', category: 'pii_email' }];
  var r = redactText(text, dets);
  assert.equal(r.count, 1, 'fallback string replace should fire');
  assert.ok(!r.text.includes('jane@example.com'));
  assert.ok(r.text.includes('[REDACTED:pii_email]'));
});

test('redact: real-world prompt (email + phone + DOB)', () => {
  var text = 'Please help me draft a support response. Customer: John Smith, DOB: 05/15/1985, phone: (415) 555-0123, email: john.smith@example.com. Issue: card declined.';
  var dets = pii.detect(text);
  var r = redactText(text, dets);
  assert.ok(r.count >= 3, 'should detect at least 3 PII items (DOB, phone, email)');
  assert.ok(!r.text.includes('john.smith@example.com'));
  assert.ok(!r.text.includes('(415) 555-0123'));
  assert.ok(r.text.includes('Please help me draft'));
  assert.ok(r.text.includes('Issue: card declined'));
  assert.ok(r.text.includes('[REDACTED:'));
});

test('redact: category appears in marker', () => {
  var text = 'SSN 123-45-6789';
  var dets = pii.detect(text);
  var r = redactText(text, dets);
  assert.ok(r.text.includes('[REDACTED:pii_ssn]'), 'category in marker');
});

test('redact: multiple categories produce multiple markers', () => {
  var text = 'SSN 123-45-6789 and email a@b.co';
  var dets = pii.detect(text);
  var r = redactText(text, dets);
  var matches = r.text.match(/\[REDACTED:/g) || [];
  assert.ok(matches.length >= 2, 'expected >= 2 markers, got ' + matches.length);
});

// ============================================================
// Credit card detection (with luhn.js loaded, production order)
// ============================================================

test('cc: detect dashed format 4111-1111-1111-1111', () => {
  var dets = pii.detect('4111-1111-1111-1111');
  var ccMatches = dets.filter(function (d) { return d.category === 'pii_credit_card'; });
  assert.ok(ccMatches.length > 0, 'should detect dashed credit card');
  assert.equal(ccMatches[0].value, '4111-1111-1111-1111');
});

test('cc: detect spaced format 4111 1111 1111 1111', () => {
  var dets = pii.detect('4111 1111 1111 1111');
  var ccMatches = dets.filter(function (d) { return d.category === 'pii_credit_card'; });
  assert.ok(ccMatches.length > 0, 'should detect spaced credit card');
  assert.equal(ccMatches[0].value, '4111 1111 1111 1111');
});

test('cc: detect dashless format 4111111111111111', () => {
  var dets = pii.detect('4111111111111111');
  assert.ok(dets.length > 0, 'should detect dashless credit card');
});

test('cc: redact dashed format', () => {
  var text = 'My card is 4111-1111-1111-1111 thanks';
  var dets = pii.detect(text);
  var r = redactText(text, dets);
  assert.ok(!r.text.includes('4111-1111-1111-1111'), 'CC should be redacted');
  assert.ok(r.text.includes('[REDACTED:pii_credit_card]'));
  assert.ok(r.text.includes('My card is'));
  assert.ok(r.text.includes('thanks'));
});

test('cc: reject invalid Luhn (1234-5678-9012-3456)', () => {
  var dets = pii.detect('1234-5678-9012-3456');
  var ccMatches = dets.filter(function (d) { return d.category === 'pii_credit_card'; });
  assert.equal(ccMatches.length, 0, 'invalid Luhn should be rejected');
});
