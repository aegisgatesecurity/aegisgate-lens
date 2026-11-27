// SPDX-License-Identifier: Apache-2.0
// Lens Business policy enforcement tests (Phase 4a).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
function freshPolicy() {
  const path = require.resolve('../../src/policy.js');
  delete require.cache[path];
  return require(path);
}

test('policy is inert without an active snapshot', () => {
  const P = freshPolicy();
  P._setState({ active: false });
  assert.equal(P.isActive(), false);
  // preScan/filterEvents are no-ops for consumers
  assert.equal(P.preScan('Project Apollo'), null);
  const events = [{ facet: 'pii', category: 'pii_ssn', value: 'x' }];
  assert.equal(P.filterEvents(events, 'text'), events);
});

test('customBlockPatterns pre-scan produces a synthetic event', () => {
  const P = freshPolicy();
  P._setState({
    active: true,
    customBlockPatterns: [
      { name: 'codenames', regex: '\\b(Project(Apollo|Zenith))\\b', severity: 'high' }
    ]
  });
  const ev = P.preScan('please review the ProjectApollo designs');
  assert.ok(ev);
  assert.equal(ev.facet, 'policy');
  assert.equal(ev.category, 'custom_block_codenames');
  assert.equal(ev.severity, 'high');
  assert.equal(P.preScan('nothing sensitive here'), null);
});

test('bad admin regex never breaks detection', () => {
  const P = freshPolicy();
  P._setState({ active: true, customBlockPatterns: [{ name: 'bad', regex: '([unclosed' }] });
  assert.equal(P.preScan('anything'), null);
});

test('facet gating suppresses disabled facets', () => {
  const P = freshPolicy();
  P._setState({
    active: true,
    facetsEnabled: { pii: true, secrets: false }
  });
  const events = [
    { facet: 'pii', category: 'pii_ssn', value: 'a' },
    { facet: 'secrets', category: 'secret_aws_key', value: 'b' }
  ];
  const out = P.filterEvents(events, 'text');
  assert.equal(out.length, 1);
  assert.equal(out[0].facet, 'pii');
});

test('allowedCategories are suppressed; blockedCategories force-keep', () => {
  const P = freshPolicy();
  P._setState({
    active: true,
    facetsEnabled: { pii: false },
    allowedCategories: ['pii_email'],
    blockedCategories: ['pii_ssn']
  });
  const events = [
    { facet: 'pii', category: 'pii_email', value: 'a' },   // suppressed (allowed list)
    { facet: 'pii', category: 'pii_ssn', value: 'b' },      // kept (forced) even though facet off
    { facet: 'secrets', category: 'secret_jwt', value: 'c' } // kept (facet not configured)
  ];
  const out = P.filterEvents(events, 'text');
  assert.equal(out.length, 2);
  assert.ok(out.some(e => e.category === 'pii_ssn'));
  assert.ok(out.some(e => e.category === 'secret_jwt'));
});

test('customAllowPatterns suppress matching values', () => {
  const P = freshPolicy();
  P._setState({
    active: true,
    customAllowPatterns: ['\\btest-[a-z0-9]+\\b']
  });
  const events = [
    { facet: 'secrets', category: 'secret_api_key', value: 'test-abc123' }, // suppressed
    { facet: 'secrets', category: 'secret_api_key', value: 'prod-xyz789' }  // kept
  ];
  const out = P.filterEvents(events, 'text');
  assert.equal(out.length, 1);
  assert.equal(out[0].value, 'prod-xyz789');
});
