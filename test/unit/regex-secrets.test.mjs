// AegisGate Lens — test/unit/regex-secrets.test.mjs
// Unit tests for the Secrets regex detector.
// Uses node:test (built-in, no Jest/Mocha).
//
// Tests STS session token heuristic and JWT near-expiry detection (v0.5.0)
// plus basic pattern coverage.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { loadModule } from '../helpers/load-module.js';
const __dirname = dirname(fileURLToPath(import.meta.url));
const LENS_ROOT = join(__dirname, '..', '..');

const secretsModule = loadModule('src/detectors/regex/secrets.js', '__lensSecrets');
const patternRegexes = secretsModule.patterns;

// Helper: generate a long base64-like string (simulates STS token)
function longToken(len) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+=';
  let s = '';
  for (let i = 0; i < len; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return s;
}

// Helper: create a JWT with a given exp claim
function makeJWT(expClaim) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ sub: 'test-user', exp: expClaim })).toString('base64url');
  const sig = 'dGhpcy1pcy1hLXNpZ25hdHVyZS1mb3ItdGVzdGluZy1wdXJwb3Nlcw';
  return `${header}.${payload}.${sig}`;
}

// =====================================================
// AWS STS Session Token Detection
// =====================================================

test('STS session token — detects aws_session_token context', () => {
  const token = longToken(450);
  const text = `aws_session_token=${token}`;
  const matches = secretsModule.detect(text);
  const stsMatch = matches.find(m => m.category === 'secret_aws_sts_session_token');
  assert.ok(stsMatch, 'Should detect STS session token with aws_session_token context');
  assert.equal(stsMatch.severity, 'critical');
});

test('STS session token — detects SessionToken context (capitalized)', () => {
  const token = longToken(450);
  const text = `"SessionToken": "${token}"`;
  const matches = secretsModule.detect(text);
  const stsMatch = matches.find(m => m.category === 'secret_aws_sts_session_token');
  assert.ok(stsMatch, 'Should detect STS session token with SessionToken context');
  assert.equal(stsMatch.severity, 'critical');
});

test('STS session token — does NOT detect long string without context (FPR)', () => {
  const token = longToken(450);
  const text = `Some random data: ${token}`;
  const matches = secretsModule.detect(text);
  const stsMatch = matches.find(m => m.category === 'secret_aws_sts_session_token');
  assert.equal(stsMatch, undefined, 'Should NOT detect long string without STS context');
});

test('STS session token — does NOT detect short string with context', () => {
  const token = longToken(50);
  const text = `aws_session_token=${token}`;
  const matches = secretsModule.detect(text);
  const stsMatch = matches.find(m => m.category === 'secret_aws_sts_session_token');
  assert.equal(stsMatch, undefined, 'Should NOT detect short string (STS tokens are 400+)');
});

// =====================================================
// AWS STS Secret Access Key Detection
// =====================================================

test('STS secret access key — detects with context', () => {
  const key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
  const text = `aws_secret_access_key=${key}`;
  const matches = secretsModule.detect(text);
  const keyMatch = matches.find(m => m.category === 'secret_aws_sts_secret_key');
  assert.ok(keyMatch, 'Should detect STS secret access key with context');
  assert.equal(keyMatch.severity, 'critical');
});

test('STS secret access key — does NOT detect without context (FPR)', () => {
  const key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
  const text = `Some value: ${key}`;
  const matches = secretsModule.detect(text);
  const keyMatch = matches.find(m => m.category === 'secret_aws_sts_secret_key');
  assert.equal(keyMatch, undefined, 'Should NOT detect secret key without context');
});

// =====================================================
// JWT Near-Expiry Detection
// =====================================================

test('JWT near-expiry — upgrades to critical when expiring within 5 min', () => {
  const nowSec = Math.floor(Date.now() / 1000);
  const jwt = makeJWT(nowSec + 120); // expires in 2 minutes
  const text = `Authorization: Bearer ${jwt}`;
  const matches = secretsModule.detect(text);
  const jwtMatch = matches.find(m => m.category === 'secret_jwt');
  assert.ok(jwtMatch, 'Should detect JWT');
  assert.equal(jwtMatch.severity, 'critical', 'Near-expiry JWT should be critical');
  assert.ok(jwtMatch.description && jwtMatch.description.includes('expires in'), 'Should have expiry description');
});

test('JWT expired — upgrades to critical when already expired', () => {
  const nowSec = Math.floor(Date.now() / 1000);
  const jwt = makeJWT(nowSec - 3600); // expired 1 hour ago
  const text = `token: ${jwt}`;
  const matches = secretsModule.detect(text);
  const jwtMatch = matches.find(m => m.category === 'secret_jwt');
  assert.ok(jwtMatch, 'Should detect JWT');
  assert.equal(jwtMatch.severity, 'critical', 'Expired JWT should be critical');
  assert.ok(jwtMatch.description && jwtMatch.description.includes('expired'), 'Should have expired description');
});

test('JWT normal — stays high severity when far from expiry', () => {
  const nowSec = Math.floor(Date.now() / 1000);
  const jwt = makeJWT(nowSec + 86400); // expires in 24 hours
  const text = `Authorization: Bearer ${jwt}`;
  const matches = secretsModule.detect(text);
  const jwtMatch = matches.find(m => m.category === 'secret_jwt');
  assert.ok(jwtMatch, 'Should detect JWT');
  assert.equal(jwtMatch.severity, 'high', 'Non-expiring JWT should stay high');
  assert.ok(!jwtMatch.description, 'Should not have expiry description');
});

test('JWT unparseable — stays high severity when payload cannot be decoded', () => {
  const text = 'eyJbad.eyJbad.bad';
  const matches = secretsModule.detect(text);
  const jwtMatch = matches.find(m => m.category === 'secret_jwt');
  // Either no match (regex may not match) or match with high severity
  if (jwtMatch) {
    assert.equal(jwtMatch.severity, 'high', 'Unparseable JWT should stay high');
  }
});

// =====================================================
// Basic Pattern Coverage (existing patterns still work)
// =====================================================

test('AWS access key — still detects AKIA prefix', () => {
  const text = 'AKIAIOSFODNN7EXAMPLE';
  const matches = secretsModule.detect(text);
  const awsMatch = matches.find(m => m.category === 'secret_aws_key');
  assert.ok(awsMatch, 'Should detect AWS access key');
  assert.equal(awsMatch.severity, 'critical');
});

test('AWS access key — still detects ASIA prefix (STS)', () => {
  const text = 'ASIAIOSFODNN7EXAMPLE';
  const matches = secretsModule.detect(text);
  const awsMatch = matches.find(m => m.category === 'secret_aws_key');
  assert.ok(awsMatch, 'Should detect STS access key ID (ASIA prefix)');
  assert.equal(awsMatch.severity, 'critical');
});

test('GitHub token — still detects', () => {
  const text = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz1234';
  const matches = secretsModule.detect(text);
  const ghMatch = matches.find(m => m.category === 'secret_github_token');
  assert.ok(ghMatch, 'Should detect GitHub token');
});

test('Private key PEM — still detects', () => {
  const text = '-----BEGIN RSA PRIVATE KEY-----';
  const matches = secretsModule.detect(text);
  const pemMatch = matches.find(m => m.category === 'secret_private_key_pem');
  assert.ok(pemMatch, 'Should detect PEM private key');
  assert.equal(pemMatch.severity, 'critical');
});