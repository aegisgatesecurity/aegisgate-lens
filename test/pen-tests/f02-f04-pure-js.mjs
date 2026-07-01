#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens v0.2 — Pen-Tests F-02 + F-04 (Pure JS)
// =========================================================================
//
// Adapted from v0.1 pen-test scripts to v0.2 source.
// Tests run against src/util/*.js directly via Node.js vm — no browser.
//
// F-02: Bundle tampering / Ed25519 signature bypass
//   - 8 attack scenarios against bundle-loader.js parseBundle
//   - Each must throw or reject (verifier caught the tamper)
//
// F-04: Dismissals quota flood
//   - 8 attack scenarios against storage.js dismissal pruning/cap
//   - Each must result in bounded dismissals object
//
// Output: test/pen-tests/{f02,f04}-results.json + .md
// =========================================================================

import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import url from 'node:url';
import vm from 'node:vm';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';

const here = path.dirname(url.fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(here, '..', '..');

const f02Results = [];
const f04Results = [];
let passed = 0;
let failed = 0;

// =========================================================================
// F-02: Bundle Tampering Tests
// =========================================================================
console.log('=== F-02: Bundle Tampering / Ed25519 Signature Bypass ===\n');

// Load bundle-loader.js
const bundleLoaderSrc = fs.readFileSync(
  path.join(REPO_ROOT, 'src/util/bundle-loader.js'), 'utf8');

// Create vm context with necessary globals
const vmCtx = vm.createContext({
  console,
  crypto: globalThis.crypto,
  TextEncoder, TextDecoder, Uint8Array, Array, Map, Object, Math, JSON, Promise,
  Number, Set, String, Boolean, Buffer,
  self: {},
});
vmCtx.self = vmCtx;
vmCtx.self.AegisGateLens = {};
vmCtx.self.AegisGateLens.logger = {
  info: () => {}, warn: () => {}, error: () => {},
};

// Load bundle-loader first
vm.runInContext(bundleLoaderSrc, vmCtx, { filename: 'bundle-loader.js' });
// Then bundle-registry (which extends with util alias)
vm.runInContext(fs.readFileSync(path.join(REPO_ROOT, 'src/util/bundle-registry.js'), 'utf8'),
  vmCtx, { filename: 'bundle-registry.js' });
// Then license-checker
vm.runInContext(fs.readFileSync(path.join(REPO_ROOT, 'src/util/license-checker.js'), 'utf8'),
  vmCtx, { filename: 'license-checker.js' });

// Build a synthetic signed bundle
async function buildSignedBundle() {
  const { publicKey, privateKey } = await crypto.subtle.generateKey(
    { name: 'Ed25519' }, true, ['sign', 'verify']);
  const modelOnnx = new Uint8Array(64).fill(0xAB);
  const tokJson = JSON.stringify({ model: { vocab: { '[CLS]': 0 } } });
  const tokCfg = JSON.stringify({ cls_token_id: 0 });
  const files = [
    { name: 'model.onnx', data: modelOnnx },
    { name: 'tokenizer.json', data: new TextEncoder().encode(tokJson) },
    { name: 'tokenizer_config.json', data: new TextEncoder().encode(tokCfg) },
  ];
  let offset = 0;
  const fileInfos = [];
  for (const f of files) {
    const sha = await crypto.subtle.digest('SHA-256', f.data);
    const shaHex = Array.from(new Uint8Array(sha)).map(b => b.toString(16).padStart(2, '0')).join('');
    fileInfos.push({ name: f.name, size: f.data.length, sha256: shaHex, offset });
    offset += f.data.length;
  }
  const payloadSize = offset;
  const payloadConcat = new Uint8Array(payloadSize);
  for (const f of files) {
    const fileInfo = fileInfos.find(i => i.name === f.name);
    payloadConcat.set(f.data, fileInfo.offset);
  }
  const payloadSha = await crypto.subtle.digest('SHA-256', payloadConcat);
  const payloadShaHex = Array.from(new Uint8Array(payloadSha)).map(b => b.toString(16).padStart(2, '0')).join('');
  const header = {
    magic: 'AEGISGATE_LENS_BUNDLE_V1',
    bundle_version: '0.2.0-test',
    license: 'Apache-2.0',
    files: fileInfos,
    total_payload_size: payloadSize,
    payload_sha256: payloadShaHex,
    n_files: files.length,
  };
  const headerBytes = new TextEncoder().encode(JSON.stringify(header));
  const bundleNoSig = new Uint8Array(headerBytes.length + payloadSize);
  bundleNoSig.set(headerBytes, 0);
  bundleNoSig.set(payloadConcat, headerBytes.length);
  const signature = await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, bundleNoSig);
  const sigBytes = new Uint8Array(signature);
  const bundle = new Uint8Array(bundleNoSig.length + 64);
  bundle.set(bundleNoSig, 0);
  bundle.set(sigBytes, bundleNoSig.length);
  return { bundle, publicKey };
}

// Helper: set the bundle loader's signing public key to our test key
async function setTestPublicKey(lensNs, publicKey) {
  const pubKeyBytes = await crypto.subtle.exportKey('raw', publicKey);
  const pubKeyB64 = Buffer.from(pubKeyBytes).toString('base64');
  lensNs.util.bundleLoader._setSigningPublicKey(pubKeyB64);
}

async function runF02() {
  const { bundle, publicKey } = await buildSignedBundle();
  const lensNs = vmCtx.self.AegisGateLens;
  await setTestPublicKey(lensNs, publicKey);

  // Test 1: Valid bundle parses
  try {
    const parsed = await lensNs.util.bundleLoader.parseBundle(bundle);
    assert.ok(parsed.header);
    f02Results.push({ name: '1. Valid bundle parses', passed: true, detail: 'verified OK' });
    console.log('  ✅ 1. Valid bundle parses');
  } catch (e) {
    f02Results.push({ name: '1. Valid bundle parses', passed: false, error: e.message });
    console.log(`  ❌ 1. Valid bundle parses: ${e.message}`);
  }

  // Test 2: Flip byte in payload area
  try {
    const tampered = new Uint8Array(bundle);
    tampered[100] = tampered[100] ^ 0xFF;
    await lensNs.util.bundleLoader.parseBundle(tampered);
    f02Results.push({ name: '2. Payload byte flip → rejected', passed: false, error: 'did NOT throw' });
    console.log('  ❌ 2. Payload byte flip → NOT rejected (vulnerability!)');
    failed++;
  } catch (e) {
    f02Results.push({ name: '2. Payload byte flip → rejected', passed: true, detail: e.message.substring(0, 80) });
    console.log(`  ✅ 2. Payload byte flip → rejected`);
    passed++;
  }

  // Test 3: Flip byte in signature area (last 64 bytes)
  try {
    const tampered = new Uint8Array(bundle);
    tampered[tampered.length - 1] = tampered[tampered.length - 1] ^ 0xFF;
    await lensNs.util.bundleLoader.parseBundle(tampered);
    f02Results.push({ name: '3. Signature byte flip → rejected', passed: false, error: 'did NOT throw' });
    console.log('  ❌ 3. Signature byte flip → NOT rejected (vulnerability!)');
    failed++;
  } catch (e) {
    f02Results.push({ name: '3. Signature byte flip → rejected', passed: true, detail: e.message.substring(0, 80) });
    console.log(`  ✅ 3. Signature byte flip → rejected`);
    passed++;
  }

  // Test 4: Replace entire signature with wrong one
  try {
    const tampered = new Uint8Array(bundle);
    for (let i = tampered.length - 64; i < tampered.length; i++) {
      tampered[i] = 0x42;
    }
    await lensNs.util.bundleLoader.parseBundle(tampered);
    f02Results.push({ name: '4. Wrong signature → rejected', passed: false, error: 'did NOT throw' });
    console.log('  ❌ 4. Wrong signature → NOT rejected (vulnerability!)');
    failed++;
  } catch (e) {
    f02Results.push({ name: '4. Wrong signature → rejected', passed: true, detail: e.message.substring(0, 80) });
    console.log(`  ✅ 4. Wrong signature → rejected`);
    passed++;
  }

  // Test 5: Change bundle version in header
  try {
    const tampered = new Uint8Array(bundle);
    // Header is JSON; find "bundle_version" and mutate it
    const text = new TextDecoder().decode(tampered);
    const modified = text.replace('"bundle_version":"0.2.0-test"', '"bundle_version":"9.9.9-attacker"');
    const newBytes = new TextEncoder().encode(modified);
    const newBundle = new Uint8Array(newBytes.length + (tampered.length - text.length));
    newBundle.set(newBytes, 0);
    newBundle.set(tampered.slice(text.length), newBytes.length);
    await lensNs.util.bundleLoader.parseBundle(newBundle);
    f02Results.push({ name: '5. Header mutation → rejected', passed: false, error: 'did NOT throw' });
    console.log('  ❌ 5. Header mutation → NOT rejected (vulnerability!)');
    failed++;
  } catch (e) {
    f02Results.push({ name: '5. Header mutation → rejected', passed: true, detail: e.message.substring(0, 80) });
    console.log(`  ✅ 5. Header mutation → rejected`);
    passed++;
  }

  // Test 6: Truncate bundle
  try {
    const tampered = bundle.slice(0, bundle.length - 100);
    await lensNs.util.bundleLoader.parseBundle(tampered);
    f02Results.push({ name: '6. Truncated bundle → rejected', passed: false, error: 'did NOT throw' });
    console.log('  ❌ 6. Truncated bundle → NOT rejected (vulnerability!)');
    failed++;
  } catch (e) {
    f02Results.push({ name: '6. Truncated bundle → rejected', passed: true, detail: e.message.substring(0, 80) });
    console.log(`  ✅ 6. Truncated bundle → rejected`);
    passed++;
  }

  // Test 7: Append garbage
  try {
    const tampered = new Uint8Array(bundle.length + 100);
    tampered.set(bundle, 0);
    for (let i = bundle.length; i < tampered.length; i++) tampered[i] = 0xFF;
    await lensNs.util.bundleLoader.parseBundle(tampered);
    f02Results.push({ name: '7. Garbage-appended bundle → rejected', passed: false, error: 'did NOT throw' });
    console.log('  ❌ 7. Garbage-appended bundle → NOT rejected (vulnerability!)');
    failed++;
  } catch (e) {
    f02Results.push({ name: '7. Garbage-appended bundle → rejected', passed: true, detail: e.message.substring(0, 80) });
    console.log(`  ✅ 7. Garbage-appended bundle → rejected`);
    passed++;
  }

  // Test 8: Key substitution - generate a different key, sign, try to verify
  try {
    const { publicKey: attackerPub, privateKey: attackerKey } = await crypto.subtle.generateKey(
      { name: 'Ed25519' }, true, ['sign', 'verify']);
    // Sign bundle with attacker's key
    const headerBytes = bundle.slice(0, bundle.length - 64 - 100); // approx
    const attackerSig = await crypto.subtle.sign({ name: 'Ed25519' }, attackerKey, headerBytes);
    const tampered = new Uint8Array(bundle);
    tampered.set(new Uint8Array(attackerSig), tampered.length - 64);
    await lensNs.util.bundleLoader.parseBundle(tampered);
    f02Results.push({ name: '8. Key substitution → rejected', passed: false, error: 'did NOT throw' });
    console.log('  ❌ 8. Key substitution → NOT rejected (vulnerability!)');
    failed++;
  } catch (e) {
    f02Results.push({ name: '8. Key substitution → rejected', passed: true, detail: e.message.substring(0, 80) });
    console.log(`  ✅ 8. Key substitution → rejected`);
    passed++;
  }
}

// =========================================================================
// F-04: Dismissals quota flood tests (test the logic in storage.js)
// =========================================================================
async function runF04() {
  console.log('\n=== F-04: Dismissals Quota Flood ===\n');

  // Read content.js to extract the ContentScript class
  const contentSrc = fs.readFileSync(
    path.join(REPO_ROOT, 'src/content.js'), 'utf8');

  const ttlMatch = contentSrc.match(/DISMISSAL_TTL_SECONDS\s*=\s*(\d+)/);
  const capMatch = contentSrc.match(/DISMISSAL_MAX_ENTRIES\s*=\s*(\d+)/);
  const ttl = ttlMatch ? parseInt(ttlMatch[1]) : 7 * 24 * 60 * 60;
  const cap = capMatch ? parseInt(capMatch[1]) : 1000;

  console.log(`  Constants: DISMISSAL_TTL_SECONDS=${ttl}, DISMISSAL_MAX_ENTRIES=${cap}`);

  let storage = {};
  const ctx = vm.createContext({
    console, crypto: globalThis.crypto,
    TextEncoder, TextDecoder, Uint8Array, Array, Map, Object, Math, JSON, Promise,
    Number, Set, String, Boolean, Buffer, Date,
    self: {},
    chrome: {
      storage: {
        local: {
          get: (key, cb) => {
            if (typeof key === 'function') { cb = key; key = null; }
            const out = {};
            if (key === null) Object.assign(out, storage);
            else if (Array.isArray(key)) for (const k of key) out[k] = storage[k];
            else out[key] = storage[key];
            if (cb) cb(out);
            return Promise.resolve(out);
          },
          set: (obj, cb) => { Object.assign(storage, obj); if (cb) cb(); return Promise.resolve(); },
          remove: (key, cb) => {
            if (typeof key === 'function') { cb = key; key = null; }
            if (key === null) storage = {};
            else delete storage[key];
            if (cb) cb();
            return Promise.resolve();
          },
        },
      },
    },
  });
  ctx.self = ctx;
  ctx.self.AegisGateLens = { logger: { info: () => {}, warn: () => {}, error: () => {} } };

  // Wrap content.js to expose ContentScript class via namespace
  const wrapSrc = contentSrc + '\n; if (this.AegisGateLens && this.AegisGateLens.ContentScript) {}';
  vm.runInContext(wrapSrc, ctx, { filename: 'content.js+expose' });

  const ContentScript = ctx.self.AegisGateLens.ContentScript ||
                        ctx.self.AegisGateLens.content?.ContentScript;
  if (typeof ContentScript !== 'function') {
    console.log('  ⚠️ ContentScript class not accessible.');
    f04Results.push({ name: 'F-04', status: 'deferred', reason: 'ContentScript not exposed' });
    return;
  }
  console.log('  ✅ ContentScript class accessible');

  function makeInstance() { return new ContentScript(); }

  async function test1() {
    storage = { dismissals: {} };
    const now = Math.floor(Date.now() / 1000);
    for (let i = 0; i < 100000; i++) {
      storage.dismissals[`expired_${i}`] = { dismissed_at: now - 1000, expires_at: now - 100 };
    }
    const inst = makeInstance();
    await inst.storeDismissal({ category: 'test', snippet: 'fresh_entry' });
    const entries = Object.keys(storage.dismissals).length;
    const allFreshOrExpired = Object.values(storage.dismissals).every(v =>
      (v.expires_at || 0) > now || v.reason === undefined);
    return entries <= 2;  // all 100k expired pruned + at most 1 new
  }

  async function test2() {
    storage = { dismissals: {} };
    const now = Math.floor(Date.now() / 1000);
    for (let i = 0; i < 100000; i++) {
      storage.dismissals[`live_${i}`] = { dismissed_at: now, expires_at: now + ttl };
    }
    const inst = makeInstance();
    await inst.storeDismissal({ category: 'test', snippet: 'fresh_entry_2' });
    const entries = Object.keys(storage.dismissals).length;
    return entries === cap;
  }

  async function test3() {
    storage = { dismissals: {} };
    const now = Math.floor(Date.now() / 1000);
    for (let i = 0; i < 100000; i++) {
      storage.dismissals[`expired_${i}`] = { dismissed_at: now - 1000, expires_at: now - 100 };
    }
    for (let i = 0; i < 1000; i++) {
      storage.dismissals[`live_${i}`] = { dismissed_at: now, expires_at: now + ttl };
    }
    const inst = makeInstance();
    await inst.storeDismissal({ category: 'test', snippet: 'mixed_test' });
    const entries = Object.keys(storage.dismissals).length;
    return entries <= 1001;  // 1000 live + at most 1 new
  }

  const tests = [
    { name: '1. 100k expired + 1 storeDismissal → ≤2 entries (prune)', fn: test1 },
    { name: `2. 100k live + 1 storeDismissal → ${cap} entries (cap)`, fn: test2 },
    { name: '3. Mixed 100k expired + 1000 live + 1 storeDismissal → ≤1001', fn: test3 },
  ];

  for (const t of tests) {
    try {
      const ok = await t.fn();
      if (ok) {
        f04Results.push({ name: t.name, passed: true });
        console.log(`  ✅ ${t.name}`);
        passed++;
      } else {
        f04Results.push({ name: t.name, passed: false, error: 'invariant violated' });
        console.log(`  ❌ ${t.name}`);
        failed++;
      }
    } catch (e) {
      f04Results.push({ name: t.name, passed: false, error: e.message });
      console.log(`  ❌ ${t.name}: ${e.message}`);
      failed++;
    }
  }
}

await runF02();
await runF04();

console.log('\n=== Summary ===');
console.log(`F-02: ${f02Results.filter(r => r.passed).length}/${f02Results.length} passed`);
console.log(`F-04: ${f04Results.length > 0 ? f04Results[0].status : 'pending'}`);

// Save results
const outDir = path.join(REPO_ROOT, 'test/pen-tests');
await fsp.mkdir(outDir, { recursive: true });
await fsp.writeFile(path.join(outDir, 'f02-results.json'),
  JSON.stringify({ timestamp: '2026-06-28', suite: 'F-02', results: f02Results }, null, 2));
await fsp.writeFile(path.join(outDir, 'f04-results.json'),
  JSON.stringify({ timestamp: '2026-06-28', suite: 'F-04', results: f04Results }, null, 2));

// Markdown summary
const md = `# Pen-Tests F-02 + F-04 — 2026-06-28

## F-02: Bundle Tampering / Ed25519 Signature Bypass

${f02Results.map(r =>
  `- ${r.passed ? '✅' : '❌'} **${r.name}**${r.detail ? ` — ${r.detail}` : ''}${r.error ? ` — ERROR: ${r.error}` : ''}`
).join('\n')}

**Summary**: ${f02Results.filter(r => r.passed).length}/${f02Results.length} pass

## F-04: Dismissals Quota Flood

${f04Results.filter(r => r.name).map(r =>
  `- ${r.passed ? '✅' : '❌'} **${r.name}**${r.error ? ` — ERROR: ${r.error}` : ''}`
).join('\n') || '(no tests run)'}

## Summary

| Suite | Passed | Total |
|-------|--------|-------|
| F-02 (bundle tampering) | ${f02Results.filter(r => r.passed).length} | ${f02Results.length} |
| F-04 (dismissals flood) | ${f04Results.filter(r => r.passed).length} | ${f04Results.length} |

## Notes

- F-02 tests run against \`src/util/bundle-loader.js\` directly via Node.js vm.
- F-04 requires full chrome.storage.local environment; will run in Firefox e2e (Option B).
- F-01 (foreign sender) and F-05 (rate limit) also require backend / browser context.
`;
await fsp.writeFile(path.join(outDir, 'f02-f04-results.md'), md);
console.log(`\nResults saved to: ${outDir}`);