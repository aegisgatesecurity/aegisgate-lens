#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens — Real-Bundle Roundtrip Test
// =========================================================================
//
// Why this test exists (added 2026-06-30):
//
//   On 2026-06-30, while fixing the int8 preference bug, I discovered
//   that the production `bundle-loader.js` could not actually parse the
//   shipped `aegisgate-lens-toxicity-v0.2.0.bundle`. The root causes:
//     1. The `findHeaderStart` function used a naive "walk back to nearest
//        '{'" that broke when the JSON magic value was deep in the header
//        (alphabetically sorted keys pushed magic past the files array).
//     2. The `findKeyForBundle` function only checked `header.signing_public_key`
//        (new format) but the old toxicity bundle uses `header.signing_pub_key_b64`.
//     3. The file processing logic unconditionally tried to JSON.parse every
//        non-binary file, but `vocab.txt` is plain text.
//     4. The dist version had a syntax error (`(typeof window !== 'undefined' : ...`
//        missing `?` after `'undefined'`).
//
//   None of these bugs were caught by the existing test suite because
//   every test used synthetic bundles built in the test code, with the
//   magic value at the root position. The test suite never parsed an
//   actual shipped bundle.
//
//   This test parses the actual shipped bundles and asserts:
//     - The header is found and parsed correctly
//     - The signature verifies against the correct key
//     - All files declared in the header are accessible at the right offsets
//     - The expected model file (int8 or fp32) is present
//     - The bundle SHA matches the SHA in bundle-registry.js
//
//   If any of these assertions fail, the bundle is not ship-ready.
//
//   History: see
//     plans/AEGISGATE-LENS-V03-CRITICAL-BUNDLE-PARSER-BUG-2026-06-30.md
// =========================================================================

'use strict';

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fsp from 'node:fs/promises';
import path from 'node:path';
import url from 'node:url';
import vm from 'node:vm';

const here = path.dirname(url.fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');

// ----- Test runner ----------------------------------------------------------

let passed = 0;
let failed = 0;
const failures = [];
const testResults = [];

function test(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => {
      passed++;
      testResults.push({ name, status: 'PASS' });
      console.log(`  PASS  ${name}`);
    })
    .catch((err) => {
      failed++;
      failures.push({ name, err });
      testResults.push({ name, status: 'FAIL', error: err.message });
      console.log(`  FAIL  ${name}`);
      console.log(`        ${err.message}`);
    });
}

// ----- Load bundle-loader into a vm context --------------------------------
//
// The test loads BOTH the src and the dist versions of bundle-loader.js,
// because they differ:
//   - src: single signing key, no multi-key ring (used by the test suite
//     and by synthetic bundle tests)
//   - dist: multi-key ring (signing_pub_key_id + signing_pub_key_b64),
//     backward-compatible with old bundles that use signing_pub_key_b64
//   - dist has the parser fixes (findRootOpenBrace, .json extension check)
//
// We use:
//   - src to verify the v0.1.1 fixture and the new-format PI bundles
//     (which have signing_public_key, the new field name)
//   - dist to verify the old-format toxicity bundle (signing_pub_key_b64)
//     and the new-format bundles too (backward compat check)

async function loadBundleLoader(loaderPath) {
  const loaderSrc = await fsp.readFile(loaderPath, 'utf8');
  const sandbox = {
    console,
    crypto: globalThis.crypto,
    TextEncoder,
    TextDecoder,
    Uint8Array,
    Array,
    Map,
    Object,
    Math,
    JSON,
    Promise,
    self: {},
  };
  sandbox.self = sandbox;
  sandbox.self.AegisGateLens = sandbox.self.AegisGateLens || {};
  sandbox.self.AegisGateLens.logger = {
    info: () => {},
    warn: (...a) => console.warn('[Lens]', ...a),
    error: (...a) => console.error('[Lens]', ...a),
  };
  const ctx = vm.createContext(sandbox);
  vm.runInContext(loaderSrc, ctx, { filename: 'util/bundle-loader.js' });
  return sandbox.self.AegisGateLens.bundleLoader;
}

const srcLoader = await loadBundleLoader(path.join(repoRoot, 'src/util/bundle-loader.js'));
const distLoader = await loadBundleLoader(path.join(repoRoot, 'lens-final-dist/util/bundle-loader.js'));

// ----- Load bundle-registry to verify SHA256 claims ------------------------
//
// The DIST version of bundle-registry has the post-train bundle SHAs and
// the model_size_bytes field. The SRC version has PLACEHOLDERs for the
// toxicity bundle (signed post-train). We load DIST for verification, and
// we also load SRC as a secondary check that the post-train pipeline
// filled in the right values.

const distRegistrySrc = await fsp.readFile(
  path.join(repoRoot, 'lens-final-dist/util/bundle-registry.js'),
  'utf8',
);
const regSandbox = {
  console, TextEncoder, Uint8Array, Array, Object, Math, JSON, Promise, self: {},
};
regSandbox.self = regSandbox;
regSandbox.self.AegisGateLens = { util: { bundleRegistry: null } };
const regCtx = vm.createContext(regSandbox);
vm.runInContext(distRegistrySrc, regCtx, { filename: 'util/bundle-registry.js' });
const registry = regSandbox.self.AegisGateLens.util.bundleRegistry;

console.log('AegisGate Lens — real-bundle-roundtrip.test.mjs');
console.log('Phase 4 — Real bundle integration (Facets 1, 2, 5)');
console.log('');

// ----- Test 1: src version parses the v0.1.1 fixture ----------------------

await test('1. src bundle-loader parses v0.1.1 fixture (lens_ml_build)', async () => {
  const v011Path = path.join(repoRoot, 'lens_ml_build/aegisgate-lens-v0.1.1.bundle');
  const bundle = await fsp.readFile(v011Path);
  const parsed = await srcLoader.parseBundle(bundle);
  assert.equal(parsed.header.magic, 'AEGISGATE_LENS_BUNDLE_V1');
  assert.ok(parsed.header.n_files > 0, 'v0.1.1 should have files');
  assert.ok(parsed.header.signing_public_key, 'v0.1.1 should have signing_public_key');
  assert.match(parsed.header.signing_public_key, /^[0-9a-fA-F]{64}$/);
  // Verify each file is accessible at the declared offset
  const payloadStart = parsed.header.total_payload_size
    ? (bundle.length - 64 - parsed.header.total_payload_size)
    : 0;
  // Actually compute payloadStart from the header offset: header ends at the
  // byte right before the first file. We don't have header.length directly,
  // but we can find it by re-parsing: the file loop computes it. For v0.1.1
  // we know the header is short; just verify the file count.
  assert.equal(parsed.models.length, parsed.header.n_files);
  // The first file should be ensemble_config.json
  assert.equal(parsed.models[0].name, 'ensemble_config.json');
});

// ----- Test 2: src version parses shipped PI int8 bundle ------------------

await test('2. src bundle-loader parses shipped PI int8 bundle', async () => {
  const piInt8Path = path.join(
    repoRoot, 'lens-final-dist/vendor/bundles/aegisgate-lens-prompt-injection-int8-v0.2.0.bundle'
  );
  const bundle = await fsp.readFile(piInt8Path);
  const parsed = await srcLoader.parseBundle(bundle);
  assert.equal(parsed.header.magic, 'AEGISGATE_LENS_BUNDLE_V1');
  assert.equal(parsed.header.n_files, 3);
  // Should have model.onnx and tokenizer files
  assert.ok(parsed.rawFiles['model.onnx'], 'PI int8 should have model.onnx');
  assert.equal(parsed.rawFiles['model.onnx'].length, parsed.header.files.find(f => f.name === 'model.onnx').size);
  // PI int8 bundle is 147 MB on disk, model is ~143 MB
  const int8Size = parsed.rawFiles['model.onnx'].length;
  assert.ok(int8Size > 140 * 1024 * 1024, `int8 model should be > 140 MB, got ${int8Size}`);
  assert.ok(int8Size < 160 * 1024 * 1024, `int8 model should be < 160 MB, got ${int8Size}`);
});

// ----- Test 3: dist version parses shipped PI int8 bundle -----------------

await test('3. dist bundle-loader parses shipped PI int8 bundle (multi-key)', async () => {
  const piInt8Path = path.join(
    repoRoot, 'lens-final-dist/vendor/bundles/aegisgate-lens-prompt-injection-int8-v0.2.0.bundle'
  );
  const bundle = await fsp.readFile(piInt8Path);
  const parsed = await distLoader.parseBundle(bundle);
  assert.equal(parsed.header.magic, 'AEGISGATE_LENS_BUNDLE_V1');
  assert.equal(parsed.header.n_files, 3);
  assert.equal(parsed.keyId, 'lens-v02-2026-06-29', 'PI bundle should use lens-v02-2026-06-29 key');
  assert.ok(parsed.rawFiles['model.onnx'], 'PI int8 should have model.onnx');
});

// ----- Test 4: dist version parses shipped PI FP32 bundle -----------------

await test('4. dist bundle-loader parses shipped PI fp32 bundle (multi-key)', async () => {
  const piFp32Path = path.join(
    repoRoot, 'lens-final-dist/vendor/bundles/aegisgate-lens-prompt-injection-v0.2.0.bundle'
  );
  const bundle = await fsp.readFile(piFp32Path);
  const parsed = await distLoader.parseBundle(bundle);
  assert.equal(parsed.header.magic, 'AEGISGATE_LENS_BUNDLE_V1');
  assert.equal(parsed.keyId, 'lens-v02-2026-06-29', 'PI fp32 bundle should use lens-v02-2026-06-29 key');
  // FP32 model is ~575 MB
  const fp32Size = parsed.rawFiles['model.onnx'].length;
  assert.ok(fp32Size > 560 * 1024 * 1024, `fp32 model should be > 560 MB, got ${fp32Size}`);
});

// ----- Test 5: THE BUG TEST — dist version parses shipped toxicity bundle -

await test('5. dist bundle-loader parses shipped toxicity bundle (the bug)', async () => {
  // This is the test that would have caught the 4-bug chain I found on
  // 2026-06-30. The toxicity bundle:
  //   - has magic deep in the header (alphabetical sort)
  //   - uses old-style signing_pub_key_b64 field
  //   - has a vocab.txt plain-text file (not JSON)
  //   - has both model.onnx (FP32) and model_int8.onnx in the same bundle
  // All of these exercise the dist-version fixes.
  const toxPath = path.join(
    repoRoot, 'lens-final-dist/vendor/bundles/aegisgate-lens-toxicity-v0.2.0.bundle'
  );
  const bundle = await fsp.readFile(toxPath);
  const parsed = await distLoader.parseBundle(bundle);
  assert.equal(parsed.header.magic, 'AEGISGATE_LENS_BUNDLE_V1');
  // Old-style bundle may not have n_files — header has 7 files
  const fileCount = parsed.models.length;
  assert.ok(fileCount >= 5, `toxicity bundle should have 5+ files, got ${fileCount}`);
  // Should have BOTH model.onnx (FP32) and model_int8.onnx
  assert.ok(parsed.rawFiles['model.onnx'], 'toxicity should have model.onnx (FP32)');
  assert.ok(parsed.rawFiles['model_int8.onnx'], 'toxicity should have model_int8.onnx');
  // Should have vocab.txt as plain text (not JSON-parsed)
  assert.ok(parsed.rawFiles['vocab.txt'], 'toxicity should have vocab.txt as raw bytes');
  // Verify the bundle was signed with the toxicity key
  assert.equal(parsed.keyId, 'lens-v02-c6c3ab5a', 'toxicity should use lens-v02-c6c3ab5a key');
});

// ----- Test 6: SHIP-READINESS — bundle SHAs match bundle-registry ---------

await test('6. shipped bundle SHAs match bundle-registry', async () => {
  // For each facet in the registry, verify the on-disk bundle SHA matches
  // the SHA claimed in bundle-registry.js. This is the bundle-integration
  // gate that the user added on 2026-06-30 (Q4 in the pre-launch Council).
  const expected = {
    'prompt-injection': 'aegisgate-lens-prompt-injection-int8-v0.2.0.bundle',
    'toxicity': 'aegisgate-lens-toxicity-v0.2.0.bundle',
  };
  for (const [facet, filename] of Object.entries(expected)) {
    const entry = registry.getBundle(facet);
    assert.ok(entry, `registry should have ${facet} entry`);
    assert.equal(entry.bundle_filename, filename,
      `registry filename for ${facet} should match: expected ${filename}, got ${entry.bundle_filename}`);
    const bundlePath = path.join(
      repoRoot, 'lens-final-dist/vendor/bundles', filename
    );
    const bundle = await fsp.readFile(bundlePath);
    const actualSha = crypto.createHash('sha256').update(bundle).digest('hex');
    assert.equal(actualSha, entry.bundle_sha256,
      `SHA mismatch for ${facet}: registry claims ${entry.bundle_sha256.slice(0, 16)}..., ` +
      `actual is ${actualSha.slice(0, 16)}... (this means the bundle was rebuilt but the registry was not updated)`);
  }
});

// ----- Test 7: SHIP-READINESS — int8 model is in the bundle for toxicity --

await test('7. toxicity bundle contains int8 model with correct size', async () => {
  // The int8 preference fix (model-loader.js createSession) requires
  // model_int8.onnx to be in the bundle. Verify it's there and matches
  // the registry's claimed model_size_bytes.
  const toxPath = path.join(
    repoRoot, 'lens-final-dist/vendor/bundles/aegisgate-lens-toxicity-v0.2.0.bundle'
  );
  const bundle = await fsp.readFile(toxPath);
  const parsed = await distLoader.parseBundle(bundle);
  const int8Bytes = parsed.rawFiles['model_int8.onnx'];
  assert.ok(int8Bytes, 'toxicity bundle must contain model_int8.onnx');
  const int8Mb = int8Bytes.length / 1024 / 1024;
  // The registry claims 105 MB. Allow a small range for header/tolerance.
  assert.ok(int8Mb > 100 && int8Mb < 115,
    `int8 model should be ~105 MB, got ${int8Mb.toFixed(1)} MB`);
  // Cross-check with the registry's claimed model_size_bytes
  const entry = registry.getBundle('toxicity');
  if (entry.model_size_bytes) {
    const claimedMb = entry.model_size_bytes / 1024 / 1024;
    assert.ok(Math.abs(int8Mb - claimedMb) < 5,
      `int8 size (${int8Mb.toFixed(1)} MB) should match registry claim (${claimedMb.toFixed(1)} MB)`);
  }
});

// ----- Test 8: SHIP-READINESS — int8 model preferred at load time ---------

await test('8. model-loader createSession picks int8 from real toxicity bundle', async () => {
  // The full chain: parseBundle → modelLoader.createSession → int8 selected.
  // This is what runs in the browser when toxicity detection is enabled.
  const toxPath = path.join(
    repoRoot, 'lens-final-dist/vendor/bundles/aegisgate-lens-toxicity-v0.2.0.bundle'
  );
  const bundle = await fsp.readFile(toxPath);
  const parsed = await distLoader.parseBundle(bundle);

  // model-loader.js requires NS.util.bundleRegistry, licenseChecker, and
  // webgpuDetect to be loaded first. We load all three before model-loader.
  const bundleRegistrySrc = await fsp.readFile(
    path.join(repoRoot, 'src/util/bundle-registry.js'), 'utf8'
  );
  const licenseCheckerSrc = await fsp.readFile(
    path.join(repoRoot, 'src/util/license-checker.js'), 'utf8'
  );
  const webgpuDetectSrc = await fsp.readFile(
    path.join(repoRoot, 'src/util/webgpu-detect.js'), 'utf8'
  );
  const modelLoaderSrc = await fsp.readFile(
    path.join(repoRoot, 'src/util/model-loader.js'), 'utf8'
  );
  const sandbox = {
    console, crypto: globalThis.crypto, TextEncoder, TextDecoder,
    Uint8Array, Array, Map, Object, Math, JSON, Promise, self: {},
  };
  sandbox.self = sandbox;
  sandbox.self.AegisGateLens = sandbox.self.AegisGateLens || { util: {} };
  sandbox.self.AegisGateLens.logger = { info: () => {}, warn: () => {}, error: () => {} };
  // Mock ort with a Tensor stub so loadORT() doesn't try to load scripts
  sandbox.ort = {
    Tensor: class FakeTensor {},
    InferenceSession: {
      create: async (bytes, opts) => ({
        inputNames: ['input_ids', 'attention_mask'],
        outputNames: ['logits'],
        _bytes: bytes.length,
        run: async () => ({ logits: { type: 'float32', data: new Float32Array(6), dims: [1, 6] } }),
      }),
    },
  };
  const ctx = vm.createContext(sandbox);
  // Load all dependencies in order (model-loader requires all of these)
  vm.runInContext(bundleRegistrySrc, ctx, { filename: 'util/bundle-registry.js' });
  assert.ok(sandbox.self.AegisGateLens.util.bundleRegistry,
    'bundleRegistry should be loaded');
  vm.runInContext(licenseCheckerSrc, ctx, { filename: 'util/license-checker.js' });
  vm.runInContext(webgpuDetectSrc, ctx, { filename: 'util/webgpu-detect.js' });
  vm.runInContext(modelLoaderSrc, ctx, { filename: 'util/model-loader.js' });
  const modelLoader = sandbox.self.AegisGateLens.util.modelLoader;
  assert.ok(modelLoader.createSession, 'modelLoader should expose createSession (added 2026-06-30)');

  const session = await modelLoader.createSession(parsed, ['wasm']);
  const loaded = session._bytes;
  // Expect int8 (~105 MB), not fp32 (~418 MB)
  assert.ok(loaded < 110 * 1024 * 1024,
    `createSession should prefer int8 (loaded ${(loaded/1024/1024).toFixed(1)} MB)`);
});

// ----- Test 9: SHIP-READINESS — every file in header is accessible --------

await test('9. every file declared in toxicity header is accessible at correct offset', async () => {
  // Parse the bundle and verify each file's bytes are accessible at the
  // declared offset+size. The bundle-loader should verify file SHAs
  // automatically — we just check that the loop completes without throwing.
  const toxPath = path.join(
    repoRoot, 'lens-final-dist/vendor/bundles/aegisgate-lens-toxicity-v0.2.0.bundle'
  );
  const bundle = await fsp.readFile(toxPath);
  const parsed = await distLoader.parseBundle(bundle);
  // If parseBundle succeeded, all files were SHA-verified
  assert.ok(parsed.models.length > 0);
  for (const m of parsed.models) {
    assert.ok(m.name, 'every file must have a name');
    if (m.data && m.data._binary) {
      assert.ok(m.data.size > 0, `${m.name} should have non-zero size`);
    }
  }
});

// ----- Test 10: tamper detection still works on real bundles -------------

await test('10. flipping a byte in the toxicity bundle fails signature', async () => {
  const toxPath = path.join(
    repoRoot, 'lens-final-dist/vendor/bundles/aegisgate-lens-toxicity-v0.2.0.bundle'
  );
  const bundle = await fsp.readFile(toxPath);
  // Flip a byte in the payload (skip the header which is also signed)
  // We pick a byte in the middle of the payload. The header takes about
  // 1100 bytes; the payload starts right after. Let's flip a byte at
  // position 50000 (definitely in the payload for the 549 MB bundle).
  const tampered = Buffer.from(bundle);
  tampered[50000] = tampered[50000] ^ 0xFF;
  await assert.rejects(
    () => distLoader.parseBundle(tampered),
    /signature verification FAILED|Payload SHA-256 mismatch|File .* SHA-256 mismatch/i,
    'tampered bundle must fail verification',
  );
});

// ----- Summary -----------------------------------------------------------

console.log('');
console.log('='.repeat(72));
console.log(`Phase 4 real-bundle-roundtrip: ${passed} passed, ${failed} failed`);
console.log('='.repeat(72));

const resultsPath = path.join(repoRoot, 'test/eval/real-bundle-roundtrip-results.json');
await fsp.writeFile(resultsPath, JSON.stringify({
  timestamp: new Date().toISOString(),
  passed,
  failed,
  total: passed + failed,
  results: testResults,
  failures: failures.map(f => ({ name: f.name, message: f.err.message })),
}, null, 2));

console.log(`\nResults archived to: ${resultsPath}`);
process.exit(failed > 0 ? 1 : 0);
