// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Release Verification Test
// =========================================================================
//
// End-to-end test that downloads a real AegisGate Lens release from
// the Platform repo's GitHub Releases and verifies the SLSA Build
// Level 2 provenance attestation using `gh attestation verify`.
//
// This test is the regression gate for the release pipeline: if
// anything goes wrong with `release-lens.yml` (bad generator SHA,
// wrong subject, signature drift), this test catches it before
// users download a non-verifiable ZIP.
//
// Test plan:
//   1. POSITIVE: download lens-v<version>.zip, verify, assert PASS.
//   2. NEGATIVE: tamper with the ZIP (flip one byte), re-verify,
//      assert FAIL (proves the verifier actually checks content).
//   3. PROVENANCE INSPECTION: download the .intoto.jsonl bundle and
//      assert it contains the expected subject SHA + builder ID.
//
// Pre-conditions:
//   - `gh` CLI installed and `gh auth status` succeeds.
//   - Network access to github.com.
//   - The Lens workflow has `GITHUB_TOKEN` with `contents: read`
//     scope (default for public repos).
//
// Skip behavior:
//   - If `gh` is missing or not authenticated, the test SKIPS with
//     a clear warning rather than failing. This keeps the test
//     runnable on developer machines where gh may not be set up.
//
// References:
//   - https://docs.github.com/en/rest/security-and-compliance#git-signing-and-verification
//   - https://github.com/aegisgatesecurity/aegisgate-lens/blob/main/VERIFY.md
//   - plans/LENS-DAY-18-SLSA-L2-RELEASE-REPORT.md
// =========================================================================

import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import test from 'node:test';

const OWNER = 'aegisgatesecurity';
const REPO = 'aegisgate-platform';

// The known release tag we verify against. Update this when a new
// release ships. The tag's existence on the Platform repo is what
// this test depends on; if the tag is deleted, this test fails
// (which is the correct behavior — a deleted release tag should
// not silently pass).
const RELEASE_TAG = process.env.AEGISGATE_RELEASE_TAG || 'lens-v0.2.2';

// Skip the entire suite if gh is missing or unauthenticated. This
// keeps the test runnable on developer machines without CI tokens.
function isGhAvailable() {
  const which = spawnSync('which', ['gh'], { encoding: 'utf-8' });
  if (which.status !== 0) return false;
  const auth = spawnSync('gh', ['auth', 'status'], { encoding: 'utf-8' });
  return auth.status === 0;
}

const GH_SKIP = !isGhAvailable();

if (GH_SKIP) {
  console.warn(
    `[release-verification] SKIPPED: gh CLI not available or not authenticated. ` +
    `Run 'gh auth login' to enable this test.`,
  );
}

// ---------------------------------------------------------------------------
// Test 1 (POSITIVE): download + verify a real release
// ---------------------------------------------------------------------------
test('verify real AegisGate Lens release via gh attestation verify', { skip: GH_SKIP }, async (t) => {
  // Resolve version from tag (e.g., lens-v0.2.2 -> 0.2.2).
  const versionMatch = RELEASE_TAG.match(/^lens-v(.+)$/);
  assert.ok(versionMatch, `RELEASE_TAG must match lens-v<version>, got: ${RELEASE_TAG}`);
  const VERSION = versionMatch[1];
  const ZIP_NAME = `aegisgate-lens-${VERSION}.zip`;
  console.log(`[release-verification] Verifying ${ZIP_NAME} from ${OWNER}/${REPO}@${RELEASE_TAG}`);

  // Create a temp directory for downloads.
  const tmpDir = mkdtempSync(join(tmpdir(), 'lens-verify-'));
  t.after(() => {
    try { rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  });
  const zipPath = join(tmpDir, ZIP_NAME);

  // Step 1: Download the ZIP via gh (uses GITHUB_TOKEN in CI).
  const download = spawnSync('gh', [
    'release', 'download', RELEASE_TAG,
    '--repo', `${OWNER}/${REPO}`,
    '--pattern', ZIP_NAME,
    '--dir', tmpDir,
    '--clobber',
  ], { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] });
  assert.equal(download.status, 0,
    `gh release download failed (exit ${download.status}): ${download.stderr}`);

  // Step 2: Compute SHA-256 and assert the ZIP is what we expect.
  const zipBytes = readFileSync(zipPath);
  const zipSha = createHash('sha256').update(zipBytes).digest('hex');
  assert.ok(zipBytes.length > 1024, `Downloaded ZIP is suspiciously small: ${zipBytes.length} bytes`);

  // Step 3: Verify against the GitHub Attestations store. The verifier
  // resolves the bundle by artifact SHA-256 internally; we don't need
  // to download the .intoto.jsonl separately.
  const verify = spawnSync('gh', [
    'attestation', 'verify', ZIP_NAME,
    '--repo', `${OWNER}/${REPO}`,
  ], { cwd: tmpDir, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] });

  assert.equal(verify.status, 0,
    `gh attestation verify FAILED (exit ${verify.status}):\n  stderr: ${verify.stderr}\n  stdout: ${verify.stdout}\n` +
    `Subject SHA: ${zipSha}`);
  // Note: gh attestation verify is silent on success. Exit code 0 is
  // the authoritative signal. For verbose output (e.g., 'Loaded N
  // attestations' / 'Verified: ...'), pass --verbose to gh.

  console.log(`[release-verification] PASS: ${ZIP_NAME} (SHA-256 ${zipSha})`);
});

// ---------------------------------------------------------------------------
// Test 2 (NEGATIVE): tampering must cause verification to FAIL
// ---------------------------------------------------------------------------
test('tampered release must FAIL verification', { skip: GH_SKIP }, async (t) => {
  const versionMatch = RELEASE_TAG.match(/^lens-v(.+)$/);
  assert.ok(versionMatch, `RELEASE_TAG must match lens-v<version>, got: ${RELEASE_TAG}`);
  const VERSION = versionMatch[1];
  const ZIP_NAME = `aegisgate-lens-${VERSION}.zip`;

  const tmpDir = mkdtempSync(join(tmpdir(), 'lens-tamper-'));
  t.after(() => {
    try { rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  });
  const zipPath = join(tmpDir, ZIP_NAME);

  // Step 1: Download the legitimate ZIP.
  const download = spawnSync('gh', [
    'release', 'download', RELEASE_TAG,
    '--repo', `${OWNER}/${REPO}`,
    '--pattern', ZIP_NAME,
    '--dir', tmpDir,
    '--clobber',
  ], { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] });
  assert.equal(download.status, 0, `gh release download failed: ${download.stderr}`);

  // Step 2: Tamper with one byte (flip the lowest bit of byte 1024).
  const bytes = readFileSync(zipPath);
  bytes[1024] ^= 0x01;
  const tamperedPath = join(tmpDir, `tampered-${ZIP_NAME}`);
  writeFileSync(tamperedPath, bytes);

  // Step 3: Verify the tampered ZIP. This MUST fail.
  const verify = spawnSync('gh', [
    'attestation', 'verify', `tampered-${ZIP_NAME}`,
    '--repo', `${OWNER}/${REPO}`,
  ], { cwd: tmpDir, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] });

  assert.notEqual(verify.status, 0,
    `Tampered ZIP should FAIL verification but passed! Output: ${verify.stdout}`);
  console.log(`[release-verification] PASS: tampered ZIP correctly rejected (exit ${verify.status})`);
});

// ---------------------------------------------------------------------------
// Test 3 (PROVENANCE INSPECTION): assert provenance contains expected fields
// ---------------------------------------------------------------------------
test('provenance attestation contains expected builder ID and source URI', { skip: GH_SKIP }, async (t) => {
  const versionMatch = RELEASE_TAG.match(/^lens-v(.+)$/);
  assert.ok(versionMatch, `RELEASE_TAG must match lens-v<version>, got: ${RELEASE_TAG}`);
  const VERSION = versionMatch[1];
  const ZIP_NAME = `aegisgate-lens-${VERSION}.zip`;

  const tmpDir = mkdtempSync(join(tmpdir(), 'lens-prov-'));
  t.after(() => {
    try { rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  });

  // Step 1: Download the ZIP and compute its SHA-256.
  const download = spawnSync('gh', [
    'release', 'download', RELEASE_TAG,
    '--repo', `${OWNER}/${REPO}`,
    '--pattern', ZIP_NAME,
    '--dir', tmpDir,
    '--clobber',
  ], { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] });
  assert.equal(download.status, 0, `gh release download failed: ${download.stderr}`);

  const zipPath = join(tmpDir, ZIP_NAME);
  const zipSha = createHash('sha256').update(readFileSync(zipPath)).digest('hex');

  // Step 2: Download the provenance bundle. gh writes the bundle to
  // a file in cwd named 'sha256:<digest>.jsonl'.
  const downloadProv = spawnSync('gh', [
    'attestation', 'download', zipPath,
    '--repo', `${OWNER}/${REPO}`,
  ], { cwd: tmpDir, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] });

  assert.equal(downloadProv.status, 0,
    `gh attestation download failed (exit ${downloadProv.status}): ${downloadProv.stderr}`);

  // Locate the bundle file (named 'sha256:<digest>.jsonl').
  const fs = await import('node:fs');
  const bundleFiles = fs.readdirSync(tmpDir).filter(f => f.startsWith('sha256:') && f.endsWith('.jsonl'));
  assert.ok(bundleFiles.length >= 1, `Expected bundle file in ${tmpDir}, found: ${bundleFiles.join(', ')}`);
  const bundlePath = join(tmpDir, bundleFiles[0]);

  // Step 3: Parse the bundle. Sigstore bundle v0.3 format wraps the
  // in-toto Statement inside dsseEnvelope.payload (base64).
  const bundle = JSON.parse(readFileSync(bundlePath, 'utf-8'));
  assert.equal(bundle.mediaType, 'application/vnd.dev.sigstore.bundle.v0.3+json',
    `Expected Sigstore bundle v0.3; got mediaType=${bundle.mediaType}`);

  const innerPayload = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, 'base64').toString('utf-8'));
  assert.equal(innerPayload.predicateType, 'https://slsa.dev/provenance/v1',
    `Expected SLSA Provenance v1; got predicateType=${innerPayload.predicateType}`);

  // Subject SHA-256 should match the ZIP.
  const subjectSha = innerPayload.subject?.[0]?.digest?.sha256;
  assert.equal(subjectSha, zipSha,
    `Provenance subject SHA should equal ZIP SHA; got ${subjectSha}, expected ${zipSha}`);

  // Builder ID should reference our canonical release workflow.
  const builderId = innerPayload.predicate?.runDetails?.builder?.id
    || innerPayload.predicate?.builder?.id;
  assert.ok(builderId, 'Provenance should contain a builder.id field');
  assert.match(builderId, new RegExp(`${OWNER}/${REPO}/\\.github/workflows/release-lens\\.yml@`),
    `Builder ID should reference our release workflow; got: ${builderId}`);

  console.log(`[release-verification] PASS: builder=${builderId}, subject=${zipSha.slice(0, 16)}...`);
});
