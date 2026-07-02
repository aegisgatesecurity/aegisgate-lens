#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Content Security Policy Test (Day 10 / F-06)
// =========================================================================
//
// Asserts that the extension's source code (src/) does NOT contain any
// dynamic code execution patterns that would be blocked by a strict
// Content Security Policy. This is the executable form of the manual
// survey done on Day 6 of the security foundation work.
//
// What we test:
//   1. No `eval(` calls anywhere in src/ (excluding JSON data files
//      where "eval" appears as a TF-IDF vocabulary token).
//   2. No `new Function(` calls anywhere in src/.
//   3. No `Function('...')` calls anywhere in src/.
//   4. No `innerHTML =` or `.innerHTML=` assignments anywhere in src/.
//   5. No `outerHTML =` or `.outerHTML=` assignments anywhere in src/.
//   6. No `document.write(` calls anywhere in src/.
//   7. No `setTimeout('...', ...)` with a string argument anywhere
//      in src/ (setTimeout with a string is implicitly eval).
//   8. The manifest.json CSP for extension_pages is set to a strict
//      policy that allows only self-hosted scripts.
//
// If any of these checks fail, a CI gate fails and the change is
// blocked. The point is to make it impossible to accidentally add
// `eval` or `innerHTML` to the extension without noticing.
//
// The threat model entry is plans/LENS-THREAT-MODEL.md finding F-06.
//
// =========================================================================

'use strict';

import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import path from 'node:path';
import url from 'node:url';

const here = path.dirname(url.fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');

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

// ----- Walk src/ and collect all .js + .html files (skip JSON data files) -

async function listSourceFiles() {
  const entries = await fsp.readdir(path.join(repoRoot, 'src'), {
    withFileTypes: true,
    recursive: true,
  });
  const files = [];
  for (const e of entries) {
    if (!e.isFile()) continue;
    const full = path.join(e.path || path.join(e.parentPath || '', e.name),
      e.name);
    // Use path.join for safety.
    const p = path.join(e.parentPath || e.path, e.name);
    if (!/\.(js|html)$/.test(p)) continue;
    // Skip JSON files entirely (TF-IDF vocabularies contain "eval").
    files.push(p);
  }
  // De-duplicate.
  return [...new Set(files)];
}

// ----- Read all source files into memory -----------------------------------

const sourceFiles = await listSourceFiles();
console.log('AegisGate Lens - Content Security Policy Test (Day 10 / F-06)');
console.log(`Scanning ${sourceFiles.length} source files in src/`);
console.log('');

// ----- The patterns we forbid ----------------------------------------------

/**
 * Patterns considered "dynamic code execution" that the strict CSP
 * (script-src 'self') would block. We assert none of them appear as
 * ACTUAL code in src/. Note: we ALLOW false positives in string
 * literals and comments because the actual function call would not
 * exist in those contexts. The patterns below look for actual
 * function-call syntax: `eval(`, `new Function(`, etc.
 */
const FORBIDDEN_PATTERNS = [
  {
    name: 'eval() call',
    // Match `eval(` but not `eval(` inside a comment or a regex
    // string. We use a word-boundary regex that catches real calls.
    regex: /(?<![.\w$])eval\s*\(/g,
    // What we accept as a benign match (string literals).
    allowIfIn: ['regex pattern', 'TF-IDF vocabulary token'],
  },
  {
    name: 'new Function() call',
    regex: /\bnew\s+Function\s*\(/g,
    allowIfIn: ['never'],
  },
  {
    name: 'Function(string) call (implicit eval)',
    regex: /\bFunction\s*\(\s*['"`]/g,
    allowIfIn: ['never'],
  },
  {
    name: 'innerHTML assignment',
    regex: /\.innerHTML\s*=/g,
    allowIfIn: ['never'],
  },
  {
    name: 'outerHTML assignment',
    regex: /\.outerHTML\s*=/g,
    allowIfIn: ['never'],
  },
  {
    name: 'document.write() call',
    regex: /\bdocument\.write(?:ln)?\s*\(/g,
    allowIfIn: ['never'],
  },
  {
    name: 'setTimeout(string, ...) call',
    regex: /\bsetTimeout\s*\(\s*['"`]/g,
    allowIfIn: ['never'],
  },
  {
    name: 'setInterval(string, ...) call',
    regex: /\bsetInterval\s*\(\s*['"`]/g,
    allowIfIn: ['never'],
  },
];

// ----- Helper: check if a match is inside a string literal or comment ------

function isLikelyCommentOrString(filePath, matchIndex, content) {
  // Walk back from matchIndex to find the start of the line.
  const lineStart = content.lastIndexOf('\n', matchIndex) + 1;
  const lineEnd = content.indexOf('\n', matchIndex);
  const line = content.slice(lineStart, lineEnd === -1 ? content.length : lineEnd);

  // Single-line comment.
  const beforeMatch = line.slice(0, matchIndex - lineStart);
  if (beforeMatch.includes('//')) {
    // Match is after a // on the same line.
    return true;
  }
  // Multi-line comment: count /* before and */ after.
  const beforeFile = content.slice(0, matchIndex);
  const openCount = (beforeFile.match(/\/\*/g) || []).length;
  const closeCount = (beforeFile.match(/\*\//g) || []).length;
  if (openCount > closeCount) return true;

  // String literal: find the nearest string delimiter before the match.
  // We look at the last 200 chars before the match and find an unmatched
  // quote (' " `). This is heuristic but good enough for the survey.
  const window = beforeFile.slice(-200);
  const singleQuotes = (window.match(/'/g) || []).length;
  const doubleQuotes = (window.match(/"/g) || []).length;
  const backticks = (window.match(/`/g) || []).length;
  // If any quote count is odd, we're inside a string. (Heuristic.)
  if (singleQuotes % 2 === 1 || doubleQuotes % 2 === 1 || backticks % 2 === 1) {
    return true;
  }
  return false;
}

// ----- Tests ---------------------------------------------------------------

for (const pattern of FORBIDDEN_PATTERNS) {
  await test(`no "${pattern.name}" in src/`, async () => {
    const hits = [];
    for (const file of sourceFiles) {
      let content;
      try {
        content = await fsp.readFile(file, 'utf8');
      } catch (err) {
        continue; // skip unreadable
      }
      const re = new RegExp(pattern.regex.source, pattern.regex.flags);
      let m;
      while ((m = re.exec(content)) !== null) {
        if (isLikelyCommentOrString(file, m.index, content)) continue;
        // Skip JSON files explicitly (vocabulary tokens).
        if (file.endsWith('.json')) continue;
        const lineStart = content.lastIndexOf('\n', m.index) + 1;
        const lineEnd = content.indexOf('\n', m.index);
        const lineNo = content.slice(0, m.index).split('\n').length;
        const lineText = content.slice(lineStart, lineEnd === -1 ? content.length : lineEnd);
        hits.push({
          file: path.relative(repoRoot, file),
          line: lineNo,
          text: lineText.trim(),
        });
      }
    }
    if (hits.length > 0) {
      const msg = hits.map((h) =>
        `    ${h.file}:${h.line}: ${h.text}`
      ).join('\n');
      throw new Error(
        `${hits.length} hit(s) for "${pattern.name}":\n${msg}`,
      );
    }
  });
}

await test('manifest.json CSP for extension_pages is strict', async () => {
  const manifest = JSON.parse(
    await fsp.readFile(path.join(repoRoot, 'src/manifest.json'), 'utf8'),
  );
  assert.ok(manifest.content_security_policy, 'manifest must declare CSP');
  const extPagesCSP = manifest.content_security_policy.extension_pages;
  assert.ok(extPagesCSP, 'CSP for extension_pages must be set');
  // Assert strict: only self-hosted scripts, no eval, no inline.
  assert.match(extPagesCSP, /script-src\s+'self'/,
    'CSP must include script-src \'self\'');
  assert.doesNotMatch(extPagesCSP, /'unsafe-eval'/,
    'CSP must NOT allow unsafe-eval');
  assert.doesNotMatch(extPagesCSP, /'unsafe-inline'/,
    'CSP must NOT allow unsafe-inline for scripts');
});

await test('manifest.json host_permissions are minimal', async () => {
  // Defense in depth: the manifest's host_permissions should only
  // include the backend. Any extra origin is a CSP-relevant finding.
  const manifest = JSON.parse(
    await fsp.readFile(path.join(repoRoot, 'src/manifest.json'), 'utf8'),
  );
  const hp = manifest.host_permissions || [];
  assert.ok(hp.length >= 1, 'must declare at least one host_permission');
  // Every host_permission must be the canonical backend or localhost.
  for (const h of hp) {
    const ok = (
      h === 'https://lens.aegisgatesecurity.io/*' ||
      h === 'http://127.0.0.1/*' ||
      h.startsWith('http://localhost')
    );
    assert.ok(ok, 'host_permission ' + h + ' is unexpected');
  }
});

await test('manifest.json permissions are minimal (no broad permissions)', async () => {
  // The Lens should only request `storage` and nothing broader.
  // <all_urls>, tabs, activeTab, etc. would be too broad.
  const manifest = JSON.parse(
    await fsp.readFile(path.join(repoRoot, 'src/manifest.json'), 'utf8'),
  );
  const perms = manifest.permissions || [];
  const ALLOWED = new Set(['storage', 'alarms', 'unlimitedStorage']);
  for (const p of perms) {
    assert.ok(ALLOWED.has(p),
      `permission "${p}" is not in the allowed list ${[...ALLOWED].join(', ')}`);
  }
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
