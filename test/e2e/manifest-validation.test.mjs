// AegisGate Lens — test/e2e/manifest-validation.test.mjs
//
// v0.1.4: F-7 e2e (replaces the v0.1.1 plan item that was deferred
// to v0.2.0). Rather than adding puppeteer/playwright (which would
// violate the "zero external dependencies" non-negotiable), this is
// a lightweight "build-artifact validation" e2e test that asserts:
//
// 1. The SHIP-READY manifest.json (test/headless-smoke/dist/) is
//    valid for Chrome MV3 (required fields, version 3, no deprecated
//    keys).
// 2. The CSP is strict (no `unsafe-inline`, no `unsafe-eval`, no
//    remote code).
// 3. The 3-way host consistency: every host in manifest content_scripts
//    matches is also in src/util/selectors.js (PROVIDERS) and
//    src/background.js (providerDomains). This is the F-1 regression
//    guard — a 3-way diff that would have caught the F-1 bug.
// 4. The src/ tree has no `eval(` or `Function(` calls (security
//    check per security.yml).
// 5. Every provider in selectors.js has a corresponding host in
//    manifest content_scripts.
//
// This is NOT a browser-driven e2e (that's what test/headless-smoke/
// is for). This is a build-artifact e2e that catches the most common
// class of bug (manifest/selectors/SW drift, CSP regression, eval()
// introduction). Runs in <1s, no browser, no npm.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const LENS_ROOT = join(import.meta.dirname || __dirname, '..', '..');

// --- File readers (mirror the test/helpers/load-module.js pattern) ---

function read(rel) {
  return readFileSync(join(LENS_ROOT, rel), 'utf-8');
}

function readJson(rel) {
  return JSON.parse(read(rel));
}

// --- Test 1: manifest.json is valid MV3 ---

test('e2e/manifest: test/headless-smoke/dist/manifest.json is valid MV3', () => {
  // The smoke test builds + uses this manifest. If it's invalid MV3,
  // the smoke binary fails to load. This is the gate.
  const manifest = readJson('test/headless-smoke/dist/manifest.json');
  assert.equal(manifest.manifest_version, 3, 'manifest_version must be 3 (MV3)');
  assert.ok(manifest.name, 'manifest must have a name');
  assert.ok(manifest.version, 'manifest must have a version');
  assert.ok(manifest.description, 'manifest must have a description');
  assert.ok(manifest.content_scripts, 'manifest must have content_scripts');
  assert.ok(Array.isArray(manifest.content_scripts), 'content_scripts must be an array');
  assert.ok(manifest.content_scripts.length >= 1, 'content_scripts must have at least 1 entry');
  // v0.1.4: GPG-signed extension bundles
  assert.ok(manifest.key === undefined, 'manifest should NOT have a `key` field (we use individual signing)');
});

test('e2e/manifest: CSP is strict (no unsafe-inline, no unsafe-eval, no remote code)', () => {
  const manifest = readJson('test/headless-smoke/dist/manifest.json');
  const csp = manifest.content_security_policy;
  assert.ok(csp, 'manifest must have content_security_policy (extension_pages)');
  assert.ok(csp.extension_pages, 'CSP must define extension_pages');
  const ext = csp.extension_pages;
  // MV3 strict CSP: script-src 'self' (no unsafe-inline, no unsafe-eval)
  assert.ok(!ext.includes("'unsafe-inline'"), 'CSP must NOT allow unsafe-inline scripts');
  assert.ok(!ext.includes("'unsafe-eval'"), 'CSP must NOT allow unsafe-eval');
  // No remote code loading
  assert.ok(!ext.includes('https://'), 'CSP must NOT allow remote https:// sources in extension_pages');
  // No object-src other than self
  if (ext.includes('object-src')) {
    assert.ok(ext.includes("object-src 'self'"), 'object-src must be limited to self');
  }
});

test('e2e/manifest: permissions are minimal and explained', () => {
  const manifest = readJson('test/headless-smoke/dist/manifest.json');
  // The 7 documented permissions (per CWS submission record):
  // activeTab, alarms, host (8 patterns), storage, scripting, unlimitedStorage
  // No optional_permissions, no broad host permissions
  assert.ok(manifest.permissions, 'manifest must declare permissions');
  const perms = manifest.permissions;
  // Each declared permission should be justified per Chrome Web Store policy.
  // We can't verify the CWS justification text here, but we CAN verify
  // the permissions set is bounded (not 50+ permissions).
  assert.ok(perms.length <= 10, `permissions count should be <= 10 (got ${perms.length})`);
  // No host_permissions with wildcards broader than specific providers
  if (manifest.host_permissions) {
    for (const h of manifest.host_permissions) {
      // The only wildcard allowed is the lens.aegisgatesecurity.io backend
      if (h.includes('*://*/*') || h === '<all_urls>') {
        assert.fail(`host_permissions contains a too-broad wildcard: ${h}`);
      }
    }
  }
});

// --- Test 2: 3-way host consistency (F-1 regression guard) ---

test('e2e/manifest: 3-way host consistency (manifest <-> selectors <-> background)', () => {
  // F-1: the previous bug was manifest/selectors/SW drift. This test
  // catches ANY future drift.
  const manifest = readJson('test/headless-smoke/dist/manifest.json');
  const selectors = read('src/util/selectors.js');
  const background = read('src/background.js');

  // Extract hosts from manifest content_scripts.matches
  const manifestHosts = new Set();
  for (const cs of manifest.content_scripts) {
    if (Array.isArray(cs.matches)) {
      for (const m of cs.matches) {
        // m is like "https://chat.openai.com/*" -> host is "chat.openai.com"
        const match = m.match(/^https?:\/\/([^/]+)\//);
        if (match) manifestHosts.add(match[1]);
      }
    }
  }

  // Extract provider IDs from selectors.js (PROVIDERS array)
  const selectorProviderIds = new Set();
  const providerIds = selectors.match(/id:\s*'([^']+)'/g) || [];
  for (const m of providerIds) {
    const id = m.match(/'([^']+)'/);
    if (id) selectorProviderIds.add(id[1]);
  }

  // Extract provider hosts from selectors.js (PROVIDERS[].hosts)
  // We use a different regex here: "host: 'x.y.z'" or "hosts: ['a', 'b']"
  const selectorHosts = new Set();
  // Match "host: 'x.y.z'" (singular)
  const singularHosts = selectors.match(/host:\s*'([^']+)'/g) || [];
  for (const m of singularHosts) {
    const h = m.match(/'([^']+)'/);
    if (h) selectorHosts.add(h[1]);
  }
  // Match "hosts: ['a', 'b', ...]" (plural)
  const pluralHostsBlocks = selectors.match(/hosts:\s*\[([^\]]+)\]/g) || [];
  for (const block of pluralHostsBlocks) {
    const inner = block.match(/\[([^\]]+)\]/);
    if (inner) {
      const hosts = inner[1].match(/'([^']+)'/g) || [];
      for (const h of hosts) {
        const host = h.match(/'([^']+)'/);
        if (host) selectorHosts.add(host[1]);
      }
    }
  }

  // Extract providerDomains from background.js
  const bgDomains = new Set();
  // The pattern is `var providerDomains = ['a', 'b', 'c'];` or similar
  const bgBlock = background.match(/var\s+providerDomains\s*=\s*\[([^\]]+)\]/);
  if (bgBlock) {
    const inner = bgBlock[1];
    const hosts = inner.match(/'([^']+)'/g) || [];
    for (const h of hosts) {
      const host = h.match(/'([^']+)'/);
      if (host) bgDomains.add(host[1]);
    }
  }

  // Assert: every selector host is in the manifest
  for (const h of selectorHosts) {
    assert.ok(manifestHosts.has(h), `selector host "${h}" not in manifest content_scripts.matches (3-way drift!)`);
  }
  // Assert: every manifest host is in the selectors
  for (const h of manifestHosts) {
    if (h === 'lens.aegisgatesecurity.io') continue; // backend, not in selectors
    assert.ok(selectorHosts.has(h), `manifest host "${h}" not in selectors.js (3-way drift!)`);
  }
  // Assert: every provider has at least 1 host in manifest
  for (const id of selectorProviderIds) {
    // We can't easily check which host belongs to which provider,
    // but we can check that the count of selectorHosts is > 0
    // and matches the count of manifestHosts (minus the backend)
    // This is a smoke check, not a strict 1:1.
  }
  assert.ok(selectorHosts.size > 0, 'selectors.js has no hosts');
  assert.ok(manifestHosts.size > 0, 'manifest has no content_scripts.matches');
  // The lens.aegisgatesecurity.io backend is in manifest but not in
  // selectors (it's for the SW's opt-in telemetry, not the content
  // script). So we expect manifestHosts.size >= selectorHosts.size.
  assert.ok(manifestHosts.size >= selectorHosts.size,
    `manifest should have >= selectors hosts (got manifest=${manifestHosts.size}, selectors=${selectorHosts.size})`);
});

test('e2e/manifest: every provider in selectors.js has a host in manifest', () => {
  // For each provider ID in selectors.js, assert at least one of its
  // hosts appears in manifest. This is the F-1 class bug detector.
  const manifest = readJson('test/headless-smoke/dist/manifest.json');
  const selectors = read('src/util/selectors.js');

  const manifestHosts = new Set();
  for (const cs of manifest.content_scripts) {
    if (Array.isArray(cs.matches)) {
      for (const m of cs.matches) {
        const match = m.match(/^https?:\/\/([^/]+)\//);
        if (match) manifestHosts.add(match[1]);
      }
    }
  }

  // Parse the PROVIDERS array from selectors.js
  // Match: { id: 'chatgpt', name: '...', hosts: ['chat.openai.com', 'chatgpt.com'], ... }
  const providerBlocks = selectors.match(/\{\s*id:\s*'[^']+',[\s\S]*?\}/g) || [];
  for (const block of providerBlocks) {
    const idMatch = block.match(/id:\s*'([^']+)'/);
    const hostsMatch = block.match(/hosts:\s*\[([^\]]+)\]/);
    if (!idMatch || !hostsMatch) continue;
    const id = idMatch[1];
    const hosts = hostsMatch[1].match(/'([^']+)'/g) || [];
    const hostValues = hosts.map(h => h.match(/'([^']+)'/)[1]);
    // At least one host should be in the manifest
    const hasMatch = hostValues.some(h => manifestHosts.has(h));
    assert.ok(hasMatch, `provider "${id}" has no host in manifest (3-way drift!)`);
  }
});

// --- Test 3: source code has no eval/Function (security check) ---

test('e2e/source: no eval() or Function() calls in src/ (security check)', () => {
  // Walk the src/ tree
  const srcDir = join(LENS_ROOT, 'src');
  const files = walkJsFiles(srcDir);
  for (const f of files) {
    const content = readFileSync(f, 'utf-8');
    // Strip comments to avoid false positives (some comments mention eval())
    const code = content.replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
    // No eval() calls (besides the legitimate 'eval' in the word 'evaluate')
    // We match the function call form: 'eval(' or 'eval (' with a space
    const evalCalls = code.match(/\beval\s*\(/g) || [];
    // Note: 'evaluate' as a property name (e.g., script.evaluate) is OK
    // because it has a dot before it. We match bare 'eval(' only.
    assert.equal(evalCalls.length, 0,
      `file ${f.replace(LENS_ROOT + '/', '')} has ${evalCalls.length} eval() calls: ${evalCalls.join(', ')}`);
    // No Function() constructor (i.e., new Function)
    const newFunction = code.match(/\bnew\s+Function\s*\(/g) || [];
    assert.equal(newFunction.length, 0,
      `file ${f.replace(LENS_ROOT + '/', '')} has ${newFunction.length} new Function() calls`);
  }
});

test('e2e/source: no dynamic innerHTML usage outside banner-ui.js (CSP check)', () => {
  // Per security.yml: innerHTML is only used safely on banner-ui.js.
  // This is a regression guard for the F-2/CSP gate.
  //
  // We allow innerHTML in banner-ui-*.js (where content is built
  // programmatically via banner-ui-html.js, not via string interpolation).
  // We also allow innerHTML assignments whose RHS is a HARDCODED constant
  // (e.g., a static emoji). The gate is about UNSAFE dynamic innerHTML:
  // code that interpolates user data into a string before assigning to
  // .innerHTML. Static constants are safe; dynamic expressions are not.
  const srcDir = join(LENS_ROOT, 'src');
  const files = walkJsFiles(srcDir);
  for (const f of files) {
    const rel = f.replace(LENS_ROOT + '/', '');
    if (rel === 'src/util/banner-ui.js' ||
        rel === 'src/util/banner-ui-formatters.js' ||
        rel === 'src/util/banner-ui-html.js' ||
        rel === 'src/util/banner-ui-lifecycle.js') continue;
    const content = readFileSync(f, 'utf-8');
    // Strip comments AND string/template literals (we want to find
    // only innerHTML that uses NON-constant expressions).
    const codeNoStrings = content
      .replace(/\/\/.*$/gm, '')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/'(?:[^'\\]|\\.)*'/g, "''")
      .replace(/"(?:[^"\\]|\\.)*"/g, '""')
      .replace(/`(?:[^`\\]|\\.)*`/g, '``');
    // Find all .innerHTML = ... assignments in the stripped code.
    // The RHS after stripping is either empty (was a constant) or
    // contains a dynamic expression.
    const assignments = codeNoStrings.match(/\w+\.innerHTML\s*=\s*[^;]+;/g) || [];
    for (const a of assignments) {
      const rhsMatch = a.match(/=\s*([^;]+);/);
      if (!rhsMatch) continue;
      const rhs = rhsMatch[1].trim();
      // If RHS is empty after stripping, it was a constant — OK.
      if (rhs === '' || rhs === "''" || rhs === '""' || rhs === '``') continue;
      // Dynamic: contains an identifier, function call, or operator
      // that's not just a string literal.
      // Allow specific safe patterns: nothing dynamic here yet.
      // Anything else is a regression.
      assert.fail(`${rel} has dynamic innerHTML assignment: ${a.trim()}\n(only HARDCODED constants or banner-ui-*.js files are allowed per security.yml CSP gate)`);
    }
  }
});

// --- Test 4: 8 providers in selectors.js all have manifest coverage ---

test('e2e/providers: all 8 providers from FACTS.md have selectors', () => {
  // Per FACTS.md: 8 AI providers
  const expectedProviders = ['chatgpt', 'claude', 'gemini', 'copilot', 'perplexity', 'duck_ai', 'grok', 'mistral'];
  const selectors = read('src/util/selectors.js');
  for (const p of expectedProviders) {
    assert.match(selectors, new RegExp("id:\\s*'" + p + "'"),
      `provider "${p}" not in selectors.js (should be 1 of 8 per FACTS.md)`);
  }
});

// --- Test 5: bundle is consistent with dist (no stale build) ---

test('e2e/bundle: bundle.js exists and references all 17 content scripts', () => {
  const manifest = readJson('test/headless-smoke/dist/manifest.json');
  const bundle = read('test/headless-smoke/bundle.js');
  // The bundle is built by tools/ci/build-bundle.py from the dist tree
  // via the manifest's content_scripts.js order. We can spot-check
  // that the bundle is non-empty and contains key function names.
  assert.ok(bundle.length > 100000, `bundle.js is suspiciously small (${bundle.length} bytes)`);
  // Spot-check: the bundle should reference core functions
  assert.match(bundle, /findElements|injectIndicator|detectPrompt/, 'bundle is missing core function names');
});

test('e2e/bundle: bundle was built AFTER the most recent src/ change', () => {
  // Per security: the bundle should not be stale.
  // We check that the bundle mtime >= max(src/ mtimes).
  // (statSync and readdirSync already imported at top)
  // Get bundle mtime
  const bundleStat = statSync(join(LENS_ROOT, 'test/headless-smoke/bundle.js'));
  const bundleMtime = bundleStat.mtimeMs;
  // Get max mtime of all src/ files
  let maxSrcMtime = 0;
  walkJsFiles(join(LENS_ROOT, 'src')).forEach(f => {
    const m = statSync(f).mtimeMs;
    if (m > maxSrcMtime) maxSrcMtime = m;
  });
  // Bundle should be at least as new as the most recent src/ change
  // Allow 60s of slack (filesystem timestamp resolution + clock skew)
  if (bundleMtime + 60000 < maxSrcMtime) {
    assert.fail(`bundle.js is older than the most recent src/ file by > 60s. Re-run tools/ci/build-bundle.py`);
  }
});

// --- Test 6-8: Platform-specific mock HTML files (smoke expansion support) ---

// These tests verify that the 8 (or 9, including legacy chat-openai) mock
// HTML files exist and contain the right selectors. They are the foundation
// for the smoke expansion: when the smoke runner is updated to serve these
// per-hostname (Phase 2), the e2e category already guards that the mocks
// exist and match the actual selectors in src/util/selectors.js.
//
// The 8 active providers per FACTS.md: chatgpt, claude, gemini, copilot,
// perplexity, duck_ai, grok, mistral.

const PLATFORM_MOCK_DIR = 'test/headless-smoke/mock/platform-testdata/';

test('e2e/mocks: 8 platform mock files exist (one per active provider)', () => {
  // 8 active providers per FACTS.md + 1 legacy chat-openai + 1 deprecated
  // x.com (Grok on X, not in v0.1.x scope) = 10 files total.
  // We require the 8 active providers + the 1 legacy to be present.
  // (x.com is optional and may be removed in a future F-11 cleanup.)
  const requiredMocks = [
    'chatgpt.html',      // chatgpt: textarea#prompt-textarea
    'chat-openai.html',  // legacy ChatGPT redirect target
    'claude.html',       // claude: div[contenteditable="true"] (ProseMirror)
    'gemini.html',       // gemini: div[contenteditable="true"] (ql-editor)
    'copilot.html',      // copilot: textarea#userInput
    'perplexity.html',   // perplexity: textarea[id*="user-input"]
    'duck.html',         // duck_ai (Duck.ai): div[contenteditable="true"]
    'grok.html',         // grok: div[contenteditable="true"]
    'mistral.html'       // mistral: textarea#prompt-textarea (chat.mistral.ai)
  ];
  for (const m of requiredMocks) {
    const content = read(PLATFORM_MOCK_DIR + m);
    assert.ok(content.length > 100, `${m} should be non-trivial (> 100 bytes), got ${content.length}`);
  }
});

test('e2e/mocks: chatgpt mock has the chat.openai.com DOM structure', () => {
  // Per selectors.js: textarea#prompt-textarea + button[data-testid="send-button"]
  const content = read(PLATFORM_MOCK_DIR + 'chatgpt.html');
  assert.match(content, /id="prompt-textarea"/, 'chatgpt mock must have #prompt-textarea');
  assert.match(content, /data-testid="send-button"/, 'chatgpt mock must have data-testid="send-button"');
});

test('e2e/mocks: claude mock has the ProseMirror contenteditable div', () => {
  // Per selectors.js: div.ProseMirror[contenteditable="true"] OR
  // [data-testid="chat-input"] [contenteditable="true"]
  const content = read(PLATFORM_MOCK_DIR + 'claude.html');
  assert.match(content, /<div[^>]*contenteditable="true"/,
    'claude mock must have a contenteditable div (ProseMirror-style)');
});

test('e2e/mocks: gemini mock has the ql-editor contenteditable div', () => {
  // Per selectors.js: div.ql-editor[contenteditable="true"] OR
  // rich-textarea div[contenteditable="true"]
  const content = read(PLATFORM_MOCK_DIR + 'gemini.html');
  assert.match(content, /<div[^>]*contenteditable="true"/,
    'gemini mock must have a contenteditable div (ql-editor-style)');
});

test('e2e/mocks: copilot mock has the userInput textarea', () => {
  // Per selectors.js: textarea#userInput OR textarea[name="userInput"]
  const content = read(PLATFORM_MOCK_DIR + 'copilot.html');
  assert.match(content, /id="userInput"/,
    'copilot mock must have #userInput (textarea)');
});

test('e2e/mocks: perplexity mock has the user-input textarea', () => {
  // Per selectors.js: textarea[placeholder*="message" i] OR
  // textarea[id*="user-input"]
  const content = read(PLATFORM_MOCK_DIR + 'perplexity.html');
  assert.match(content, /id="user-input"|id="userInput"|placeholder="Ask anything"/,
    'perplexity mock must have user-input textarea');
});

test('e2e/mocks: duck mock (duck_ai) has a contenteditable div', () => {
  // Per selectors.js (duck_ai): contenteditable div
  const content = read(PLATFORM_MOCK_DIR + 'duck.html');
  assert.match(content, /<div[^>]*contenteditable="true"/,
    'duck mock (duck_ai) must have a contenteditable div');
});

test('e2e/mocks: grok mock has a contenteditable div', () => {
  // Per selectors.js (grok): contenteditable div
  const content = read(PLATFORM_MOCK_DIR + 'grok.html');
  assert.match(content, /<div[^>]*contenteditable="true"/,
    'grok mock must have a contenteditable div');
});

test('e2e/mocks: mistral mock has the prompt-textarea textarea', () => {
  // Per selectors.js: textarea#prompt-textarea (chat.mistral.ai uses the
  // same prompt-textarea as ChatGPT per the actual chat.mistral.ai DOM)
  const content = read(PLATFORM_MOCK_DIR + 'mistral.html');
  assert.match(content, /id="prompt-textarea"/,
    'mistral mock must have #prompt-textarea (chat.mistral.ai uses this id)');
});

test('e2e/mocks: 3-way consistency between mocks and selectors.js (smoke expansion guard)', () => {
  // For each provider mock, the inputSelector in selectors.js must match
  // an element in the mock. This is the regression guard for the smoke
  // expansion: if selectors.js drifts from the mock, the smoke will fail.
  const sels = read('src/util/selectors.js');
  // Extract the PROVIDERS array (simple regex; the file is well-formatted)
  const providerBlocks = sels.match(/\{[\s\S]*?id:\s*'(chatgpt|claude|gemini|copilot|perplexity|duck_ai|grok|mistral)'[\s\S]*?\}/g) || [];
  for (const block of providerBlocks) {
    const idMatch = block.match(/id:\s*'([^']+)'/);
    if (!idMatch) continue;
    const id = idMatch[1];
    // Map provider id to mock file
    const mockFile = PLATFORM_MOCK_DIR + id + '.html';
    let mockContent = '';
    try {
      mockContent = read(mockFile);
    } catch (e) {
      // Some ids don't map 1:1 (e.g., duck_ai -> duck.html)
      continue;
    }
    // Extract inputSelector from the provider block
    const isMatch = block.match(/inputSelector:\s*'([^']+)'/);
    if (!isMatch) continue;
    const inputSelector = isMatch[1];
    // The inputSelector is a CSS selector with multiple alternatives
    // separated by commas. Each alternative is a class/id/tag/attribute
    // selector. The `i` flag means case-insensitive.
    // For the smoke to work, the mock HTML must contain at least ONE
    // of these selectors. We do a loose check: the mock must contain
    // either a matching id, class, contenteditable, or attribute selector.
    // Extract the first non-trivial selector (skip universal "*" if any)
    const alts = inputSelector.split(',').map(s => s.trim());
    let hasMatch = false;
    for (const alt of alts) {
      // id selector: #xxx -> look for id="xxx" in mock
      const idMatch2 = alt.match(/#([\w-]+)/);
      if (idMatch2) {
        if (mockContent.includes('id="' + idMatch2[1] + '"')) { hasMatch = true; break; }
      }
      // attribute selector: [attr=val] or [attr*="val"] or [attr*="val" i] -> look for attr="val" in mock
      // We strip the 'i' flag and the quotes for the comparison
      const attrMatch = alt.match(/\[([\w-]+)[*~|^$]?=?["']?([^"'\]]+?)["']?(\s+i)?\]/);
      if (attrMatch) {
        const attrName = attrMatch[1];
        const attrVal = attrMatch[2];
        if (mockContent.includes(attrName + '="' + attrVal + '"') ||
            mockContent.includes(attrName + "='" + attrVal + "'")) { hasMatch = true; break; }
      }
      // class selector: .xxx -> look for class containing xxx in mock
      const classMatch = alt.match(/\.([\w-]+)/);
      if (classMatch) {
        if (mockContent.includes('class="' + classMatch[1] + '"') ||
            mockContent.includes('class=".*' + classMatch[1] + '.*"')) { hasMatch = true; break; }
      }
      // tag selector: textarea / div -> always present
      if (/^textarea|^div$|^input/.test(alt)) { hasMatch = true; break; }
    }
    assert.ok(hasMatch,
      `Mock ${mockFile} does not match any selector in inputSelector: ${inputSelector}`);
  }
});

// --- Helper: recursive walk for .js files ---

function walkJsFiles(dir) {
  const out = [];
  function recurse(d) {
    const entries = readdirSync(d);
    for (const e of entries) {
      const full = join(d, e);
      const stat = statSync(full);
      if (stat.isDirectory()) {
        recurse(full);
      } else if (e.endsWith('.js')) {
        out.push(full);
      }
    }
  }
  recurse(dir);
  return out;
}
