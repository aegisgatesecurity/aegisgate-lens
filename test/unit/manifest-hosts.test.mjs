// AegisGate Lens — test/unit/manifest-hosts.test.mjs
// Asserts that the three sources-of-truth for supported AI provider
// hosts are kept in sync:
//
//   1. manifest.json (Chrome Web Store manifest, content_scripts.matches)
//   2. src/util/selectors.js (PROVIDERS[].hosts)
//   3. src/background.js (providerDomains array used for dynamic injection)
//
// If any of these three diverge, the content script either fails to
// load on a supported host OR loads on an unsupported host. Both are
// shipped-state bugs we want to catch in CI.
//
// v0.1.2 F-1: added this test to lock the fix.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const LENS_ROOT = join(__dirname, '..', '..');

// --- Helpers ---

// Read the manifest content_scripts.matches array and return the set
// of bare hostnames (strip "https://" prefix and "/*" suffix).
function manifestHosts() {
  const m = JSON.parse(readFileSync(join(LENS_ROOT, 'manifest.json'), 'utf8'));
  const cs = m.content_scripts[0].matches;
  return new Set(cs.map(function (s) {
    return s.replace(/^https?:\/\//, '').replace(/\/\*$/, '');
  }));
}

// Parse src/util/selectors.js PROVIDERS[].hosts via regex. We do NOT
// load the module (it has runtime deps); we just regex-grep.
function selectorsHosts() {
  const src = readFileSync(join(LENS_ROOT, 'src/util/selectors.js'), 'utf8');
  // Match: hosts: ['a', 'b', 'c']  (single-quoted strings, comma-separated)
  const re = /hosts:\s*\[([^\]]+)\]/g;
  const set = new Set();
  let m;
  while ((m = re.exec(src)) !== null) {
    const list = m[1];
    const strs = list.match(/'[^']+'/g) || [];
    for (const s of strs) {
      set.add(s.slice(1, -1));
    }
  }
  return set;
}

// Parse src/background.js providerDomains array via regex. We do NOT
// load the module (it requires chrome.* globals); we just regex-grep.
function swProviderDomains() {
  const src = readFileSync(join(LENS_ROOT, 'src/background.js'), 'utf8');
  // Find the array block: providerDomains = [ ... ];
  const re = /providerDomains\s*=\s*\[([^\]]+)\]/;
  const m = re.exec(src);
  if (!m) {
    throw new Error('background.js: providerDomains array not found');
  }
  const list = m[1];
  const strs = list.match(/'[^']+'/g) || [];
  return new Set(strs.map(function (s) { return s.slice(1, -1); }));
}

// --- Tests ---

test('manifest-hosts: all three sources are non-empty', function () {
  const m = manifestHosts();
  const s = selectorsHosts();
  const sw = swProviderDomains();
  assert.ok(m.size > 0, 'manifest.json content_scripts.matches is empty');
  assert.ok(s.size > 0, 'selectors.js PROVIDERS[].hosts is empty');
  assert.ok(sw.size > 0, 'background.js providerDomains is empty');
});

test('manifest-hosts: manifest ∩ selectors.js are equal', function () {
  const m = manifestHosts();
  const s = selectorsHosts();
  const mOnly = [...m].filter(function (h) { return !s.has(h); }).sort();
  const sOnly = [...s].filter(function (h) { return !m.has(h); }).sort();
  assert.deepEqual(mOnly, [],
    'manifest has hosts not in selectors.js (content script will load but provider is unidentified): ' + JSON.stringify(mOnly));
  assert.deepEqual(sOnly, [],
    'selectors.js has hosts not in manifest (provider is supported but content script never loads): ' + JSON.stringify(sOnly));
});

test('manifest-hosts: manifest ∩ background.js providerDomains are equal', function () {
  const m = manifestHosts();
  const sw = swProviderDomains();
  const mOnly = [...m].filter(function (h) { return !sw.has(h); }).sort();
  const swOnly = [...sw].filter(function (h) { return !m.has(h); }).sort();
  assert.deepEqual(mOnly, [],
    'manifest has hosts not in background.js providerDomains (dynamic injection will not fire): ' + JSON.stringify(mOnly));
  assert.deepEqual(swOnly, [],
    'background.js providerDomains has hosts not in manifest (dynamic injection fires on unsupported host): ' + JSON.stringify(swOnly));
});

test('manifest-hosts: selectors.js ∩ background.js providerDomains are equal', function () {
  const s = selectorsHosts();
  const sw = swProviderDomains();
  const sOnly = [...s].filter(function (h) { return !sw.has(h); }).sort();
  const swOnly = [...sw].filter(function (h) { return !s.has(h); }).sort();
  assert.deepEqual(sOnly, [],
    'selectors.js has hosts not in background.js providerDomains: ' + JSON.stringify(sOnly));
  assert.deepEqual(swOnly, [],
    'background.js providerDomains has hosts not in selectors.js: ' + JSON.stringify(swOnly));
});

test('manifest-hosts: no legacy hosts (v0.1.2 cleanup)', function () {
  const m = manifestHosts();
  const s = selectorsHosts();
  const sw = swProviderDomains();
  // v0.1.2: removed duckduckgo.com, x.com, twitter.com
  const FORBIDDEN = ['duckduckgo.com', 'x.com', 'twitter.com'];
  for (const h of FORBIDDEN) {
    assert.ok(!m.has(h), 'manifest still has legacy host: ' + h);
    assert.ok(!s.has(h), 'selectors.js still has legacy host: ' + h);
    assert.ok(!sw.has(h), 'background.js still has legacy host: ' + h);
  }
});

test('manifest-hosts: required canonical hosts present (v0.1.0-beta ship set)', function () {
  const m = manifestHosts();
  const REQUIRED = [
    'chat.openai.com', 'chatgpt.com',
    'claude.ai',
    'gemini.google.com',
    'copilot.microsoft.com',
    'duck.ai',
    'perplexity.ai',
    'grok.com',
    'chat.mistral.ai', 'le-chat.mistral.ai',
    'chat.deepseek.com',
    'meta.ai'
  ];
  for (const h of REQUIRED) {
    assert.ok(m.has(h), 'manifest is missing required host: ' + h);
  }
});

test('manifest-hosts: www variants present (v0.1.2 adds)', function () {
  const m = manifestHosts();
  // These were added in v0.1.2 because the user can land on the
  // www subdomain of these providers.
  const WWW_VARIANTS = ['www.perplexity.ai', 'www.grok.com', 'www.meta.ai'];
  for (const h of WWW_VARIANTS) {
    assert.ok(m.has(h), 'manifest is missing www variant: ' + h);
  }
});
