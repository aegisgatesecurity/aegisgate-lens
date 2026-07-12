// AegisGate Lens — test/unit/prompt-detect-pause.test.mjs
// v0.1.4: tests for the global "Pause Lens" cached state in
// prompt-detect-dom.js. Mirrors the structure of
// test/unit/prompt-detect-dom-toggle.test.mjs (sister test file
// from G1).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { LENS_ROOT } from '../helpers/load-module.js';

const SRC = readFileSync(join(LENS_ROOT, 'src/util/prompt-detect-dom.js'), 'utf-8');
const CONST = readFileSync(join(LENS_ROOT, 'src/util/constants.js'), 'utf-8');

// Helper: strip line comments to avoid false positives on code
// that mentions a pattern in a comment.
function stripComments(s) {
  return s.replace(/\/\/[^\n]*/g, '');
}

test('source has the cached _pausedUntil default of 0 (not paused)', () => {
  // Default 0 = not paused. The pause check `if (_pausedUntil > 0 ...)`
  // ensures 0 is treated as "not paused". Critical that we default to
  // 0, not some future timestamp that would silently disable detection.
  assert.match(SRC, /var _pausedUntil = 0/, '_pausedUntil should default to 0');
});

test('onInput has the pause early-return guard in the right order', () => {
  // The pause check should appear:
  //   - AFTER the `if (!state.input || !selectors) return;` guard
  //     (so we don't try to access state.input if it's null)
  //   - BEFORE the `var value = selectors.getInputValue(...)` call
  //     (so we skip the selector call entirely)
  //   - BEFORE the `var dets = detectPrompt(value)` call
  //     (so we skip the regex scan)
  const startMatch = SRC.match(/function onInput\(state, detectPrompt\) \{/);
  if (!startMatch || startMatch.index === undefined) throw new Error('onInput not found');
  const start = startMatch.index + startMatch[0].length;
  const endMatch = SRC.substring(start).match(/state\.lastDetections = dets/);
  if (!endMatch || endMatch.index === undefined) throw new Error('end marker not found');
  const fnSrc = SRC.substring(start, start + endMatch.index);
  const inputGuardIdx = fnSrc.indexOf('!state.input');
  const valueCallIdx = fnSrc.indexOf('getInputValue');
  const pauseIdx = fnSrc.indexOf('_pausedUntil');
  assert.ok(inputGuardIdx > 0, 'input guard should be present');
  assert.ok(valueCallIdx > 0, 'getInputValue should be present');
  assert.ok(pauseIdx > 0, 'pause check should be present');
  assert.ok(inputGuardIdx < pauseIdx, 'input guard must come before pause check');
  assert.ok(pauseIdx < valueCallIdx, 'pause check must come before getInputValue');
});

test('onInput pause check uses Date.now() < _pausedUntil (auto-expiring)', () => {
  // The comparison should be Date.now() < _pausedUntil (not <=, not
  // === Date.now()). The strict < means detection is paused
  // UNTIL the timestamp, and resumes the millisecond the timestamp
  // passes. This is the standard "expiry" pattern.
  const onInputMatch = SRC.match(/function onInput\(state, detectPrompt\) \{[\s\S]*?function/)?.[0] || '';
  assert.match(onInputMatch, /Date\.now\(\) < _pausedUntil/, 'onInput should use Date.now() < _pausedUntil for auto-expiry');
});

test('onInput has exactly one pause check (regression guard)', () => {
  // Make sure the edit didn't accidentally duplicate the check.
  // Exclude comments to avoid false positives (the comment text
  // "Date.now() < _pausedUntil" matches the same regex).
  const startMatch = SRC.match(/function onInput\(state, detectPrompt\) \{/);
  if (!startMatch || startMatch.index === undefined) throw new Error('onInput not found');
  const start = startMatch.index + startMatch[0].length;
  const endMatch = SRC.substring(start).match(/state\.lastDetections = dets/);
  if (!endMatch || endMatch.index === undefined) throw new Error('end marker not found');
  const fnSrcNoComments = stripComments(SRC.substring(start, start + endMatch.index));
  const matches = fnSrcNoComments.match(/Date\.now\(\) < _pausedUntil/g) || [];
  assert.equal(matches.length, 1, `onInput should have exactly one Date.now() < _pausedUntil check (excluding comments), found ${matches.length}`);
});

test('source has exactly 1 _loadPausedUntil call at module init (excluding fn def)', () => {
  // The cache should be loaded exactly once at module init.
  // Exclude the function definition itself.
  const callOnly = SRC.replace(/function _loadPausedUntil[\s\S]*?\n  \}/g, '');
  const matches = callOnly.match(/_loadPausedUntil\(\)/g) || [];
  assert.equal(matches.length, 1, `_loadPausedUntil should be called exactly once at module init, found ${matches.length}`);
});

test('storage key in prompt-detect-dom.js matches the canonical key in constants.js', () => {
  const canonical = CONST.match(/PAUSE_UNTIL:\s*'([^']+)'/)?.[1];
  assert.ok(canonical, 'constants.js should define PAUSE_UNTIL');
  assert.match(
    SRC,
    new RegExp("PAUSE_UNTIL_KEY\\s*=\\s*'" + canonical.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&') + "'"),
    'prompt-detect-dom.js PAUSE_UNTIL_KEY must match constants.STORAGE_KEYS.PAUSE_UNTIL'
  );
});

test('PAUSE_UNTIL onChanged listener updates _pausedUntil (not other state)', () => {
  // The listener for PAUSE_UNTIL should only touch _pausedUntil.
  // Find the onChanged block that references PAUSE_UNTIL_KEY by
  // searching for the KEY first, then the surrounding block.
  const keyIdx = SRC.indexOf("PAUSE_UNTIL_KEY = 'aegisgate_lens_pause_until';");
  assert.ok(keyIdx > 0, 'PAUSE_UNTIL_KEY declaration should exist');
  // Find the onChanged.addListener that comes AFTER the key
  const addListenerAfter = SRC.indexOf('chrome.storage.onChanged.addListener', keyIdx);
  assert.ok(addListenerAfter > 0, 'an onChanged.addListener should follow PAUSE_UNTIL_KEY');
  // Find the matching close of that listener (track braces)
  let depth = 0;
  let endIdx = addListenerAfter;
  for (let i = addListenerAfter; i < SRC.length; i++) {
    if (SRC[i] === '{') depth++;
    else if (SRC[i] === '}') {
      depth--;
      if (depth === 0) { endIdx = i; break; }
    }
  }
  const block = SRC.substring(addListenerAfter, endIdx + 1);
  // The block should reference _pausedUntil (the cache var)
  assert.match(block, /_pausedUntil/, 'PAUSE_UNTIL onChanged block should update _pausedUntil');
  // Should NOT touch _showIndicator (no cross-state leak)
  assert.doesNotMatch(block, /_showIndicator/, 'PAUSE_UNTIL onChanged block should NOT touch _showIndicator');
});
