// AegisGate Lens — test/unit/popup-pause.test.mjs
// v0.1.4: tests for the popup "Pause Lens for 1h / 1d" buttons.
// Mirrors the structure of test/unit/popup-settings.test.mjs (sister
// test file from G1).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { LENS_ROOT } from '../helpers/load-module.js';

function read(rel) { return readFileSync(join(LENS_ROOT, rel), 'utf8'); }

const SRC = read('src/popup/popup.js');
const HTML = read('src/popup/popup.html');
const CONST = read('src/util/constants.js');

test('storage key matches constants.STORAGE_KEYS.PAUSE_UNTIL', () => {
  const canonical = CONST.match(/PAUSE_UNTIL:\s*'([^']+)'/)?.[1];
  assert.ok(canonical, 'constants.STORAGE_KEYS.PAUSE_UNTIL must be defined');
  assert.match(
    SRC,
    new RegExp("'" + canonical.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&') + "'"),
    'popup.js must reference the canonical storage key'
  );
});

test('readPausedUntil defaults to 0 on missing key (no behavior change)', () => {
  // The function should return { pausedUntil: 0 } when:
  //   - chrome is undefined
  //   - chrome.storage is undefined
  //   - the result doesn't have the key
  // The pattern: validate typeof === 'number' && > 0, with fallback to 0.
  assert.match(SRC, /function readPausedUntil\(\) \{[\s\S]*?pausedUntil: 0/, 'readPausedUntil must have a 0 fallback');
  assert.match(SRC, /typeof v === 'number' && v > 0/, 'readPausedUntil must validate number type');
});

test('setPausedUntil persists via chrome.storage.local.set', () => {
  assert.match(SRC, /function setPausedUntil\(value\) \{[\s\S]*?\.storage\.local\.set/, 'setPausedUntil must use chrome.storage.local.set');
});

test('setPausedUntil coerces invalid values to 0', () => {
  // setPausedUntil(undefined) or setPausedUntil(NaN) or setPausedUntil(-1)
  // should all store 0, not NaN or -1. This prevents the pause from
  // being "stuck on" by corrupt storage.
  assert.match(SRC, /\(typeof value === 'number' && value > 0\) \? value : 0/, 'setPausedUntil must coerce invalid values to 0');
});

test('formatPauseUntil returns "Not paused" for 0 or past timestamps', () => {
  // Pure function, no DOM. Should handle 0, null, past timestamps.
  assert.match(SRC, /function formatPauseUntil\(ms\) \{[\s\S]*?'Not paused'/, 'formatPauseUntil must return "Not paused" for invalid input');
  assert.match(SRC, /ms <= Date\.now\(\)\) return 'Not paused'/, 'formatPauseUntil must treat past timestamps as "Not paused"');
});

test('formatPauseUntil includes a time and "today"/"tomorrow" marker', () => {
  assert.match(SRC, /'until ' \+ time \+ ' today'/, 'formatPauseUntil must include "today" marker for same-day');
  assert.match(SRC, /'until ' \+ time \+ ' tomorrow'/, 'formatPauseUntil must include "tomorrow" marker for next-day');
});

test('bindPauseButtons wires exactly 2 buttons via wireBtn calls (1h + 1d)', () => {
  // bindPauseButtons defines a nested wireBtn function then calls
  // it twice. The actual addEventListener is inside wireBtn's body.
  // We verify the structural model: 2 wireBtn calls, 1 wireBtn def.
  // We also verify the wireBtn body has 1 addEventListener call.
  const startMatch = SRC.match(/function bindPauseButtons\(\) \{/);
  if (!startMatch || startMatch.index === undefined) throw new Error('bindPauseButtons not found');
  const start = startMatch.index + startMatch[0].length;
  const endMatch = SRC.substring(start).match(/\}\)\(\);\s*$/);
  if (!endMatch || endMatch.index === undefined) throw new Error('IIFE end not found');
  const block = SRC.substring(start, start + endMatch.index);
  // Find the wireBtn function body
  const wireBtnDef = block.match(/function wireBtn\(btn, hours\) \{[\s\S]*?\n    \}/);
  assert.ok(wireBtnDef, 'wireBtn function should be defined inside bindPauseButtons');
  // Verify the wireBtn body has exactly 1 addEventListener call
  const addEventCalls = (wireBtnDef[0].match(/btn\.addEventListener\(/g) || []).length;
  assert.equal(addEventCalls, 1, `wireBtn body should have 1 addEventListener call, found ${addEventCalls}`);
  // Verify wireBtn is called exactly 2 times (1h + 1d)
  const wireBtnCalls = (block.match(/wireBtn\(btn\d[a-z],\s*\d+\)/g) || []).length;
  assert.equal(wireBtnCalls, 2, `bindPauseButtons should call wireBtn exactly 2 times, found ${wireBtnCalls}`);
});

test('bindPauseButtons has defensive typeof guard for test-shim compat', () => {
  // Same pattern as G1's bindShowIndicator. Test shim returns mock
  // elements WITHOUT addEventListener; bind must guard against that.
  const startMatch = SRC.match(/function bindPauseButtons\(\) \{/);
  if (!startMatch || startMatch.index === undefined) throw new Error('bindPauseButtons not found');
  const start = startMatch.index + startMatch[0].length;
  const endMatch = SRC.substring(start).match(/\}\)\(\);\s*$/);
  if (!endMatch || endMatch.index === undefined) throw new Error('IIFE end not found');
  const block = SRC.substring(start, start + endMatch.index);
  assert.match(block, /typeof btn\.addEventListener !== 'function'/, 'bindPauseButtons should guard typeof addEventListener');
});

test('bindPauseButtons is wired into the popup onLoad', () => {
  // onLoad must call bindPauseButtons() so the buttons are wired.
  const onLoadMatch = SRC.match(/function onLoad\(\) \{[\s\S]*?\n  \}/)?.[0] || '';
  assert.match(onLoadMatch, /bindPauseButtons\(\)/, 'onLoad must call bindPauseButtons()');
});

test('1h button computes correct future timestamp (Date.now() + 1*60*60*1000)', () => {
  // Verify the math: 1 hour = 60 * 60 * 1000 ms.
  assert.match(SRC, /hours \* 60 \* 60 \* 1000/, '1h button should use hours*60*60*1000 ms math');
});

test('1d button uses 24 hours (data-pause-hours="24" or wireBtn(_, 24))', () => {
  // 1 day = 24 hours. Verify either the HTML attribute or the
  // wireBtn call uses 24.
  const htmlHas = HTML.match(/data-pause-hours="24"/);
  const jsHas = SRC.match(/wireBtn\(btn1d,\s*24\)/);
  assert.ok(htmlHas || jsHas, '1d button must use 24 hours (via HTML attribute or wireBtn call)');
});

test('popup.html has both 1h and 1d buttons', () => {
  assert.match(HTML, /id="pause-1h"/, 'popup.html must have pause-1h button');
  assert.match(HTML, /id="pause-1d"/, 'popup.html must have pause-1d button');
});

test('popup.html has the pause status line', () => {
  // The status line shows "Not paused" or "until 3:45 PM today" etc.
  assert.match(HTML, /id="pause-value"/, 'popup.html must have pause-value status line');
});

test('popup.html has a clear, accessible label for the pause section', () => {
  // The "Pause Lens" label is the visible text. Verify the help text
  // explains what pause does (so users don't confuse it with dismiss).
  assert.match(HTML, /Suppresses all detection globally/, 'help text should explain the global scope');
  assert.match(HTML, /Auto-resumes when the time expires/, 'help text should mention auto-resume');
});

test('source has exactly 2 wireBtn call invocations (1h + 1d), excluding the function definition', () => {
  // Regression guard: prevent duplicate button wiring.
  // Count `wireBtn(` calls (not the function definition `function wireBtn(`).
  // Use a negative lookbehind to exclude the function definition.
  // Since JS regex lookbehind is supported in Node 20+, this is safe.
  const startMatch = SRC.match(/function bindPauseButtons\(\) \{/);
  if (!startMatch || startMatch.index === undefined) throw new Error('bindPauseButtons not found');
  const start = startMatch.index + startMatch[0].length;
  const endMatch = SRC.substring(start).match(/\}\)\(\);\s*$/);
  if (!endMatch || endMatch.index === undefined) throw new Error('IIFE end not found');
  const block = SRC.substring(start, start + endMatch.index);
  // Match `wireBtn(` NOT preceded by "function ". We use a simpler
  // approach: match the wireBtn( call form, which is the only form
  // we care about (wireBtn(btn1h, 1) or wireBtn(btn1d, 24)).
  const calls = block.match(/wireBtn\(btn\d[a-z],\s*\d+\)/g) || [];
  assert.equal(calls.length, 2, `bindPauseButtons should call wireBtn exactly 2 times (1h + 1d), found ${calls.length}`);
});
