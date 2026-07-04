// AegisGate Lens — test/unit/regex-source-xss.test.mjs
// Unit tests for the XSS regex detector.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const LENS_ROOT = join(__dirname, '..', '..');

function loadModule(relPath, globalKey) {
  const src = readFileSync(join(LENS_ROOT, relPath), 'utf8');
  (0, eval)(src);
  return globalThis[globalKey];
}

const xss = loadModule('src/detectors/regex/source_xss.js', '__lensXSS');
if (!xss) throw new Error('Failed to load xss module');

function hasCategory(matches, cat) {
  return matches.some(m => m.category === cat);
}

test('xss: <script> tag detected', () => {
  const m = xss.detect('Hello <script>alert(1)</script> world');
  assert.equal(hasCategory(m, 'xss_script_tag'), true);
});
test('xss: <script src=...> detected', () => {
  const m = xss.detect('<script src="evil.js"></script>');
  assert.equal(hasCategory(m, 'xss_script_tag'), true);
});

test('xss: onclick event handler detected', () => {
  const m = xss.detect('<a href="#" onclick="alert(1)">click</a>');
  assert.equal(hasCategory(m, 'xss_event_handler'), true);
});
test('xss: onerror event handler detected', () => {
  const m = xss.detect('<img src="x" onerror="alert(1)">');
  assert.equal(hasCategory(m, 'xss_event_handler'), true);
});
test('xss: onload event handler detected', () => {
  const m = xss.detect('<body onload="alert(1)">');
  assert.equal(hasCategory(m, 'xss_event_handler'), true);
});

test('xss: javascript: URL detected', () => {
  const m = xss.detect('<a href="javascript:alert(1)">click</a>');
  assert.equal(hasCategory(m, 'xss_javascript_url'), true);
});
test('xss: javascript: in src detected', () => {
  const m = xss.detect('<iframe src="javascript:alert(1)">');
  assert.equal(hasCategory(m, 'xss_javascript_url'), true);
});

test('xss: data:text/html URL detected', () => {
  const m = xss.detect('<a href="data:text/html,<script>alert(1)</script>">click</a>');
  assert.equal(hasCategory(m, 'xss_data_url'), true);
});
test('xss: data:image URL NOT flagged (safe image)', () => {
  const m = xss.detect('<img src="data:image/png;base64,iVBORw0K">');
  assert.equal(hasCategory(m, 'xss_data_url'), false);
});

test('xss: <svg> with onload detected (svg-specific)', () => {
  // When the script is INSIDE <svg>, xss_svg_script fires. When the
  // script is just inside a <script> tag, xss_script_tag fires.
  // <svg onload="..."> tests the svg-specific pattern.
  const m = xss.detect('<svg onload="alert(1)"></svg>');
  assert.equal(hasCategory(m, 'xss_svg_script'), true);
});
test('xss: <svg><script> matches xss_script_tag (the script, not the svg)', () => {
  // The script inside the SVG is matched by xss_script_tag, not
  // xss_svg_script. The svg-specific pattern only fires when the
  // SVG ITSELF has an on* handler or inline script in its tag.
  const m = xss.detect('<svg><script>alert(1)</script></svg>');
  assert.equal(hasCategory(m, 'xss_script_tag'), true);
});
test('xss: <svg> with onload detected', () => {
  const m = xss.detect('<svg onload="alert(1)"></svg>');
  assert.equal(hasCategory(m, 'xss_svg_script'), true);
});

test('xss: DOM clobbering via <img id=cookie> detected', () => {
  const m = xss.detect('<img id="cookie">');
  assert.equal(hasCategory(m, 'xss_dom_clobbering'), true);
});
test('xss: DOM clobbering via <form name=write> detected', () => {
  const m = xss.detect('<form name="write"></form>');
  assert.equal(hasCategory(m, 'xss_dom_clobbering'), true);
});

test('xss: benign HTML is not flagged', () => {
  const m = xss.detect('<p>Hello <b>world</b></p>');
  assert.equal(m.length, 0);
});
test('xss: benign prompt is not flagged', () => {
  const m = xss.detect('What is the capital of France?');
  assert.equal(m.length, 0);
});
test('xss: empty string returns empty', () => assert.deepEqual(xss.detect(''), []));
test('xss: non-string returns empty', () => {
  assert.deepEqual(xss.detect(null), []);
  assert.deepEqual(xss.detect(42), []);
});
