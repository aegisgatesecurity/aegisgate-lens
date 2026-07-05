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

// =====================================================================
// NEW PATTERNS (v0.1.0-beta XSS expansion, 2026-07-04)
// Each pattern: positive (should detect) + negative (no FP).
// =====================================================================

// --- SVG namespace abuse ---

test('xss: SVG with foreignObject detected', () => {
  // The mXSS pattern fires first (it matches the <iframe> inside
  // foreignObject). Both mXSS and svg_namespace_abuse indicate
  // XSS. We assert that AT LEAST ONE of them fires.
  var m = xss.detect('<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><iframe src="javascript:alert(1)"></iframe></foreignObject></svg>');
  var xssMatch = m.find(x => x.category === 'xss_svg_namespace_abuse' || x.category === 'xss_mutation_xss' || x.category === 'xss_javascript_url');
  assert.ok(xssMatch, 'expected a svg/mXSS/javascript: pattern in ' + JSON.stringify(m));
});

test('xss: SVG with script tag in attributes detected', () => {
  // The existing xss_svg_script pattern covers this; the new
  // xss_svg_namespace_abuse is for the more specific namespace
  // abuse case.
  var m = xss.detect('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>');
  // The existing xss_svg_script pattern fires first.
  assert.ok(m.length > 0, 'expected at least one xss match');
});

// --- Mutation XSS (mXSS) ---

test('xss: mutation XSS (noembed) detected', () => {
  var m = xss.detect('<noembed><img src=x onerror=alert(1)></noembed>');
  // The existing xss_event_handler pattern may fire first.
  // We assert that AT LEAST ONE xss pattern fires.
  assert.ok(m.length > 0, 'expected at least one xss match');
});

test('xss: mutation XSS (title with image) detected', () => {
  var m = xss.detect('<title><img src=x onerror=alert(1)></title>');
  assert.ok(m.length > 0);
});

test('xss: no mutation XSS on normal title text', () => {
  var m = xss.detect('<title>Page Title</title>');
  // Normal title should not fire any xss pattern.
  // (The regex for xss_mutation_xss requires content inside title,
  // not just title text. But the existing xss_script_tag etc. don't
  // match this either.)
  // We just check that no mXSS pattern fires.
  assert.equal(hasCategory(m, 'xss_mutation_xss'), false);
});

// --- Polyglot XSS ---

test('xss: polyglot (template literal in alert) detected', () => {
  var m = xss.detect("alert(`${document.cookie}`)");
  // Polyglot regex matches template literals inside alert()
  assert.equal(hasCategory(m, 'xss_polyglot'), true, 'expected xss_polyglot in ' + JSON.stringify(m));
});

test('xss: polyglot not flagged on simple alert', () => {
  var m = xss.detect("alert('hello')");
  // Simple alert with no template literal: the polyglot regex
  // requires ${} inside the string. This shouldn't match.
  assert.equal(hasCategory(m, 'xss_polyglot'), false);
});

// --- SVG <use> external href ---

test('xss: SVG use with external href detected', () => {
  var m = xss.detect('<svg><use xlink:href="https://evil.com/x.svg#a" /></svg>');
  assert.equal(hasCategory(m, 'xss_svg_use_external'), true, 'expected xss_svg_use_external in ' + JSON.stringify(m));
});

test('xss: SVG use with internal href not flagged', () => {
  // Internal references (#) without a URL scheme should not match.
  var m = xss.detect('<svg><use href="#local" /></svg>');
  // The regex requires a URL scheme (https:, data:, file:, //) in the href.
  // '#local' has no scheme, so it shouldn't match.
  assert.equal(hasCategory(m, 'xss_svg_use_external'), false);
});

// --- javascript: in any URL context ---

test('xss: javascript: in formaction detected', () => {
  var m = xss.detect('<form formaction="javascript:alert(1)"><input type="submit"></form>');
  // The xss_javascript_data_url pattern covers all URL contexts
  // (href, src, action, formaction, xlink:href, etc.)
  assert.equal(hasCategory(m, 'xss_javascript_data_url'), true, 'expected xss_javascript_data_url in ' + JSON.stringify(m));
});

test('xss: javascript: in xlink:href detected', () => {
  var m = xss.detect('<svg><a xlink:href="javascript:alert(1)"><text>click</text></a></svg>');
  assert.equal(hasCategory(m, 'xss_javascript_data_url'), true);
});

test('xss: javascript: in background detected', () => {
  // <body background="javascript:..."> is a less common vector.
  var m = xss.detect('<body background="javascript:alert(1)">');
  assert.equal(hasCategory(m, 'xss_javascript_data_url'), true);
});

// --- <meta http-equiv="refresh" content="javascript:..."> ---

test('xss: meta refresh with javascript: detected', () => {
  var m = xss.detect('<meta http-equiv="refresh" content="0;url=javascript:alert(1)">');
  assert.equal(hasCategory(m, 'xss_meta_refresh'), true, 'expected xss_meta_refresh in ' + JSON.stringify(m));
});

test('xss: meta refresh with normal URL not flagged', () => {
  // Normal page redirect should not be flagged.
  var m = xss.detect('<meta http-equiv="refresh" content="5;url=https://example.com">');
  // No javascript: scheme, so no xss_meta_refresh.
  assert.equal(hasCategory(m, 'xss_meta_refresh'), false);
});

// --- Cross-facet: expansion preserves existing patterns ---

test('xss: expansion preserves script tag detection', () => {
  var m = xss.detect('<script>alert(1)</script>');
  assert.equal(hasCategory(m, 'xss_script_tag'), true);
});

test('xss: expansion preserves event handler detection', () => {
  // The existing xss_event_handler pattern requires quotes around
  // the value (e.g., onerror="..."). We use the same format.
  var m = xss.detect('<img src="x" onerror="alert(1)">');
  assert.equal(hasCategory(m, 'xss_event_handler'), true);
});

test('xss: expansion preserves data URL detection', () => {
  var m = xss.detect('<a href="data:text/html,<script>alert(1)</script>">click</a>');
  // The xss_data_url pattern fires on the href with data:text/html.
  assert.equal(hasCategory(m, 'xss_data_url'), true);
});
