// AegisGate Lens — test/unit/banner-ui-not-pii.test.mjs
// v0.1.4: tests for the new "Not PII — dismiss for 24h" button
// added to the banner actions row. The button reuses the existing
// data-action="dismiss" so handleAction routes correctly to the
// 24h per-domain dismiss map.
//
// These tests are source-level invariants (not runtime) because
// the banner UI uses real DOM events that are hard to test in
// Node without jsdom. The pattern mirrors test/unit/popup-settings.test.mjs.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { LENS_ROOT } from '../helpers/load-module.js';

const SRC = readFileSync(join(LENS_ROOT, 'src/util/banner-ui-html.js'), 'utf-8');

test('buildBannerHTML includes the "Not PII" button', () => {
  // The button is inserted in the actions row between
  // data-action="send" and data-action="false-positive".
  assert.match(
    SRC,
    /Not PII.*?dismiss for 24h/s,
    'buildBannerHTML output should include the "Not PII" button label'
  );
});

test('"Not PII" button uses data-action="dismiss" (same as × icon)', () => {
  // The button must use data-action="dismiss" so handleAction
  // routes it to the existing 24h per-domain dismiss code path.
  // Find the new button by its label and verify the data-action.
  // We grep for the button block between data-action="send" and
  // data-action="false-positive".
  const buttonBlock = SRC.match(
    /data-action="send"[\s\S]*?(?=data-action="false-positive")/
  );
  assert.ok(buttonBlock, 'could not find the slice between send and false-positive buttons');
  assert.match(
    buttonBlock[0],
    /data-action="dismiss"/,
    'the new "Not PII" button must use data-action="dismiss"'
  );
});

test('"Not PII" button has accessible aria-label', () => {
  // The visible label says "Not PII — dismiss for 24h" but the
  // aria-label should be clearer for screen readers.
  const buttonBlock = SRC.match(
    /data-action="send"[\s\S]*?(?=data-action="false-positive")/
  );
  assert.ok(buttonBlock, 'could not find the button block');
  assert.match(
    buttonBlock[0],
    /aria-label="Dismiss this detection for 24 hours"/,
    'the new button should have an accessible aria-label'
  );
});

test('"Not PII" button has a title (tooltip) for discoverability', () => {
  // A title attribute helps mouse users understand the button
  // before they click. Also helps users who don't see the long
  // aria-label as visible text.
  const buttonBlock = SRC.match(
    /data-action="send"[\s\S]*?(?=data-action="false-positive")/
  );
  assert.ok(buttonBlock, 'could not find the button block');
  assert.match(
    buttonBlock[0],
    /title="[^"]*(?:24 hours|24h)[^"]*"/,
    'the new button should have a title attribute mentioning 24h or 24 hours'
  );
});

test('"Not PII" button uses lens-btn-ghost style (consistent with Send anyway)', () => {
  // Visual consistency: the new button should use the same style
  // class as the existing "Send anyway" button (lens-btn-ghost).
  // This groups the two "less common" actions visually.
  const buttonBlock = SRC.match(
    /data-action="send"[\s\S]*?(?=data-action="false-positive")/
  );
  assert.ok(buttonBlock, 'could not find the button block');
  assert.match(
    buttonBlock[0],
    /class="lens-btn lens-btn-ghost"/,
    'the new button should use lens-btn-ghost class (matches Send anyway)'
  );
});

test('"Not PII" button is inserted EXACTLY between send and false-positive (regression guard)', () => {
  // Order check: cancel → redact → send → NEW: not-pii → false-positive.
  // This guards against future edits reordering the actions row.
  const cancelIdx = SRC.indexOf('data-action="cancel"');
  const redactIdx = SRC.indexOf('data-action="redact"');
  const sendIdx = SRC.indexOf('data-action="send"');
  const notPiiIdx = SRC.indexOf('Not PII');
  const falsePosIdx = SRC.indexOf('data-action="false-positive"');
  assert.ok(cancelIdx > 0 && redactIdx > 0 && sendIdx > 0 && notPiiIdx > 0 && falsePosIdx > 0, 'all 5 button actions should be present');
  assert.ok(cancelIdx < redactIdx, 'cancel must come before redact');
  assert.ok(redactIdx < sendIdx, 'redact must come before send');
  assert.ok(sendIdx < notPiiIdx, 'send must come before not-pii (new button)');
  assert.ok(notPiiIdx < falsePosIdx, 'not-pii must come before false-positive');
});

test('× icon still exists (regression guard for flow-dismiss-flow smoke test)', () => {
  // The flow-dismiss-flow smoke test clicks the × icon via
  // .lens-icon-btn[data-action="dismiss"]. The new button uses
  // the SAME data-action but a DIFFERENT class (lens-btn not
  // lens-icon-btn). The × icon must still be there.
  assert.match(
    SRC,
    /lens-icon-btn[^>]*data-action="dismiss"/,
    'the × icon (lens-icon-btn) with data-action="dismiss" must still exist'
  );
});

test('source has exactly 1 "Not PII" insertion (regression guard)', () => {
  // Multiple insertions would mean the edit was applied twice.
  const count = (SRC.match(/Not PII/g) || []).length;
  assert.equal(count, 1, `expected exactly 1 "Not PII" insertion, found ${count}`);
});
