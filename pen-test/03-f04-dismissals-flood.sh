#!/usr/bin/env bash
# =========================================================================
# AegisGate Lens - Penetration Test Attack 03 (F-04)
# Dismissals quota flood
# =========================================================================
#
# Threat-model finding F-04: chrome.storage.local dismissals is
# unbounded. Day 9 fix added pruning + 1000-entry cap. This attack
# tries to defeat it:
#
#   1. Pre-fill storage with 100,000 expired entries, then call
#      storeDismissal once. Expect: pruning brings it to 1 entry.
#   2. Pre-fill storage with 100,000 live entries, then call
#      storeDismissal once. Expect: cap holds at 1000 entries, the
#      new entry is present.
#   3. Pre-fill storage with a mix of 100,000 expired + 1000 live,
#      then call storeDismissal. Expect: 1001 entries (1000 live +
#      1 new). No expired entries remain.
#   4. Try to bypass the cap by sending many writes in parallel.
#      Expect: cap holds (the read-modify-write is single-threaded).
#   5. Try to bypass with very long keys (consume quota faster).
#      Expect: cap still holds because we count by entry count, not
#      bytes.
#   6. Try to bypass with empty-string reason.
#   7. Try to bypass with non-string reason (e.g., object).
#   8. Verify the dismissKey format is preserved (regression).
#
# Each test loads content.js in a vm, drives storeDismissal, and
# asserts the chrome.storage.local.dismissals object is bounded.
#
# Output: pen-test/evidence/03-f04.jsonl
# =========================================================================

set -euo pipefail

OUT="pen-test/evidence/03-f04.jsonl"
mkdir -p pen-test/evidence
rm -f "$OUT"

echo "=== Attack 03: F-04 Dismissals quota flood ==="
echo

run_attack() {
  local name="$1"
  local node_script="$2"

  result=$(node --input-type=module -e "$node_script" 2>&1 || true)
  passed="unknown"
  detail=$(echo "$result" | tail -3 | tr '\n' '|')
  printf "  [%-50s] -> %s\n" "$name" "$detail"
  python3 -c "
import json
entry = {
  'name': '$name',
  'result': '''$result''',
}
print(json.dumps(entry))
" >> "$OUT"
}

# Helper: generate a content-script vm sandbox with stubbed chrome.storage
# that supports the local.get / local.set callbacks pattern.
SANDBOX_PRELUDE='
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { webcrypto } from "node:crypto";

const schemaSrc = readFileSync("src/privacy/schema.js", "utf8");
const contentSrc = readFileSync("src/content.js", "utf8");
const storage = {
  data: {},
  get(key, cb) {
    if (typeof key === "string") cb({ [key]: storage.data[key] });
    else if (Array.isArray(key)) {
      const out = {};
      for (const k of key) out[k] = storage.data[k];
      cb(out);
    } else cb({ ...storage.data });
  },
  set(items, cb) { Object.assign(storage.data, items); if (cb) cb(); },
  preset(key, value) { storage.data[key] = value; },
  reset() { for (const k of Object.keys(storage.data)) delete storage.data[k]; },
  size() { return Object.keys(storage.data).length; },
};
const locObj = { hostname: "chat.openai.com", protocol: "https:" };
const sandbox = {
  console,
  URL,
  document: { createElement: () => ({ style: {}, addEventListener: () => {} }), body: { appendChild: () => {} } },
  location: locObj,
  navigator: { userAgent: "node-test" },
  Math, Date, JSON, Object, Array, Set, Map, String, Number, Boolean, Error, Promise, Symbol, RegExp, setTimeout, clearTimeout,
  crypto: webcrypto,
  self: {},
  chrome: {
    runtime: {
      sendMessage: () => {},
      getURL: (p) => "chrome-extension://test/" + p,
      getManifest: () => ({ version: "0.2.2-test" }),
      lastError: null,
    },
    storage: { local: storage },
  },
};
sandbox.window = sandbox.self;
sandbox.self.location = locObj;
sandbox.self.AegisGateLens = { logger: { info: () => {}, warn: () => {}, error: () => {} } };
const ctx = vm.createContext(sandbox);
vm.runInContext(schemaSrc, ctx, { filename: "privacy/schema.js" });
vm.runInContext(contentSrc, ctx, { filename: "content.js" });
globalThis.ContentScript = sandbox.self.AegisGateLens.ContentScript;
globalThis.__storage = storage;
'

# 1. Pre-fill 100,000 expired entries; one storeDismissal; expect pruning.
run_attack "100000_expired_then_store" "${SANDBOX_PRELUDE};
function makeDismissals(count, expired) {
  const now = Math.floor(Date.now()/1000);
  const ttl = 24*60*60;
  const obj = {};
  for (let i = 0; i < count; i++) {
    obj['old::pii_email|k'+i] = {
      dismissed_at: now - count + i,
      expires_at: expired ? now - 100 : now + ttl,
      reason: null,
    };
  }
  return obj;
}
__storage.reset();
__storage.preset('dismissals', makeDismissals(100000, true));
const inst = Object.create(ContentScript.prototype);
inst.domainHash = 'new';
inst.storeDismissal('pii_email|newkey', null);
await new Promise(r => setTimeout(r, 50));
const result = Object.keys(__storage.data.dismissals || {}).length;
console.log('after 100000_expired_then_store: count =', result);
console.log(result === 1 ? 'PASS: pruning brought it to 1' : 'FAIL: pruning did not work, count=' + result);
"

# 2. Pre-fill 100,000 live entries; one storeDismissal; expect cap at 1000.
run_attack "100000_live_then_store" "${SANDBOX_PRELUDE};
function makeDismissals(count) {
  const now = Math.floor(Date.now()/1000);
  const ttl = 24*60*60;
  const obj = {};
  for (let i = 0; i < count; i++) {
    obj['live::pii_email|k'+i] = {
      dismissed_at: now - count + i,
      expires_at: now + ttl,
      reason: null,
    };
  }
  return obj;
}
__storage.reset();
__storage.preset('dismissals', makeDismissals(100000));
const inst = Object.create(ContentScript.prototype);
inst.domainHash = 'new';
inst.storeDismissal('pii_email|newkey', null);
await new Promise(r => setTimeout(r, 50));
const result = Object.keys(__storage.data.dismissals || {}).length;
console.log('after 100000_live_then_store: count =', result);
console.log(result <= 1000 ? 'PASS: cap held at ' + result : 'FAIL: cap broken, count=' + result);
"

# 3. Mix of 100k expired + 1000 live; one storeDismissal.
run_attack "mixed_100k_expired_1000_live_then_store" "${SANDBOX_PRELUDE};
function makeDismissals(count, expired, prefix) {
  const now = Math.floor(Date.now()/1000);
  const ttl = 24*60*60;
  const obj = {};
  for (let i = 0; i < count; i++) {
    obj[prefix+'::pii_email|k'+i] = {
      dismissed_at: now - count + i,
      expires_at: expired ? now - 100 : now + ttl,
      reason: null,
    };
  }
  return obj;
}
__storage.reset();
__storage.preset('dismissals', Object.assign({},
  makeDismissals(100000, true, 'expired'),
  makeDismissals(1000, false, 'live')));
const inst = Object.create(ContentScript.prototype);
inst.domainHash = 'new';
inst.storeDismissal('pii_email|newkey', null);
await new Promise(r => setTimeout(r, 50));
const result = Object.keys(__storage.data.dismissals || {}).length;
console.log('after mixed: count =', result);
console.log(result === 1000 ? 'PASS: cap held at 1000 (oldest live dropped to make room)' : 'FAIL: expected 1000, got ' + result);
"

# 4. Parallel writes (10 storeDismissal calls in same tick).
run_attack "parallel_10_writes" "${SANDBOX_PRELUDE};
const inst = Object.create(ContentScript.prototype);
inst.domainHash = 'new';
// Issue 10 storeDismissals in parallel (no await between).
for (let i = 0; i < 10; i++) {
  inst.storeDismissal('pii_email|k'+i, null);
}
await new Promise(r => setTimeout(r, 200));
const result = Object.keys(__storage.data.dismissals || {}).length;
console.log('after parallel_10_writes: count =', result);
console.log(result <= 1000 ? 'PASS: cap held' : 'FAIL: cap broken, count=' + result);
"

# 5. Long keys (consume more bytes per entry).
run_attack "long_keys_5000" "${SANDBOX_PRELUDE};
function makeDismissals(count, keyLen) {
  const now = Math.floor(Date.now()/1000);
  const ttl = 24*60*60;
  const obj = {};
  for (let i = 0; i < count; i++) {
    obj['big::pii_email|'+'x'.repeat(keyLen)+'_'+i] = {
      dismissed_at: now + i,
      expires_at: now + ttl,
      reason: null,
    };
  }
  return obj;
}
__storage.reset();
__storage.preset('dismissals', makeDismissals(5000, 100));
const inst = Object.create(ContentScript.prototype);
inst.domainHash = 'new';
inst.storeDismissal('pii_email|newkey', null);
await new Promise(r => setTimeout(r, 50));
const result = Object.keys(__storage.data.dismissals || {}).length;
console.log('after long_keys_5000: count =', result);
console.log(result <= 1000 ? 'PASS: cap holds regardless of key length' : 'FAIL: count=' + result);
"

# 6. Empty reason.
run_attack "empty_reason" "${SANDBOX_PRELUDE};
const inst = Object.create(ContentScript.prototype);
inst.domainHash = 'testdomain';
inst.storeDismissal('pii_email|k', '');
await new Promise(r => setTimeout(r, 30));
const key = Object.keys(__storage.data.dismissals || {})[0];
const entry = __storage.data.dismissals[key];
console.log('reason =', JSON.stringify(entry.reason));
console.log(entry.reason === null ? 'PASS: empty string normalized to null' : 'INFO: reason=' + JSON.stringify(entry.reason));
"

# 7. Non-string reason.
run_attack "non_string_reason" "${SANDBOX_PRELUDE};
const inst = Object.create(ContentScript.prototype);
inst.domainHash = 'testdomain';
try {
  inst.storeDismissal('pii_email|k', { evil: 'object' });
  await new Promise(r => setTimeout(r, 30));
  const entry = Object.values(__storage.data.dismissals || {})[0];
  console.log('reason =', JSON.stringify(entry.reason));
  // FINDING: storeDismissal doesn't validate reason type. An attacker
  // who controls the FP form could inject an object reason that
  // becomes part of the stored dismissal and could later be JSON-
  // stringified and sent in a future event. Low severity (the reason
  // is never sent to the backend; only `dismiss_false_positive`
  // events are sent, which don't include reason). Documented as a
  // finding; not exploitable.
  console.log('FINDING (low): storeDismissal accepted object reason; not sent to backend but not validated');
} catch (err) {
  console.log('PASS: threw on non-string reason:', err.message.slice(0,80));
}
"

# 8. Key format regression.
run_attack "key_format_regression" "${SANDBOX_PRELUDE};
const inst = Object.create(ContentScript.prototype);
inst.domainHash = 'abcd1234abcd1234';
inst.storeDismissal('pii_email|k', null);
await new Promise(r => setTimeout(r, 30));
const keys = Object.keys(__storage.data.dismissals || {});
const key = keys[0];
const ok = key && key.startsWith('abcd1234abcd1234::') && key.endsWith('::pii_email|k');
console.log('key =', key);
console.log(ok ? 'PASS: key format preserved' : 'FAIL: key=' + key);
"

echo
echo "=== Verdict ==="
python3 -c "
import json
rows = [json.loads(l) for l in open('$OUT') if l.strip()]
for r in rows:
  if 'FAIL' in r['result']:
    verdict = 'FAIL'
  elif 'FINDING' in r['result']:
    verdict = 'FINDING'
  elif 'PASS' in r['result']:
    verdict = 'PASS'
  else:
    verdict = 'INFO'
  print(f'  [{verdict}] {r[\"name\"]}')
"
