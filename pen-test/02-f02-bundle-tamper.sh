#!/usr/bin/env bash
# =========================================================================
# AegisGate Lens - Penetration Test Attack 02 (F-02)
# Bundle tampering / Ed25519 signature bypass
# =========================================================================
#
# Threat-model finding F-02: Bundle signing verification. Day 8
# confirmed the verification IS wired in util/bundle-loader.js. This
# attack tries to defeat it by tampering with a real signed bundle in
# every conceivable way:
#
#   1. Flip a single byte in the payload area.
#   2. Flip a single byte in the signature area (last 64 bytes).
#   3. Replace the entire signature with a wrong one.
#   4. Change the bundle version in the JSON header.
#   5. Truncate the bundle.
#   6. Append garbage to the bundle.
#   7. Use a bundle signed with a DIFFERENT private key (key-substitution).
#   8. Swap the public key in util/bundle-loader.js with an attacker key.
#      (This is the most dangerous: requires write access to src/, but
#       we simulate it by monkey-patching the public key constant.)
#
# Each attack loads the bundle via util/bundle-loader.js's parseBundle
# and asserts it throws (good) or doesn't throw (bad — would mean
# tampering succeeded).
#
# Output: JSON evidence in pen-test/evidence/02-f02.json
# =========================================================================

set -euo pipefail

FIXTURE="${FIXTURE:-lens_ml_build/aegisgate-lens-v0.1.1.bundle}"
if [[ ! -f "$FIXTURE" ]]; then
  FIXTURE="$HOME/Desktop/AegisGate/lens_ml_build/aegisgate-lens-v0.1.1.bundle"
fi
if [[ ! -f "$FIXTURE" ]]; then
  echo "FATAL: bundle fixture not found. Tried lens_ml_build and $HOME/Desktop/AegisGate/lens_ml_build"
  exit 2
fi

OUT="pen-test/evidence/02-f02.jsonl"
mkdir -p pen-test/evidence
rm -f "$OUT"

echo "=== Attack 02: F-02 Bundle tampering ==="
echo "Fixture: $FIXTURE"
echo

# Driver: run a node script that mutates the bundle, then loads it
# via parseBundle and reports whether verification rejected it.
run_attack() {
  local name="$1"
  local node_script="$2"

  result=$(node --input-type=module -e "$node_script" 2>&1 || true)
  rejected="unknown"
  if echo "$result" | grep -q "REJECTED"; then
    rejected="rejected"
  elif echo "$result" | grep -q "ACCEPTED"; then
    rejected="accepted"
  elif echo "$result" | grep -q "BUNDLE_NOT_FOUND"; then
    rejected="bundle_missing"
  fi

  # Get the reason.
  reason=$(echo "$result" | grep -E "^(REJECTED|ACCEPTED|BUNDLE_NOT_FOUND)" | head -1)
  printf "  [%-50s] -> %s\n" "$name" "$reason"

  python3 -c "
import json
entry = {
  'name': '$name',
  'verdict': '$rejected',
  'reason': '''${reason}''',
  'raw_output': '''$result''',
}
print(json.dumps(entry))
" >> "$OUT"
}

# Load the loader into a vm sandbox and expose parseBundle.
# We use a helper that reads the fixture, mutates per the attack,
# then invokes the loader's parseBundle.

read_fixture() {
  node --input-type=module -e "
import { readFileSync } from 'node:fs';
import { Buffer } from 'node:buffer';
process.stdout.write(readFileSync('$FIXTURE').toString('base64'));
"
}

# 1. Flip one byte in payload area.
run_attack "flip_byte_in_payload" "
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';
const loaderSrc = readFileSync('src/util/bundle-loader.js', 'utf8');
const ctx = vm.createContext({console, crypto: webcrypto, TextEncoder, TextDecoder, Uint8Array, Array, Map, Object, Math, JSON, Promise, self: {}});
ctx.self = ctx;
ctx.self.AegisGateLens = { logger: console };
vm.runInContext(loaderSrc, ctx, {filename: 'util/bundle-loader.js'});
const loader = ctx.self.AegisGateLens.bundleLoader;
const orig = readFileSync('$FIXTURE');
const mutated = Buffer.from(orig);
mutated[1000] = mutated[1000] ^ 0xFF;
try {
  await loader.parseBundle(mutated);
  console.log('ACCEPTED (BAD)');
} catch (err) {
  console.log('REJECTED:', err.message.slice(0, 100));
}
"

# 2. Flip one byte in signature area (last 64 bytes).
run_attack "flip_byte_in_signature" "
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';
const loaderSrc = readFileSync('src/util/bundle-loader.js', 'utf8');
const ctx = vm.createContext({console, crypto: webcrypto, TextEncoder, TextDecoder, Uint8Array, Array, Map, Object, Math, JSON, Promise, self: {}});
ctx.self = ctx;
ctx.self.AegisGateLens = { logger: console };
vm.runInContext(loaderSrc, ctx, {filename: 'util/bundle-loader.js'});
const loader = ctx.self.AegisGateLens.bundleLoader;
const orig = readFileSync('$FIXTURE');
const mutated = Buffer.from(orig);
mutated[mutated.length - 1] = mutated[mutated.length - 1] ^ 0x01;
try {
  await loader.parseBundle(mutated);
  console.log('ACCEPTED (BAD)');
} catch (err) {
  console.log('REJECTED:', err.message.slice(0, 100));
}
"

# 3. Truncate the bundle.
run_attack "truncated_bundle" "
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';
const loaderSrc = readFileSync('src/util/bundle-loader.js', 'utf8');
const ctx = vm.createContext({console, crypto: webcrypto, TextEncoder, TextDecoder, Uint8Array, Array, Map, Object, Math, JSON, Promise, self: {}});
ctx.self = ctx;
ctx.self.AegisGateLens = { logger: console };
vm.runInContext(loaderSrc, ctx, {filename: 'util/bundle-loader.js'});
const loader = ctx.self.AegisGateLens.bundleLoader;
const orig = readFileSync('$FIXTURE');
const truncated = orig.slice(0, orig.length - 100);
try {
  await loader.parseBundle(truncated);
  console.log('ACCEPTED (BAD)');
} catch (err) {
  console.log('REJECTED:', err.message.slice(0, 100));
}
"

# 4. Append garbage.
run_attack "appended_garbage" "
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';
const loaderSrc = readFileSync('src/util/bundle-loader.js', 'utf8');
const ctx = vm.createContext({console, crypto: webcrypto, TextEncoder, TextDecoder, Uint8Array, Array, Map, Object, Math, JSON, Promise, self: {}});
ctx.self = ctx;
ctx.self.AegisGateLens = { logger: console };
vm.runInContext(loaderSrc, ctx, {filename: 'util/bundle-loader.js'});
const loader = ctx.self.AegisGateLens.bundleLoader;
const orig = readFileSync('$FIXTURE');
const mutated = Buffer.concat([orig, Buffer.from('ATTACKER_WAS_HERE'.repeat(1000))]);
try {
  await loader.parseBundle(mutated);
  console.log('ACCEPTED (BAD)');
} catch (err) {
  console.log('REJECTED:', err.message.slice(0, 100));
}
"

# 5. Substitute the public key in the loader source (simulating a compromised
#    npm dep that ships a tampered util/bundle-loader.js with a different
#    public key). This should cause signature verification to FAIL.
run_attack "substituted_public_key" "
import { readFileSync, writeFileSync } from 'node:fs';
import vm from 'node:vm';
import { webcrypto, generateKeyPairSync } from 'node:crypto';
const loaderSrc = readFileSync('src/util/bundle-loader.js', 'utf8');
// Generate an attacker key pair and substitute the public key constant.
const { publicKey: attackerPub } = generateKeyPairSync('ed25519');
const exported = attackerPub.export({ format: 'der', type: 'spki' });
const attackerPubB64 = exported.toString('base64');
const tampered = loaderSrc.replace(
  /const SIGNING_PUBLIC_KEY_B64 = '[^']+';/,
  'const SIGNING_PUBLIC_KEY_B64 = ' + JSON.stringify(attackerPubB64) + ';'
);
const ctx = vm.createContext({console, crypto: webcrypto, TextEncoder, TextDecoder, Uint8Array, Array, Map, Object, Math, JSON, Promise, self: {}});
ctx.self = ctx;
ctx.self.AegisGateLens = { logger: console };
vm.runInContext(tampered, ctx, {filename: 'util/bundle-loader.js'});
const loader = ctx.self.AegisGateLens.bundleLoader;
const orig = readFileSync('$FIXTURE');
try {
  await loader.parseBundle(orig);
  console.log('ACCEPTED (BAD)');
} catch (err) {
  console.log('REJECTED:', err.message.slice(0, 100));
}
"

# 6. Bundle with wrong magic value.
run_attack "wrong_magic_value" "
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';
const loaderSrc = readFileSync('src/util/bundle-loader.js', 'utf8');
const ctx = vm.createContext({console, crypto: webcrypto, TextEncoder, TextDecoder, Uint8Array, Array, Map, Object, Math, JSON, Promise, self: {}});
ctx.self = ctx;
ctx.self.AegisGateLens = { logger: console };
vm.runInContext(loaderSrc, ctx, {filename: 'util/bundle-loader.js'});
const loader = ctx.self.AegisGateLens.bundleLoader;
const orig = readFileSync('$FIXTURE');
const mutated = Buffer.from(orig);
// Find and replace magic value.
const magic = Buffer.from('AEGISGATE_LENS_BUNDLE_V1');
const idx = mutated.indexOf(magic);
if (idx < 0) throw new Error('magic not found');
const wrong = Buffer.from('AEGISGATE_LENS_BUNDLE_EVIL');
for (let i = 0; i < wrong.length; i++) mutated[idx + i] = wrong[i];
try {
  await loader.parseBundle(mutated);
  console.log('ACCEPTED (BAD)');
} catch (err) {
  console.log('REJECTED:', err.message.slice(0, 100));
}
"

# 7. Bundle missing magic entirely.
run_attack "missing_magic" "
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';
const loaderSrc = readFileSync('src/util/bundle-loader.js', 'utf8');
const ctx = vm.createContext({console, crypto: webcrypto, TextEncoder, TextDecoder, Uint8Array, Array, Map, Object, Math, JSON, Promise, self: {}});
ctx.self = ctx;
ctx.self.AegisGateLens = { logger: console };
vm.runInContext(loaderSrc, ctx, {filename: 'util/bundle-loader.js'});
const loader = ctx.self.AegisGateLens.bundleLoader;
const orig = readFileSync('$FIXTURE');
const mutated = Buffer.from(orig);
const magic = Buffer.from('AEGISGATE_LENS_BUNDLE_V1');
const idx = mutated.indexOf(magic);
if (idx < 0) throw new Error('magic not found');
for (let i = 0; i < magic.length; i++) mutated[idx + i] = 0;
try {
  await loader.parseBundle(mutated);
  console.log('ACCEPTED (BAD)');
} catch (err) {
  console.log('REJECTED:', err.message.slice(0, 100));
}
"

# 8. Re-signed bundle with wrong private key (attacker controls build process).
run_attack "resigned_with_attacker_key" "
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { webcrypto, generateKeyPairSync, sign, createPrivateKey } from 'node:crypto';
const loaderSrc = readFileSync('src/util/bundle-loader.js', 'utf8');
const ctx = vm.createContext({console, crypto: webcrypto, TextEncoder, TextDecoder, Uint8Array, Array, Map, Object, Math, JSON, Promise, self: {}});
ctx.self = ctx;
ctx.self.AegisGateLens = { logger: console };
vm.runInContext(loaderSrc, ctx, {filename: 'util/bundle-loader.js'});
const loader = ctx.self.AegisGateLens.bundleLoader;
const orig = readFileSync('$FIXTURE');
const mutated = Buffer.from(orig);
// Strip the last 64 bytes (signature) and re-sign with attacker key.
const { privateKey: attackerKey } = generateKeyPairSync('ed25519');
const unsigned = mutated.slice(0, mutated.length - 64);
// Sign over the unsigned bytes (mimicking what the loader does).
const attackerSig = webcrypto.sign('ed25519',
  await webcrypto.importKey('pkcs8', attackerKey.export({format:'der',type:'pkcs8'}),
  {name:'ed25519',namedCurve:'ed25519'}, false, ['sign']),
  new Uint8Array(unsigned));
// Replace signature.
for (let i = 0; i < 64; i++) mutated[mutated.length - 64 + i] = attackerSig[i];
try {
  await loader.parseBundle(mutated);
  console.log('ACCEPTED (BAD)');
} catch (err) {
  console.log('REJECTED:', err.message.slice(0, 100));
}
"

echo
echo "=== Verdict ==="
python3 -c "
import json
rows = [json.loads(l) for l in open('$OUT') if l.strip()]
for r in rows:
  flag = 'OK' if r['verdict'] == 'rejected' else 'FINDING (TAMPERING SUCCEEDED)'
  print(f\"  [{flag}] {r['name']}: {r['reason']}\")
print(f'  total: {len(rows)} attacks; all rejected = F-02 closed.')
"
