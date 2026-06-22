#!/usr/bin/env bash
# =========================================================================
# AegisGate Lens - Penetration Test Attack 01 (F-01)
# Foreign sender / Authorization bypass
# =========================================================================
#
# Threat-model finding F-01: Service worker accepts onMessage from any
# sender. Day 8 fix added sender.id validation. This attack tries to
# defeat the fix from the wire side by forging / replaying / smuggling
# tokens and headers.
#
# This script attacks the wire protocol, not the in-extension message
# bus. The Lens backend has its OWN auth (Bearer token); the attack
# surface here is:
#   1. No bearer token (should 401).
#   2. Wrong bearer token (should 401).
#   3. Bearer token in wrong header (e.g., X-Auth instead of Authorization).
#   4. Bearer token in query string (must NOT be honored).
#   5. Bearer token in cookie (must NOT be honored).
#   6. Bearer token smuggling via chunked transfer / duplicate headers.
#   7. Very long bearer token (DoS).
#
# Output: JSON evidence per attempt in pen-test/evidence/01-f01.json
# =========================================================================

set -euo pipefail

TARGET="${TARGET:-http://127.0.0.1:9999}"
GOOD_TOKEN="${GOOD_TOKEN:-pentest-token-12345}"
OUT="pen-test/evidence/01-f01.json"
mkdir -p pen-test/evidence

echo "=== Attack 01: F-01 Foreign sender / Authorization bypass ==="
echo "Target: $TARGET"
echo

# Helper: log an attempt with full HTTP details.
attempt() {
  local name="$1"
  local method="$2"
  local path="$3"
  shift 3
  local args=("$@")
  local resp status body

  resp=$(curl -s -w "\n__HTTP_STATUS__%{http_code}" "$@" "${TARGET}${path}" 2>&1 || true)
  status=$(echo "$resp" | sed -n 's/.*__HTTP_STATUS__\([0-9]*\)/\1/p' | tail -1)
  body=$(echo "$resp" | sed '/__HTTP_STATUS__/d')
  # Truncate long bodies for readability.
  body_short=$(echo "$body" | head -c 200)

  printf "  [%-50s] -> HTTP %s\n" "$name" "$status"

  # Append to JSON evidence.
  # Use python3 to build JSONL (jq may not be on host, but python3 is).
  python3 -c "
import json
entry = {
  'name': '$name',
  'method': '$method',
  'path': '$path',
  'status': int('$status') if '$status'.isdigit() else 0,
  'body': '''$body_short''',
}
print(json.dumps(entry))
" >> "$OUT.jsonl"
}

# Start fresh.
rm -f "$OUT.jsonl"

# 1. No bearer token.
attempt "no_token" GET "/api/v1/lens/stats"
# 2. Correct bearer token (sanity baseline).
attempt "correct_token" GET "/api/v1/lens/stats" \
  -H "Authorization: Bearer $GOOD_TOKEN"
# 3. Wrong bearer token.
attempt "wrong_token" GET "/api/v1/lens/stats" \
  -H "Authorization: Bearer wrong-token-xyz"
# 4. Lowercase scheme.
attempt "lowercase_bearer" GET "/api/v1/lens/stats" \
  -H "Authorization: bearer $GOOD_TOKEN"
# 5. Token in X-Auth header (should be ignored).
attempt "x_auth_header" GET "/api/v1/lens/stats" \
  -H "X-Auth: Bearer $GOOD_TOKEN"
# 6. Token in query string (should NOT be honored).
attempt "query_param_token" GET "/api/v1/lens/stats?token=$GOOD_TOKEN"
# 7. Token in cookie.
attempt "cookie_token" GET "/api/v1/lens/stats" \
  -H "Cookie: token=$GOOD_TOKEN"
# 8. Duplicate Authorization headers.
attempt "duplicate_auth_headers" GET "/api/v1/lens/stats" \
  -H "Authorization: Bearer wrong" \
  -H "Authorization: Bearer $GOOD_TOKEN"
# 9. Very long token (10KB).
LONG=$(printf 'A%.0s' {1..10240})
attempt "very_long_token" GET "/api/v1/lens/stats" \
  -H "Authorization: Bearer $LONG"
# 10. Token with leading whitespace (RFC 7235 says it should be tolerated,
#     but Go's http.Request sets it as-is).
attempt "leading_whitespace" GET "/api/v1/lens/stats" \
  -H "Authorization: Bearer  $GOOD_TOKEN"
# 11. POST with no body to a route that requires auth.
attempt "post_telemetry_no_auth" POST "/api/v1/lens/telemetry"
# 12. POST with valid token, valid body, malformed JSON.
attempt "post_telemetry_bad_json" POST "/api/v1/lens/telemetry" \
  -H "Authorization: Bearer $GOOD_TOKEN" \
  -H "Content-Type: application/json" \
  -d 'this is not json'

echo
echo "=== Verdict ==="
python3 -c "
import json, collections
rows = [json.loads(l) for l in open('$OUT.jsonl') if l.strip()]
buckets = collections.Counter(r['status'] for r in rows)
for status, count in sorted(buckets.items()):
    print(f'  HTTP {status}: {count} attempt(s)')
print(f'  total: {len(rows)} attempt(s)')
"
echo
echo "Evidence written to: $OUT.jsonl"
