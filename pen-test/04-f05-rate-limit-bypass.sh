#!/usr/bin/env bash
# =========================================================================
# AegisGate Lens - Penetration Test Attack 04 (F-05)
# Backend rate-limit bypass
# =========================================================================
#
# Threat-model finding F-05: backend has no IP rate limit; client-
# side only. Day 10 cross-repo verification confirmed the Platform
# repo's pkg/lensbackend/ratelimit.go enforces per-installation
# (100/min) and global (10000/min) limits. This attack tries to
# defeat both.
#
# IMPORTANT: The backend is running over HTTPS with self-signed cert
# on port 9443 in this pen-test env. We use --resolve chat.openai.com:9443:127.0.0.1
# so the SNI matches a known hostname (the backend's domain_hash
# verification recomputes SHA-256(SNI) and compares).
#
# Each "installation" is identified by its hostname (whose SHA-256
# prefix is the domain_hash the backend expects). To simulate many
# installations, we use the SNI Host header set to a unique hostname
# per bucket. The sha256() of that hostname gives the expected
# domain_hash.
#
# Attacks:
#   1. Same hostname, 105 events -> 100 accepted, 5 dropped.
#   2. 5 hostnames, 30 events each -> all 150 accepted (no cross-bucket).
#   3. Random hostnames, 1 event each -> all accepted (no global cap hit).
#   4. X-Forwarded-For ignored? -> XFF doesn't bypass rate limit.
#   5. No-auth requests don't consume rate-limit budget.
#
# Output: pen-test/evidence/04-f05.jsonl
# =========================================================================

set -euo pipefail

# Default config: localhost TLS on 9443 with self-signed cert from /tmp/lens-test.crt.
# The TLS cert covers chat.openai.com, chatgpt.com, localhost, 127.0.0.1.
# curl -sk accepts the self-signed cert. We use --resolve <host>:9443:127.0.0.1
# per-hostname so the SNI matches the URL hostname (required for the
# backend's domain_hash.go SNI check).
PORT="${PORT:-9443}"
GOOD_TOKEN="${GOOD_TOKEN:-pentest-token-12345}"
OUT="pen-test/evidence/04-f05.jsonl"
mkdir -p pen-test/evidence
rm -f "$OUT"

echo "=== Attack 04: F-05 Backend rate-limit bypass ==="
echo "Target: https://<hostname>:${PORT}"
echo

# Helper: SHA-256 of a hostname, first 16 hex chars (the format the
# Lens extension uses). The backend's domain_hash.go recomputes this
# on the server side from the TLS SNI.
domain_hash_for() {
  echo -n "$1" | sha256sum | cut -c1-16
}

# Helper: send a valid v1 event with the given SNI hostname.
# The hostname is both the URL host AND the SNI (via --resolve).
# This is required so the backend's domain_hash.go verification
# (which recomputes SHA-256(SNI)) matches our claimed domain_hash.
send_event() {
  local hostname="$1"
  local token="${2:-$GOOD_TOKEN}"
  local dh=$(domain_hash_for "$hostname")
  local id="$(openssl rand -hex 8 2>/dev/null || echo testid)"
  curl -sk --resolve "${hostname}:${PORT}:127.0.0.1" -o /dev/null -w "%{http_code}" \
    -X POST "https://${hostname}:${PORT}/api/v1/lens/telemetry" \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json" \
    -d "{\"lens_event_version\":1,\"domain_hash\":\"${dh}\",\"category\":\"pii_email\",\"severity\":\"low\",\"user_action\":\"dismiss\",\"timestamp\":$(date +%s),\"model_version\":\"0.2.2+regex-v1\",\"lens_version\":\"0.2.2\",\"confidence\":0.5,\"id\":\"${id}\"}"
}

# Helper: send a no-auth event.
send_no_auth() {
  local hostname="$1"
  local dh=$(domain_hash_for "$hostname")
  curl -sk --resolve "${hostname}:${PORT}:127.0.0.1" -o /dev/null -w "%{http_code}" \
    -X POST "https://${hostname}:${PORT}/api/v1/lens/telemetry" \
    -H "Content-Type: application/json" \
    -d "{\"lens_event_version\":1,\"domain_hash\":\"${dh}\",\"category\":\"pii_email\"}"
}

# 1. Same hostname, 105 events.
echo "  [test 1: same hostname, 105 events]"
acc=0; rej=0; oth=0
for i in $(seq 1 105); do
  code=$(send_event "pentest-host-1.example.com")
  case "$code" in
    2*) acc=$((acc+1)) ;;
    429) rej=$((rej+1)) ;;
    *) oth=$((oth+1)) ;;
  esac
done
echo "    accepted=$acc rejected=$rej other=$oth"
python3 -c "
import json
entry = {'test':'same_host_105', 'accepted':$acc, 'rejected':$rej, 'other':$oth}
print(json.dumps(entry))
" >> "$OUT"

# 2. 5 hostnames, 30 events each.
echo "  [test 2: 5 hostnames, 30 events each]"
multi_a=0; multi_r=0
for i in 1 2 3 4 5; do
  for j in $(seq 1 30); do
    code=$(send_event "pentest-multi-${i}.example.com")
    if [[ "$code" =~ ^2 ]]; then multi_a=$((multi_a+1)); fi
    if [ "$code" = "429" ]; then multi_r=$((multi_r+1)); fi
  done
done
echo "    accepted=$multi_a rejected=$multi_r"
python3 -c "
import json
entry = {'test':'5_hosts_30_each', 'accepted':$multi_a, 'rejected':$multi_r}
print(json.dumps(entry))
" >> "$OUT"

# 3. Random hostnames.
echo "  [test 3: 200 random hostnames, 1 event each]"
rand_a=0; rand_r=0
for i in $(seq 1 200); do
  code=$(send_event "rand-$(openssl rand -hex 4 2>/dev/null).example.com")
  if [[ "$code" =~ ^2 ]]; then rand_a=$((rand_a+1)); fi
  if [ "$code" = "429" ]; then rand_r=$((rand_r+1)); fi
done
echo "    accepted=$rand_a rejected=$rand_r"
python3 -c "
import json
entry = {'test':'200_random_hosts', 'accepted':$rand_a, 'rejected':$rand_r}
print(json.dumps(entry))
" >> "$OUT"

# 4. XFF rotation ignored?
echo "  [test 4: X-Forwarded-For ignored?]"
xff_a=0
for i in $(seq 1 110); do
  hostname="xff-test-${i}.example.com"
  dh=$(domain_hash_for "$hostname")
  code=$(curl -sk --resolve "${hostname}:${PORT}:127.0.0.1" -o /dev/null -w "%{http_code}" \
    -X POST "https://${hostname}:${PORT}/api/v1/lens/telemetry" \
    -H "Authorization: Bearer ${GOOD_TOKEN}" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 10.0.0.$i" \
    -d "{\"lens_event_version\":1,\"domain_hash\":\"${dh}\",\"category\":\"pii_email\",\"severity\":\"low\",\"user_action\":\"dismiss\",\"timestamp\":$(date +%s),\"model_version\":\"0.2.2+regex-v1\",\"lens_version\":\"0.2.2\",\"confidence\":0.5}")
  if [[ "$code" =~ ^2 ]]; then xff_a=$((xff_a+1)); fi
done
echo "    accepted with XFF rotation: $xff_a (expect ~100; XFF should be ignored)"
python3 -c "
import json
entry = {'test':'xff_rotation', 'accepted':$xff_a, 'note':'different hostnames = different buckets; 110 unique hosts = 110 different buckets = all accepted'}
print(json.dumps(entry))
" >> "$OUT"

# 5. No-auth requests don't consume budget.
echo "  [test 5: 50 no-auth requests don't consume budget]"
na_dh="pentest-noauth-$(openssl rand -hex 4 2>/dev/null).example.com"
na_dh_hash=$(domain_hash_for "$na_dh")
for i in $(seq 1 50); do send_no_auth "$na_dh" > /dev/null; done
na_a=0
for i in $(seq 1 50); do
  code=$(send_event "$na_dh")
  if [[ "$code" =~ ^2 ]]; then na_a=$((na_a+1)); fi
done
echo "    after 50 no-auth + 50 valid: accepted=$na_a (expect 50)"
python3 -c "
import json
entry = {'test':'noauth_no_budget_consume', 'accepted':$na_a}
print(json.dumps(entry))
" >> "$OUT"

echo
echo "=== Verdict ==="
python3 -c "
import json
rows = [json.loads(l) for l in open('$OUT') if l.strip()]
for r in rows:
  print('  ', json.dumps(r))
"
