#!/bin/bash
# =========================================================================
# AegisGate Lens v0.2 — Chrome 120 launcher for testing
# =========================================================================
#
# Uses Chrome-for-Testing 120.0.6046.0 (downloaded 2026-06-28) on Xvfb display :88.
# Chrome 120 supports --load-extension (Chrome 130+ silently drops unpacked
# extensions in this environment; see test/eval/CHROME-LOAD-FIX-2026-06-28.md).
#
# Usage:
#   bash test/scripts/launch-chrome120.sh          # default port 9719
#   bash test/scripts/launch-chrome120.sh 9720     # custom port
#
# Once running, use ChromeDevTools MCP or raw CDP to drive the browser.
# ========================================================================
set +e

REPO="/home/chaos/Desktop/AegisGate/lens-repo-bootstrap-v02"
DIST="$REPO/lens-final-dist"
CHROME="$REPO/.chrome120/chrome-linux64/chrome"
PORT="${1:-9719}"
DATADIR="$REPO/.chrome120/chrome120-test"
LOG="$REPO/.chrome120/chrome120-launch.log"
DISPLAY_NUM="${DISPLAY_NUM:-88}"

if [ ! -f "$CHROME" ]; then
  echo "ERROR: Chrome 120 binary not found at $CHROME"
  echo "Download from: https://storage.googleapis.com/chrome-for-testing-public/120.0.6046.0/linux64/chrome-linux64.zip"
  exit 2
fi
if [ ! -f "$DIST/manifest.json" ]; then
  echo "ERROR: dist not found at $DIST — run build-v02-dist.sh first"
  exit 2
fi

# Cleanup old instances
pkill -9 -f "chrome-linux64.*${DATADIR}" 2>/dev/null
sleep 2
rm -rf "$DATADIR"
mkdir -p "$DATADIR"

# Start Xvfb if not already running on :88
if ! pgrep -f "Xvfb :${DISPLAY_NUM}" > /dev/null; then
  echo "Starting Xvfb on :${DISPLAY_NUM}..."
  Xvfb ":${DISPLAY_NUM}" -screen 0 1280x1024x24 > /tmp/xvfb${DISPLAY_NUM}.log 2>&1 &
  sleep 2
fi

echo "=== Chrome 120 test launch ===" > "$LOG"
echo "DIST:   $DIST" >> "$LOG"
echo "PORT:   $PORT" >> "$LOG"
echo "DATA:   $DATADIR" >> "$LOG"

DISPLAY=":${DISPLAY_NUM}" "$CHROME" \
  --no-sandbox \
  --disable-gpu \
  --user-data-dir="$DATADIR" \
  --remote-debugging-port="$PORT" \
  --remote-allow-origins='*' \
  --load-extension="$DIST" \
  --disable-extensions-except="$DIST" \
  --no-first-run \
  --noerrdialogs \
  about:blank >> "$LOG" 2>&1 &
PID=$!
echo "PID:    $PID" >> "$LOG"

# Wait for CDP
for i in $(seq 1 15); do
  sleep 1
  if curl -s --max-time 1 "http://localhost:$PORT/json/version" > /dev/null 2>&1; then
    echo "CDP ready after ${i}s" >> "$LOG"
    break
  fi
done

echo "" >> "$LOG"
echo "=== Targets ===" >> "$LOG"
curl -s --max-time 3 "http://localhost:$PORT/json" >> "$LOG" 2>&1

# Print log
cat "$LOG"