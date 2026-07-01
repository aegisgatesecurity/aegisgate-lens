#!/usr/bin/env python3
"""
AegisGate Lens v0.2 — Firefox Lane (M1-M4) using mock ONNX

Drives Firefox via geckodriver W3C protocol to test:
  M1: Fixture loads + WebGPU probe (env probe)
  M2: Mock ONNX session via prewarm() (validates JS pipeline end-to-end)
  M3: Sliding-window test cases (real JS sliding logic)
  M4: JS-only latency benchmark

Outputs: test/eval/firefox-m1-m4-results.{json,md}
"""
import json
import time
import subprocess
import urllib.request
import socket
import os
import sys
from pathlib import Path

REPO = Path('/home/chaos/Desktop/AegisGate/lens-repo-bootstrap-v02')
GECKO_PORT = 9580


def w3c(method, endpoint, body=None, timeout=60):
    """W3C WebDriver request to geckodriver."""
    import urllib.request as ur
    url = f'http://localhost:{GECKO_PORT}/session/{SID}/{endpoint}'
    data = json.dumps(body).encode() if body else None
    headers = {'Content-Type': 'application/json'} if body else {}
    req = ur.Request(url, method=method, data=data, headers=headers)
    try:
        resp = json.loads(ur.urlopen(req, timeout=timeout).read())
        if 'value' in resp:
            return resp['value']
        return resp
    except urllib.error.HTTPError as e:
        return {'error': e.code, 'body': e.read().decode()[:500]}


# ============================================================================
# STEP 1: Setup (Xvfb, fixture server, geckodriver, Firefox session)
# ============================================================================
print('=== Setup ===')
for proc in ['firefox', 'geckodriver', 'serve.py']:
    subprocess.run(['pkill', '-9', '-f', proc], capture_output=True)
subprocess.run(['pkill', '-9', '-f', 'Xvfb :77'], capture_output=True)
time.sleep(2)

# Xvfb on :77
xvfb = subprocess.Popen(['Xvfb', ':77', '-screen', '0', '1280x1024x24'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
os.environ['DISPLAY'] = ':77'
time.sleep(2)

# Fixture server on 8765
try:
    s = socket.socket(); s.bind(('127.0.0.1', 8765)); s.close()
except OSError:
    subprocess.run(['pkill', '-9', '-f', 'serve.py'], capture_output=True)
    time.sleep(1)
server = subprocess.Popen(['python3', str(REPO / 'test' / 'firefox' / 'serve.py')],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2)
try:
    urllib.request.urlopen('http://localhost:8765/logic-test.html', timeout=3)
    print('  ✅ fixture server up')
except Exception as e:
    print(f'  ❌ server: {e}'); sys.exit(2)

# Geckodriver on 9580
gecko = subprocess.Popen(['/home/chaos/.local/bin/geckodriver', '--port', str(GECKO_PORT)],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(3)

# Firefox session
import urllib.request as ur
req = ur.Request(f'http://localhost:{GECKO_PORT}/session',
                  method='POST',
                  data=json.dumps({
                      'capabilities': {
                          'alwaysMatch': {
                              'browserName': 'firefox',
                              'moz:firefoxOptions': {
                                  'args': [],
                                  'prefs': {
                                      'webgpu.disabled': False,
                                      'dom.webgpu.enabled': True,
                                  },
                              },
                          }
                      }
                  }).encode(),
                  headers={'Content-Type': 'application/json'})
resp = json.loads(ur.urlopen(req, timeout=30).read())
SID = resp['sessionId']
print(f'  ✅ Firefox session: {SID}')

# Navigate to logic-test page
w3c('POST', 'url', {'url': 'http://localhost:8765/logic-test.html'}, timeout=30)
time.sleep(5)

# ============================================================================
# M1: Environment probe
# ============================================================================
print('\n=== M1: Environment probe ===')
env = w3c('POST', 'execute/sync', {
    'script': 'return JSON.stringify({webgpu: typeof navigator.gpu !== "undefined", hasAGL: typeof window.AegisGateLens !== "undefined", hasTM: !!(window.AegisGateLens && window.AegisGateLens.util && window.AegisGateLens.util.transformerModernBert), threshold: window.AegisGateLens && window.AegisGateLens.util && window.AegisGateLens.util.transformerModernBert ? window.AegisGateLens.util.transformerModernBert.getConfig().threshold : null, config: window.AegisGateLens && window.AegisGateLens.util && window.AegisGateLens.util.transformerModernBert ? window.AegisGateLens.util.transformerModernBert.getConfig() : null})',
    'args': [],
})
print(f'  {env}')

# ============================================================================
# M2: Prewarm with mock ONNX session
# ============================================================================
print('\n=== M2: Mock ONNX prewarm ===')
# Wait for page IIFE prewarm to complete (it prewarms with mock on load)
time.sleep(3)
m2_status = w3c('POST', 'execute/sync', {
    'script': 'return document.getElementById("prewarm").textContent',
    'args': [],
})
print(f'  Status: {m2_status}')

# Force a fresh prewarm to make sure
prewarm_js = '''(function(){
  var sess = {inputNames:["input_ids","attention_mask"], outputNames:["logits"],
    run: function(feeds){ return Promise.resolve({logits: {dims:[1,2], data: new Float32Array([1.0, 0.0])}}); }};
  var tok = function(text){ return {input_ids: new BigInt64Array(2), attention_mask: new BigInt64Array(2)}; };
  return window.AegisGateLens.util.transformerModernBert._reset()
    .then(function(){
      return window.AegisGateLens.util.transformerModernBert.prewarm({
        session: sess, tokenizer: tok,
        tokenizerConfig: {cls_token_id:0, sep_token_id:1, pad_token_id:2, unk_token_id:3}
      });
    }).then(function(){ return "prewarmed"; }).catch(function(e){ return "ERR: " + e.message; });
})()'''
m2_result = w3c('POST', 'execute/sync', {'script': prewarm_js, 'args': []})
print(f'  Result: {m2_result}')

# ============================================================================
# M3: Test cases
# ============================================================================
print('\n=== M3: Test cases (click button) ===')
w3c('POST', 'execute/sync', {
    'script': 'document.getElementById("btnTest").click()',
    'args': [],
})
time.sleep(2)
m3_results_text = w3c('POST', 'execute/sync', {
    'script': 'return document.getElementById("results").textContent',
    'args': [],
})
print(f'  Results:\n{m3_results_text}')

# Parse M3 results
m3_results = []
if m3_results_text:
    for line in m3_results_text.split('\n'):
        if '✅' in line or '❌' in line:
            passed = '✅' in line
            m3_results.append({'name': line.strip(), 'passed': passed})

# ============================================================================
# M4: Latency benchmark
# ============================================================================
print('\n=== M4: Latency benchmark (click button) ===')
w3c('POST', 'execute/sync', {
    'script': 'document.getElementById("btnBench").click()',
    'args': [],
})
time.sleep(10)  # Let benchmark complete
m4_results_text = w3c('POST', 'execute/sync', {
    'script': 'return document.getElementById("benchResults").textContent',
    'args': [],
})
print(f'  Results:\n{m4_results_text}')

# Get structured benchmark data
bench_data = w3c('POST', 'execute/sync', {
    'script': 'return JSON.stringify(window.__BENCHMARK__ || {})',
    'args': [],
})
print(f'  Bench data: {bench_data}')

# ============================================================================
# Save + summary
# ============================================================================
out_dir = REPO / 'test/eval'
out_dir.mkdir(exist_ok=True)
results = {
    'timestamp': '2026-06-28',
    'm1_environment': env,
    'm2_prewarm': {'status': m2_status, 'result': m2_result},
    'm3_test_cases': m3_results_text,
    'm3_parsed': m3_results,
    'm4_latency': m4_results_text,
    'm4_data': bench_data,
}
(out_dir / 'firefox-m1-m4-results.json').write_text(json.dumps(results, indent=2, default=str))

print('\n=== Done ===')
print(f'Session {SID} still alive for further manual testing.')
print('Cleanup: w3c DELETE on the session, then kill gecko/xvfb/server')

# Don't cleanup — leave running so user can do additional tests
# Subprocess cleanup happens when parent script exits