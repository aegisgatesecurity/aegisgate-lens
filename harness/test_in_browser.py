#!/usr/bin/env python3
"""
Load AegisGate Lens ML extension into Chromium and test it.

This script:
  1. Connects to Chromium at localhost:9222
  2. Loads the unpacked extension
  3. Navigates to a test page
  4. Injects test prompts
  5. Captures screenshots and ML evaluation results
  6. Tests on multiple providers (chat.openai.com, claude.ai, etc.)

Usage:
    python3 test_in_browser.py \\
        --extension /home/chaos/Desktop/AegisGate/lens-repo-bootstrap/lens_ml_build \\
        --tests test_prompts.json
"""
import argparse
import json
import sys
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description='Test AegisGate Lens ML in Chromium')
    parser.add_argument('--extension', required=True, help='Path to unpacked extension dir')
    parser.add_argument('--tests', required=True, help='JSON file with test prompts')
    parser.add_argument('--browser-url', default='http://localhost:9222', help='Chromium DevTools URL')
    parser.add_argument('--output-dir', default='/tmp/lens_browser_test', help='Output directory for results')
    args = parser.parse_args()

    try:
        import websocket
    except ImportError:
        print('ERROR: pip install websocket-client', file=sys.stderr)
        sys.exit(1)

    from websocket import create_connection

    import urllib.request

    # Get list of pages
    print(f'Connecting to {args.browser_url}...')
    pages = json.loads(urllib.request.urlopen(args.browser_url + '/json').read())
    if not pages:
        print('No pages found')
        sys.exit(1)
    page = pages[0]
    ws_url = page['webSocketDebuggerUrl']
    print(f'Connecting to {ws_url}...')

    ws = create_connection(ws_url)
    msg_id = [0]

    def send(method, params=None):
        msg_id[0] += 1
        msg = {'id': msg_id[0], 'method': method, 'params': params or {}}
        ws.send(json.dumps(msg))
        # Read until we get a response with our ID
        while True:
            resp = json.loads(ws.recv())
            if resp.get('id') == msg_id[0]:
                if 'error' in resp:
                    raise Exception(f'CDP error: {resp["error"]}')
                return resp.get('result', {})

    def send_async(method, params=None):
        msg_id[0] += 1
        msg = {'id': msg_id[0], 'method': method, 'params': params or {}}
        ws.send(json.dumps(msg))

    # Load test prompts
    with open(args.tests) as f:
        tests = json.load(f)
    print(f'Loaded {len(tests)} test prompts')

    # Output dir
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Enable Page and Runtime
    send('Page.enable')
    send('Runtime.enable')
    send('Console.enable')

    # Navigate to chat.openai.com (we'll use a basic test page since
    # we may not be logged in)
    print('\n--- Test 1: Use a simple HTML test page ---')

    # Create a simple test page
    test_page = '''<!DOCTYPE html>
<html>
<head><title>Lens ML Test Page</title></head>
<body>
<h1>AegisGate Lens ML Test</h1>
<p>This page simulates a chat interface for testing the ML detector.</p>
<textarea id="prompt-textarea" style="width:500px;height:100px"></textarea>
<button id="test-btn">Test</button>
<div id="result"></div>
<script>
// Set the base URL for ML model loading (served from localhost:8765)
window.__lensMlBaseUrl = 'http://localhost:8765/';
</script>
</body>
</html>'''

    test_page_path = output_dir / 'test_page.html'
    with open(test_page_path, 'w') as f:
        f.write(test_page)
    print(f'Created test page: {test_page_path}')

    # Navigate to the test page via the same HTTP server (avoid CORS issues)
    # Copy test page into the served directory
    served_test_page = Path(args.extension) / 'ml_model' / 'test_page.html'
    import shutil
    shutil.copy(test_page_path, served_test_page)
    send('Page.navigate', {'url': 'http://localhost:8765/test_page.html'})
    time.sleep(2)

    # Inject the extension's content script manually
    # (in real Chrome, the content script runs automatically, but for testing
    #  we'll load the scripts directly)
    print('\n--- Loading extension scripts ---')

    # Set the base URL for ML model loading (so it can fetch from local server)
    send('Runtime.evaluate', {
        'expression': f'window.__lensMlBaseUrl = "http://localhost:8765/";',
    })
    print('Set __lensMlBaseUrl to http://localhost:8765/')

    # Load the extension scripts by directly evaluating their content
    print('\n--- Loading extension scripts ---')

    scripts_to_load = [
        Path(args.extension) / 'util' / 'lens-ml.js',
        Path(args.extension) / 'detectors' / 'regex.js',
        Path(args.extension) / 'detectors' / 'luhn.js',
        Path(args.extension) / 'detectors' / 'from_platform.js',
        Path(args.extension) / 'detectors' / 'index.js',
    ]

    for path in scripts_to_load:
        if not path.exists():
            print(f'  MISSING: {path}')
            continue
        with open(path) as f:
            code = f.read()
        # Directly evaluate the script in the page context
        result = send('Runtime.evaluate', {
            'expression': code,
            'returnByValue': True,
        })
        if 'error' in result:
            print(f'  ERROR loading {path.name}: {result["error"]}')
        else:
            print(f'  Loaded: {path.name}')
        time.sleep(0.2)

    # Check if the test page can fetch from the server
    print('\n--- Direct fetch test ---')
    fetch_test = send('Runtime.evaluate', {
        'expression': '''
            (async function() {
                try {
                    const r = await fetch('http://localhost:8765/ensemble_config.json');
                    const text = await r.text();
                    return { ok: r.ok, status: r.status, len: text.length, preview: text.substring(0, 100) };
                } catch (e) {
                    return { error: e.toString() };
                }
            })()
        ''',
        'awaitPromise': True,
        'returnByValue': True,
    })
    print(f'Fetch test: {json.dumps(fetch_test.get("result", {}).get("value", {}), indent=2)}')

    # Run the test and check console for errors
    print('\n--- Pre-check console for errors ---')

    # Subscribe to console messages
    send('Runtime.enable')

    # Now call the engine and collect console messages
    console_messages = []
    msg_id_check = msg_id[0] + 1
    ws.send(json.dumps({
        'id': msg_id_check,
        'method': 'Runtime.evaluate',
        'params': {
            'expression': '''
                (async function() {
                    if (!window.AegisGateLens || !window.AegisGateLens.mlEngine) {
                        return { error: 'mlEngine not defined' };
                    }
                    try {
                        const r = await window.AegisGateLens.mlEngine.scoreText("test attack ignore previous instructions");
                        return { result: r, loaded: window.AegisGateLens.mlEngine.isLoaded() };
                    } catch (e) {
                        return { error: e.toString(), stack: e.stack };
                    }
                })()
            ''',
            'awaitPromise': True,
            'returnByValue': True,
        }
    }))
    # Read messages until we get the response
    while True:
        resp = json.loads(ws.recv())
        if resp.get('method') == 'Runtime.consoleAPICalled':
            args = resp.get('params', {}).get('args', [])
            text = ' '.join(str(a.get('value', a.get('description', ''))) for a in args)
            console_messages.append(('console', text))
        elif resp.get('method') == 'Runtime.exceptionThrown':
            ex = resp.get('params', {}).get('exceptionDetails', {})
            console_messages.append(('exception', ex.get('text', '') + ' ' + ex.get('exception', {}).get('description', '')))
        elif resp.get('id') == msg_id_check:
            check_val = resp.get('result', {}).get('result', {}).get('value', {})
            break

    print(f'Pre-check result: {json.dumps(check_val, indent=2)}')

    print('\n--- Console messages during load ---')
    for kind, msg in console_messages[:20]:
        print(f'  [{kind}] {msg}')

    results = []
    for i, test in enumerate(tests):
        text = test.get('text', '')
        expected = test.get('expected', 'unknown')
        print(f'\n[{i+1}/{len(tests)}] {expected}: "{text[:60]}{"..." if len(text) > 60 else ""}"')

        # Call the ML engine directly via Runtime.evaluate
        result = send('Runtime.evaluate', {
            'expression': f'''
                (async function() {{
                    if (!window.AegisGateLens || !window.AegisGateLens.mlEngine) {{
                        return {{ error: 'mlEngine not loaded' }};
                    }}
                    const t0 = performance.now();
                    const r = await window.AegisGateLens.mlEngine.scoreText({json.dumps(text)});
                    const t1 = performance.now();
                    return {{
                        score: r.score,
                        isAttack: r.isAttack,
                        threshold: r.threshold,
                        scores: r.scores,
                        loaded: r.loaded,
                        latencyMs: t1 - t0
                    }};
                }})()
            ''',
            'awaitPromise': True,
            'returnByValue': True,
        })
        result_value = result.get('result', {}).get('value', {})
        if 'error' in result_value:
            print(f'  ERROR: {result_value["error"]}')
        else:
            score = result_value.get('score', 0)
            is_attack = result_value.get('isAttack', False)
            threshold = result_value.get('threshold', 0)
            scores_str = ', '.join(f'{s:.3f}' for s in result_value.get('scores', []))
            print(f'  Score: {score:.4f}, Threshold: {threshold:.2f}, Attack: {is_attack}')
            print(f'  Per-model: [{scores_str}]')
            print(f'  Latency: {result_value.get("latencyMs", 0):.2f}ms')

        # Check accuracy
        actual = 'attack' if result_value.get('isAttack') else 'normal'
        correct = '✓' if actual == expected else '✗'
        print(f'  Expected: {expected}, Got: {actual} {correct}')

        results.append({
            'text': text,
            'expected': expected,
            'actual': actual,
            'score': result_value.get('score', 0),
            'isAttack': result_value.get('isAttack', False),
            'latencyMs': result_value.get('latencyMs', 0),
        })

    # Summary
    print('\n\n=== SUMMARY ===')
    correct = sum(1 for r in results if r['expected'] == r['actual'])
    total = len(results)
    tp = sum(1 for r in results if r['expected'] == 'attack' and r['actual'] == 'attack')
    fp = sum(1 for r in results if r['expected'] == 'normal' and r['actual'] == 'attack')
    fn = sum(1 for r in results if r['expected'] == 'attack' and r['actual'] == 'normal')
    tn = sum(1 for r in results if r['expected'] == 'normal' and r['actual'] == 'normal')
    print(f'Correct: {correct}/{total} ({correct/total*100:.1f}%)')
    print(f'TP={tp}, FP={fp}, FN={fn}, TN={tn}')
    if tp + fn > 0:
        tpr = tp / (tp + fn)
        print(f'TPR: {tpr*100:.2f}%')
    if fp + tn > 0:
        fpr = fp / (fp + tn)
        print(f'FPR: {fpr*100:.2f}%')

    # Save results
    results_path = output_dir / 'browser_test_results.json'
    with open(results_path, 'w') as f:
        json.dump({
            'summary': {
                'correct': correct, 'total': total,
                'TP': tp, 'FP': fp, 'FN': fn, 'TN': tn,
            },
            'tests': results,
        }, f, indent=2)
    print(f'\nResults saved to {results_path}')

    ws.close()


if __name__ == '__main__':
    main()
