#!/usr/bin/env python3
"""
Test AegisGate Lens on real AI provider pages.

Usage:
    python3 test_real_provider.py \\
        --extension /home/chaos/Desktop/AegisGate/lens-repo-bootstrap/lens_ml_build \\
        --provider chatgpt \\
        --prompts /tmp/lens_test_prompts.json
"""
import argparse
import json
import sys
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description='Test on real AI provider')
    parser.add_argument('--extension', required=True)
    parser.add_argument('--provider', default='chatgpt', choices=['chatgpt', 'claude', 'gemini', 'copilot'])
    parser.add_argument('--prompts', required=True)
    parser.add_argument('--browser-url', default='http://localhost:9222')
    parser.add_argument('--output-dir', default='/tmp/lens_real_test')
    args = parser.parse_args()

    try:
        import websocket
    except ImportError:
        print('ERROR: pip install websocket-client', file=sys.stderr)
        sys.exit(1)
    from websocket import create_connection
    import urllib.request

    provider_urls = {
        'chatgpt': 'https://chat.openai.com',
        'claude': 'https://claude.ai',
        'gemini': 'https://gemini.google.com',
        'copilot': 'https://copilot.microsoft.com',
    }

    prompt_selectors = {
        'chatgpt': '#prompt-textarea',
        'claude': 'div[contenteditable="true"]',
        'gemini': 'div[contenteditable="true"]',
        'copilot': '#userInput',
    }

    print(f'Connecting to {args.browser_url}...')
    pages = json.loads(urllib.request.urlopen(args.browser_url + '/json').read())
    page = pages[0]
    ws_url = page['webSocketDebuggerUrl']
    print(f'Page: {page["title"]} ({page["url"]})')

    ws = create_connection(ws_url)
    msg_id = [0]
    def send(method, params=None):
        msg_id[0] += 1
        msg = {'id': msg_id[0], 'method': method, 'params': params or {}}
        ws.send(json.dumps(msg))
        while True:
            resp = json.loads(ws.recv())
            if resp.get('id') == msg_id[0]:
                if 'error' in resp:
                    return None
                return resp.get('result', {})

    with open(args.prompts) as f:
        tests = json.load(f)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Set up: Set __lensMlBaseUrl BEFORE navigation
    send('Page.enable')
    send('Runtime.enable')

    # Navigate to provider
    print(f'\n--- Navigating to {args.provider} ---')
    url = provider_urls[args.provider]
    send('Page.navigate', {'url': url})
    time.sleep(3)

    # Check if we landed on the right page
    nav_check = send('Runtime.evaluate', {
        'expression': 'window.location.href',
    })
    if nav_check:
        actual_url = nav_check.get('result', {}).get('value', '')
        print(f'Loaded: {actual_url[:80]}')
        if 'login' in actual_url.lower() or 'auth' in actual_url.lower():
            print('WARN: Page requires login, content script may not work')

    # Inject ML base URL
    send('Runtime.evaluate', {
        'expression': 'window.__lensMlBaseUrl = "http://localhost:8765/";',
    })

    # Inject the lens-ml.js script
    print('\n--- Loading scripts ---')
    ml_path = Path(args.extension) / 'util' / 'lens-ml.js'
    with open(ml_path) as f:
        code = f.read()
    send('Runtime.evaluate', {'expression': code})
    print(f'Loaded: {ml_path.name}')
    time.sleep(1)

    # Check if prompt selector exists
    sel = prompt_selectors[args.provider]
    has_prompt = send('Runtime.evaluate', {
        'expression': f'!!document.querySelector("{sel}")',
    })
    print(f'Prompt area "{sel}" exists: {has_prompt}')

    # Test prompts by typing into the prompt area
    print('\n--- Running tests on real page ---')
    results = []
    for i, test in enumerate(tests[:5]):  # First 5 only
        text = test.get('text', '')
        expected = test.get('expected', 'unknown')
        print(f'\n[{i+1}/{min(5, len(tests))}] {expected}: "{text[:50]}{"..." if len(text) > 50 else ""}"')

        # Set the prompt text via Runtime.evaluate
        set_result = send('Runtime.evaluate', {
            'expression': f'''
                (function() {{
                    const el = document.querySelector("{sel}");
                    if (!el) return {{ error: 'no prompt element' }};
                    if (el.tagName === 'TEXTAREA') {{
                        const setter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value').set;
                        setter.call(el, {json.dumps(text)});
                        el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                    }} else if (el.isContentEditable) {{
                        el.textContent = {json.dumps(text)};
                        el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                    }}
                    return {{ ok: true, value: el.value || el.textContent }};
                }})()
            ''',
            'returnByValue': True,
        })
        if not set_result or 'error' in str(set_result.get('result', {}).get('value', '')):
            err = set_result.get('result', {}).get('value', {}).get('error', 'unknown') if set_result else 'no result'
            print(f'  Could not set prompt: {err}')
            continue

        # Wait for detect cycle
        time.sleep(1)

        # Check if banner is showing
        banner = send('Runtime.evaluate', {
            'expression': '!!document.getElementById("__aegisgate_lens_banner__")',
        })
        banner_visible = banner.get('result', {}).get('value', False) if banner else False
        print(f'  Banner visible: {banner_visible}')

        # Get banner content
        if banner_visible:
            content = send('Runtime.evaluate', {
                'expression': '''
                    (function() {
                        const b = document.getElementById('__aegisgate_lens_banner__');
                        return b ? b.textContent.substring(0, 200) : '';
                    })()
                ''',
                'returnByValue': True,
            })
            text_content = content.get('result', {}).get('value', '') if content else ''
            print(f'  Banner text: {text_content[:100]}...')

        # Screenshot
        ss = send('Page.captureScreenshot', {'format': 'png'})
        if ss and 'data' in ss:
            ss_path = output_dir / f'{args.provider}_test_{i+1}.png'
            import base64
            with open(ss_path, 'wb') as f:
                f.write(base64.b64decode(ss['data']))
            print(f'  Screenshot: {ss_path}')

        results.append({
            'text': text,
            'expected': expected,
            'banner_visible': banner_visible,
        })

    # Save results
    results_path = output_dir / f'{args.provider}_results.json'
    with open(results_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f'\nResults: {results_path}')

    ws.close()


if __name__ == '__main__':
    main()
