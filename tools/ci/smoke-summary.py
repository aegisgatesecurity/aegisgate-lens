#!/usr/bin/env python3
"""
v0.1.3 B6fix3: parse a smoke-report.json and print a summary.

Used by the CI workflow after the headless smoke test runs. The
smoke binary writes smoke-report.json in the repo root; this
script reads it and prints a human-readable summary (and a
non-zero exit code if the gate is false).

Apache 2.0. Copyright 2026 AegisGate Security, LLC.
"""
import json
import sys

try:
    r = json.load(open('smoke-report.json'))
except FileNotFoundError:
    print('smoke-report.json not found', file=sys.stderr)
    sys.exit(1)

print('total:', r['total'])
print('passed:', r['passed'])
print('failed:', r['failed'])
print('gate:', r['gate'])
for x in r['results']:
    status = 'PASS' if x['passed'] else 'FAIL'
    name = x['name']
    print('  [' + status + '] ' + name)

# Exit non-zero if the gate failed
sys.exit(0 if r.get('gate', False) else 1)
