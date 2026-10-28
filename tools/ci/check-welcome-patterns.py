#!/usr/bin/env python3
"""
CI Gate: Verify Lens welcome page pattern counts match source code.

This script counts the actual regex patterns in the detector source files
and compares them to the numbers displayed on the welcome page.
Fails (exit 1) if any count is stale.

Usage: python3 tools/ci/check-welcome-patterns.py
"""
import re
import sys
import os

LENS_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC_DIR = os.path.join(LENS_ROOT, "src", "detectors", "regex")
WELCOME_HTML = os.path.join(LENS_ROOT, "src", "welcome", "welcome.html")
SCHEMA_JS = os.path.join(LENS_ROOT, "src", "privacy", "schema.js")

def count_patterns_in_file(filepath):
    """Count pattern entries (lines matching '  key_name: {') in a detector file."""
    if not os.path.exists(filepath):
        return 0
    with open(filepath) as f:
        content = f.read()
    # Match pattern keys: indented identifier followed by ': {'
    # Exclude the wrapping 'patterns' or 'PATTERNS' object
    # Include digits in key names (e.g., ot_dnp3_control_relay)
    keys = re.findall(r'^\s{2,}([a-z0-9_]+):\s*\{', content, re.MULTILINE)
    keys = [k for k in keys if k not in ('patterns', 'PATTERNS')]
    return len(keys)

def count_pii_patterns():
    """PII patterns are split across 4 sub-files, loaded by pii.js aggregator."""
    sub_files = [
        'pii-us-core.js',
        'pii-us-extended.js',
        'pii-international-id.js',
        'pii-financial.js',
    ]
    total = 0
    for f in sub_files:
        path = os.path.join(SRC_DIR, f)
        count = count_patterns_in_file(path)
        total += count
    return total

def count_patterns(facet):
    """Count patterns for a given facet."""
    file_map = {
        'pii': None,  # handled by count_pii_patterns
        'secrets': 'secrets.js',
        'xss': 'source_xss.js',
        'compliance': 'compliance.js',
        'ot': 'ot-protocols.js',
    }
    if facet == 'pii':
        return count_pii_patterns()
    filename = file_map.get(facet)
    if not filename:
        return 0
    return count_patterns_in_file(os.path.join(SRC_DIR, filename))

def extract_welcome_count(html, label):
    """Extract the count from a feature card by its h3 label."""
    # Pattern: <div class="count">NN</div> ... <h3>Label</h3>
    pattern = r'<div class="count">(\d+)</div>\s*<h3>' + re.escape(label) + r'</h3>'
    m = re.search(pattern, html, re.IGNORECASE)
    if m:
        return int(m.group(1))
    return None

def extract_welcome_total(html):
    """Extract the total pattern count from the subtitle."""
    m = re.search(r'(\d+)\s+regex\s+patterns', html, re.IGNORECASE)
    if m:
        return int(m.group(1))
    return None

def main():
    errors = []
    passed = []

    if not os.path.exists(WELCOME_HTML):
        print(f"ERROR: Welcome page not found: {WELCOME_HTML}")
        sys.exit(1)

    with open(WELCOME_HTML) as f:
        html = f.read()

    # Check each facet
    checks = [
        ('pii', 'PII Patterns'),
        ('secrets', 'Secrets Patterns'),
        ('xss', 'XSS Patterns'),
        ('compliance', 'Compliance Patterns'),
        ('ot', 'OT/ICS Protocols'),
    ]

    actual_total = 0
    for facet, label in checks:
        actual = count_patterns(facet)
        expected = extract_welcome_count(html, label)
        actual_total += actual

        if expected is None:
            errors.append(f"  ❌ '{label}' card not found in welcome page")
        elif actual != expected:
            errors.append(f"  ❌ {label}: welcome says {expected}, source has {actual}")
        else:
            passed.append(f"  ✅ {label}: {actual} patterns (matches source)")

    # Check total
    welcome_total = extract_welcome_total(html)
    if welcome_total is None:
        errors.append("  ❌ Total regex pattern count not found in subtitle")
    elif welcome_total != actual_total:
        errors.append(f"  ❌ Total: welcome says {welcome_total}, source total is {actual_total}")
    else:
        passed.append(f"  ✅ Total: {actual_total} regex patterns (matches source)")

    # Check version tag
    version_match = re.search(r'id="lens-version-tag">v([^<]+)<', html)
    if version_match:
        welcome_version = version_match.group(1)
        manifest_path = os.path.join(LENS_ROOT, "manifest.json")
        if os.path.exists(manifest_path):
            with open(manifest_path) as f:
                manifest = re.search(r'"version"\s*:\s*"([^"]+)"', f.read())
            if manifest:
                manifest_version = manifest.group(1)
                if welcome_version == manifest_version:
                    passed.append(f"  ✅ Version: v{welcome_version} (matches manifest)")
                else:
                    errors.append(f"  ❌ Version: welcome says v{welcome_version}, manifest says {manifest_version}")

    # Print results
    print("=== Welcome Page Pattern Count Check ===\n")
    for p in passed:
        print(p)
    if errors:
        print("\n--- ERRORS ---")
        for e in errors:
            print(e)
        print(f"\n❌ FAILED: {len(errors)} mismatch(es) found. Update src/welcome/welcome.html!")
        sys.exit(1)
    else:
        print(f"\n✅ PASSED: All pattern counts match source code.")
        sys.exit(0)

if __name__ == '__main__':
    main()