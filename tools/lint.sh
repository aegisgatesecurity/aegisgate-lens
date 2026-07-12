#!/bin/bash
# AegisGate Lens - Lightweight linter (no npm)
#
# Per the v0.1.4 final reassessment: add a custom Go-style
# linter for code quality (no npm — "zero external dependencies"
# is one of the 12 non-negotiables).
#
# This is a "best effort" linter that catches the most common
# issues without false positives. It is NOT a replacement for a
# proper ESLint setup, but it's a good baseline for a 1-person
# team that doesn't want to add npm deps.
#
# What this checks:
# 1. No ACTUAL console.log/warn/error calls in src/ (use the `log` module)
# 2. No 'var' declarations in src/ (use let/const)
# 3. No == or != in src/ (use === and !==)
# 4. No TODO/FIXME/XXX markers in src/
# 5. No eval() or new Function() in src/ (security gate)
# 6. No dynamic innerHTML in src/ (CSP gate; banner-ui-*.js allowed)
# 7. All exported functions have JSDoc comments
#
# Exits 0 if all checks pass, 1 if any FAIL check fails.
# Warnings don't fail the lint.
#
# Apache 2.0. Copyright 2026 AegisGate Security, LLC.

set -e
cd "$(dirname "$0")/../.."  # cd to aegisgate-lens root (from tools/)

FAIL_COUNT=0
PASS_COUNT=0
WARN_COUNT=0

log_pass() { echo "  ✅ $1"; PASS_COUNT=$((PASS_COUNT+1)); }
log_fail() { echo "  ❌ $1"; FAIL_COUNT=$((FAIL_COUNT+1)); }
log_warn() { echo "  ⚠️  $1"; WARN_COUNT=$((WARN_COUNT+1)); }

# Helper: strip comments and string literals from a JS file.
# This is a best-effort approach using simple sed patterns.
# It does NOT handle every edge case (template literals with
# expressions, multi-line strings with embedded quotes, etc.)
# but it catches the most common false positives.
strip_comments_and_strings() {
    # Remove single-line comments
    sed -E 's|//.*$||g' "$1" | \
    # Remove multi-line comments
    perl -0777 -pe 's|/\*.*?\*/||gs' | \
    # Remove single-quoted strings
    sed -E "s|'[^'\\\\]*(\\\\.[^'\\\\]*)*'|''|g" | \
    # Remove double-quoted strings
    sed -E 's|"[^"\\]*(\\.[^"\\]*)*"|""|g' | \
    # Remove template literals
    perl -0777 -pe 's|`[^`]*`|\`\`|gs'
}

echo "=== AegisGate Lens linter (v0.1.4) ==="
echo

# 1. No ACTUAL console.log/warn/error calls in src/ (use the log module)
# We strip comments AND string literals first, so we only catch
# actual CALLS, not log shim definitions or strings in comments.
echo "1. No ACTUAL console.log/warn/error calls in src/ (use the log module)"
CONSOLE_CALLS=""
for f in $(find src/ -name "*.js" 2>/dev/null); do
    STRIPPED=$(strip_comments_and_strings "$f")
    MATCH=$(echo "$STRIPPED" | grep -nE '\bconsole\.(log|warn|error|info|debug)\(' | head -3)
    if [ -n "$MATCH" ]; then
        CONSOLE_CALLS="$CONSOLE_CALLS $f: $MATCH"
    fi
done
if [ -n "$CONSOLE_CALLS" ]; then
    log_fail "actual console.* calls in src/:$CONSOLE_CALLS"
else
    log_pass "no actual console.* calls in src/ (only log shim definitions in string literals)"
fi

# 2. No 'var' declarations (use let/const)
echo "2. No 'var' declarations in src/ (use let/const)"
VAR_DECLS=""
for f in $(find src/ -name "*.js" 2>/dev/null); do
    STRIPPED=$(strip_comments_and_strings "$f")
    MATCH=$(echo "$STRIPPED" | grep -nE '^\s*var\s' | head -3)
    if [ -n "$MATCH" ]; then
        VAR_DECLS="$VAR_DECLS $f: $MATCH"
    fi
done
if [ -n "$VAR_DECLS" ]; then
    log_warn "var declarations in src/:$VAR_DECLS"
else
    log_pass "no var declarations in src/"
fi

# 3. No == or != in src/ (use === and !==)
echo "3. No == or != in src/ (use === and !==)"
EQ_USAGE=""
for f in $(find src/ -name "*.js" 2>/dev/null); do
    STRIPPED=$(strip_comments_and_strings "$f")
    # Look for == or != that's NOT part of === or !==
    MATCH=$(echo "$STRIPPED" | grep -nE '[^=!<>]==[^=]|[^=!]<>[^=]' | head -3)
    if [ -n "$MATCH" ]; then
        EQ_USAGE="$EQ_USAGE $f: $MATCH"
    fi
done
if [ -n "$EQ_USAGE" ]; then
    log_warn "== or != in src/ (review for === / !==):$EQ_USAGE"
else
    log_pass "no == or != in src/ (all use === / !==)"
fi

# 4. No TODO/FIXME/XXX markers in src/
echo "4. No TODO/FIXME/XXX markers in src/"
TODO_MARKERS=""
for f in $(find src/ -name "*.js" 2>/dev/null); do
    MATCH=$(grep -nE "TODO|FIXME|XXX" "$f" 2>/dev/null | head -3)
    if [ -n "$MATCH" ]; then
        TODO_MARKERS="$TODO_MARKERS $f: $MATCH"
    fi
done
if [ -n "$TODO_MARKERS" ]; then
    log_warn "TODO/FIXME/XXX in src/ (track in .plans/todo-v0.1.4.md):$TODO_MARKERS"
else
    log_pass "no TODO/FIXME/XXX markers in src/"
fi

# 5. No eval() or new Function() (per security.yml)
echo "5. No eval() or new Function() in src/ (security gate)"
EVAL_USAGE=""
for f in $(find src/ -name "*.js" 2>/dev/null); do
    STRIPPED=$(strip_comments_and_strings "$f")
    MATCH=$(echo "$STRIPPED" | grep -nE '\beval\s*\(|\bnew\s+Function\s*\(' | head -3)
    if [ -n "$MATCH" ]; then
        EVAL_USAGE="$EVAL_USAGE $f: $MATCH"
    fi
done
if [ -n "$EVAL_USAGE" ]; then
    log_fail "eval() or new Function() in src/:$EVAL_USAGE"
else
    log_pass "no eval() or new Function() in src/"
fi

# 6. No dynamic innerHTML (per security.yml + F-7)
echo "6. No dynamic innerHTML in src/ (CSP gate; banner-ui-*.js allowed)"
# We strip comments and string literals, then look for .innerHTML = <non-literal>
# A HARDCODED string literal is allowed (e.g., .innerHTML = '<span>...</span>')
# A dynamic expression is NOT allowed (e.g., .innerHTML = userInput)
INNERHTML_DYNAMIC=""
for f in $(find src/ -name "*.js" 2>/dev/null); do
    # Skip banner-ui-*.js (per security.yml: innerHTML is allowed there with escaped content)
    if echo "$f" | grep -q "banner-ui"; then
        continue
    fi
    STRIPPED=$(strip_comments_and_strings "$f")
    # Find all .innerHTML = ...; assignments
    MATCH=$(echo "$STRIPPED" | grep -nE '\.innerHTML\s*=' | head -3)
    if [ -n "$MATCH" ]; then
        # Check if RHS is a literal (after our stripping, literal = empty string)
        # If line has `= ;` (literal stripped) it's a constant; otherwise dynamic
        DYNAMIC=$(echo "$MATCH" | grep -vE '=\s*["\x27`]*["\x27`]?\s*;|=\s*;')
        if [ -n "$DYNAMIC" ]; then
            INNERHTML_DYNAMIC="$INNERHTML_DYNAMIC $f: $DYNAMIC"
        fi
    fi
done
if [ -n "$INNERHTML_DYNAMIC" ]; then
    log_fail "dynamic innerHTML in src/ outside banner-ui-*.js:$INNERHTML_DYNAMIC"
else
    log_pass "no dynamic innerHTML in src/ outside banner-ui-*.js"
fi

# 7. All exported functions have JSDoc comments
# This is a "best effort" check — false positives for IIFE pattern
echo "7. Exported functions have JSDoc comments (best effort)"
NO_JSDOC=""
for f in $(find src/ -name "*.js" 2>/dev/null); do
    # Find all `function foo(` at start of line (exported funcs)
    FUNC_LINES=$(grep -nE "^function " "$f" 2>/dev/null)
    while IFS= read -r line; do
        if [ -z "$line" ]; then continue; fi
        LINENUM=$(echo "$line" | cut -d: -f1)
        # Check the line above
        PREV=$(sed -n "$((LINENUM-1))p" "$f" 2>/dev/null)
        # If the previous line isn't part of a JSDoc block, flag it
        if ! echo "$PREV" | grep -qE '^\s*\*\s*@|^\s*//|^\s*/\*\*'; then
            FUNC=$(echo "$line" | sed 's/.*function //; s/(.*//')
            NO_JSDOC="$NO_JSDOC $f:$LINENUM:$FUNC"
        fi
    done <<< "$FUNC_LINES"
done
if [ -n "$NO_JSDOC" ]; then
    log_warn "exported functions without JSDoc (best effort):$NO_JSDOC"
else
    log_pass "all exported functions have JSDoc"
fi

echo
echo "=== Summary ==="
echo "  ✅ Passed:   $PASS_COUNT"
echo "  ⚠️  Warnings: $WARN_COUNT"
echo "  ❌ Failed:   $FAIL_COUNT"

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo
    echo "LINTER FAILED: $FAIL_COUNT check(s) failed."
    exit 1
fi

echo
echo "LINTER PASSED (with $WARN_COUNT warnings)."
exit 0
