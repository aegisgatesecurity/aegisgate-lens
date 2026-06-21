// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Detector Entry Point
// =========================================================================
//
// The detect() function is the only public API of the
// detectors/ module. It takes a string (the prompt text the
// user is typing) and returns a list of Detection objects.
//
// The function is deterministic, side-effect-free, and
// synchronous. The browser calls it from the content script
// (content.ts) on every input event. The Detection list is
// then:
//   1. Filtered to remove overlaps (e.g., "4111-1111-1111-1111"
//      matches both credit_card_visa_v1 and credit_card_amex_v1;
//      keep only the highest-severity match).
//   2. Displayed in the warning UI.
//   3. Sent to the API (api/client.ts) LensEvent, with
//      the prompt content STRIPPED — only the metadata
//      (category, severity, span) crosses the wire.
//
// IMPORTANT: detect() is the ONLY place in the extension that
// sees the prompt content. Every other module receives
// already-extracted metadata. This is the structural
// enforcement of the privacy boundary.
//
// v0.1 pre-release.
// =========================================================================

import { COMPILED_PATTERNS } from "./regex.js";
import { isLuhnValid } from "./luhn.js";
import type {
  Category,
  Detection,
  RegexPattern,
  Severity,
} from "../types.js";

/**
 * Options for detect().
 */
export interface DetectOptions {
  /**
   * Categories to skip. By default, all 7 categories are
   * checked. The user can disable specific categories in
   * the popup UI; the popup then passes the disabled
   * categories via this option.
   */
  disabledCategories?: ReadonlySet<Category>;

  /**
   * Maximum number of detections to return. The default
   * (50) is a conservative bound to prevent pathological
   * inputs (e.g., a 10MB pasted document) from causing UI
   * jank. Detections beyond the limit are discarded.
   */
  maxDetections?: number;
}

const DEFAULT_MAX_DETECTIONS = 50;

/**
 * Run all v0.1 detectors on the input text and return the
 * list of detections.
 *
 * The function is pure: same input + same options = same
 * output. It does not retain any state.
 */
export function detect(
  text: string,
  options: DetectOptions = {},
): ReadonlyArray<Detection> {
  if (typeof text !== "string" || text.length === 0) {
    return [];
  }
  const max = options.maxDetections ?? DEFAULT_MAX_DETECTIONS;
  const disabled = options.disabledCategories ?? new Set();

  // Collect all raw matches.
  const raw: Detection[] = [];
  for (const { pattern, regex } of COMPILED_PATTERNS) {
    if (disabled.has(pattern.category)) {
      continue;
    }
    for (const match of text.matchAll(regex)) {
      // Top-of-loop cap check: bail out have
      // 4x the detection limit, before doing any work on
      // the current match. The previous implementation had
      // the check at the bottom, which could slightly
      // exceed the cap by (remaining_patterns) matches.
      if (raw.length >= max * 4) break;
      if (match.index === undefined) continue;
      const matchText = match[0];
      // Credit card patterns get the Luhn filter.
      if (pattern.category === "pii_credit_card") {
        if (!isLuhnValid(matchText)) {
          continue;
        }
      }
      raw.push({
        category: pattern.category,
        severity: pattern.severity,
        match: matchText,
        start: match.index,
        end: match.index + matchText.length,
        pattern: pattern.name,
      });
    }
    if (raw.length >= max * 4) break;
  }

  // Sort by start index, then by severity (highest first).
  raw.sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    return severityRank(b.severity) - severityRank(a.severity);
  });

  // Suppress overlaps: if two detections overlap, keep the
  // one with the higher severity rank, breaking ties by
  // the longer match.
  const accepted: Detection[] = [];
  for (const d of raw) {
    if (accepted.length >= max) break;
    let overlapped = false;
    for (const a of accepted) {
      if (overlaps(a, d)) {
        overlapped = true;
        break;
      }
    }
    if (!overlapped) {
      accepted.push(d);
    }
  }
  return accepted;
}

/**
 * Two detections overlap if their character spans intersect.
 */
function overlaps(a: Detection, b: Detection): boolean {
  return a.start < b.end && b.start < a.end;
}

/**
 * Numeric rank for a severity. Higher is more severe. Mirrors
 * the Go side's severityRank function.
 */
function severityRank(s: Severity): number {
  switch (s) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 3;
    case "low":
      return 2;
    case "info":
      return 1;
  }
}

/**
 * Build a stable, human-readable label for a detection.
 * Used in the warning UI.
 */
export function describeDetection(d: Detection): string {
  const prefix = describeCategory(d.category);
  return `${prefix} (severity: ${d.severity})`;
}

export function describeCategory(c: Category): string {
  switch (c) {
    case "pii_email":
      return "Email address";
    case "pii_phone":
      return "Phone number";
    case "pii_ssn":
      return "Social Security number";
    case "pii_credit_card":
      return "Credit card number";
    case "secret_api_key":
      return "API key or token";
    case "source_code":
      return "Source code (private key)";
  }
}

/**
 * Look up a pattern definition by name. Used by the
 * schema-generation step in the build tool to keep the
 * TypeScript types and the Go struct in sync.
 */
export function getPatternByName(name: string): RegexPattern | undefined {
  for (const p of COMPILED_PATTERNS) {
    if (p.pattern.name === name) return p.pattern;
  }
  return undefined;
}
