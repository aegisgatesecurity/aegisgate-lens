// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Event Schema Validator (Browser Side)
// =========================================================================
//
// This is the browser-side mirror of the backend's
// validateEvent() in pkg/lensbackend/validation.go. The two
// MUST agree on the field set, field types, and field
// constraints. The build tool (tools/build-lens-extension/
// in the Platform monorepo) generates a JSON Schema from the
// Go struct's json tags and validates this file against it.
//
// The validation here is the first line of defense: the
// extension validates every event BEFORE serializing it,
// before encrypting, before putting it on the wire. The
// backend then validates again as a defense in depth.
//
// The 9 fields are the §1.1 schema. Adding, removing, or
// renaming a field is a breaking change to the Lens protocol.
//
// v0.1 pre-release.
// =========================================================================

import type {
  Category,
  Severity,
  UserAction,
  LensEvent,
} from "../types.js";

/** The required fields. Adding a field here forces a breaking change. */
const REQUIRED_FIELDS: ReadonlyArray<keyof LensEvent> = [
  "domain_hash",
  "category",
  "severity",
  "user_action",
  "timestamp",
  "model_version",
  "lens_version",
  "confidence",
];

/** The valid categories. Must match validation.go AllCategories. */
const VALID_CATEGORIES: ReadonlyArray<Category> = [
  "pii_email",
  "pii_phone",
  "pii_ssn",
  "pii_credit_card",
  "secret_api_key",
  "source_code",
];

/** The valid severities. Must match validation.go isValidSeverity. */
const VALID_SEVERITIES: ReadonlyArray<Severity> = [
  "info",
  "low",
  "medium",
  "high",
  "critical",
];

/** The valid user actions. Must match validation.go AllUserActions. */
const VALID_USER_ACTIONS: ReadonlyArray<UserAction> = [
  "send_anyway",
  "edit",
  "cancel",
  "dismiss",
];

/** Domain hash length: 16 hex characters. Must match validation.go. */
const DOMAIN_HASH_LENGTH = 16;

/** Confidence range. Must match validation.go. */
const MIN_CONFIDENCE = 0.0;
const MAX_CONFIDENCE = 1.0;

/** Timestamp must be within ±24 hours of the client's wall clock. */
const TIMESTAMP_TOLERANCE_SECONDS = 24 * 60 * 60;

/**
 * Result of a validate() call. Either valid=true with the
 * normalized event, or valid=false with a human-readable
 * reason (safe to log, never includes the event payload).
 */
export type ValidationResult =
  | { valid: true; event: LensEvent }
  | { valid: false; reason: string };

/**
 * Validate an event against the §1.1 schema. This is the
 * browser-side pre-flight check; the backend re-validates.
 *
 * @param raw The event as captured. May have extra fields
 *            (the check rejects them).
 * @param nowMillis The client's wall-clock time, in
 *            milliseconds since the unix epoch. Defaults
 *            to Date.now(). Pass an explicit value in tests
 *            to make them deterministic.
 * @returns ValidationResult indicating pass/fail.
 */
export function validate(
  raw: unknown,
  nowMillis: number = Date.now(),
): ValidationResult {
  // Reject non-objects.
  if (typeof raw !== "object" || raw === null) {
    return fail("event must be an object");
  }
  const obj = raw as Record<string, unknown>;

  // Reject unknown fields. This is the schema-is-an-allowlist
  // guarantee from the privacy policy. The backend does the
  // same with DisallowUnknownFields.
  const allowed: ReadonlySet<string> = new Set([
    ...REQUIRED_FIELDS,
    "id", // optional
  ]);
  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) {
      return fail(`unknown field: ${key}`);
    }
  }

  // Required fields.
  for (const field of REQUIRED_FIELDS) {
    if (!(field in obj)) {
      return fail(`missing required field: ${field}`);
    }
  }

  // domain_hash: exactly 16 lowercase hex chars.
  if (typeof obj.domain_hash !== "string") {
    return fail("domain_hash must be a string");
  }
  if (obj.domain_hash.length !== DOMAIN_HASH_LENGTH) {
    return fail(
      `domain_hash must be ${DOMAIN_HASH_LENGTH} hex chars, got ${obj.domain_hash.length}`,
    );
  }
  if (!/^[0-9a-f]{16}$/.test(obj.domain_hash)) {
    return fail("domain_hash must be lowercase hex");
  }

  // category: enum.
  if (typeof obj.category !== "string") {
    return fail("category must be a string");
  }
  if (!VALID_CATEGORIES.includes(obj.category as Category)) {
    return fail(`category ${JSON.stringify(obj.category)} is not valid`);
  }

  // severity: enum.
  if (typeof obj.severity !== "string") {
    return fail("severity must be a string");
  }
  if (!VALID_SEVERITIES.includes(obj.severity as Severity)) {
    return fail(`severity ${JSON.stringify(obj.severity)} is not valid`);
  }

  // user_action: enum.
  if (typeof obj.user_action !== "string") {
    return fail("user_action must be a string");
  }
  if (!VALID_USER_ACTIONS.includes(obj.user_action as UserAction)) {
    return fail(`user_action ${JSON.stringify(obj.user_action)} is not valid`);
  }

  // timestamp: positive int, within ±24h of now.
  if (typeof obj.timestamp !== "number" || !Number.isInteger(obj.timestamp)) {
    return fail("timestamp must be an integer");
  }
  if (obj.timestamp <= 0) {
    return fail("timestamp must be positive");
  }
  const nowSeconds = Math.floor(nowMillis / 1000);
  const delta = obj.timestamp - nowSeconds;
  if (Math.abs(delta) > TIMESTAMP_TOLERANCE_SECONDS) {
    return fail("timestamp must be within ±24h of client clock");
  }

  // model_version: non-empty, contains "+".
  if (typeof obj.model_version !== "string") {
    return fail("model_version must be a string");
  }
  if (obj.model_version.length === 0) {
    return fail("model_version must be non-empty");
  }
  if (!obj.model_version.includes("+")) {
    return fail('model_version must contain "+" (e.g., "0.1.0+regex-v1")');
  }

  // lens_version: non-empty.
  if (typeof obj.lens_version !== "string") {
    return fail("lens_version must be a string");
  }
  if (obj.lens_version.length === 0) {
    return fail("lens_version must be non-empty");
  }

  // confidence: number in [0.0, 1.0].
  if (typeof obj.confidence !== "number" || !Number.isFinite(obj.confidence)) {
    return fail("confidence must be a finite number");
  }
  if (obj.confidence < MIN_CONFIDENCE || obj.confidence > MAX_CONFIDENCE) {
    return fail(
      `confidence must be in [${MIN_CONFIDENCE}, ${MAX_CONFIDENCE}], got ${obj.confidence}`,
    );
  }

  // id: optional string (or absent).
  if (obj.id !== undefined) {
    if (typeof obj.id !== "string") {
      return fail("id must be a string when present");
    }
  }

  // Build the normalized event. We do NOT include fields that
  // were not in the input, even if they have zero values.
  const event: LensEvent = {
    domain_hash: obj.domain_hash,
    category: obj.category as Category,
    severity: obj.severity as Severity,
    user_action: obj.user_action as UserAction,
    timestamp: obj.timestamp,
    model_version: obj.model_version,
    lens_version: obj.lens_version,
    confidence: obj.confidence,
  };
  if (typeof obj.id === "string") {
    event.id = obj.id;
  }
  return { valid: true, event };
}

/**
 * Internal helper: returns a failed ValidationResult with the
 * given reason. The reason is safe to log and safe to show
 * to the user; it does NOT include the event payload.
 */
function fail(reason: string): ValidationResult {
  return { valid: false, reason };
}
