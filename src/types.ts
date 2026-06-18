// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Shared TypeScript Types
// =========================================================================
//
// This file is the SOURCE OF TRUTH for the Lens's wire format.
// The Go struct `pkg/lensbackend.Event` in the Platform monorepo
// (consolidated/aegisgate-platform/pkg/lensbackend/validation.go)
// is the other source of truth. Both MUST be kept in sync.
//
// The sync mechanism is the build tool in the Platform monorepo
// (tools/build-lens-extension/) which generates a JSON Schema
// from the Go struct's json tags, then validates this TypeScript
// file's types against that schema as part of `go test
// ./tools/build-lens-extension/...`. If they drift, the build
// fails.
//
// The 9 fields below are the §1.1 schema. Adding, removing, or
// renaming a field is a breaking change to the Lens protocol
// and requires:
//   1. A major version bump of the Lens backend
//   2. A coordinated update of the Lens extension
//   3. A privacy policy disclosure
// See plans/AEGISGATE-LENS-PRIVACY-POLICY-DRAFT.md §1.1.
//
// v0.1 pre-release.
// =========================================================================

/**
 * The 7 categories of sensitive data the Lens detects in v0.1.
 * Adding a new category is a breaking change. See CONTRIBUTING.md.
 */
export type Category =
  | "pii_email"
  | "pii_phone"
  | "pii_ssn"
  | "pii_credit_card"
  | "secret_api_key"
  | "source_code";

/**
 * The 5 severity levels. Matches pkg/ioc.Severity and
 * pkg/logging.Severity so downstream IOCs are compatible.
 */
export type Severity = "info" | "low" | "medium" | "high" | "critical";

/**
 * The 4 user actions. The privacy policy §3.1 commits to
 * tracking what the user did in response to the warning, but
 * only this enum — never free-form text.
 */
export type UserAction = "send_anyway" | "edit" | "cancel" | "dismiss";

/**
 * The 4 AI providers supported in v0.1. (ChatGPT is the only
 * provider in v0.1; the others are placeholders for v0.2+.)
 */
export type Provider = "chatgpt" | "claude" | "gemini" | "copilot";

/**
 * The Event payload sent to POST /api/v1/lens/telemetry.
 *
 * The 9 fields below are the complete wire format. The
 * DisallowUnknownFields setting on the backend's JSON decoder
 * rejects any extra field.
 */
export interface LensEvent {
  /** SHA-256 of the AI provider's hostname, truncated to 16 hex chars. */
  domain_hash: string;

  /** The sensitive-data category that was detected. */
  category: Category;

  /** The severity of the detection. */
  severity: Severity;

  /** What the user did in response to the warning. */
  user_action: UserAction;

  /** Unix-second timestamp of the detection, stamped by the extension. */
  timestamp: number;

  /** Classifier identifier, e.g., "0.1.0+regex-v1". Must contain a "+". */
  model_version: string;

  /** Lens extension version, e.g., "0.1.0". */
  lens_version: string;

  /** Classifier confidence, 0.0..1.0. */
  confidence: number;

  /** Optional client-side UUID for client-side dedup. Not stored. */
  id?: string;
}

/**
 * Response from POST /api/v1/lens/telemetry.
 */
export interface TelemetryResponse {
  status: "received";
}

/**
 * Response from GET /api/v1/lens/check?domain=<hostname>.
 */
export interface CheckResponse {
  /** "clean" if no IOC matches the domain; "known_threat" otherwise. */
  verdict: "clean" | "known_threat";
  /** The hostname that was checked (echoed back). */
  domain: string;
  /** Present when verdict is "known_threat". */
  category?: Category;
  /** First time the IOC was observed (RFC 3339). */
  first_seen?: string;
  /** Most recent observation (RFC 3339). */
  last_seen?: string;
  /** Number of times observed across all installations. */
  count?: number;
  /** Worst severity observed. */
  severity?: Severity;
}

/**
 * Response from GET /api/v1/lens/stats.
 */
export interface StatsResponse {
  /** Start of the aggregation window (RFC 3339). */
  window_start: string;
  /** End of the aggregation window (RFC 3339). */
  window_end: string;
  /** Total events in the window. */
  events_24h: number;
  /** Events per category. */
  by_category: Record<Category, number>;
  /** Events per user action. */
  by_user_action: Record<UserAction, number>;
  /** Total IOCs in the store. */
  ioc_count: number;
}

/**
 * Response from GET /api/v1/lens/healthz.
 */
export interface HealthzResponse {
  status: "ok";
  version: string;
}

/**
 * The detect() result: a single detection with optional matched
 * span. Used internally; not part of the wire format.
 */
export interface Detection {
  category: Category;
  severity: Severity;
  /** The matched substring (used locally; NEVER sent to the backend). */
  match: string;
  /** Start index in the source text. */
  start: number;
  /** End index in the source text. */
  end: number;
  /** The pattern name that matched (e.g., "aws_access_key_v1"). */
  pattern: string;
}

/**
 * Local audit log entry. Stored in chrome.storage.local, NEVER
 * sent to the backend. Visible to the user in the popup.
 */
export interface LocalAuditEntry {
  timestamp: number;
  domain_hash: string;
  category: Category;
  severity: Severity;
  user_action: UserAction;
  /** Truncated prompt snippet for local display (e.g., first 40 chars). */
  snippet: string;
}

/**
 * The opt-in state, stored in chrome.storage.sync so it survives
 * browser restarts and is shared across devices via the user's
 * Chrome profile.
 */
export interface OptInState {
  /** Master opt-in. When false, no telemetry is sent. */
  enabled: boolean;
  /** When the user first opted in (unix seconds). */
  opted_in_at: number;
  /** When the user last changed the setting (unix seconds). */
  last_changed_at: number;
  /** The Lens version that this state was created with. */
  lens_version: string;
}

/**
 * A regex pattern definition. The detectors/regex.ts file
 * exports a Patterns array of these.
 */
export interface RegexPattern {
  /** The category this pattern detects. */
  category: Category;
  /** Default severity if the pattern matches. */
  severity: Severity;
  /** Canonical pattern name (used in the detection's pattern field). */
  name: string;
  /** The regex pattern itself (ES2020 RegExp syntax). */
  pattern: string;
  /** Human-readable description for the popup UI. */
  description: string;
}
