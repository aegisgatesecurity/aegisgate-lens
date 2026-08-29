// AegisGate Lens — api/messages.js
// Message type constants + builders for content-script <-> SW
// communication.
//
// All messages are validated by the SW against a whitelist of
// types and shapes. The SW MUST reject any message that does
// not match the expected shape, even from a trusted sender
// (defense in depth; the content script is our own code, but
// a compromised renderer should not be able to inject messages
// that the SW would then forward to the backend).
//
// Per docs/ARCHITECTURE-v0.1.3.md Section 8 (content-script-
// to-SW transport), messages use chrome.runtime.sendMessage with
// a {type, payload} envelope. The SW checks sender.id against
// chrome.runtime.id (F-01 from the threat model) and validates
// the payload shape against this module's schemas.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  // Message types. These are the ONLY types the SW will accept.
  // Adding a new type requires:
  //   1. Adding the constant here
  //   2. Adding the handler in background.js
  //   3. Adding tests in api-messages.test.mjs
  var MESSAGE_TYPES = {
    // From content script
    PING: 'PING',                           // health check
    DETECTION: 'DETECTION',                 // a new detection was found
    USER_ACTION: 'USER_ACTION',             // user clicked a banner button
    FP_REPORTS: 'FP_REPORTS',               // user opted in to send FP report(s)
    GET_OPT_IN_STATE: 'GET_OPT_IN_STATE',   // popup asks for opt-in state
    OPEN_LENS_POPUP: 'OPEN_LENS_POPUP',     // content script → SW: open the extension popup (Bug #4)

    // From SW
    PONG: 'PONG',
    ACK: 'ACK',                             // generic acknowledgement
    ERROR: 'ERROR',                         // SW returned an error
    OPT_IN_STATE: 'OPT_IN_STATE'            // opt-in state response
  };

  // User action values (banner button clicks)
  var USER_ACTIONS = {
    CANCEL: 'cancel',
    REDACT: 'redact',
    SEND: 'send',
    DISMISS: 'dismiss',
    DISMISS_OPTIN: 'dismiss_optin',
    DISMISS_PRIVATE: 'dismiss_private'
  };

  // Schema-version for the message envelope. Bump if the
  // message shape changes incompatibly.
  var MESSAGE_VERSION = '0.1.0-beta';

  // --- Builders ---
  // Each builder returns a message object {type, version, payload}
  // that the SW can validate. Builders NEVER include the prompt
  // text, URLs, or page content (the privacy guarantee).

  function buildPing() {
    return {
      type: MESSAGE_TYPES.PING,
      version: MESSAGE_VERSION,
      payload: { timestamp: Math.floor(Date.now() / 1000) }
    };
  }

  function buildDetection(event, domainHash) {
    // event is a DetectionEvent from the dispatcher (with
    // facet, category, severity, count, sample, matches).
    // We strip the matches (which contain raw values) before
    // sending; the SW only needs the metadata.
    return {
      type: MESSAGE_TYPES.DETECTION,
      version: MESSAGE_VERSION,
      payload: {
        timestamp: Math.floor(Date.now() / 1000),
        domain_hash: domainHash,
        facet: event.facet,
        category: event.category,
        severity: event.severity,
        count: event.count,
        // We do NOT include event.sample (raw value) or
        // event.matches (which contain raw values). The
        // SW only needs the metadata.
        has_ml_score: typeof event.ml_score === 'number'
      }
    };
  }

  function buildUserAction(action, domainHash) {
    return {
      type: MESSAGE_TYPES.USER_ACTION,
      version: MESSAGE_VERSION,
      payload: {
        timestamp: Math.floor(Date.now() / 1000),
        domain_hash: domainHash,
        action: action
      }
    };
  }

  // The FP report is the ONLY thing the user has explicitly
  // opted in to send. The payload is already sanitized by
  // dismiss.buildFPReport (no prompt text, no URLs, no page
  // content, no user ID).
  function buildFPReports(reports) {
    return {
      type: MESSAGE_TYPES.FP_REPORTS,
      version: MESSAGE_VERSION,
      payload: {
        timestamp: Math.floor(Date.now() / 1000),
        reports: reports || []
      }
    };
  }

  // --- Validators (used by the SW to defend against malicious
  // or corrupted messages) ---

  // Validate that a message has the expected envelope shape
  function isValidEnvelope(msg) {
    if (msg === null || typeof msg !== 'object') return false;
    if (typeof msg.type !== 'string') return false;
    if (typeof msg.version !== 'string') return false;
    if (!msg.payload || typeof msg.payload !== 'object') return false;
    return true;
  }

  // Validate a detection message
  function isValidDetection(msg) {
    if (!isValidEnvelope(msg)) return false;
    if (msg.type !== MESSAGE_TYPES.DETECTION) return false;
    var p = msg.payload;
    return typeof p.timestamp === 'number' && p.timestamp > 0 &&
           typeof p.domain_hash === 'string' && /^[0-9a-f]{16}$/.test(p.domain_hash) &&
           typeof p.facet === 'string' &&
           typeof p.category === 'string' &&
           ['low', 'medium', 'high', 'critical'].indexOf(p.severity) !== -1 &&
           typeof p.count === 'number' && p.count > 0;
  }

  // Validate an FP report message (the only one that can carry
  // PII-adjacent data, and even that is sanitized)
  function isValidFPReports(msg) {
    if (!isValidEnvelope(msg)) return false;
    if (msg.type !== MESSAGE_TYPES.FP_REPORTS) return false;
    var p = msg.payload;
    if (!Array.isArray(p.reports)) return false;
    // Each report must NOT have prompt text, URLs, etc.
    for (var i = 0; i < p.reports.length; i++) {
      var r = p.reports[i];
      if (typeof r !== 'object' || r === null) return false;
      // Privacy: explicit whitelist check. None of these fields
      // are allowed in an FP report.
      var forbidden = ['text', 'prompt', 'url', 'page_content',
                       'page', 'input', 'output', 'value', 'matches',
                       'cookies', 'keystrokes', 'mouse', 'fingerprint'];
      for (var j = 0; j < forbidden.length; j++) {
        if (r[forbidden[j]] !== undefined) return false;
      }
      // Required fields
      if (typeof r.domain_hash !== 'string' || !/^[0-9a-f]{16}$/.test(r.domain_hash)) return false;
      if (typeof r.category !== 'string') return false;
      if (typeof r.facet !== 'string') return false;
      if (typeof r.severity !== 'string' || ['low', 'medium', 'high', 'critical'].indexOf(r.severity) === -1) return false;
      // L-4 fix: Validate optional fields when present.
      if (r.reason !== undefined && (typeof r.reason !== 'string' || ['test_data', 'own_data', 'legitimate_use_case'].indexOf(r.reason) === -1)) return false;
      if (r.timestamp !== undefined && (typeof r.timestamp !== 'number' || r.timestamp <= 0)) return false;
      if (r.pattern_id !== undefined && typeof r.pattern_id !== 'string') return false;
      if (r.ml_score !== undefined && typeof r.ml_score !== 'number') return false;
      if (r.ml_threshold !== undefined && typeof r.ml_threshold !== 'number') return false;
      if (r.ml_model_version !== undefined && typeof r.ml_model_version !== 'string') return false;
    }
    return true;
  }

  var module = {
    MESSAGE_TYPES: MESSAGE_TYPES,
    USER_ACTIONS: USER_ACTIONS,
    MESSAGE_VERSION: MESSAGE_VERSION,
    buildPing: buildPing,
    buildDetection: buildDetection,
    buildUserAction: buildUserAction,
    buildFPReports: buildFPReports,
    isValidEnvelope: isValidEnvelope,
    isValidDetection: isValidDetection,
    isValidFPReports: isValidFPReports
  };

  if (typeof self !== 'undefined') self.__lensMessages = module;
  if (typeof window !== 'undefined') window.__lensMessages = module;
  /**
   * @type {import("./typedefs").LensMessages}
   */
  if (typeof globalThis !== 'undefined') globalThis.__lensMessages = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);
