/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - License Checker (v0.2.0 NEW)
   =========================================================================

   Validates the license of every model bundle at load time. This is the
   "Lesson #99-tangential" guard: prevents us from accidentally shipping a
   model whose license forbids redistribution as a browser extension.

   REJECTED licenses (return false):
     - elastic-2.0 (forbids hosted/managed service use; a browser extension
       counts as "managed service" by Elastic's definition)
     - cc-by-nc-* (non-commercial only; can't redistribute commercially)
     - Other non-OSI-approved licenses

   ALLOWED licenses (return true):
     - Apache-2.0 (preferred; explicit patent grant)
     - MIT (permissive)
     - BSD-2-Clause / BSD-3-Clause (permissive)
     - Apache-2.0 with LLVM exceptions (acceptable for ML models)
     - OpenRAIL (Responsible AI License; permissive with use-based restrictions)

   Plain JavaScript, no transpilation, no dependencies.
   ========================================================================= */

'use strict';

(function () {
  const NS = (typeof window !== 'undefined' ? window : self).AegisGateLens =
    (typeof window !== 'undefined' ? window : self).AegisGateLens || {};

  // License identifiers we permit. Keys are normalized lowercase.
  const ALLOWED_LICENSES = new Set([
    'apache-2.0',
    'apache2',
    'apache-2.0-with-llvm-exceptions',
    'mit',
    'bsd-2-clause',
    'bsd-3-clause',
    'openrail',
    'openrail++',
    'bigscience-rail-1.0',
    'cc0-1.0',  // public domain dedication
  ]);

  // Licenses we explicitly reject.
  const REJECTED_LICENSES = new Set([
    'elastic-2.0',
    'elastic-1.0',
    'cc-by-nc-4.0',
    'cc-by-nc-sa-4.0',
    'cc-by-nc',
    'gpl-3.0',  // copyleft; not appropriate for embedded models
    'agpl-3.0',
    'cc-by-nd-4.0',
    'sspl',  // server side public license
  ]);

  /**
   * Audit a license string at load time. Returns {ok, reason}.
   * @param {string} licenseId - License identifier (HuggingFace format)
   * @param {string} modelId - The model ID (for logging)
   * @returns {{ok: boolean, reason: string}}
   */
  function auditLicense(licenseId, modelId) {
    if (typeof licenseId !== 'string' || licenseId.length === 0) {
      return { ok: false, reason: `license missing for model ${modelId}` };
    }

    const normalized = licenseId.toLowerCase().trim();

    if (REJECTED_LICENSES.has(normalized)) {
      return {
        ok: false,
        reason: `model ${modelId} uses ${normalized} which forbids redistribution as a browser extension (privacy posture)`,
      };
    }

    if (!ALLOWED_LICENSES.has(normalized)) {
      return {
        ok: false,
        reason: `model ${modelId} uses unknown/non-approved license "${normalized}"; must be one of ${[...ALLOWED_LICENSES].join(', ')}`,
      };
    }

    return { ok: true, reason: `license ${normalized} approved for redistribution` };
  }

  /**
   * Audit a bundle entry (uses bundle-registry.js format).
   * @param {Object} bundleEntry - From BUNDLE_REGISTRY
   * @returns {{ok: boolean, reason: string}}
   */
  function auditBundleLicense(bundleEntry) {
    if (!bundleEntry || !bundleEntry.base_checkpoint || !bundleEntry.base_license) {
      return { ok: false, reason: 'bundle entry missing checkpoint or license' };
    }
    return auditLicense(bundleEntry.base_license, bundleEntry.base_checkpoint);
  }

  NS.util = NS.util || {};
  NS.util.licenseChecker = {
    ALLOWED_LICENSES: [...ALLOWED_LICENSES],
    REJECTED_LICENSES: [...REJECTED_LICENSES],
    auditLicense,
    auditBundleLicense,
  };
})();
