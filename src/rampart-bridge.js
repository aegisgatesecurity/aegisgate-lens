// SPDX-License-Identifier: Apache-2.0
// AegisGate Lens — Rampart Signal Bridge
//
// Sends detection signals from Lens (browser extension) to Rampart
// (local MITM proxy) for cross-layer signal correlation.
//
// Architecture:
//   - Lens detects threats in the browser (page content, prompts)
//   - Rampart detects threats in the proxy layer (API requests/responses)
//   - When both are running on the same machine, Lens sends signals
//     to Rampart's localhost endpoint for correlation
//   - If both layers detect threats on the same domain, severity is
//     escalated and blocks may be recommended
//
// Air-gap / privacy:
//   - This is localhost-only communication (127.0.0.1)
//   - Only metadata is sent: hashed domain, category, severity, rule ID
//   - No prompt text, no PII values, no page content
//   - Lens checks if Rampart is running before sending (health check)
//   - If Rampart is not running, signals are silently dropped
//   - Opt-in: user must enable Rampart correlation in Lens settings
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function () {
  'use strict';

  var RAMPART_BRIDGE = {
    // Default Rampart signal endpoint (localhost)
    signalEndpoint: 'http://127.0.0.1:8443/api/v1/lens-signals',
    healthEndpoint: 'http://127.0.0.1:8443/api/v1/lens-signals/healthz',

    // Connection state
    rampartAvailable: false,
    lastHealthCheck: 0,
    healthCheckInterval: 30000, // 30 seconds

    // Statistics
    stats: {
      signalsSent: 0,
      signalsFailed: 0,
      escalations: 0,
      blocksRecommended: 0
    },

    /**
     * Check if Rampart is running on localhost.
     * @param {function} callback - Called with (available: boolean)
     */
    checkAvailability: function (callback) {
      var now = Date.now();
      // Cache health check for 30 seconds
      if (now - this.lastHealthCheck < this.healthCheckInterval) {
        if (callback) callback(this.rampartAvailable);
        return;
      }

      this.lastHealthCheck = now;

      var self = this;
      try {
        var xhr = new XMLHttpRequest();
        xhr.open('GET', this.healthEndpoint, true);
        xhr.timeout = 2000; // 2 second timeout
        xhr.onload = function () {
          if (xhr.status === 200) {
            self.rampartAvailable = true;
          } else {
            self.rampartAvailable = false;
          }
          if (callback) callback(self.rampartAvailable);
        };
        xhr.onerror = function () {
          self.rampartAvailable = false;
          if (callback) callback(false);
        };
        xhr.ontimeout = function () {
          self.rampartAvailable = false;
          if (callback) callback(false);
        };
        xhr.send();
      } catch (e) {
        self.rampartAvailable = false;
        if (callback) callback(false);
      }
    },

    /**
     * Send a detection signal to Rampart for correlation.
     * @param {object} detection - Detection metadata
     * @param {string} detection.hashedDomain - SHA-256 hash of domain
     * @param {string} detection.category - Detection category
     * @param {string} detection.severity - "low"|"medium"|"high"|"critical"
     * @param {string} detection.ruleId - Rule that triggered
     * @param {string} detection.direction - "page"|"request"
     * @param {string} detection.action - "warned"|"blocked"|"logged"
     * @param {function} callback - Called with correlation result or null
     */
    sendSignal: function (detection, callback) {
      if (!this.rampartAvailable) {
        // Silently skip if Rampart is not running
        if (callback) callback(null);
        return;
      }

      var signal = {
        hashed_domain: detection.hashedDomain || '',
        category: detection.category || '',
        severity: detection.severity || 'low',
        rule_id: detection.ruleId || '',
        timestamp: new Date().toISOString(),
        direction: detection.direction || 'page',
        action: detection.action || 'warned'
      };

      // Validate required fields
      if (!signal.hashed_domain || !signal.category || !signal.severity) {
        if (callback) callback(null);
        return;
      }

      var self = this;
      try {
        var xhr = new XMLHttpRequest();
        xhr.open('POST', this.signalEndpoint, true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.timeout = 3000; // 3 second timeout

        xhr.onload = function () {
          if (xhr.status === 200) {
            self.stats.signalsSent++;
            try {
              var result = JSON.parse(xhr.responseText);
              if (result.escalated) {
                self.stats.escalations++;
              }
              if (result.recommend_block) {
                self.stats.blocksRecommended++;
              }
              if (callback) callback(result);
            } catch (e) {
              if (callback) callback(null);
            }
          } else {
            self.stats.signalsFailed++;
            if (callback) callback(null);
          }
        };

        xhr.onerror = function () {
          self.stats.signalsFailed++;
          self.rampartAvailable = false; // Rampart may have stopped
          if (callback) callback(null);
        };

        xhr.ontimeout = function () {
          self.stats.signalsFailed++;
          if (callback) callback(null);
        };

        xhr.send(JSON.stringify(signal));
      } catch (e) {
        self.stats.signalsFailed++;
        if (callback) callback(null);
      }
    },

    /**
     * Get bridge statistics.
     * @returns {object} stats object
     */
    getStats: function () {
      return this.stats;
    },

    /**
     * Set custom endpoint URLs (for non-default Rampart configurations).
     * @param {string} baseUrl - Rampart base URL (e.g., "http://127.0.0.1:9000")
     */
    setBaseUrl: function (baseUrl) {
      if (baseUrl) {
        this.signalEndpoint = baseUrl + '/api/v1/lens-signals';
        this.healthEndpoint = baseUrl + '/api/v1/lens-signals/healthz';
        this.rampartAvailable = false; // Reset state
        this.lastHealthCheck = 0;
      }
    },

    /**
     * Reset statistics.
     */
    resetStats: function () {
      this.stats = {
        signalsSent: 0,
        signalsFailed: 0,
        escalations: 0,
        blocksRecommended: 0
      };
    }
  };

  // Export for use by Lens background script
  if (typeof self !== 'undefined') {
    self.__aegisgateRampartBridge = RAMPART_BRIDGE;
  }
  if (typeof globalThis !== 'undefined') {
    globalThis.__aegisgateRampartBridge = RAMPART_BRIDGE;
  }
})();