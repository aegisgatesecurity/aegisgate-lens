// SPDX-License-Identifier: Apache-2.0
// AegisGate Lens — IOC Pull Module
//
// Fetches IOC (Indicator of Compromise) updates from Platform or the
// Cloudflare Worker community endpoint. IOCs are SHA-256 fingerprints
// of known threats observed by other AegisGate instances.
//
// Architecture:
//   - Lens periodically fetches IOC updates from Platform (if configured)
//     or the Cloudflare Worker community endpoint
//   - IOCs are stored in chrome.storage.local for offline use
//   - During page scanning, Lens checks if detections match known IOCs
//   - Matching IOCs can escalate severity or trigger warnings
//
// Air-gap / privacy:
//   - If no endpoint is configured, Lens uses bundled patterns only
//   - IOC fingerprints are SHA-256 hashes — no PII, no prompt text
//   - Fetch is opt-in (user must enable IOC updates in settings)
//   - Uses If-Modified-Since for bandwidth efficiency
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function () {
  'use strict';

  var IOC_PULL = {
    // Default endpoints
    platformEndpoint: null, // Set by user (e.g., "https://platform.example.com:9091")
    communityEndpoint: 'https://lens.aegisgatesecurity.io/api/v1/ioc/latest',

    // State
    enabled: false,
    lastUpdated: null,
    pullInterval: 300000, // 5 minutes
    pullTimer: null,

    // IOC cache (stored in chrome.storage.local)
    iocs: [],
    maxIOCs: 1000, // Max IOCs to keep in local storage

    // Statistics
    stats: {
      pullsSuccessful: 0,
      pullsFailed: 0,
      iocsLoaded: 0,
      iocsMatched: 0,
      lastPullTime: null
    },

    /**
     * Initialize the IOC pull module.
     * @param {object} options - Configuration options
     * @param {string} options.platformUrl - Platform URL (optional)
     * @param {string} options.apiKey - Platform API key (optional)
     * @param {boolean} options.enabled - Whether IOC pull is enabled
     */
    init: function (options) {
      options = options || {};
      this.enabled = options.enabled || false;
      if (options.platformUrl) {
        this.platformEndpoint = options.platformUrl.replace(/\/$/, '') + '/api/v1/ioc/latest';
      }
      if (options.apiKey) {
        this._apiKey = options.apiKey;
      }

      // Load cached IOCs from storage
      var self = this;
      this._loadFromStorage(function () {
        if (self.enabled) {
          self.startPullLoop();
        }
      });
    },

    /**
     * Pull IOC updates from the configured endpoint.
     * @param {function} callback - Called with (success: boolean, count: number)
     */
    pull: function (callback) {
      if (!this.enabled) {
        if (callback) callback(false, 0);
        return;
      }

      var endpoint = this.platformEndpoint || this.communityEndpoint;
      var self = this;

      try {
        var xhr = new XMLHttpRequest();
        var url = endpoint;
        if (this.lastUpdated) {
          url += '?since=' + encodeURIComponent(this.lastUpdated);
        }

        xhr.open('GET', url, true);
        xhr.timeout = 10000; // 10 second timeout
        xhr.setRequestHeader('Content-Type', 'application/json');

        if (this._apiKey && this.platformEndpoint) {
          xhr.setRequestHeader('Authorization', 'Bearer ' + this._apiKey);
        }

        xhr.onload = function () {
          if (xhr.status === 200) {
            try {
              var data = JSON.parse(xhr.responseText);
              if (data.iocs && Array.isArray(data.iocs)) {
                self._mergeIOCs(data.iocs);
                self.lastUpdated = data.updated_at || new Date().toISOString();
                self.stats.pullsSuccessful++;
                self.stats.iocsLoaded = self.iocs.length;
                self.stats.lastPullTime = new Date().toISOString();
                self._saveToStorage();
                if (callback) callback(true, data.iocs.length);
              } else {
                self.stats.pullsFailed++;
                if (callback) callback(false, 0);
              }
            } catch (e) {
              self.stats.pullsFailed++;
              if (callback) callback(false, 0);
            }
          } else if (xhr.status === 304) {
            // Not modified — use cached IOCs
            self.stats.pullsSuccessful++;
            if (callback) callback(true, 0);
          } else {
            self.stats.pullsFailed++;
            if (callback) callback(false, 0);
          }
        };

        xhr.onerror = function () {
          self.stats.pullsFailed++;
          if (callback) callback(false, 0);
        };

        xhr.ontimeout = function () {
          self.stats.pullsFailed++;
          if (callback) callback(false, 0);
        };

        xhr.send();
      } catch (e) {
        self.stats.pullsFailed++;
        if (callback) callback(false, 0);
      }
    },

    /**
     * Check if a detection matches a known IOC.
     * @param {string} fingerprint - SHA-256 hash of the detection
     * @returns {object|null} Matching IOC entry or null
     */
    checkFingerprint: function (fingerprint) {
      if (!fingerprint || !this.iocs) return null;

      for (var i = 0; i < this.iocs.length; i++) {
        if (this.iocs[i].fingerprint === fingerprint) {
          this.stats.iocsMatched++;
          return this.iocs[i];
        }
      }
      return null;
    },

    /**
     * Check if a rule ID + hashed domain combination matches a known IOC.
     * @param {string} ruleId - Detection rule ID
     * @param {string} hashedDomain - Hashed domain
     * @returns {object|null} Matching IOC entry or null
     */
    checkRuleDomain: function (ruleId, hashedDomain) {
      if (!ruleId || !hashedDomain || !this.iocs) return null;

      for (var i = 0; i < this.iocs.length; i++) {
        var ioc = this.iocs[i];
        if (ioc.rule_id === ruleId && ioc.hashed_domain === hashedDomain) {
          this.stats.iocsMatched++;
          return ioc;
        }
      }
      return null;
    },

    /**
     * Get all cached IOCs.
     * @returns {array} Array of IOC entries
     */
    getAllIOCs: function () {
      return this.iocs || [];
    },

    /**
     * Get the number of cached IOCs.
     * @returns {number}
     */
    getIOCCount: function () {
      return this.iocs ? this.iocs.length : 0;
    },

    /**
     * Get statistics.
     * @returns {object}
     */
    getStats: function () {
      return this.stats;
    },

    /**
     * Start the background pull loop.
     */
    startPullLoop: function () {
      if (this.pullTimer) return;

      var self = this;
      // Initial pull
      this.pull();

      // Periodic pulls
      this.pullTimer = setInterval(function () {
        self.pull();
      }, this.pullInterval);
    },

    /**
     * Stop the background pull loop.
     */
    stopPullLoop: function () {
      if (this.pullTimer) {
        clearInterval(this.pullTimer);
        this.pullTimer = null;
      }
    },

    /**
     * Set the pull interval.
     * @param {number} intervalMs - Interval in milliseconds
     */
    setPullInterval: function (intervalMs) {
      this.pullInterval = intervalMs;
      if (this.pullTimer) {
        this.stopPullLoop();
        this.startPullLoop();
      }
    },

    // --- Internal methods ---

    /**
     * Merge new IOCs into the cache, replacing duplicates.
     * @param {array} newIOCs - Array of IOC entries from the server
     */
    _mergeIOCs: function (newIOCs) {
      var existing = {};
      for (var i = 0; i < this.iocs.length; i++) {
        existing[this.iocs[i].fingerprint] = this.iocs[i];
      }

      for (var j = 0; j < newIOCs.length; j++) {
        var ioc = newIOCs[j];
        if (ioc.fingerprint) {
          existing[ioc.fingerprint] = ioc;
        }
      }

      var merged = [];
      for (var fp in existing) {
        if (existing.hasOwnProperty(fp)) {
          merged.push(existing[fp]);
        }
      }

      // Cap at maxIOCs (keep most recently seen)
      if (merged.length > this.maxIOCs) {
        merged.sort(function (a, b) {
          var aTime = a.last_seen ? new Date(a.last_seen).getTime() : 0;
          var bTime = b.last_seen ? new Date(b.last_seen).getTime() : 0;
          return bTime - aTime;
        });
        merged = merged.slice(0, this.maxIOCs);
      }

      this.iocs = merged;
    },

    /**
     * Save IOCs to chrome.storage.local.
     */
    _saveToStorage: function () {
      try {
        if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
          chrome.storage.local.set({
            __aegisgate_iocs: this.iocs,
            __aegisgate_iocs_last_updated: this.lastUpdated
          });
        }
      } catch (e) {
        // Storage may not be available in all contexts
      }
    },

    /**
     * Load IOCs from chrome.storage.local.
     * @param {function} callback - Called when loading is complete
     */
    _loadFromStorage: function (callback) {
      var self = this;
      try {
        if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
          chrome.storage.local.get(['__aegisgate_iocs', '__aegisgate_iocs_last_updated'], function (result) {
            if (result && result.__aegisgate_iocs) {
              self.iocs = result.__aegisgate_iocs;
              self.lastUpdated = result.__aegisgate_iocs_last_updated || null;
              self.stats.iocsLoaded = self.iocs.length;
            }
            if (callback) callback();
          });
        } else {
          if (callback) callback();
        }
      } catch (e) {
        if (callback) callback();
      }
    },

    /**
     * Clear all cached IOCs.
     */
    clearCache: function () {
      this.iocs = [];
      this.lastUpdated = null;
      this._saveToStorage();
    },

    /**
     * Reset statistics.
     */
    resetStats: function () {
      this.stats = {
        pullsSuccessful: 0,
        pullsFailed: 0,
        iocsLoaded: 0,
        iocsMatched: 0,
        lastPullTime: null
      };
    }
  };

  // Export for use by Lens background script
  if (typeof self !== 'undefined') {
    self.__aegisgateIOCPull = IOC_PULL;
  }
  if (typeof globalThis !== 'undefined') {
    globalThis.__aegisgateIOCPull = IOC_PULL;
  }
})();