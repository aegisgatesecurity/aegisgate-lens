// AegisGate Lens — util/typedefs.js
//
// Central JSDoc type definitions for every module export in the
// Lens. Loaded once at boot (manifest declares it as the second
// content_script after constants.js). At runtime this file has no
// effect; its purpose is to give editors (VS Code, WebStorm,
// GitHub code review) the ability to type-check and auto-complete
// against the actual runtime shape of every module.
//
// Per the v0.1.1 code-quality plan (item 4).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  /**
   * @typedef {Object} LensConstants
   * @property {number} DEBOUNCE_MS
   * @property {number} BANNER_FADE_IN_MS
   * @property {number} BANNER_MAX_ITEMS
   * @property {number} BANNER_Z_INDEX
   * @property {number} MAX_EVENTS_RING
   * @property {number} MAX_USER_ACTIONS
   * @property {{DISMISSALS: string, USER_ACTIONS: string, FP_REPORTS_QUEUE: string, OPT_IN: string, SESSION_DISMISS: string}} STORAGE_KEYS
   * @property {number} DISMISS_TTL_MS
   * @property {string} STORAGE_SCHEMA_VERSION
   * @property {{TEST_DATA: string, OWN_DATA: string, LEGITIMATE: string}} FP_REASON
   * @property {Object<string, string>} COLORS
   * @property {{CRITICAL: string, HIGH: string, MEDIUM: string, LOW: string}} SEVERITY
   * @property {string[]} CATEGORY_PREFIXES
   * @property {{PII: string, SECRETS: string, XSS: string, COMPLIANCE: string}} FACETS
   * @property {{LEARN_MORE: string, PLATFORM_CTA: string, PRIVACY: string, SUPPORT: string, HOMEPAGE: string}} URLS
   */

  /**
   * @typedef {Object} LensLogger
   * @property {(m: string) => void} info
   * @property {(m: string) => void} warn
   * @property {(m: string, e?: Error) => void} error
   */

  /**
   * @typedef {('critical'|'high'|'medium'|'low')} LensSeverity
   */

  /**
   * @typedef {Object} LensDetectionEvent
   * @property {string} category
   * @property {LensSeverity} severity
   * @property {string} [sample]
   * @property {number} [index]
   * @property {string} [pattern]
   * @property {string} [facet]
   */

  /**
   * @typedef {Object} LensDetectionResult
   * @property {LensDetectionEvent[]} events
   * @property {string} [facet]
   */

  /**
   * @typedef {Object} LensDomainHash
   * @property {(hostname: string) => string} hash
   * @property {(hostname: string) => Promise<string>} hashAsync
   */

  /**
   * @typedef {Object} LensProvider
   * @property {string} id
   * @property {string} name
   * @property {string[]} hosts
   * @property {string} inputSelector
   * @property {string} [sendSelector]
   * @property {string} [containerSelector]
   * @property {('button'|'form'|'enter'|'unknown')} submitMethod
   * @property {boolean} [isContentEditable]
   * @property {string} version
   */

  /**
   * @typedef {Object} LensSelectors
   * @property {LensProvider[]} PROVIDERS
   * @property {() => LensProvider | null} identifyProvider
   * @property {() => HTMLElement | null} findInput
   * @property {() => string} getInputValue
   * @property {(el: HTMLElement, value: string) => void} setInputValue
   * @property {() => HTMLElement | null} findSendButton
   * @property {() => HTMLElement | null} findContainer
   */

  /**
   * @typedef {Object} LensDetectorPattern
   * @property {string} key
   * @property {string} category
   * @property {RegExp} re
   * @property {LensSeverity} severity
   * @property {string} [description]
   */

  /**
   * @typedef {Object} LensDetector
   * @property {string} facet
   * @property {Object<string, LensDetectorPattern>} patterns
   * @property {(text: string) => LensDetectionEvent[]} detect
   * @property {string} version
   */

  /**
   * @typedef {Object} LensDispatcher
   * @property {(text: string) => LensDetectionEvent[]} detect
   * @property {string[]} [facets]
   * @property {Object<string, LensDetector>} [_modules]
   */

  /**
   * @typedef {Object} LensBannerOptions
   * @property {(action: string, payload: Object) => void} [onAction]
   * @property {string} [learnMoreUrl]
   * @property {string} [platformUrl]
   * @property {string} [scope]
   */

  /**
   * @typedef {Object} LensBannerState
   * @property {HTMLElement} el
   * @property {LensDetectionEvent[]} events
   * @property {LensBannerOptions} opts
   * @property {boolean} visible
   */

  /**
   * @typedef {Object} LensBannerUI
   * @property {(events: LensDetectionEvent[], opts?: LensBannerOptions) => void} show
   * @property {() => void} hide
   * @property {() => boolean} isVisible
   * @property {() => HTMLElement | null} getElement
   * @property {() => void} injectStyles
   */

  /**
   * @typedef {Object} LensPromptDetect
   * @property {() => void} attach
   * @property {() => void} detach
   * @property {() => void} onInput
   * @property {() => void} onSendClick
   * @property {() => void} onKeyDown
   * @property {(text: string) => LensDetectionEvent[]} detect
   * @property {() => boolean} isAttached
   * @property {() => string} getState
   */

  /**
   * @typedef {Object} LensDismissRecord
   * @property {string} domainHash
   * @property {string} category
   * @property {string} [patternId]
   * @property {string} reason
   * @property {number} expiresAt
   * @property {string} schemaVersion
   */

  /**
   * @typedef {Object} LensDismiss
   * @property {() => Promise<Object<string, LensDismissRecord>>} getAll
   * @property {(domainHash: string, category: string, patternId: string, reason: string) => Promise<boolean>} add
   * @property {(domainHash: string, category: string, patternId: string) => Promise<boolean>} isDismissed
   * @property {(domainHash: string, category: string, patternId: string) => Promise<boolean>} remove
   * @property {() => Promise<void>} clearAll
   * @property {() => Promise<number>} prune
   * @property {string} STORAGE_KEY
   * @property {number} TTL_MS
   * @property {string} SCHEMA_VERSION
   */

  /**
   * @typedef {Object} LensMessageEnvelope
   * @property {string} type
   * @property {string} version
   * @property {Object} payload
   */

  /**
   * @typedef {Object} LensMessages
   * @property {Object<string, string>} TYPE
   * @property {(msg: Object) => boolean} isValidEnvelope
   * @property {(msg: Object) => boolean} isValidFPReports
   * @property {(msg: Object) => boolean} isValidUserAction
   */

  /**
   * @typedef {Object} LensPrivacyCategory
   * @property {string} id
   * @property {string} name
   * @property {string} facet
   * @property {string} description
   * @property {string[]} examples
   */

  /**
   * @typedef {Object} LensSchema
   * @property {string} version
   * @property {LensPrivacyCategory[]} categories
   * @property {Object<string, string[]>} [patternsByCategory]
   */

  if (typeof globalThis !== 'undefined') {
    globalThis.__lensTypedefs = {
      version: '0.1.1',
      loaded: new Date().toISOString()
    };
  }
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));
