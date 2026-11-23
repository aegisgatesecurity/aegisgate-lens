// AegisGate Lens — ml/threat-detector-js.js
// WITHDRAWN 2026-11-23: The CharCNN-BiLSTM threat model was trained on a
// corpus whose attack-side labels failed audit (~71% flip rate). The model
// weights have been removed from this repository. This module remains as a
// no-op stub so the extension keeps working with regex detection only.
// Do not restore the model without a re-audited corpus, retrain, and
// re-baselined metrics (see docs/ML-WITHDRAWN.md).
(function (global) {
  'use strict';
  var log = (global && global.console) || console;
  try { log.warn('[AegisGate Lens] ML threat detection is WITHDRAWN (2026-11-23); running regex-only'); } catch (e) {}

  function loadModel() { return Promise.resolve({ withdrawn: true }); }
  function classify() { return Promise.resolve({ isAdversarial: false, score: 0, modelVersion: 'withdrawn-2026-11-23', withdrawn: true }); }
  function unloadModel() {}
  function getDiagnostics() { return { modelLoaded: false, withdrawn: true, modelVersion: 'withdrawn-2026-11-23', inferenceEngine: 'none' }; }

  var module = {
    loadModel: loadModel,
    classify: classify,
    unloadModel: unloadModel,
    getDiagnostics: getDiagnostics,
    MAX_SEQ_LEN: 512,
    PAD_ID: 0,
    UNK_ID: 1,
    THRESHOLD: 0.5,
    MODEL_VERSION: 'withdrawn-2026-11-23'
  };

  if (typeof self !== 'undefined') self.__lensThreatDetector = module;
  if (typeof window !== 'undefined') window.__lensThreatDetector = module;
  if (typeof globalThis !== 'undefined') globalThis.__lensThreatDetector = module;
})(typeof globalThis !== 'undefined' ? globalThis : this);
