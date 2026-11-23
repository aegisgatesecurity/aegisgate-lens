<!-- SPDX-License-Identifier: Apache-2.0 -->
# ML Detection Withdrawn (2026-11-23)

**The ML threat detector in AegisGate Lens is WITHDRAWN and hard-disabled.**

The Char CNN-BiLSTM weights (`threat_cnn_bilstm_weights.bin.json`, "v22b-js") were exported from the same model lineage that failed corpus label audit (~71% attack-side flip rate; see internal report `corpus-certification-2026-11-23`). All detection-rate claims derived from it are void, including the "100% adversarial detection" and "98.99% detection rate" figures in the Terms of Service, README, and AMO listing.

The weights file has been removed from the repository, the content-script no longer loads it, and `src/detectors/ml/threat-detector-js.js` is now a no-op stub: `classify()` returns `{ isAdversarial: false, score: 0 }`. AegisGate Lens operates as a pure deterministic (regex/facet) detector. This is a safe degradation: no ML decisions are made.

The regex detection layer is unaffected. Performance, detection, and FP/FN figures quoted for regex layers were not produced by the withdrawn model and remain as previously published (they have not been re-audited).

**Reinstatement:** only after corpus re-audit, scoped rebuild, retrain, re-baseline, and re-publication of evaluation data.
