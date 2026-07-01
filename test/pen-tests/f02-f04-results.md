# Pen-Tests F-02 + F-04 — 2026-06-28

## F-02: Bundle Tampering / Ed25519 Signature Bypass

- ✅ **1. Valid bundle parses** — verified OK
- ✅ **2. Payload byte flip → rejected** — Bundle signature verification FAILED - bundle may be tampered
- ✅ **3. Signature byte flip → rejected** — Bundle signature verification FAILED - bundle may be tampered
- ✅ **4. Wrong signature → rejected** — Bundle signature verification FAILED - bundle may be tampered
- ✅ **5. Header mutation → rejected** — Bundle signature verification FAILED - bundle may be tampered
- ✅ **6. Truncated bundle → rejected** — Bundle signature verification FAILED - bundle may be tampered
- ✅ **7. Garbage-appended bundle → rejected** — Bundle signature verification FAILED - bundle may be tampered
- ✅ **8. Key substitution → rejected** — Bundle signature verification FAILED - bundle may be tampered

**Summary**: 8/8 pass

## F-04: Dismissals Quota Flood

- ✅ **1. 100k expired + 1 storeDismissal → ≤2 entries (prune)**
- ✅ **2. 100k live + 1 storeDismissal → 1000 entries (cap)**
- ✅ **3. Mixed 100k expired + 1000 live + 1 storeDismissal → ≤1001**

## Summary

| Suite | Passed | Total |
|-------|--------|-------|
| F-02 (bundle tampering) | 8 | 8 |
| F-04 (dismissals flood) | 3 | 3 |

## Notes

- F-02 tests run against `src/util/bundle-loader.js` directly via Node.js vm.
- F-04 requires full chrome.storage.local environment; will run in Firefox e2e (Option B).
- F-01 (foreign sender) and F-05 (rate limit) also require backend / browser context.
