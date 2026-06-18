# src/

This directory will hold the TypeScript source files for the AegisGate Lens browser extension.

**Status: empty in v0.1-pre-build. Populated in Step D of the build sequence.**

The files that will live here (per `plans/AEGISGATE-LENS-ARCHITECTURE-v1.md` in the Platform monorepo):

```
src/
├── content.ts                # ~400 LOC — DOM observation, regex detection
├── service-worker.ts         # ~300 LOC — message routing, opt-in state, telemetry queue
├── popup.html
├── popup.ts                  # ~200 LOC — opt-in toggle, local audit log viewer
├── detectors/
│   ├── regex.ts              # The 7 categories of regex patterns
│   ├── luhn.ts               # Credit card Luhn check
│   └── types.ts              # Category/severity enums
├── privacy/
│   ├── schema.ts             # The 9-field event schema
│   └── domain_hash.ts        # SHA-256 truncation via Web Crypto API
├── api/
│   └── client.ts             # fetch wrapper with 100/min rate limit
└── types.ts                  # Shared types
```

**No third-party dependencies.** The TypeScript is hand-written ES2020, bundled by a Go program in the Platform monorepo, with no `npm` anywhere. See `../docs/NO-EXTERNAL-DEPS.md` for the full constraint.

The schema validation in `src/privacy/schema.ts` is the same as the one in `pkg/lensbackend/validation.go` in the Platform monorepo. The build tool in the Platform generates a `dist/schema.json` from the Go struct tags so the TypeScript code and the Go code cannot drift.
