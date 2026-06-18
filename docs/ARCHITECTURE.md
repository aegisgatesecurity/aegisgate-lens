# Architecture

The canonical architecture document for AegisGate Lens lives in the [AegisGate Platform monorepo](https://github.com/aegisgatesecurity/aegisgate-platform):

**[AEGISGATE-LENS-ARCHITECTURE-v1.md](https://github.com/aegisgatesecurity/aegisgate-platform/blob/main/plans/AEGISGATE-LENS-ARCHITECTURE-v1.md)**

The document is owned by the Platform monorepo because the architecture spans both the Lens extension (this repo) and the Lens backend (in the Platform monorepo at `pkg/lensbackend/`). The Platform monorepo is the single source of truth.

## Summary (v0.1)

- **Extension:** Manifest V3 Chrome extension, hand-written TypeScript, no third-party JS deps.
- **Backend:** Go service in the Platform monorepo, single static binary, reuses `pkg/ioc`, `pkg/attestation`, `pkg/auth`, `pkg/logging`, `upstream/aegisgate/pkg/resilience/ratelimit`.
- **Build:** A Go program in the Platform monorepo at `tools/build-lens-extension/`. This repo is the source files and assets only.
- **Data flow:** Browser (anonymized metadata only) → TLS 1.2+ → Backend → `pkg/ioc.Store` → AegisGate Gateway (via existing gossip protocol).
- **Privacy boundary:** The only fields that cross the wire are the 9 fields in the §1.1 schema (`domain_hash`, `category`, `severity`, `user_action`, `timestamp`, `model_version`, `lens_version`, `confidence`, `id`). The `id` is dropped server-side; the other 8 are validated and aggregated into IOCs.

## Why the build lives in the Platform monorepo, not here

A few reasons:

1. **Reuse.** The Platform's regex patterns, schema definitions, and IOC store types can be referenced from the build tool. Importing from the Platform repo into a tool in this repo would require git submodule or vendoring, which is fragile.
2. **Single CI.** The Platform's CI is already mature (gofmt, go vet, govulncheck, CodeQL, 0 open alerts). Adding a second CI for this repo doubles the maintenance.
3. **Single release artifact identity.** The Lens's release version is the Platform's release version + a Lens-specific suffix. Bundling the build with the Platform release means the two are guaranteed in lockstep.
4. **No npm.** The constraint is "no npm anywhere in the Lens stack." A CI in this repo would need to be carefully constructed to avoid `actions/setup-node`; by putting the CI in the Platform, the constraint is enforced once.

The trade-off: this repo does not have a green "build passing" badge. Instead, the README points to the Platform's CI, which builds the extension as a release artifact.
