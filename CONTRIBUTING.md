# Contributing to AegisGate Lens

Thank you for your interest in AegisGate Lens. This document explains how to contribute. **The single most important rule is at the top, in large text.** Please read it.

---

## 🚫 ABSOLUTE: No npm, no node_modules, no package.json. Ever.

**AegisGate Lens is a privacy product. Every third-party package is a potential supply-chain attack vector. We do not use `npm` and we do not use `node_modules`.**

Specifically:

- ❌ **No `package.json`.** The repository does not contain a `package.json` file. If your PR adds one, the PR will be rejected.
- ❌ **No `package-lock.json`, `yarn.lock`, or any other lockfile.**
- ❌ **No `node_modules/`** in the repo or in any commit.
- ❌ **No `npm install`, `npm ci`, `yarn`, `pnpm`, or any package manager** anywhere in the build process, the CI workflows, or the development instructions.
- ❌ **No `actions/setup-node`** in any GitHub Actions workflow. The CI runs Go only.
- ❌ **No third-party JavaScript libraries** (no `transformers.js`, no `onnxruntime-web`, no `lodash`, no `axios`, no `prettier`, no `eslint`, no `jest`, no `vitest`, no `mocha`, no `chai`, no `react`, no `vue`, no `svelte`, no `jquery`, no `moment`, no `dayjs`, no `rxjs`, no nothing).
- ❌ **No vendored `tsc.js` or any other vendored JS file.** If we need a transpiler, we hand-transpile.
- ❌ **No `esbuild`, `webpack`, `rollup`, `parcel`, `vite`, `swc`, `babel`, or any bundler installed via `npm`.** The build tool is a Go program that lives in the [Platform monorepo](https://github.com/aegisgatesecurity/aegisgate-platform), and it does not depend on any of these.
- ❌ **No remote code loading at runtime.** The extension does not `import()` URLs, does not fetch code from CDNs, does not eval strings.

If you believe you have a legitimate need for any of the above, open an issue first to discuss it. The bar is "is this strictly necessary to ship the v0.1 feature set?" If the answer is no, the answer is no.

### Why?

The full rationale is in [`docs/NO-EXTERNAL-DEPS.md`](docs/NO-EXTERNAL-DEPS.md). The short version:

1. **Privacy.** The Lens is a privacy product. Every dep is a potential supply-chain attack vector. Audit burden should be zero, not "audited quarterly."
2. **Operational simplicity.** No `package-lock.json` drift, no `npm audit` failures at 2am, no transitive dep surprises.
3. **Consistency with the Platform.** The Platform is Go-only with a closed dep set. The Lens matches.
4. **Solo-dev pragmatism.** One founder, one repo, one binary, zero supply-chain surprises.

### The CI check

The Platform's CI includes a grep check that fails the build if any of the forbidden files appear. Specifically:

```bash
if [ -f package.json ] || [ -d node_modules ] || [ -f package-lock.json ] || [ -f yarn.lock ]; then
  echo "ERROR: npm artifacts found in repo"
  exit 1
fi
```

This check runs on every PR. It cannot be bypassed.

---

## What is welcome

- **Bug reports** via the [`bug_report.md`](.github/ISSUE_TEMPLATE/bug_report.md) template.
- **Feature requests** via the [`feature_request.md`](.github/ISSUE_TEMPLATE/feature_request.md) template.
- **Documentation improvements** to this repo (clarifications, typo fixes, additional examples).
- **Test cases** for the detector (corpus samples in `test/`) — **as JSON files, not as JS code**. The corpus is the test input; the test harness is a Go program in the Platform monorepo.
- **Privacy policy feedback** — open an issue with the label `privacy`.

When the extension source is published (Step D in the build sequence), code contributions will be welcome. Until then, the source files in `src/` are placeholders; please do not open PRs adding to them.

---

## Pull request process (when source is published)

1. **Open an issue first** for non-trivial changes. Discuss the approach before you write code.
2. **Fork the repo** and create a feature branch.
3. **Make your change** consistent with the existing code style.
4. **Verify locally** that:
   - The Platform's CI checks pass: `cd ../aegisgate-platform && go test -race ./pkg/lensbackend/...`
   - The `No npm check` passes: there is no `package.json` etc. anywhere in your changes.
5. **Open a PR** with a clear description of what changed and why.
6. **Wait for review.** The founder is the only reviewer and has limited time. Be patient.

---

## Coding style

For the Go build tool (in the Platform monorepo): follow the Platform's existing style. `gofmt`, `go vet`, `staticcheck` are enforced.

For the TypeScript source (in this repo, when it lands in Step D): hand-written ES2020, no transpilation. The build tool's lint rules will enforce:
- No `eval`, no `Function(`, no `innerHTML`.
- No `fetch` outside the allowlist.
- No `import()` of remote URLs.
- No `prompt`, `content`, `input`, `textarea`, `url`, or `host` in any log line.

---

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0. See [`LICENSE`](LICENSE).

---

## Code of Conduct

This project adheres to the Contributor Covenant. See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Be kind. Be patient. We are all here to build something good.


---

## Development environment setup

This section explains how to set up a local development environment to run the Lens tests, build the extension, and submit a PR.

### Prerequisites

- **Node.js 20 LTS** (matches what the extension stores target). Use `nvm` or `fnm` to manage Node versions.
- **Git** for version control.
- **Google Chrome 120+** for manual testing of the extension.
- A Unix-like shell (bash, zsh). Windows users: use WSL2.
- A text editor with JavaScript syntax highlighting. VSCode with the `vscode-eslint` and `vscode-jest` extensions is recommended.

No `npm install` is required. The Lens has **zero third-party JavaScript dependencies** (see `SECURITY.md` and `docs/NO-EXTERNAL-DEPS.md`).

### Clone the repository

```bash
git clone https://github.com/aegisgatesecurity/aegisgate-lens.git
cd aegisgatesecurity-aegisgate-lens
git checkout v0.3.0-rc1  # or main for the latest dev
```

### Run the test suite

```bash
# All test suites
for t in test/*.test.mjs; do node "$t"; done
```

Test counts (as of v0.3.0-rc1): 233/233 passing across 21 suites. Each suite prints its own PASS/FAIL summary.

### Run a single test

```bash
node test/model-loader.test.mjs
```

### Real-browser end-to-end test

The real-browser E2E test requires Chrome 120 (Chrome-for-Testing). To run:

```bash
# Download Chrome-for-Testing 120 to a gitignored location (NOT /tmp/)
mkdir -p .chrome120
cd .chrome120
wget -q https://storage.googleapis.com/chrome-for-testing-public/120.0.6046.0/linux64/chrome-linux64.zip
unzip -q chrome-linux64.zip
cd ..

# Start Chrome 120 on Xvfb display :88
bash test/scripts/launch-chrome120.sh 9720

# In a separate terminal, run the Python E2E test
.venv-v02/bin/python test/scripts/chrome120-comprehensive-test.py
```

### Build the production extension ZIP

```bash
# The build tool is a Go program in the Platform monorepo
cd ../aegisgate-platform
go run tools/build-lens-extension/ --src ../aegisgatesecurity-aegisgate-lens/
```

### Project structure (v0.3.0)

```
.
├── src/                          # Extension source (vanilla JavaScript, IIFE pattern)
│   ├── manifest.json            # MV3 manifest
│   ├── content.js                # Content script (the only code that sees prompt text)
│   ├── service-worker.js         # MV3 service worker (router)
│   ├── popup.js                  # Popup UI
│   ├── storage.js                # chrome.storage wrapper
│   ├── api/client.js             # Telemetry client (with privacy boundary)
│   ├── detectors/                # 5-facet regex cascade
│   ├── privacy/                  # domain_hash, schema
│   └── util/                     # logger, opt-in, model-loader, bundle-loader, etc.
├── test/                         # 21 test suites, 233/233 passing
├── docs/                         # ARCHITECTURE, THREAT-MODEL, COMPLIANCE-MATRIX, etc.
├── pen-test/                     # Security pen-tests (F-01 to F-15)
├── harness/                      # Manual test harnesses
├── .github/                      # CI workflows, issue/PR templates, CODEOWNERS
├── plans/                        # Internal planning docs (gitignored)
├── lens-final-dist/              # The built extension (shipped artifact)
└── lens-final-dist-firefox/      # Firefox port
```

### Code style

- Vanilla JavaScript, ES2020+ features. No TypeScript, no transpilation.
- IIFE pattern for modules. No global namespace pollution. See `src/util/logger.js` for an example.
- JSDoc comments on all public functions. Use `node --check` for syntax validation.
- No `eval`, no `Function(`, no `innerHTML` (CSP-enforced in the extension).
- No third-party libraries. No `package.json`. (See `docs/NO-EXTERNAL-DEPS.md` for the full rationale.)

### Submitting a PR

1. Fork the repo.
2. Create a feature branch: `git checkout -b feature/your-change`
3. Make your changes.
4. Run the test suite (above). All 233 tests must pass.
5. Sign off your commits: `git commit -s` (DCO, see `DCO.md`).
6. Push the branch and open a PR using the `PULL_REQUEST_TEMPLATE.md`.
7. The CI will run the 21 test suites.

### Common pitfalls

- **Do not add `package.json` or `node_modules/`.** The CI grep check will fail the build.
- **Do not commit secrets or PII to test fixtures.**
- **Do not modify the Ed25519 signing keys in `keys/`** without coordinating with the maintainer.

