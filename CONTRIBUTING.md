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
