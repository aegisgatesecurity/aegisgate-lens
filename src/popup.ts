// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Popup UI
// =========================================================================
//
// The popup is the small UI that appears when the user clicks
// the Lens icon in the browser toolbar. It shows:
//
//   - The opt-in toggle.
//   - A summary of the user's 24-hour contribution.
//   - The local audit log (last N events).
//   - A "Clear local history" button.
//   - A link to the privacy policy.
//
// The popup does NOT show prompt content. It shows only
// metadata (category, severity, timestamp).
//
// v0.1 pre-release.
// =========================================================================

import { Storage } from "./storage.js";
import type {
  Category,
  LocalAuditEntry,
  OptInState,
} from "./types.js";

/**
 * The current Lens version.
 *
 * KEPT IN SYNC by tools/build-lens-extension in the
 * Platform monorepo. DO NOT EDIT THIS LINE; the build tool
 * templates it from version.txt at the Platform monorepo root.
 */
const LENS_VERSION = "0.1.0";

/** All categories, in display order. */
const CATEGORIES: ReadonlyArray<Category> = [
  "pii_email",
  "pii_phone",
  "pii_ssn",
  "pii_credit_card",
  "secret_api_key",
  "source_code",
];

/** The storage layer. */
const storage = new Storage();

/**
 * The current set of disabled categories. Held in module
 * scope so the toggle handler always sees the latest value
 * (the previous implementation captured the initial set in
 * a closure, so toggling category A then category B would
 * silently re-enable A).
 */
let currentDisabled: ReadonlySet<Category> = new Set();

/**
 * Run on DOMContentLoaded. Loads the opt-in state and
 * audit log, wires the toggle, renders the UI.
 */
document.addEventListener("DOMContentLoaded", () => {
  void init();
});

async function init(): Promise<void> {
  const state = await storage.getOptInState();
  const audit = await storage.getLocalAudit();
  currentDisabled = await storage.getDisabledCategories();
  renderOptIn(state);
  renderStats(state);
  renderAudit(audit);
  renderCategoryToggles(currentDisabled);
  wireClearButton();
  wireOptInToggle();
  wireCategoryToggles();
}

/** Render the opt-in toggle and the version line. */
function renderOptIn(state: OptInState): void {
  const toggle = document.getElementById("opt-in-toggle") as HTMLInputElement | null;
  if (toggle) toggle.checked = state.enabled;
  const version = document.getElementById("version");
  if (version) version.textContent = `Lens v${LENS_VERSION}`;
}

/** Render the "what you've contributed" stats area. */
function renderStats(state: OptInState): void {
  const statsEl = document.getElementById("stats");
  if (!statsEl) return;
  if (!state.enabled) {
    statsEl.textContent =
      "Telemetry is OFF. The Lens will still detect locally; nothing is sent to any server.";
    return;
  }
  // Pull fresh stats from the backend. The handleStats
  // function in the service worker returns the response;
  // here we display a summary line.
  chrome.runtime.sendMessage({ type: "lens.stats" }, (resp) => {
    if (!resp || resp.error) {
      statsEl.textContent = "Backend stats unavailable. Try again later.";
      return;
    }
    statsEl.textContent =
      `Last 24h: ${resp.events_24h} events across ` +
      `${Object.keys(resp.by_category ?? {}).length} categories. ` +
      `Network IOCs: ${resp.ioc_count ?? 0}.`;
  });
}

/** Render the local audit log. */
function renderAudit(audit: ReadonlyArray<LocalAuditEntry>): void {
  const list = document.getElementById("audit-list");
  if (!list) return;
  while (list.firstChild) list.removeChild(list.firstChild);
  if (audit.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No local detections yet.";
    list.appendChild(li);
    return;
  }
  for (const e of audit.slice(0, 100)) {
    const li = document.createElement("li");
    const ts = new Date(e.timestamp).toLocaleString();
    li.textContent =
      `[${ts}] ${describeCategory(e.category)} (${e.severity}) ` +
      `→ ${e.user_action}`;
    list.appendChild(li);
  }
}

/** Render the per-category on/off toggles. */
function renderCategoryToggles(disabled: ReadonlySet<Category>): void {
  const container = document.getElementById("category-toggles");
  if (!container) return;
  while (container.firstChild) container.removeChild(container.firstChild);
  for (const c of CATEGORIES) {
    const id = `cat-${c}`;
    const wrap = document.createElement("label");
    wrap.setAttribute("for", id);
    Object.assign(wrap.style, {
      display: "flex",
      alignItems: "center",
      gap: "8px",
      padding: "4px 0",
    });
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.id = id;
    cb.checked = !disabled.has(c);
    cb.dataset.category = c;
    const span = document.createElement("span");
    span.textContent = describeCategory(c);
    wrap.appendChild(cb);
    wrap.appendChild(span);
    container.appendChild(wrap);
  }
}

/** Wire the opt-in toggle. */
function wireOptInToggle(): void {
  const toggle = document.getElementById("opt-in-toggle") as HTMLInputElement | null;
  if (!toggle) return;
  toggle.addEventListener("change", () => {
    const enabled = toggle.checked;
    chrome.runtime.sendMessage({
      type: "lens.optIn",
      enabled,
    });
    void enabled; // unused beyond send
  });
}

/** Wire the per-category toggles. */
function wireCategoryToggles(): void {
  const container = document.getElementById("category-toggles");
  if (!container) return;
  container.addEventListener("change", (ev) => {
    const target = ev.target as HTMLInputElement | null;
    if (!target || target.tagName !== "INPUT") return;
    const cat = target.dataset.category as Category | undefined;
    if (!cat) return;
    // Read the LATEST disabled set from module scope, not
    // a stale closure capture. This is the fix for the bug
    // where toggling category A then category B would
    // silently re-enable A.
    const next = new Set(currentDisabled);
    if (target.checked) {
      next.delete(cat);
    } else {
      next.add(cat);
    }
    currentDisabled = next;
    void storage.setDisabledCategories(next);
  });
}

/** Wire the "Clear local history" button. */
function wireClearButton(): void {
  const btn = document.getElementById("clear-local") as HTMLButtonElement | null;
  if (!btn) return;
  btn.addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "lens.clearLocalAudit" }, () => {
      void storage.getLocalAudit().then((audit) => renderAudit(audit));
    });
  });
}

/** Human-readable description for a category. */
function describeCategory(c: Category): string {
  switch (c) {
    case "pii_email":
      return "Email address";
    case "pii_phone":
      return "Phone number";
    case "pii_ssn":
      return "Social Security number";
    case "pii_credit_card":
      return "Credit card number";
    case "secret_api_key":
      return "API key or token";
    case "source_code":
      return "Source code (private key)";
  }
}
