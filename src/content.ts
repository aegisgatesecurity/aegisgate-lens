// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Content Script
// =========================================================================
//
// The content script runs in the context of the AI provider's
// web page (e.g., chat.openai.com). It is the ONLY place in
// the extension that sees the user's prompt text. It:
//
//   1. Observes DOM mutations on the prompt input area.
//   2. Calls detectors/detect() on the prompt text.
//   3. Renders the warning UI inline (a banner at the top
//      of the prompt area) when sensitive data is detected.
//   4. Sends a LensEvent to the service worker (NOT to the
//      backend directly) when the user takes an action
//      (send_anyway, edit, cancel, dismiss).
//
// Privacy boundary: the content script never makes a network
// request directly. All outbound traffic is via the service
// worker, which applies the rate limit and the auth header.
//
// v0.1 pre-release.
// =========================================================================

import { detect, describeCategory } from "./detectors/index.js";
import { computeDomainHash } from "./privacy/domain_hash.js";
import type { Category, Detection, LensEvent, Severity } from "./types.js";

/** The supported AI providers, mapped by hostname. */
interface ProviderInfo {
  /** The provider's canonical name. */
  name: string;
  /** CSS selector for the prompt input (textarea or contenteditable). */
  promptSelector: string;
  /** CSS selector for the send button. */
  sendSelector: string;
}

const PROVIDERS: ReadonlyMap<string, ProviderInfo> = new Map([
  [
    "chat.openai.com",
    {
      name: "chatgpt",
      promptSelector: "#prompt-textarea",
      sendSelector: 'button[data-testid="send-button"]',
    },
  ],
  [
    "chatgpt.com",
    {
      name: "chatgpt",
      promptSelector: "#prompt-textarea",
      sendSelector: 'button[data-testid="send-button"]',
    },
  ],
  [
    "claude.ai",
    {
      name: "claude",
      promptSelector: 'div[contenteditable="true"]',
      sendSelector: 'button[aria-label*="Send"]',
    },
  ],
  [
    "gemini.google.com",
    {
      name: "gemini",
      promptSelector: 'div[contenteditable="true"]',
      sendSelector: 'button[aria-label*="Send"]',
    },
  ],
  [
    "copilot.microsoft.com",
    {
      name: "copilot",
      promptSelector: "#userInput",
      sendSelector: 'button[type="submit"]',
    },
  ],
  [
    "duck.ai",
    {
      name: "duck",
      promptSelector: 'textarea[id*="user-input"], div[contenteditable="true"]',
      sendSelector: 'button[aria-label*="Send"]',
    },
  ],
]);

/** Throttle interval for re-running detect() on input. */
const DETECT_THROTTLE_MS = 250;

/**
 * ContentScript is the entry point. One instance per
 * top-level frame. It is created by the init() function
 * when the DOM is ready.
 */
class ContentScript {
  private hostname: string = "";
  private provider = null;
  private domainHash: string = "";
  private banner = null;
  private currentDetections: Array = [];
  private lastDetectAt = 0;
  private pendingDetect = null;

  /**
   * Initialize the content script for the current page.
   * Called from the script's top-level await.
   */
  async init(): Promise<void> {
    this.hostname = window.location.hostname.toLowerCase();
    const info = PROVIDERS.get(this.hostname);
    if (!info) {
      // Not a supported provider; do nothing.
      return;
    }
    this.provider = info;
    this.domainHash = await computeDomainHash(this.hostname);
    // Wait for the prompt area to appear, then attach.
    await this.waitForPrompt();
    this.attach();
  }

  /**
   * Wait for the prompt input to appear in the DOM. The AI
   * providers are SPAs, so the prompt area is rendered
   * after the initial JS loads.
   */
  private async waitForPrompt(): Promise<void> {
    const sel = this.provider.promptSelector;
    for (let i = 0; i < 60; i++) {
      if (document.querySelector(sel)) return;
      await sleep(500);
    }
  }

  /**
   * Attach the input listener. We use a throttled detect:
   * every DETECT_THROTTLE_MS, we re-run the detector on
   * the current prompt text.
   */
  private attach(): void {
    const el = document.querySelector(this.provider.promptSelector);
    if (!el) return;
    el.addEventListener("input", () => this.scheduleDetect());
    el.addEventListener("keyup", () => this.scheduleDetect());
    el.addEventListener("paste", () => this.scheduleDetect());
  }

  /**
   * Schedule a detect run. Throttled to DETECT_THROTTLE_MS.
   */
  private scheduleDetect(): void {
    if (this.pendingDetect !== null) return;
    const elapsed = Date.now() - this.lastDetectAt;
    const delay = Math.max(0, DETECT_THROTTLE_MS - elapsed);
    this.pendingDetect = window.setTimeout(() => {
      this.pendingDetect = null;
      this.lastDetectAt = Date.now();
      this.runDetect();
    }, delay);
  }

  /**
   * Run the detector on the current prompt text. Update
   * the banner UI accordingly.
   */
  private runDetect(): void {
    const el = document.querySelector(this.provider.promptSelector);
    if (!el) return;
    const text = readPromptText(el);
    const detections = detect(text);
    this.currentDetections = detections;
    if (detections.length > 0) {
      this.showBanner(detections);
    } else {
      this.hideBanner();
    }
  }

  /**
   * Show the warning banner. The banner lists each detection
   * with a "Send anyway", "Edit", or "Cancel" button.
   */
  private showBanner(detections: Array): void {
    if (this.banner && document.body.contains(this.banner)) {
      // Update the existing banner's content.
      this.updateBannerContent(detections);
      return;
    }
    const banner = document.createElement("div");
    banner.id = "__aegisgate_lens_banner__";
    banner.setAttribute("role", "alert");
    banner.setAttribute("aria-live", "polite");
    Object.assign(banner.style, {
      // v0.1: banner is at the top of the page (max z-index
      // for visibility). v0.2 (L-4 backlog): consider
      // placing the banner inline near the prompt area, not
      // the page top, since chat apps put the prompt at the
      // bottom. v0.1 placement is "always visible" and is
      // the conservative choice.
      position: "fixed",
      top: "0",
      left: "0",
      right: "0",
      zIndex: "2147483647",
      background: "#fef3c7",
      borderBottom: "2px solid #f59e0b",
      padding: "12px 16px",
      // paddingRight leaves room for the absolute-positioned
      // dismiss button (×) so the action buttons don't
      // collide with it.
      paddingRight: "40px",
      fontFamily:
        '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      fontSize: "14px",
      color: "#1f2937",
      boxShadow: "0 2px 8px rgba(0,0,0,0.08)",
    });
    document.body.appendChild(banner);
    this.banner = banner;
    this.updateBannerContent(detections);
  }

  /**
   * Update the banner's content. Replaces children; does
   * not recreate the banner element.
   */
  private updateBannerContent(detections: Array): void {
    if (!this.banner) return;
    // Clear.
    while (this.banner.firstChild) {
      this.banner.removeChild(this.banner.firstChild);
    }
    // Header.
    const header = document.createElement("div");
    Object.assign(header.style, {
      fontWeight: "600",
      marginBottom: "6px",
    });
    const count = detections.length;
    header.textContent =
      `🛡️ AegisGate Lens: ${count} sensitive item${count === 1 ? "" : "s"} detected in your prompt.`;
    this.banner.appendChild(header);
    // List.
    const list = document.createElement("ul");
    Object.assign(list.style, {
      margin: "0 0 8px 0",
      paddingLeft: "20px",
    });
    for (const d of detections) {
      const li = document.createElement("li");
      li.textContent = `${describeCategory(d.category)} (${d.severity}) — match: "${d.match}"`;
      list.appendChild(li);
    }
    this.banner.appendChild(list);
    // Actions row: Cancel (left), Edit, Send anyway (right).
    // The Dismiss button is a small × in the corner of the
    // banner; it emits a 'dismiss' user_action and hides
    // the banner without changing the prompt.
    const dismissBtn = document.createElement("button");
    dismissBtn.textContent = "×";
    dismissBtn.setAttribute("aria-label", "Dismiss this warning");
    Object.assign(dismissBtn.style, {
      position: "absolute",
      top: "8px",
      right: "12px",
      background: "transparent",
      border: "none",
      fontSize: "20px",
      lineHeight: "1",
      cursor: "pointer",
      color: "#1f2937",
      padding: "0 4px",
    });
    dismissBtn.addEventListener("click", () => {
      this.recordAction("dismiss");
      this.hideBanner();
    });
    this.banner.appendChild(dismissBtn);
    // Actions.
    const actions = document.createElement("div");
    Object.assign(actions.style, {
      display: "flex",
      gap: "8px",
    });
    actions.appendChild(
      this.makeActionButton("Cancel", "critical", () => {
        this.recordAction("cancel");
        this.clearPrompt();
        this.hideBanner();
      }),
    );
    actions.appendChild(
      this.makeActionButton("Edit", "low", () => {
        this.recordAction("edit");
        this.hideBanner();
      }),
    );
    actions.appendChild(
      this.makeActionButton("Send anyway", "high", () => {
        this.recordAction("send_anyway");
        this.hideBanner();
      }),
    );
    this.banner.appendChild(actions);
  }

  /**
   * Build a button with the given label, severity-tinted,
   * that calls onClick on click.
   */
  private makeActionButton(
    label: string,
    severity: Severity,
    onClick,
  ): HTMLButtonElement {
    const btn = document.createElement("button");
    btn.textContent = label;
    Object.assign(btn.style, {
      padding: "6px 12px",
      border: "none",
      borderRadius: "4px",
      cursor: "pointer",
      fontSize: "13px",
      fontWeight: "500",
    });
    const tint = severityTint(severity);
    btn.style.background = tint.bg;
    btn.style.color = tint.fg;
    btn.addEventListener("click", onClick);
    return btn;
  }

  /**
   * Hide the banner. The next detect() run will show it
   * again if detections are still present.
   */
  private hideBanner(): void {
    if (this.banner && document.body.contains(this.banner)) {
      document.body.removeChild(this.banner);
    }
    this.banner = null;
  }

  /**
   * Clear the prompt input. Used by the "Cancel" action.
   */
  private clearPrompt(): void {
    const el = document.querySelector(this.provider.promptSelector);
    if (!el) return;
    if (el instanceof HTMLTextAreaElement) {
      el.value = "";
      el.dispatchEvent(new Event("input", { bubbles: true }));
    } else if (el instanceof HTMLElement && el.isContentEditable) {
      el.textContent = "";
      el.dispatchEvent(new Event("input", { bubbles: true }));
    }
  }

  /**
   * Record a user action by sending a LensEvent to the
   * service worker. The event contains no prompt content;
   * only the metadata (category, severity, user_action).
   */
  private recordAction(userAction: "send_anyway" | "edit" | "cancel" | "dismiss"): void {
    if (this.currentDetections.length === 0) return;
    // For "send_anyway" / "edit" / "cancel", we send one
    // event per detection. The backend aggregates them.
    for (const d of this.currentDetections) {
      const event: LensEvent = {
        domain_hash: this.domainHash,
        category: d.category,
        severity: d.severity,
        user_action: userAction,
        timestamp: Math.floor(Date.now() / 1000),
        model_version: LENS_VERSION + "+regex-v1",
        lens_version: LENS_VERSION,
        confidence: 1.0,
      };
      chrome.runtime.sendMessage({
        type: "lens.telemetry",
        event,
      });
    }
  }
}

// =====================================================================
// Module-level helpers
// =====================================================================

/**
 * The current Lens version.
 *
 * KEPT IN SYNC by tools/build-lens-extension in the
 * Platform monorepo. DO NOT EDIT THIS LINE; the build tool
 * templates it from version.txt at the Platform monorepo root.
 */
const LENS_VERSION = "0.1.0";

/** Read the prompt text from a textarea or contenteditable. */
function readPromptText(el: Element): string {
  if (el instanceof HTMLTextAreaElement) {
    return el.value;
  }
  if (el instanceof HTMLElement && el.isContentEditable) {
    return el.textContent ?? "";
  }
  return "";
}

/** Tint for a button by severity. */
function severityTint(s) {
  switch (s) {
    case "critical":
      return { bg: "#dc2626", fg: "#ffffff" };
    case "high":
      return { bg: "#f59e0b", fg: "#1f2937" };
    case "medium":
      return { bg: "#fbbf24", fg: "#1f2937" };
    case "low":
      return { bg: "#e5e7eb", fg: "#1f2937" };
    case "info":
      return { bg: "#e5e7eb", fg: "#1f2937" };
  }
}

/** Sleep helper. */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// =====================================================================
// Entry point
// =====================================================================

if (typeof window !== "undefined" && typeof document !== "undefined") {
  const script = new ContentScript();
  script.init().catch((err: unknown) => {
    // Log only the error message, NOT the full error object.
    // The full object could in principle contain the prompt
    // text (if a future bug throws an error that includes
    // it). The message is what a developer needs; the
    // extension should never break the page. The error is
    // NOT shown to the user.
    const msg = err instanceof Error ? err.message : String(err);
    console.warn("[AegisGate Lens] init failed:", msg);
  });
}
