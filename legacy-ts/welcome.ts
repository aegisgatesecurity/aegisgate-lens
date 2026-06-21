// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Welcome Page Script
// =========================================================================
//
// Tiny script that wires the "Opt in" button on the welcome
// page. The opt-in state is stored by the service worker.
//
// v0.1 pre-release.
// =========================================================================

document.getElementById("opt-in-btn")?.addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "lens.optIn", enabled: true }, () => {
    // Close the welcome tab after opt-in.
    window.close();
  });
});
