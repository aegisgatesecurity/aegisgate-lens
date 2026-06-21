document.getElementById("opt-in-btn")?.addEventListener("click", () => {
 chrome.runtime.sendMessage({ type: "lens.optIn", enabled: true }, () => {
 
 window.close();
 });
});