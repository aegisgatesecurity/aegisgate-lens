const MAX_LOCAL_AUDIT_ENTRIES = 1000;
const KEY_LOCAL_AUDIT = "lens.local_audit";
const KEY_BASE_URL_OVERRIDE = "lens.__base_url_override";
export class Storage {
 async getOptInState(){
 const result = await chrome.storage.sync.get(KEY_OPT_IN);
 const stored = result[KEY_OPT_IN];
 if (stored && typeof stored === "object") {
 return stored;
 }
 
 return {
 enabled: false,
 opted_in_at: 0,
 last_changed_at: 0,
 lens_version: LENS_VERSION,
 };
 }
 async setOptInState(state){
 await chrome.storage.sync.set({ [KEY_OPT_IN]: state });
 }
 async getBearerToken(){
 const result = await chrome.storage.local.get(KEY_BEARER_TOKEN);
 return (result[KEY_BEARER_TOKEN]) ?? "";
 }
 async setBearerToken(token){
 await chrome.storage.local.set({ [KEY_BEARER_TOKEN]: token });
 }
 async appendLocalAudit(entry){
 const result = await chrome.storage.local.get(KEY_LOCAL_AUDIT);
 const log = (result[KEY_LOCAL_AUDIT]) ?? [];
 log.push(entry);
 if (log.length > MAX_LOCAL_AUDIT_ENTRIES) {
 log.splice(0, log.length - MAX_LOCAL_AUDIT_ENTRIES);
 }
 await chrome.storage.local.set({ [KEY_LOCAL_AUDIT]: log });
 }
 async getLocalAudit(){
 const result = await chrome.storage.local.get(KEY_LOCAL_AUDIT);
 const log = (result[KEY_LOCAL_AUDIT]) ?? [];
 return [...log].reverse();
 }
 async clearLocalAudit(){
 await chrome.storage.local.remove(KEY_LOCAL_AUDIT);
 }
 async getDisabledCategories(){
 const result = await chrome.storage.local.get(KEY_DISABLED_CATEGORIES);
 const arr = (result[KEY_DISABLED_CATEGORIES]) ?? [];
 return new Set(arr);
 }
 async setDisabledCategories(cats){
 await chrome.storage.local.set({
 [KEY_DISABLED_CATEGORIES]: [...cats],
 });
 }
 async getBaseUrlOverride(){
 const result = await chrome.storage.local.get(KEY_BASE_URL_OVERRIDE);
 return (result[KEY_BASE_URL_OVERRIDE]) ?? "";
 }
 async setBaseUrlOverride(url){
 await chrome.storage.local.set({ [KEY_BASE_URL_OVERRIDE]: url });
 }
 static async generateBearerToken(){
 const bytes = new Uint8Array(32);
 crypto.getRandomValues(bytes);
 let out = "";
 for (let i = 0; i < bytes.length; i++) {
 out += (bytes[i] >> 4).toString(16);
 out += (bytes[i] & 0x0f).toString(16);
 }
 return out;
 }
}
const LENS_VERSION = "0.1.0";
const storage = new Storage();
let currentDisabled= new Set();
document.addEventListener("DOMContentLoaded", () => {
 void init();
});
async function init(){
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
function renderStats(state){
 const statsEl = document.getElementById("stats");
 if (!statsEl) return;
 if (!state.enabled) {
 statsEl.textContent =
 "Telemetry is OFF. The Lens will still detect locally; nothing is sent to any server.";
 return;
 }
 
 
 
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
function renderCategoryToggles(disabled){
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
function wireCategoryToggles(){
 const container = document.getElementById("category-toggles");
 if (!container) return;
 container.addEventListener("change", (ev) => {
 const target = ev.target;
 if (!target || target.tagName !== "INPUT") return;
 const cat = target.dataset.category;
 if (!cat) return;
 
 
 
 
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
function describeCategory(c){
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