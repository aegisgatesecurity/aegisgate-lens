const PATTERNS= [
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 {
 category: "pii_email",
 severity: "high",
 name: "email_v1",
 pattern:
 "[a-zA-Z0-9](?:[a-zA-Z0-9._%+-]{0,62}[a-zA-Z0-9])?@[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,253}[a-zA-Z0-9])?\\.[a-zA-Z]{2,}",
 description: "Email address (RFC 5322 pragmatic subset, bounded to prevent backtracking)",
 },
 
 
 
 
 
 
 {
 category: "pii_phone",
 severity: "high",
 name: "phone_na_v1",
 pattern:
 "(?:\\+?1[-.\\s]?)?\\(?[2-9][0-9]{2}\\)?[-.\\s]?[2-9][0-9]{2}[-.\\s]?[0-9]{4}",
 description: "North American phone number (NANP format)",
 },
 
 
 
 
 
 
 
 {
 category: "pii_ssn",
 severity: "critical",
 name: "ssn_v1",
 pattern:
 "(?!000|666|9\\d{2})\\d{3}[-\\s]?(?!00)\\d{2}[-\\s]?(?!0000)\\d{4}",
 description: "US Social Security Number (XXX-XX-XXXX)",
 },
 
 
 
 
 
 
 
 
 
 
 
 
 {
 category: "pii_credit_card",
 severity: "critical",
 name: "credit_card_visa_v1",
 pattern: "4[0-9]{12}(?:[0-9]{3})?(?:[0-9]{3})?",
 description: "Visa credit card number",
 },
 {
 category: "pii_credit_card",
 severity: "critical",
 name: "credit_card_mastercard_v1",
 pattern:
 "(?:5[1-5][0-9]{14}|2(?:2(?:2[1-9]|[3-9][0-9])|[3-6][0-9][0-9]|7(?:[01][0-9]|20))[0-9]{12})",
 description: "Mastercard credit card number",
 },
 {
 category: "pii_credit_card",
 severity: "critical",
 name: "credit_card_amex_v1",
 pattern: "3[47][0-9]{13}",
 description: "American Express credit card number (15 digits)",
 },
 
 
 
 
 
 
 {
 category: "secret_api_key",
 severity: "critical",
 name: "aws_access_key_v1",
 pattern: "AKIA[0-9A-Z]{16}",
 description: "AWS Access Key ID",
 },
 {
 category: "secret_api_key",
 severity: "critical",
 name: "github_pat_v1",
 pattern: "ghp_[a-zA-Z0-9]{36}",
 description: "GitHub Personal Access Token (classic)",
 },
 {
 category: "secret_api_key",
 severity: "critical",
 name: "github_oauth_v1",
 pattern: "gho_[a-zA-Z0-9]{36}",
 description: "GitHub OAuth Access Token",
 },
 {
 category: "secret_api_key",
 severity: "critical",
 name: "stripe_live_key_v1",
 pattern: "sk_live_[a-zA-Z0-9]{24,}",
 description: "Stripe Live Secret Key",
 },
 {
 category: "secret_api_key",
 severity: "critical",
 name: "google_api_key_v1",
 pattern: "AIza[0-9A-Za-z\\-_]{35}",
 description: "Google API Key",
 },
 
 
 
 
 
 
 
 {
 category: "source_code",
 severity: "critical",
 name: "rsa_private_key_v1",
 pattern:
 "-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
 description: "PEM private key (RSA, EC, DSA, OpenSSH, PGP)",
 },
];
const PATTERNS_BY_CATEGORY = (() => {
 const m = new Map();
 for (const p of PATTERNS) {
 const list = m.get(p.category) ?? [];
 list.push(p);
 m.set(p.category, list);
 }
 return m;
})();
const COMPILED =
 PATTERNS.map((p) => ({
 pattern: p,
 regex: new RegExp(p.pattern, "g"),
 }));
const COMPILED_PATTERNS = COMPILED;
function isLuhnValid(s){
 if (typeof s !== "string" || s.length === 0) {
 return false;
 }
 
 let digits = "";
 for (let i = 0; i < s.length; i++) {
 const c = s.charCodeAt(i);
 if (c >= 0x30 && c <= 0x39) {
 digits += s[i];
 }
 }
 if (digits.length < 2) {
 return false; 
 }
 
 
 
 
 
 
 
 
 
 let sum = 0;
 let shouldDouble = false; 
 for (let i = digits.length - 1; i >= 0; i--) {
 let d = digits.charCodeAt(i) - 0x30;
 if (shouldDouble) {
 d *= 2;
 if (d > 9) {
 d -= 9;
 }
 }
 sum += d;
 shouldDouble = !shouldDouble;
 }
 return sum % 10 === 0;
}
const TEST_CARDS= [
 { network: "Visa (test)", number: "4111-1111-1111-1111" },
 { network: "Visa (test, 13-digit)", number: "4222-2222-2222-2" },
 { network: "Mastercard (test)", number: "5555-5555-5555-4444" },
 { network: "Mastercard (2-series test)", number: "5105-1051-0510-5100" },
 { network: "Amex (test)", number: "3782-822463-10005" },
 { network: "Discover (test)", number: "6011-1111-1111-1117" },
 { network: "JCB (test)", number: "3530-1113-3330-0000" },
 { network: "Diners Club (test)", number: "3056-9309-0259-04" },
];
const INVALID_CARDS= [
 "4111-1111-1111-1112", 
 "5555-5555-5555-4445", 
 "3782-822463-10006", 
 "1234-5678-9012-3456", 
];
const DEFAULT_MAX_DETECTIONS = 50;
function detect(
 text,
 options= {},
){
 if (typeof text !== "string" || text.length === 0) {
 return [];
 }
 const max = options.maxDetections ?? DEFAULT_MAX_DETECTIONS;
 const disabled = options.disabledCategories ?? new Set();
 
 const raw= [];
 for (const { pattern, regex } of COMPILED_PATTERNS) {
 if (disabled.has(pattern.category)) {
 continue;
 }
 for (const match of text.matchAll(regex)) {
 
 
 
 
 if (raw.length >= max * 4) break;
 if (match.index === undefined) continue;
 const matchText = match[0];
 
 if (pattern.category === "pii_credit_card") {
 if (!isLuhnValid(matchText)) {
 continue;
 }
 }
 raw.push({
 category: pattern.category,
 severity: pattern.severity,
 match: matchText,
 start: match.index,
 end: match.index + matchText.length,
 pattern: pattern.name,
 });
 }
 if (raw.length >= max * 4) break;
 }
 
 raw.sort((a, b) => {
 if (a.start !== b.start) return a.start - b.start;
 return severityRank(b.severity) - severityRank(a.severity);
 });
 
 
 
 const accepted= [];
 for (const d of raw) {
 if (accepted.length >= max) break;
 let overlapped = false;
 for (const a of accepted) {
 if (overlaps(a, d)) {
 overlapped = true;
 break;
 }
 }
 if (!overlapped) {
 accepted.push(d);
 }
 }
 return accepted;
}
function overlaps(a, b){
 return a.start < b.end && b.start < a.end;
}
function severityRank(s){
 switch (s) {
 case "critical":
 return 5;
 case "high":
 return 4;
 case "medium":
 return 3;
 case "low":
 return 2;
 case "info":
 return 1;
 }
}
function describeDetection(d){
 const prefix = describeCategory(d.category);
 return `${prefix} (severity: ${d.severity})`;
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
function getPatternByName(name){
 for (const p of COMPILED_PATTERNS) {
 if (p.pattern.name === name) return p.pattern;
 }
 return undefined;
}
const DOMAIN_HASH_LENGTH = 16;
async function computeDomainHash(hostname){
 if (typeof hostname !== "string" || hostname.length === 0) {
 throw new Error("hostname must be a non-empty string");
 }
 const normalized = hostname.toLowerCase();
 const bytes = new TextEncoder().encode(normalized);
 const digest = await crypto.subtle.digest(ALGORITHM, bytes);
 return bufferToHex(new Uint8Array(digest)).slice(0, DOMAIN_HASH_LENGTH);
}
function computeDomainHashSync(hostname){
 if (typeof hostname !== "string" || hostname.length === 0) {
 throw new Error("hostname must be a non-empty string");
 }
 const normalized = hostname.toLowerCase();
 const bytes = new TextEncoder().encode(normalized);
 const digest = sha256Sync(bytes);
 return bufferToHex(digest).slice(0, DOMAIN_HASH_LENGTH);
}
function bufferToHex(bytes){
 let out = "";
 for (let i = 0; i < bytes.length; i++) {
 const b = bytes[i];
 out += (b >> 4).toString(16);
 out += (b & 0x0f).toString(16);
 }
 return out;
}
const K= [
 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
function rotr(x, n){
 return ((x >>> n) | (x << (32 - n))) >>> 0;
}
function sha256Sync(bytes){
 
 
 
 const bitLen = bytes.length * 8;
 const padLen = (64 - ((bytes.length + 9) % 64)) % 64;
 const totalLen = bytes.length + 1 + padLen + 8;
 const padded = new Uint8Array(totalLen);
 padded.set(bytes, 0);
 padded[bytes.length] = 0x80;
 
 const view = new DataView(padded.buffer);
 
 
 view.setUint32(totalLen - 8, Math.floor(bitLen / 0x100000000), false);
 view.setUint32(totalLen - 4, bitLen >>> 0, false);
 
 const H= [
 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
 0x1f83d9ab, 0x5be0cd19,
 ];
 
 for (let chunk = 0; chunk < totalLen; chunk += 64) {
 const W = new Array(64);
 for (let i = 0; i < 16; i++) {
 W[i] = view.getUint32(chunk + i * 4, false);
 }
 for (let i = 16; i < 64; i++) {
 const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
 const s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
 W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
 }
 let a = H[0], b = H[1], c = H[2], d = H[3];
 let e = H[4], f = H[5], g = H[6], h = H[7];
 for (let i = 0; i < 64; i++) {
 const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
 const ch = (e & f) ^ (~e & g);
 const temp1 = (h + S1 + ch + K[i] + W[i]) >>> 0;
 const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
 const mj = (a & b) ^ (a & c) ^ (b & c);
 const temp2 = (S0 + mj) >>> 0;
 h = g;
 g = f;
 f = e;
 e = (d + temp1) >>> 0;
 d = c;
 c = b;
 b = a;
 a = (temp1 + temp2) >>> 0;
 }
 H[0] = (H[0] + a) >>> 0;
 H[1] = (H[1] + b) >>> 0;
 H[2] = (H[2] + c) >>> 0;
 H[3] = (H[3] + d) >>> 0;
 H[4] = (H[4] + e) >>> 0;
 H[5] = (H[5] + f) >>> 0;
 H[6] = (H[6] + g) >>> 0;
 H[7] = (H[7] + h) >>> 0;
 }
 
 const out = new Uint8Array(32);
 const outView = new DataView(out.buffer);
 for (let i = 0; i < 8; i++) {
 outView.setUint32(i * 4, H[i], false);
 }
 return out;
}
const KNOWN_VECTORS= [
 { hostname: "chat.openai.com", hash: "b5d56b87a192a38e" },
 { hostname: "claude.ai", hash: "743e483ae01f1fa2" },
 { hostname: "gemini.google.com", hash: "f8226d80a7c25a04" },
 { hostname: "copilot.microsoft.com", hash: "7cbff059b404bede" },
];
const DETECT_THROTTLE_MS = 250;
class ContentScript {
 hostname= "";
 provider= null;
 domainHash= "";
 banner= null;
 currentDetections= [];
 lastDetectAt = 0;
 pendingDetect= null;
 async init(){
 this.hostname = window.location.hostname.toLowerCase();
 const info = PROVIDERS.get(this.hostname);
 if (!info) {
 
 return;
 }
 this.provider = info;
 this.domainHash = await computeDomainHash(this.hostname);
 
 await this.waitForPrompt();
 this.attach();
 }
 async waitForPrompt(){
 const sel = this.provider.promptSelector;
 for (let i = 0; i < 60; i++) {
 if (document.querySelector(sel)) return;
 await sleep(500);
 }
 }
 attach(){
 const el = document.querySelector(this.provider.promptSelector);
 if (!el) return;
 el.addEventListener("input", () => this.scheduleDetect());
 el.addEventListener("keyup", () => this.scheduleDetect());
 el.addEventListener("paste", () => this.scheduleDetect());
 }
 scheduleDetect(){
 if (this.pendingDetect !== null) return;
 const elapsed = Date.now() - this.lastDetectAt;
 const delay = Math.max(0, DETECT_THROTTLE_MS - elapsed);
 this.pendingDetect = window.setTimeout(() => {
 this.pendingDetect = null;
 this.lastDetectAt = Date.now();
 this.runDetect();
 }, delay);
 }
 runDetect(){
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
 showBanner(detections){
 if (this.banner && document.body.contains(this.banner)) {
 
 this.updateBannerContent(detections);
 return;
 }
 const banner = document.createElement("div");
 banner.id = "__aegisgate_lens_banner__";
 banner.setAttribute("role", "alert");
 banner.setAttribute("aria-live", "polite");
 Object.assign(banner.style, {
 
 
 
 
 
 
 position: "fixed",
 top: "0",
 left: "0",
 right: "0",
 zIndex: "2147483647",
 background: "#fef3c7",
 borderBottom: "2px solid #f59e0b",
 padding: "12px 16px",
 
 
 
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
 updateBannerContent(detections){
 if (!this.banner) return;
 
 while (this.banner.firstChild) {
 this.banner.removeChild(this.banner.firstChild);
 }
 
 const header = document.createElement("div");
 Object.assign(header.style, {
 fontWeight: "600",
 marginBottom: "6px",
 });
 const count = detections.length;
 header.textContent =
 `🛡️ AegisGate Lens: ${count} sensitive item${count === 1 ? "" : "s"} detected in your prompt.`;
 this.banner.appendChild(header);
 
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
 makeActionButton(
 label,
 severity,
 onClick,
 ){
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
 hideBanner(){
 if (this.banner && document.body.contains(this.banner)) {
 document.body.removeChild(this.banner);
 }
 this.banner = null;
 }
 clearPrompt(){
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
 recordAction(userAction){
 if (this.currentDetections.length === 0) return;
 
 
 for (const d of this.currentDetections) {
 const event= {
 domain_hash: this.domainHash,
 category: d.category,
 severity: d.severity,
 user_action: userAction,
 timestamp: Math.floor(Date.now() / 1000),
 model_version: `${LENS_VERSION}+regex-v1`,
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
const LENS_VERSION = "0.1.0";
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
function sleep(ms){
 return new Promise((resolve) => setTimeout(resolve, ms));
}
if (typeof window !== "undefined" && typeof document !== "undefined") {
 const script = new ContentScript();
 script.init().catch((err) => {
 
 
 
 
 
 
 const msg = err instanceof Error ? err.message : String(err);
 console.warn("[AegisGate Lens] init failed:", msg);
 });
}