const VALID_CATEGORIES= [
 "pii_email",
 "pii_phone",
 "pii_ssn",
 "pii_credit_card",
 "secret_api_key",
 "source_code",
];
const VALID_USER_ACTIONS= [
 "send_anyway",
 "edit",
 "cancel",
 "dismiss",
];
const MIN_CONFIDENCE = 0.0;
const MAX_CONFIDENCE = 1.0;
export function validate(
 raw,
 nowMillis= Date.now(),
){
 
 if (typeof raw !== "object" || raw === null) {
 return fail("event must be an object");
 }
 const obj = raw;
 
 
 
 const allowed= new Set([
 ...REQUIRED_FIELDS,
 "id", 
 ]);
 for (const key of Object.keys(obj)) {
 if (!allowed.has(key)) {
 return fail(`unknown field: ${key}`);
 }
 }
 
 for (const field of REQUIRED_FIELDS) {
 if (!(field in obj)) {
 return fail(`missing required field: ${field}`);
 }
 }
 
 if (typeof obj.domain_hash !== "string") {
 return fail("domain_hash must be a string");
 }
 if (obj.domain_hash.length !== DOMAIN_HASH_LENGTH) {
 return fail(
 `domain_hash must be ${DOMAIN_HASH_LENGTH} hex chars, got ${obj.domain_hash.length}`,
 );
 }
 if (!/^[0-9a-f]{16}$/.test(obj.domain_hash)) {
 return fail("domain_hash must be lowercase hex");
 }
 
 if (typeof obj.category !== "string") {
 return fail("category must be a string");
 }
 if (!VALID_CATEGORIES.includes(obj.category)) {
 return fail(`category ${JSON.stringify(obj.category)} is not valid`);
 }
 
 if (typeof obj.severity !== "string") {
 return fail("severity must be a string");
 }
 if (!VALID_SEVERITIES.includes(obj.severity)) {
 return fail(`severity ${JSON.stringify(obj.severity)} is not valid`);
 }
 
 if (typeof obj.user_action !== "string") {
 return fail("user_action must be a string");
 }
 if (!VALID_USER_ACTIONS.includes(obj.user_action)) {
 return fail(`user_action ${JSON.stringify(obj.user_action)} is not valid`);
 }
 
 if (typeof obj.timestamp !== "number" || !Number.isInteger(obj.timestamp)) {
 return fail("timestamp must be an integer");
 }
 if (obj.timestamp <= 0) {
 return fail("timestamp must be positive");
 }
 const nowSeconds = Math.floor(nowMillis / 1000);
 const delta = obj.timestamp - nowSeconds;
 if (Math.abs(delta) > TIMESTAMP_TOLERANCE_SECONDS) {
 return fail("timestamp must be within ±24h of client clock");
 }
 
 if (typeof obj.model_version !== "string") {
 return fail("model_version must be a string");
 }
 if (obj.model_version.length === 0) {
 return fail("model_version must be non-empty");
 }
 if (!obj.model_version.includes("+")) {
 return fail('model_version must contain "+" (e.g., "0.1.0+regex-v1")');
 }
 
 if (typeof obj.lens_version !== "string") {
 return fail("lens_version must be a string");
 }
 if (obj.lens_version.length === 0) {
 return fail("lens_version must be non-empty");
 }
 
 if (typeof obj.confidence !== "number" || !Number.isFinite(obj.confidence)) {
 return fail("confidence must be a finite number");
 }
 if (obj.confidence < MIN_CONFIDENCE || obj.confidence > MAX_CONFIDENCE) {
 return fail(
 `confidence must be in [${MIN_CONFIDENCE}, ${MAX_CONFIDENCE}], got ${obj.confidence}`,
 );
 }
 
 if (obj.id !== undefined) {
 if (typeof obj.id !== "string") {
 return fail("id must be a string when present");
 }
 }
 
 
 const event= {
 domain_hash: obj.domain_hash,
 category: obj.category: obj.severity: obj.user_action: obj.timestamp,
 model_version: obj.model_version,
 lens_version: obj.lens_version,
 confidence: obj.confidence,
 };
 if (typeof obj.id === "string") {
 event.id = obj.id;
 }
 return { valid: true, event };
}
function fail(reason){
 return { valid: false, reason };
}
const DEFAULT_EVENTS_PER_MINUTE = 100;
const DEFAULT_BASE_URL = "https://lens.aegisgatesecurity.io";
const ALLOWED_SCHEMES= ["https", "http"];
const ALLOWED_HOSTS_FOR_HTTP= new Set([
 "localhost",
 "127.0.0.1",
 "[::1]",
]);
export class APIClient {
 cfg{
 fetchImpl: typeof fetch;
 };
 rateLimitState;
 constructor(config) {
 
 let url;
 try {
 url = new URL(config.baseUrl);
 } catch {
 throw new Error(`invalid baseUrl: ${config.baseUrl}`);
 }
 if (!ALLOWED_SCHEMES.includes(url.protocol.slice(0, -1) as "https" | "http")) {
 throw new Error(
 `unsupported scheme: ${url.protocol} (must be https, or http for localhost)`,
 );
 }
 if (url.protocol === "http:" && !ALLOWED_HOSTS_FOR_HTTP.has(url.hostname)) {
 throw new Error(
 `http is only allowed for localhost/127.0.0.1; got ${url.hostname}`,
 );
 }
 if (!config.bearerToken || config.bearerToken.length === 0) {
 throw new Error("bearerToken must be non-empty");
 }
 this.cfg = {
 baseUrl: config.baseUrl,
 bearerToken: config.bearerToken,
 eventsPerMinute: config.eventsPerMinute ?? DEFAULT_EVENTS_PER_MINUTE,
 
 
 
 
 fetchImpl: config.fetchImpl ?? globalThis.fetch,
 };
 this.rateLimitState = new RateLimitState(this.cfg.eventsPerMinute);
 }
 async sendEvent(event){
 
 const v = validate(event);
 if (!v.valid) {
 throw new Error(`client-side validation failed: ${v.reason}`);
 }
 
 if (!this.rateLimitState.allow()) {
 return false; 
 
 
 }
 
 
 const url = `${this.cfg.baseUrl}/api/v1/lens/telemetry`;
 const resp = await this.cfg.fetchImpl(url, {
 method: "POST",
 headers: {
 "Authorization": `Bearer ${this.cfg.bearerToken}`,
 "Content-Type": "application/json",
 },
 body: JSON.stringify(event),
 });
 if (!resp.ok) {
 throw new Error(
 `telemetry HTTP ${resp.status}: ${await safeReadBody(resp)}`,
 );
 }
 return true;
 }
 async checkDomain(hostname){
 const url = new URL(`${this.cfg.baseUrl}/api/v1/lens/check`);
 url.searchParams.set("domain", hostname);
 const resp = await this.cfg.fetchImpl(url.href, {
 method: "GET",
 headers: {
 "Authorization": `Bearer ${this.cfg.bearerToken}`,
 },
 });
 if (!resp.ok) {
 throw new Error(`check HTTP ${resp.status}: ${await safeReadBody(resp)}`);
 }
 return (await resp.json());
 }
 async getStats(){
 const resp = await this.cfg.fetchImpl(
 `${this.cfg.baseUrl}/api/v1/lens/stats`,
 {
 method: "GET",
 headers: {
 "Authorization": `Bearer ${this.cfg.bearerToken}`,
 },
 },
 );
 if (!resp.ok) {
 throw new Error(`stats HTTP ${resp.status}: ${await safeReadBody(resp)}`);
 }
 return (await resp.json());
 }
 async healthz(){
 const resp = await this.cfg.fetchImpl(
 `${this.cfg.baseUrl}/api/v1/lens/healthz`,
 { method: "GET" },
 );
 if (!resp.ok) {
 throw new Error(`healthz HTTP ${resp.status}`);
 }
 return (await resp.json());
 }
}
class RateLimitState {
 cap;
 ring;
 writeIdx = 0;
 count = 0;
 windowStart = 0;
 constructor(eventsPerMinute) {
 this.cap = eventsPerMinute;
 this.ring = new Array(eventsPerMinute);
 for (let i = 0; i < eventsPerMinute; i++) {
 this.ring[i] = 0;
 }
 }
 allow(){
 const now = Date.now();
 
 
 if (now - this.windowStart > 60_000) {
 this.windowStart = now;
 this.count = 0;
 this.writeIdx = 0;
 for (let i = 0; i < this.cap; i++) {
 this.ring[i] = 0;
 }
 }
 
 
 
 
 if (this.count === this.cap) {
 const oldest = this.ring[this.writeIdx];
 if (now - oldest < 60_000) {
 return false; 
 }
 
 this.ring[this.writeIdx] = now;
 this.writeIdx = (this.writeIdx + 1) % this.cap;
 return true;
 }
 
 this.ring[this.writeIdx] = now;
 this.writeIdx = (this.writeIdx + 1) % this.cap;
 this.count++;
 return true;
 }
}
async function safeReadBody(resp){
 try {
 return await resp.text();
 } catch {
 return "<unreadable>";
 }
}
const KEY_OPT_IN = "lens.opt_in";
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
chrome.runtime.onStartup.addListener(() => {
 onStartup().catch((err) =>
 console.warn("[AegisGate Lens] onStartup failed:", err),
 );
});
async function onFirstInstall(){
 await storage.setBearerToken(await Storage.generateBearerToken());
 const now = Math.floor(Date.now() / 1000);
 const state= {
 enabled: false,
 opted_in_at: 0,
 last_changed_at: now,
 lens_version: LENS_VERSION,
 };
 await storage.setOptInState(state);
 
 await chrome.tabs.create({
 url: chrome.runtime.getURL("welcome.html"),
 });
}
async function onUpdate(previousVersion){
 const state = await storage.getOptInState();
 if (state.lens_version !== LENS_VERSION) {
 state.lens_version = LENS_VERSION;
 state.last_changed_at = Math.floor(Date.now() / 1000);
 await storage.setOptInState(state);
 }
 
 
 void previousVersion; 
}
async function onStartup(){
 const baseUrl = (await storage.getBaseUrlOverride()) || DEFAULT_BACKEND_URL;
 const token = await storage.getBearerToken();
 if (!token) return; 
 const client = new APIClient({ baseUrl, bearerToken: token });
 try {
 const h = await client.healthz();
 console.info(
 `[AegisGate Lens] backend reachable: ${h.version} (${h.status})`,
 );
 } catch (err) {
 
 
 
 
 console.warn("[AegisGate Lens] backend unreachable:", err);
 }
}
async function handleTelemetry(event){
 const optIn = await storage.getOptInState();
 if (!optIn.enabled) {
 return; 
 
 
 }
 
 
 
 
 await storage.appendLocalAudit({
 timestamp: event.timestamp * 1000,
 domain_hash: event.domain_hash,
 category: event.category,
 severity: event.severity,
 user_action: event.user_action,
 });
 
 const client = await getClient();
 try {
 await client.sendEvent(event);
 } catch (err) {
 
 
 
 console.warn("[AegisGate Lens] sendEvent failed:", err);
 }
}
async function handleOptIn(enabled){
 const state = await storage.getOptInState();
 const now = Math.floor(Date.now() / 1000);
 state.enabled = enabled;
 state.last_changed_at = now;
 if (enabled && state.opted_in_at === 0) {
 state.opted_in_at = now;
 }
 await storage.setOptInState(state);
}
async function handleGetState(){
 optIn: OptInState;
 localAudit: ReadonlyArray;
 disabledCategories: ReadonlyArray;
}> {
 const optIn = await storage.getOptInState();
 const localAudit = await storage.getLocalAudit();
 const disabledCategories = await storage.getDisabledCategories();
 return {
 optIn,
 localAudit,
 disabledCategories: [...disabledCategories],
 };
}
async function handleStats(){
 const optIn = await storage.getOptInState();
 if (!optIn.enabled) {
 return { error: "not opted in" };
 }
 const client = await getClient();
 return await client.getStats();
}
async function getClient(){
 const baseUrl =
 (await storage.getBaseUrlOverride()) || DEFAULT_BACKEND_URL;
 const token = await storage.getBearerToken();
 return new APIClient({ baseUrl, bearerToken: token });
}