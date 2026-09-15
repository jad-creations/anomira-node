import { AsyncLocalStorage } from "node:async_hooks";
import { EventBuffer } from "./buffer.js";
import { checkGeoVelocity } from "./geo-velocity.js";
import { scanForLeaks } from "./sensitive.js";
import type { AnomiraConfig, SdkEvent, FirewallRule, EndpointDeclaration } from "./types.js";
import { EventName } from "./types.js";
import { detectAgent } from "./agent-detection.js";
import { computeBrowserFingerprint, extractHttp2Settings, extractUpstreamTls } from "./behavioral-fingerprint.js";
import { scanForSsrf } from "./ssrf.js";
import { scanRequestForJwtAttacks } from "./jwt-detect.js";
import { detectHoneypotType, generateHoneypotResponse, makeAdminLoginFailed } from "./honeypot-responses.js";
import { randomBytes } from "node:crypto";
import { SDK_USER_AGENT } from "./version.js";
import { hasPathTraversal } from "./path-traversal.js";
import { scanForXss } from "./xss-detect.js";

interface RequestContext {
  endpoint: string;
  method:   string;
  ip:       string;
}

// One shared ALS instance per SDK module load
const requestContext = new AsyncLocalStorage<RequestContext>();

const DEFAULT_INGEST_URL    = "https://ingest.anomira.io/v1/events";
const DEFAULT_BATCH_SIZE    = 100;
const DEFAULT_FLUSH_MS      = 5_000;
const DEFAULT_MAX_RETRIES   = 3;

// ── Sensitive field taxonomy ──────────────────────────────────────────────────
// Categorised so the dashboard can apply the right security action per category.
// Field names are checked via Object.keys() — values via VALUE_PATTERNS below.
// All detection runs in onFinish (after response sent) — zero client latency.

const SENSITIVE_FIELDS: Record<string, string[]> = {
  identity: [
    "first_name", "last_name", "full_name", "name",
    "bvn", "nin", "ssn", "national_id", "tin",
    "passport", "passport_number",
    "drivers_license", "license_number",
    "voter_id",
    "dob", "date_of_birth", "birth_date", "birthdate",
    "gender", "marital_status", "nationality",
  ],
  contact: [
    "email",
    "phone", "phone_number", "mobile", "mobile_number",
    "address", "street", "city", "state", "postal_code", "zip",
  ],
  financial: [
    "card_number", "credit_card", "debit_card", "cvv",
    "account_number", "bank_account", "routing_number", "sort_code",
    "iban", "swift", "wallet_id",
  ],
  authentication: [
    "password", "pin", "otp",
    "secret", "private_key", "api_key",
    "access_token", "refresh_token", "jwt", "bearer_token",
    "security_answer", "mother_maiden_name",
  ],
  biometric: [
    "fingerprint", "face_id", "iris", "voiceprint", "biometric",
  ],
  health: [
    "medical_record", "diagnosis", "blood_group", "insurance_id",
  ],
  fintech: [
    "kyc_id", "customer_id", "beneficiary_account", "transaction_pin",
    "wallet_balance", "bank_verification_number",
    "virtual_account", "monnify_account", "paystack_customer", "flutterwave_customer",
  ],
};

// Reverse lookup: lowercase field name → category (built once at module load)
const FIELD_CATEGORY_MAP = new Map<string, string>();
for (const [cat, fields] of Object.entries(SENSITIVE_FIELDS)) {
  for (const f of fields) FIELD_CATEGORY_MAP.set(f, cat);
}

// Value-level patterns — only applied to string values ≤ 200 chars.
// Catches obfuscated/generic field names ("x1", "identifier", etc.).
// Each regex is anchored to avoid partial matches on longer strings.
const VALUE_PATTERNS: { name: string; category: string; re: RegExp }[] = [
  { name: "email",       category: "contact",        re: /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/ },
  { name: "bvn_nin",     category: "identity",       re: /^\d{11}$/ },
  { name: "card_number", category: "financial",      re: /^\d{13,19}$/ },
  { name: "phone_ng",    category: "contact",        re: /^(?:\+234|0)[789][01]\d{8}$/ },
  { name: "jwt",         category: "authentication", re: /^eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\./ },
  { name: "iban",        category: "financial",      re: /^[A-Z]{2}\d{2}[A-Z0-9]{4,30}$/ },
];

/**
 * AnomiraClient — the core SDK object.
 *
 * Instantiate once and reuse across your application:
 *
 * ```ts
 * import { Anomira } from "@anomira/node-sdk";
 *
 * export const sentinel = new Anomira({
 *   apiKey: process.env.SENTINEL_API_KEY!,
 *   appId:  process.env.SENTINEL_APP_ID!,
 * });
 * ```
 */
export class AnomiraClient {
  readonly config: Required<Omit<AnomiraConfig, "getUserId" | "getIp" | "detect" | "autoBlock">> & {
    getUserId:      NonNullable<AnomiraConfig["getUserId"]>;
    getIp:          NonNullable<AnomiraConfig["getIp"]>;
    detect:         Required<NonNullable<AnomiraConfig["detect"]>>;
    captureConsole: boolean;
    service:        string;
    autoBlock:      Required<NonNullable<AnomiraConfig["autoBlock"]>>;
  };

  private readonly buffer: EventBuffer;
  private readonly logBuffer: Array<{ level: string; service: string; message: string; meta: Record<string, unknown>; ts: number }> = [];
  private logFlushTimer:        ReturnType<typeof setInterval> | null = null;
  private blocklistTimer:       ReturnType<typeof setInterval> | null = null;
  private firewallTimer:        ReturnType<typeof setInterval> | null = null;
  private communityThreatTimer: ReturnType<typeof setInterval> | null = null;
  /** True when credentials are missing — all operations become no-ops. */
  private disabled = false;
  /** In-process cache of manually blocked IPs — refreshed every 60 s. */
  private blockedIpCache: Set<string> = new Set();
  /** In-process cache of whitelisted IPs — these always bypass the block check. */
  private whitelistedIpCache: Set<string> = new Set();
  /** In-process cache of community threat IPs with their confidence scores.
   *  Populated from Anomira's federated threat network — IPs confirmed malicious
   *  across multiple customers. Refreshed every 60 s. */
  private communityThreatCache: Map<string, { score: number; topAttack: string }> = new Map();
  /**
   * Set of honeypot paths to intercept. When a request matches, the SDK returns
   * a fake response instead of forwarding to the customer's route handlers.
   * Synced from ingest every 60 s. Keys are lowercase path strings.
   */
  private honeypotPaths: Set<string> = new Set();
  /**
   * Set of active canary token strings embedded in previously-served honeypot
   * responses. When any of these appear in a request's Authorization header or
   * body, a http.canary.triggered event is fired.
   * Synced from ingest every 60 s (max 100 tokens, sliding 7-day window).
   */
  private canaryTokenCache: Set<string> = new Set();
  /** In-process cache of firewall rules with pre-compiled regex — refreshed every 60 s. */
  private compiledRules: Array<{ rule: FirewallRule; re?: RegExp }> = [];
  // Saved originals — used by SDK internals so patched console doesn't recurse
  private readonly _origLog   = console.log.bind(console);
  private readonly _origWarn  = console.warn.bind(console);
  private readonly _origError = console.error.bind(console);

  constructor(config: AnomiraConfig) {
    if (!config.apiKey || !config.appId) {
      const missing = [!config.apiKey && "apiKey", !config.appId && "appId"].filter(Boolean).join(", ");
      console.warn(`[Anomira] SDK disabled — missing config: ${missing}. Set SENTINEL_API_KEY and SENTINEL_APP_ID to enable monitoring.`);
      this.disabled = true;
      // Provide safe defaults so the rest of the class doesn't blow up
      this.config = {
        apiKey: "", appId: "", ingestUrl: DEFAULT_INGEST_URL, geoLookupUrl: "",
        maxBatchSize: DEFAULT_BATCH_SIZE, flushIntervalMs: DEFAULT_FLUSH_MS,
        maxRetries: DEFAULT_MAX_RETRIES, debug: false, captureConsole: false, service: "app",
        getUserId: defaultGetUserId, getIp: defaultGetIp,
        detect:    { bruteForce: true, rateAbuse: true, pathTraversal: true, xss: true, scanDetection: true, geoVelocity: true, ssrf: true, jwtManipulation: true },
        autoBlock: { enabled: true, communityThreshold: 85 },
      };
      this.buffer = new EventBuffer({ appId: "", apiKey: "", ingestUrl: DEFAULT_INGEST_URL, maxBatchSize: 0, flushIntervalMs: 999_999_999, maxRetries: 0, debug: false });
      return;
    }

    this.config = {
      apiKey:          config.apiKey,
      appId:           config.appId,
      ingestUrl:       config.ingestUrl       ?? DEFAULT_INGEST_URL,
      geoLookupUrl:    config.geoLookupUrl    ?? "",
      maxBatchSize:    config.maxBatchSize    ?? DEFAULT_BATCH_SIZE,
      flushIntervalMs: config.flushIntervalMs ?? DEFAULT_FLUSH_MS,
      maxRetries:      config.maxRetries      ?? DEFAULT_MAX_RETRIES,
      debug:           config.debug           ?? false,
      captureConsole:  config.captureConsole  ?? false,
      service:         config.service         ?? "app",
      getUserId:       config.getUserId       ?? defaultGetUserId,
      getIp:           config.getIp           ?? defaultGetIp,
      detect: {
        bruteForce:    config.detect?.bruteForce    ?? true,
        rateAbuse:     config.detect?.rateAbuse     ?? true,
        pathTraversal: config.detect?.pathTraversal ?? true,
        xss:           config.detect?.xss           ?? true,
        scanDetection: config.detect?.scanDetection ?? true,
        geoVelocity:   config.detect?.geoVelocity   ?? true,
        ssrf:               config.detect?.ssrf               ?? true,
        jwtManipulation:    config.detect?.jwtManipulation    ?? true,
      },
      autoBlock: {
        enabled:            config.autoBlock?.enabled            ?? true,
        communityThreshold: config.autoBlock?.communityThreshold ?? 85,
      },
    };

    this.buffer = new EventBuffer({
      appId:          this.config.appId,
      apiKey:         this.config.apiKey,
      ingestUrl:      this.config.ingestUrl,
      maxBatchSize:   this.config.maxBatchSize,
      flushIntervalMs:this.config.flushIntervalMs,
      maxRetries:     this.config.maxRetries,
      debug:          this.config.debug,
    });

    void this.#validateCredentials();

    // Fetch blocked-IP list immediately, then refresh every 60 s
    void this.#refreshBlocklist();
    this.blocklistTimer = setInterval(() => { void this.#refreshBlocklist(); }, 60_000);
    if (this.blocklistTimer.unref) this.blocklistTimer.unref();

    // Fetch firewall rules immediately, then refresh every 60 s
    void this.#refreshFirewallRules();
    this.firewallTimer = setInterval(() => { void this.#refreshFirewallRules(); }, 60_000);
    if (this.firewallTimer.unref) this.firewallTimer.unref();

    // Fetch honeypot paths immediately, then refresh every 60 s.
    void this.#refreshHoneypotPaths();
    const honeypotTimer = setInterval(() => { void this.#refreshHoneypotPaths(); }, 60_000);
    if ((honeypotTimer as { unref?: () => void }).unref) (honeypotTimer as { unref: () => void }).unref();

    // Fetch canary tokens (harvested credential strings to detect in requests).
    void this.#refreshCanaryTokens();
    const canaryTimer = setInterval(() => { void this.#refreshCanaryTokens(); }, 60_000);
    if ((canaryTimer as { unref?: () => void }).unref) (canaryTimer as { unref: () => void }).unref();

    // Fetch community threat intelligence immediately, then refresh every 60 s.
    // This is the "invisible security" layer — IPs from Anomira's federated
    // network are auto-blocked when their confidence score meets the threshold,
    // regardless of whether a human has manually reviewed them.
    void this.#refreshCommunityThreats();
    this.communityThreatTimer = setInterval(() => { void this.#refreshCommunityThreats(); }, 60_000);
    if (this.communityThreatTimer.unref) this.communityThreatTimer.unref();

    // Flush logs every 10s (separate from events buffer)
    this.logFlushTimer = setInterval(() => { void this.#flushLogs(); }, 10_000);
    if (this.logFlushTimer.unref) this.logFlushTimer.unref();

    if (this.config.captureConsole) this.#interceptConsole();
  }

  #interceptConsole(): void {
    const map: Array<[keyof Console, "debug" | "info" | "warn" | "error"]> = [
      ["debug", "debug"],
      ["log",   "info"],
      ["info",  "info"],
      ["warn",  "warn"],
      ["error", "error"],
    ];
    for (const [method, level] of map) {
      const original = (console[method] as (...a: unknown[]) => void).bind(console);
      (console as unknown as Record<string, unknown>)[method] = (...args: unknown[]) => {
        original(...args);  // still prints to terminal
        // Skip SDK's own internal messages to avoid noise in the Logs dashboard
        const first = args[0];
        if (typeof first === "string" && first.startsWith("[Anomira]")) return;
        const message = args
          .map((a) => (typeof a === "string" ? a : JSON.stringify(a)))
          .join(" ");
        const ctx = requestContext.getStore();
        this.log(level, message, {
          service: this.config.service,
          ...(ctx ? { endpoint: ctx.endpoint, method: ctx.method, ip: ctx.ip } : {}),
        });
      };
    }
  }

  async #refreshBlocklist(): Promise<void> {
    const syncUrl = this.config.ingestUrl.replace(/\/v1\/events$/, "/v1/blocked-ips/sync");
    try {
      const res = await fetch(syncUrl, {
        headers: {
          Authorization:  `Bearer ${this.config.apiKey}`,
          "User-Agent": SDK_USER_AGENT,
        },
        signal: AbortSignal.timeout(5_000),
      });
      if (!res.ok) return;
      const data = await res.json() as { ips?: string[]; allowedIps?: string[] };
      this.blockedIpCache    = new Set(data.ips ?? []);
      this.whitelistedIpCache = new Set(data.allowedIps ?? []);
      if (this.config.debug && this.blockedIpCache.size > 0) {
        this._origLog(`[Anomira] blocklist refreshed — ${this.blockedIpCache.size} blocked, ${this.whitelistedIpCache.size} whitelisted`);
      }
    } catch {
      // Network error: keep the existing cache, never throw
    }
  }

  async #refreshCommunityThreats(): Promise<void> {
    const syncUrl = this.config.ingestUrl.replace(/\/v1\/events$/, "/v1/community-threats/sync");
    try {
      const res = await fetch(syncUrl, {
        headers: {
          Authorization: `Bearer ${this.config.apiKey}`,
          "User-Agent": SDK_USER_AGENT,
        },
        signal: AbortSignal.timeout(5_000),
      });
      if (!res.ok) return;

      const data = await res.json() as {
        threats?: Array<{ ip: string; score: number; topAttack: string }>;
      };

      const newCache = new Map<string, { score: number; topAttack: string }>();
      for (const t of data.threats ?? []) {
        newCache.set(t.ip, { score: t.score, topAttack: t.topAttack });
      }
      this.communityThreatCache = newCache;

      if (this.config.debug && newCache.size > 0) {
        this._origLog(`[Anomira] community threats refreshed — ${newCache.size} known threat IPs`);
      }
    } catch {
      // Network error: keep the existing cache, never throw
    }
  }

  async #refreshHoneypotPaths(): Promise<void> {
    const syncUrl = this.config.ingestUrl.replace(/\/v1\/events$/, "/v1/honeypots/sync");
    try {
      const res = await fetch(syncUrl, {
        headers: { Authorization: `Bearer ${this.config.apiKey}`, "User-Agent": SDK_USER_AGENT },
        signal:  AbortSignal.timeout(5_000),
      });
      if (!res.ok) return;
      const data = await res.json() as { paths?: string[] };
      this.honeypotPaths = new Set((data.paths ?? []).map((p) => p.toLowerCase()));
      if (this.config.debug && this.honeypotPaths.size > 0) {
        this._origLog(`[Anomira] honeypot paths refreshed — ${this.honeypotPaths.size} traps active`);
      }
    } catch { /* keep existing cache on error */ }
  }

  async #refreshCanaryTokens(): Promise<void> {
    const syncUrl = this.config.ingestUrl.replace(/\/v1\/events$/, "/v1/canary-tokens/sync");
    try {
      const res = await fetch(syncUrl, {
        headers: { Authorization: `Bearer ${this.config.apiKey}`, "User-Agent": SDK_USER_AGENT },
        signal:  AbortSignal.timeout(5_000),
      });
      if (!res.ok) return;
      const data = await res.json() as { tokens?: string[] };
      this.canaryTokenCache = new Set(data.tokens ?? []);
    } catch { /* keep existing cache on error */ }
  }

  async #refreshFirewallRules(): Promise<void> {
    const syncUrl = this.config.ingestUrl.replace(/\/v1\/events$/, "/v1/firewall-rules/sync");
    try {
      const res = await fetch(syncUrl, {
        headers: {
          Authorization: `Bearer ${this.config.apiKey}`,
          "User-Agent": SDK_USER_AGENT,
        },
        signal: AbortSignal.timeout(5_000),
      });
      if (!res.ok) return;
      const data = await res.json() as { rules?: FirewallRule[] };
      this.compiledRules = (data.rules ?? []).map((rule) => ({
        rule,
        re: rule.operator === "regex" ? (() => { try { return new RegExp(rule.value, "i"); } catch { return undefined; } })() : undefined,
      }));
      if (this.config.debug && this.compiledRules.length > 0) {
        this._origLog(`[Anomira] firewall rules refreshed — ${this.compiledRules.length} active rules`);
      }
    } catch {
      // Network error: keep existing cache, never throw
    }
  }

  /** Evaluate all cached firewall rules against the current request.
   *  Returns the first matching rule, or null if none match. */
  #matchFirewallRule(req: {
    url:     string;
    body:    unknown;
    headers: Record<string, string | undefined>;
    ip:      string;
  }): { rule: FirewallRule } | null {
    for (const { rule, re } of this.compiledRules) {
      let target: string;
      switch (rule.field) {
        case "url":        target = req.url; break;
        case "body":       target = typeof req.body === "string" ? req.body : JSON.stringify(req.body ?? ""); break;
        case "header":     target = req.headers[(rule.headerName ?? "").toLowerCase()] ?? ""; break;
        case "user_agent": target = req.headers["user-agent"] ?? ""; break;
        case "ip":         target = req.ip; break;
        default:           continue;
      }

      const matched = rule.operator === "regex"
        ? (re?.test(target) ?? false)
        : rule.operator === "contains"    ? target.includes(rule.value)
        : rule.operator === "equals"      ? target === rule.value
        : rule.operator === "starts_with" ? target.startsWith(rule.value)
        : rule.operator === "ends_with"   ? target.endsWith(rule.value)
        : false;

      if (matched) return { rule };
    }
    return null;
  }

  async #flushLogs(): Promise<void> {
    if (this.logBuffer.length === 0) return;
    const batch = this.logBuffer.splice(0, 500);
    const logsUrl = this.config.ingestUrl.replace(/\/v1\/events$/, "/v1/logs");
    try {
      const res = await fetch(logsUrl, {
        method:   "POST",
        redirect: "manual",
        headers: {
          Authorization:  `Bearer ${this.config.apiKey}`,
          "Content-Type": "application/json",
          "User-Agent": SDK_USER_AGENT,
        },
        body:   JSON.stringify({ appId: this.config.appId, logs: batch }),
        signal: AbortSignal.timeout(8_000),
      });
      if (this.config.debug) {
        this._origLog(`[Anomira] [logs] ✅ sent ${batch.length} log entries (${res.status})`);
      }
    } catch {
      // Re-queue on failure — put them back at the front
      this.logBuffer.unshift(...batch);
    }
  }

  async #validateCredentials(): Promise<void> {
    // Derive the ping URL from the ingest URL: swap /v1/events → /v1/ping
    const pingUrl = this.config.ingestUrl.replace(/\/v1\/events$/, "/v1/ping")
      + `?appId=${encodeURIComponent(this.config.appId)}`;

    try {
      const res = await fetch(pingUrl, {
        method:   "GET",
        redirect: "manual",
        headers: {
          Authorization: `Bearer ${this.config.apiKey}`,
          "User-Agent": SDK_USER_AGENT,
        },
        signal: AbortSignal.timeout(5_000),
      });

      if (res.status >= 300 && res.status < 400) {
        this._origWarn(`[Anomira] ❌ Wrong ingest URL — got redirect to ${res.headers.get("location")}. Check SENTINEL_INGEST_URL.`);
        return;
      }
      if (res.ok) {
        this._origLog(`[Anomira] ✅ Connected (appId: ${this.config.appId.slice(0, 8)}…)`);
        return;
      }
      if (res.status === 401) {
        this._origWarn("[Anomira] ❌ Invalid API key — check your SENTINEL_API_KEY");
        return;
      }
      if (res.status === 403) {
        this._origWarn("[Anomira] ❌ App not found or appId mismatch — check your SENTINEL_APP_ID");
        return;
      }
      this._origWarn(`[Anomira] ⚠️  Ingest returned HTTP ${res.status} — check your configuration`);
    } catch {
      this._origWarn("[Anomira] ⚠️  Could not reach ingest endpoint — check SENTINEL_INGEST_URL (current: " + this.config.ingestUrl + ")");
    }
  }

  // ─── Public API ────────────────────────────────────────────────────────────

  /**
   * Extract the real client IP from a request object, reading forwarded headers
   * in the correct priority order (Cloudflare → XFF → X-Real-IP → socket).
   *
   * Use this instead of `req.ip` when tracking events manually. `req.ip` in
   * Express without `trust proxy` set returns the proxy's address (127.0.0.1
   * behind Nginx), which breaks geo-detection and IP blocking.
   *
   * ```ts
   * // ✅ Correct — reads X-Forwarded-For / CF-Connecting-IP automatically
   * sentinel.track(EventName.OTP_FAILED, {
   *   ip:     sentinel.getClientIp(req),
   *   userId: req.body.phone,
   *   meta:   { endpoint: "/api/verify-otp" },
   * });
   *
   * // ❌ Wrong behind a proxy — req.ip is 127.0.0.1 without trust proxy configured
   * sentinel.track(EventName.OTP_FAILED, { ip: req.ip, ... });
   * ```
   */
  getClientIp(req: unknown): string {
    return this.config.getIp(req);
  }

  /**
   * Track a custom security event.
   *
   * ```ts
   * sentinel.track(EventName.OTP_FAILED, {
   *   ip:     sentinel.getClientIp(req),   // use getClientIp, not req.ip
   *   userId: req.body.phone,
   *   meta:   { endpoint: "/api/verify-otp", attempts: 3 },
   * });
   * ```
   */
  /**
   * Returns true if the IP should be blocked. Synchronous — no network call.
   *
   * Checks two independent sources:
   *   1. Manual blocklist  — IPs explicitly blocked by the customer or via playbooks.
   *   2. Community threats — IPs from Anomira's federated network whose confidence
   *                         score meets the autoBlock.communityThreshold (default 85).
   *                         Only active when autoBlock.enabled is true (the default).
   *
   * If a customer sets autoBlock.enabled = false, only the manual blocklist is checked.
   */
  isBlocked(ip: string): boolean {
    if (this.disabled) return false;

    // Whitelist always wins — trusted IPs bypass block and community checks
    if (this.whitelistedIpCache.has(ip)) return false;

    // Check manual blocklist
    if (this.blockedIpCache.has(ip)) return true;

    // Check community threat network (active when autoBlock.enabled = true)
    if (this.config.autoBlock.enabled) {
      const threat = this.communityThreatCache.get(ip);
      if (threat && threat.score >= this.config.autoBlock.communityThreshold) return true;
    }

    return false;
  }

  /**
   * Returns the block reason for an IP — useful for logging or custom responses.
   * Returns null if the IP is not blocked.
   */
  blockReason(ip: string): { source: "manual" | "community"; score?: number; topAttack?: string } | null {
    if (this.disabled) return null;
    if (this.blockedIpCache.has(ip)) return { source: "manual" };
    if (this.config.autoBlock.enabled) {
      const threat = this.communityThreatCache.get(ip);
      if (threat && threat.score >= this.config.autoBlock.communityThreshold) {
        return { source: "community", score: threat.score, topAttack: threat.topAttack };
      }
    }
    return null;
  }

  /**
   * Fire-and-forget: report a blocked-IP attempt to the ingest server so the
   * dashboard can show that the block is actively working.
   * Called automatically by the Express/Fastify middleware — no manual call needed.
   */
  reportBlockedHit(ip: string, meta: { method: string; url: string; userAgent: string }): void {
    if (this.disabled) return;
    const blockedHitUrl = this.config.ingestUrl.replace(/\/v1\/events$/, "/v1/blocked-hit");
    fetch(blockedHitUrl, {
      method:  "POST",
      headers: {
        "Content-Type":  "application/json",
        "Authorization": `Bearer ${this.config.apiKey}`,
      },
      body: JSON.stringify({
        appId:     this.config.appId,
        ip,
        method:    meta.method,
        endpoint:  meta.url,
        userAgent: meta.userAgent,
        ts:        Date.now(),
      }),
    }).catch(() => null);
  }

  /** Evaluate firewall rules against a request. Returns the matched rule or null. Synchronous. */
  matchFirewallRule(req: {
    url:     string;
    body:    unknown;
    headers: Record<string, string | undefined>;
    ip:      string;
  }): { rule: FirewallRule } | null {
    return this.#matchFirewallRule(req);
  }

  track(
    eventName: string,
    data: {
      /**
       * Client IP address. Optional — when omitted or empty the SDK
       * automatically reads it from the active request context set by the
       * Express/Fastify middleware.  This means developers calling track()
       * inside a request handler get the correct IP for free, with no extra
       * configuration required.
       *
       * Only pass this explicitly when calling track() outside a request
       * context (e.g. from a background job or a webhook handler that has
       * the IP available separately).
       */
      ip?:     string;
      userId?: string;
      meta?:   Record<string, unknown>;
    },
  ): void {
    if (this.disabled) return;

    // ── IP auto-resolution ────────────────────────────────────────────────────
    // Priority order:
    //   1. Explicitly passed ip (non-empty, non-zero)
    //   2. IP from the active request context (set by Express/Fastify middleware)
    //   3. Fall back to "0.0.0.0" so the event is still recorded
    const ctx = requestContext.getStore();
    const resolvedIp =
      (data.ip && data.ip !== "0.0.0.0" && data.ip !== "")
        ? data.ip
        : (ctx?.ip ?? "0.0.0.0");

    // Warn in debug mode when an explicitly-passed IP looks like a proxy address.
    // This catches the common mistake of passing `req.ip` behind Nginx, where
    // `req.ip` returns 127.0.0.1 unless Express trust proxy is configured.
    if (this.config.debug && data.ip && isPrivateIp(data.ip)) {
      this._origWarn(
        `[Anomira] Warning: track() received a private/loopback IP "${data.ip}" for event "${eventName}". ` +
        `Behind a reverse proxy, req.ip is the proxy's address — use sentinel.getClientIp(req) instead.`,
      );
    }

    // ── Endpoint auto-resolution ──────────────────────────────────────────────
    // If the caller didn't include an endpoint in meta, inject it from context.
    // This ensures REQUEST SAMPLE shows a real endpoint, not "POST —".
    const resolvedMeta: Record<string, unknown> | undefined =
      ctx?.endpoint && !data.meta?.["endpoint"]
        ? { endpoint: ctx.endpoint, method: ctx.method, ...data.meta }
        : data.meta;

    const event: SdkEvent = {
      name:   eventName,
      ts:     Date.now(),
      ip:     resolvedIp,
      userId: data.userId,
      meta:   resolvedMeta,
    };
    this.buffer.push(event);
  }

  /**
   * Track a successful login AND run geo-velocity check.
   * If impossible travel is detected, automatically fires an additional
   * `auth.login.geo_velocity` event with full context.
   *
   * ```ts
   * await sentinel.trackLogin({
   *   ip:     req.ip,
   *   userId: user.id,
   * });
   * ```
   */
  async trackLogin(data: {
    ip?:     string;
    userId:  string;
    meta?:   Record<string, unknown>;
  }): Promise<void> {
    if (this.disabled) return;
    const tsMs = Date.now();

    // Resolve IP the same way track() does — from context when not passed
    const ctx        = requestContext.getStore();
    const resolvedIp = (data.ip && data.ip !== "0.0.0.0") ? data.ip : (ctx?.ip ?? "0.0.0.0");

    // Record the successful login
    this.track(EventName.LOGIN_SUCCESS, { ...data, ip: resolvedIp, meta: { ...data.meta } });

    // Check for geo-velocity if enabled
    if (!this.config.detect.geoVelocity) return;

    try {
      const result = await checkGeoVelocity(data.userId, resolvedIp, tsMs, this.config.geoLookupUrl || undefined);
      if (!result) return;

      this.track(EventName.GEO_VELOCITY, {
        ip:     resolvedIp,
        userId: data.userId,
        meta: {
          distanceKm:  result.distanceKm,
          speedKmH:    result.speedKmH,
          fromIp:      result.from.ip,
          fromCity:    result.from.city,
          fromCountry: result.from.country,
          toCity:      result.to.city,
          toCountry:   result.to.country,
          minutesDiff: Math.round((result.to.tsMs - result.from.tsMs) / 60_000),
          ...data.meta,
        },
      });
    } catch {
      // Geo-velocity check failures are always silent
    }
  }

  /**
   * Track phone-based authentication (OTP via SMS, WhatsApp, or call).
   * The ingest service uses this to detect SIM swap patterns:
   * if the same userId authenticates via phone but then appears on a new
   * device/IP shortly after, it's flagged as a suspected SIM swap.
   *
   * ```ts
   * await sentinel.trackPhoneAuth({
   *   ip:     req.ip,
   *   userId: user.id,
   *   phone:  user.phoneNumber,
   * });
   * ```
   */
  trackPhoneAuth(data: {
    ip?:     string;
    userId:  string;
    phone:   string;
    meta?:   Record<string, unknown>;
  }): void {
    if (this.disabled) return;
    this.track(EventName.PHONE_AUTH, {
      ip:     data.ip, // track() auto-resolves from context if empty
      userId: data.userId,
      meta:   { phone: data.phone, ...data.meta },
    });
  }

  /**
   * Send a structured log entry to the Anomira Logs dashboard.
   *
   * ```ts
   * sentinel.log("info",  "User registered",         { userId: user.id });
   * sentinel.log("warn",  "Slow DB query detected",  { queryMs: 1240 });
   * sentinel.log("error", "Payment failed",           { reason: err.message });
   * ```
   */
  log(
    level:    "debug" | "info" | "warn" | "error" | "fatal",
    message:  string,
    meta?:    Record<string, unknown> & { service?: string },
  ): void {
    if (this.disabled) return;
    const { service, ...rest } = meta ?? {};

    const leaks = scanForLeaks(message);
    if (leaks.length > 0) {
      rest["sensitiveLeaks"] = leaks.map((l) => l.type);
      if (this.config.debug) {
        this._origWarn(
          `[Anomira] ⚠️  Sensitive data in log (${leaks.map((l) => l.label).join(", ")}): "${message.slice(0, 60)}…"`,
        );
      }
    }

    this.logBuffer.push({ level, service: service ?? this.config.service, message, meta: rest, ts: Date.now() });
    if (this.config.debug && leaks.length === 0) {
      this._origLog(`[Anomira] log:${level} ${message}`);
    }
    if (this.logBuffer.length >= 50) void this.#flushLogs();
  }

  /**
   * Declare your API's known endpoints so Anomira can flag undiscovered
   * traffic as shadow endpoints.
   *
   * Call this once on startup after your routes are registered:
   *
   * ```ts
   * await sentinel.declareEndpoints([
   *   { method: "GET",  path: "/api/users/:id",  auth: true  },
   *   { method: "POST", path: "/api/orders",     auth: true  },
   *   { method: "GET",  path: "/api/health",     auth: false },
   * ]);
   * ```
   */
  async declareEndpoints(endpoints: EndpointDeclaration[]): Promise<void> {
    if (this.disabled || endpoints.length === 0) return;
    const url = this.config.ingestUrl.replace(/\/v1\/events$/, "/v1/declare-endpoints");
    try {
      await fetch(url, {
        method: "POST",
        headers: {
          Authorization:  `Bearer ${this.config.apiKey}`,
          "Content-Type": "application/json",
          "User-Agent": SDK_USER_AGENT,
        },
        body: JSON.stringify({ appId: this.config.appId, endpoints }),
        signal: AbortSignal.timeout(10_000),
      });
    } catch {
      // Network errors must never crash the host app
    }
  }

  /**
   * Flush all pending events immediately.
   * Useful before a graceful shutdown outside of the process lifecycle hooks.
   */
  async flush(): Promise<void> {
    if (this.disabled) return;
    // Clear all refresh timers so they don't fire after shutdown
    if (this.blocklistTimer)       { clearInterval(this.blocklistTimer);       this.blocklistTimer       = null; }
    if (this.firewallTimer)        { clearInterval(this.firewallTimer);        this.firewallTimer        = null; }
    if (this.communityThreatTimer) { clearInterval(this.communityThreatTimer); this.communityThreatTimer = null; }
    if (this.logFlushTimer)        { clearInterval(this.logFlushTimer);        this.logFlushTimer        = null; }
    await Promise.all([this.buffer.flush(), this.#flushLogs()]);
  }

  /**
   * Express middleware — auto-instruments all routes.
   *
   * ```ts
   * app.use(sentinel.express());
   * ```
   */
  express() {
    return createExpressMiddleware(this);
  }

  /**
   * Fastify plugin — auto-instruments all routes.
   *
   * ```ts
   * await app.register(sentinel.fastify());
   * ```
   */
  fastify() {
    return createFastifyPlugin(this);
  }
}

// ─── Default extractors ──────────────────────────────────────────────────────

/**
 * Automatic userId extraction — tries every common Node.js auth pattern
 * in priority order so the SDK works with zero configuration for most apps.
 *
 * Tier 1: req.user.*
 *   Set by Passport.js, express-jwt v6, Firebase Admin SDK, @fastify/passport,
 *   @fastify/jwt, most JWT-verification middleware.
 *   Fields tried: id, userId, sub (JWT standard), _id (MongoDB), uid (Firebase),
 *   user_id (snake_case), accountId, account_id, customerId, customer_id.
 *
 * Tier 2: req.auth.*
 *   express-jwt v7+ moved from req.user to req.auth. Same field list as Tier 1.
 *
 * Tier 3: Direct on req
 *   Some custom middleware sets req.userId / req.accountId directly.
 *
 * Tier 4: req.session.*
 *   express-session with req.session.userId or req.session.user.id.
 *
 * Tier 5: JWT payload decode from Authorization header  ← LAST RESORT
 *   Decodes the JWT token in the Authorization: Bearer header WITHOUT verifying
 *   the signature (verification is the app's auth middleware's job — not ours).
 *   Used purely to extract the userId claim from the payload.
 *   Works even when the developer forgot to register their auth middleware before
 *   the Anomira middleware, or uses a custom auth system that doesn't set req.user.
 *   Claims tried: sub, id, userId, user_id, uid, accountId, account_id.
 *
 * If none of these find a userId, returns undefined — the event is recorded as
 * anonymous traffic and is excluded from per-user behavioral analysis.
 *
 * Customers can always override this with getUserId: (req) => req.myCustomField.
 */
function defaultGetUserId(req: unknown): string | undefined {
  const r = req as Record<string, unknown>;

  // ── Tier 1: req.user.* ────────────────────────────────────────────────────
  const user = r["user"] as Record<string, unknown> | undefined;
  if (user && typeof user === "object") {
    const id = pickId(user);
    if (id) return id;
  }

  // ── Tier 2: req.auth.* (express-jwt v7+) ─────────────────────────────────
  const auth = r["auth"] as Record<string, unknown> | undefined;
  if (auth && typeof auth === "object") {
    const id = pickId(auth);
    if (id) return id;
  }

  // ── Tier 3: Direct on req ─────────────────────────────────────────────────
  const direct =
    (r["userId"]     as string | undefined) ??
    (r["user_id"]    as string | undefined) ??
    (r["accountId"]  as string | undefined) ??
    (r["account_id"] as string | undefined) ??
    (r["customerId"] as string | undefined);
  if (direct && typeof direct === "string") return direct;

  // ── Tier 4: req.session.* (express-session) ───────────────────────────────
  const session = r["session"] as Record<string, unknown> | undefined;
  if (session && typeof session === "object") {
    const sessionDirect =
      (session["userId"]  as string | undefined) ??
      (session["user_id"] as string | undefined);
    if (sessionDirect) return sessionDirect;

    const sessionUser = session["user"] as Record<string, unknown> | undefined;
    if (sessionUser && typeof sessionUser === "object") {
      const id = pickId(sessionUser);
      if (id) return id;
    }
  }

  // ── Tier 5: JWT decode from Authorization header ──────────────────────────
  // Decode without verifying — we only want the userId claim, not to authenticate.
  const headers = r["headers"] as Record<string, string | string[] | undefined> | undefined;
  const rawAuth = headers?.["authorization"];
  const authStr = Array.isArray(rawAuth) ? rawAuth[0] : rawAuth;
  if (authStr?.startsWith("Bearer ")) {
    const token = authStr.slice(7);
    try {
      const parts = token.split(".");
      if (parts.length === 3) {
        // Base64URL → Base64 (replace - with + and _ with /) then pad to 4-byte boundary
        const b64    = parts[1]!.replace(/-/g, "+").replace(/_/g, "/");
        const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
        const payload = JSON.parse(
          Buffer.from(padded, "base64").toString("utf8"),
        ) as Record<string, unknown>;
        const jwtId = pickId(payload);
        if (jwtId) return jwtId;
        // Some JWTs wrap user data one level deep: { data: { id: "..." } }
        for (const val of Object.values(payload)) {
          if (val && typeof val === "object" && !Array.isArray(val)) {
            const nested = pickId(val as Record<string, unknown>);
            if (nested) return nested;
          }
        }
      }
    } catch {
      // Not a valid JWT or decode failed — move on silently
    }
  }

  return undefined;
}

/**
 * Extract the most likely userId field from a plain object.
 * Returns the first non-empty string found among the standard field names,
 * or undefined if nothing useful is found.
 */
function pickId(obj: Record<string, unknown>): string | undefined {
  const id =
    (obj["id"]          as string | undefined) ??
    (obj["sub"]         as string | undefined) ??  // JWT standard claim
    (obj["userId"]      as string | undefined) ??
    (obj["user_id"]     as string | undefined) ??
    (obj["uid"]         as string | undefined) ??  // Firebase
    (obj["_id"]         as string | undefined) ??  // MongoDB
    (obj["accountId"]   as string | undefined) ??
    (obj["account_id"]  as string | undefined) ??
    (obj["customerId"]  as string | undefined) ??
    (obj["customer_id"] as string | undefined);
  // Only return if it's a non-empty string (guards against null, 0, undefined)
  return typeof id === "string" && id.length > 0 ? id : undefined;
}

function normalizeIp(raw: string): string {
  if (raw === "::1") return "127.0.0.1";
  if (raw === "::ffff:127.0.0.1") return "127.0.0.1";
  if (raw.startsWith("::ffff:")) return raw.slice(7);
  return raw;
}

function isPrivateIp(ip: string): boolean {
  return (
    ip === "127.0.0.1"          ||
    ip === "::1"                ||
    ip === "0.0.0.0"            ||
    ip.startsWith("10.")        ||
    ip.startsWith("192.168.")   ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip)
  );
}

function defaultGetIp(req: unknown): string {
  const r   = req as Record<string, unknown>;
  const fwd = r["headers"] as Record<string, string | string[] | undefined> | undefined;

  // Pull the first non-empty value from a header (handles comma-lists like XFF)
  function firstHdr(name: string): string | undefined {
    const v = fwd?.[name];
    if (!v) return undefined;
    const s = (Array.isArray(v) ? v[0] : v.split(",")[0])?.trim();
    return s || undefined;
  }

  // Priority order: CDN/cloud-specific headers first (harder to spoof when behind
  // those services), then standard XFF, then socket fallback.
  const ip =
    firstHdr("cf-connecting-ip")     ??   // Cloudflare
    firstHdr("true-client-ip")       ??   // Cloudflare Enterprise / Akamai
    firstHdr("x-forwarded-for")      ??   // Nginx, AWS ALB, GCP LB, most proxies
    firstHdr("x-real-ip")            ??   // Nginx (single-IP alternative to XFF)
    firstHdr("fastly-client-ip")     ??   // Fastly CDN
    firstHdr("x-client-ip")          ??   // Generic reverse proxies
    firstHdr("x-cluster-client-ip")  ??   // Cluster / k8s ingress
    (r["socket"] as { remoteAddress?: string } | undefined)?.remoteAddress ??
    "0.0.0.0";

  return normalizeIp(ip);
}

// ─── Fake response sender (shared by honeypot + credential handlers) ─────────

import type { HoneypotResponse } from "./honeypot-responses.js";

function sendFakeResponse(res: Record<string, unknown>, fakeResponse: HoneypotResponse): void {
  const allHeaders: Record<string, string> = {
    "Content-Type": fakeResponse.contentType,
    ...fakeResponse.headers,
  };
  if (typeof res["set"] === "function") {
    (res["set"] as (h: Record<string, string>) => void)(allHeaders);
  } else if (typeof res["setHeader"] === "function") {
    for (const [k, v] of Object.entries(allHeaders)) {
      (res["setHeader"] as (k: string, v: string) => void)(k, v);
    }
  }
  if (typeof res["status"] === "function") {
    (res["status"] as (c: number) => unknown)(fakeResponse.statusCode);
  } else {
    res["statusCode"] = fakeResponse.statusCode;
  }
  if (typeof res["end"] === "function") {
    (res["end"] as (b: string) => void)(fakeResponse.body);
  }
}

// ─── Lazy imports for middleware factories ───────────────────────────────────
// Imported lazily so the SDK has no hard dependency on express/fastify at runtime

function isLoopbackIp(ip: string): boolean {
  return ip === "127.0.0.1" || ip === "0.0.0.0" || ip === "::1";
}

function createExpressMiddleware(client: AnomiraClient) {
  let ipCheckCount = 0;
  let ipLoopCount  = 0;
  let ipWarnFired  = false;

  let userIdCheckCount = 0;
  let userIdMissCount  = 0;
  let userIdWarnFired  = false;

  return async function sentinelMiddleware(
    req:  Record<string, unknown>,
    res:  Record<string, unknown>,
    next: () => void,
  ) {
    const startMs = Date.now();
    const ip      = client.config.getIp(req);

    // Warn once if the first 20 requests are consistently loopback — almost
    // always means the reverse proxy isn't forwarding X-Forwarded-For.
    if (!ipWarnFired && ipCheckCount < 20) {
      ipCheckCount++;
      if (isLoopbackIp(ip)) ipLoopCount++;
      if (ipCheckCount === 20 && ipLoopCount >= 16) {
        ipWarnFired = true;
        console.warn(
          "[Anomira] WARNING: client IP not captured on 80%+ of requests.\n" +
          "  Your app is likely behind a reverse proxy (Nginx, Cloudflare, AWS ALB)\n" +
          "  that is not forwarding client IP headers. Alerts will have no IP attribution.\n\n" +
          "  Nginx fix:   proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n" +
          "               proxy_set_header X-Real-IP         $remote_addr;\n" +
          "  Express fix: app.set('trust proxy', 1);\n" +
          "  Fastify fix: Fastify({ trustProxy: true })\n" +
          "  Docs:        https://docs.anomira.io/sdk/ip-capture"
        );
      }
    }

    // ── Block check — synchronous, zero latency ──
    if (client.isBlocked(ip)) {
      const method_ = (req["method"] as string | undefined)?.toUpperCase() ?? "GET";
      const url_    = (req["originalUrl"] as string | undefined) ?? (req["url"] as string | undefined) ?? "/";
      const ua_     = (req["headers"] as Record<string, string | undefined> | undefined)?.["user-agent"] ?? "";
      const reason_ = client.blockReason(ip);
      client.reportBlockedHit(ip, { method: method_, url: url_, userAgent: ua_ });

      // Emit a tracking event so the community auto-block is visible in the dashboard
      if (reason_?.source === "community") {
        client.track("http.community_threat_blocked", {
          ip,
          meta: {
            endpoint:  url_,
            method:    method_,
            score:     reason_.score,
            topAttack: reason_.topAttack,
            source:    "anomira_network",
          },
        });
      }

      const res_ = res as Record<string, unknown>;
      if (typeof res_["status"] === "function") {
        (res_["status"] as (c: number) => unknown)(403);
      } else {
        res_["statusCode"] = 403;
      }
      if (typeof res_["end"] === "function") (res_["end"] as (b: string) => void)('{"error":"Forbidden"}');
      return;
    }

    const userId  = client.config.getUserId(req);
    const method  = (req["method"] as string | undefined)?.toUpperCase() ?? "GET";
    const url     = (req["originalUrl"] as string | undefined) ?? (req["url"] as string | undefined) ?? "/";

    const headers     = req["headers"] as Record<string, string | string[] | undefined> | undefined;
    const headersStr  = headers as Record<string, string | undefined> | undefined;
    const ua          = (typeof headers?.["user-agent"] === "string" ? headers["user-agent"] : "") ?? "";
    const agentInfo   = detectAgent(headers ?? {});
    const fingerprint = computeBrowserFingerprint(headers ?? {}, ua);
    const h2settings  = extractHttp2Settings(req);
    const upstreamTls = extractUpstreamTls(headers ?? {});

    // ── Browser SDK payload ────────────────────────────────────────────────────
    // Cookie (anomira_fp) is the primary transport — survives Next.js rewrites,
    // reverse proxies, and any middleware that strips custom headers.
    // Header (X-Anomira-FP) is secondary — used when cookie is absent.
    const cookieHeader  = headers?.["cookie"] as string | undefined;
    const cookieToken   = cookieHeader
      ? (cookieHeader.split(";").map((c) => c.trim()).find((c) => c.startsWith("anomira_fp="))?.slice("anomira_fp=".length) ?? "")
      : "";
    const browserFpRaw  = cookieToken || (headers?.["x-anomira-fp"] as string | undefined) || "";

    let browserFp: { fp: string; bot: number; sigs: string; uid?: string; pst?: boolean; ttf?: number; tts?: number } | null = null;
    if (browserFpRaw) {
      try {
        const raw = JSON.parse(Buffer.from(browserFpRaw, "base64").toString("utf8")) as Record<string, unknown>;
        if (typeof raw["v"] === "number" && typeof raw["fp"] === "string") {
          browserFp = {
            fp:   raw["fp"]  as string,
            bot:  (raw["bot"] as number | undefined) ?? 0,
            sigs: ((raw["sigs"] as string[] | undefined) ?? []).join(","),
            uid:  typeof raw["uid"] === "string" && raw["uid"] ? raw["uid"] as string : undefined,
            pst:  (raw["frm"] as { pst?: boolean } | undefined)?.pst,
            ttf:  (raw["frm"] as { ttf?: number } | undefined)?.ttf,
            tts:  (raw["frm"] as { tts?: number } | undefined)?.tts,
          };
        }
      } catch { /* malformed payload — ignore */ }
    }

    // ── Canary token detection ─────────────────────────────────────────────────
    // Scan the Authorization header for canary JWTs (JWT `jti` claim contains
    // the canary token). If found, fire a CRITICAL canary_triggered event —
    // this means the attacker obtained a credential from our honeypot and is
    // now using it against the real API.
    if (client["canaryTokenCache"] && (client["canaryTokenCache"] as Set<string>).size > 0) {
      const authHeader = (typeof headers?.["authorization"] === "string" ? headers["authorization"] : "") ?? "";
      if (authHeader.startsWith("Bearer ")) {
        const bearerToken = authHeader.slice(7);
        // Check if the bearer token itself IS a canary token
        if ((client["canaryTokenCache"] as Set<string>).has(bearerToken)) {
          client.track("http.canary.triggered", {
            ip, userId,
            meta: { endpoint: url, method, token: bearerToken.slice(0, 16), source: "authorization_header" },
          });
        }
        // Also decode JWT and check jti/kid against canary cache
        try {
          const parts = bearerToken.split(".");
          if (parts.length === 3) {
            const b64h = (parts[0] ?? "").replace(/-/g, "+").replace(/_/g, "/");
            const hdr  = JSON.parse(Buffer.from(b64h + "==", "base64").toString()) as Record<string, unknown>;
            const b64p = (parts[1] ?? "").replace(/-/g, "+").replace(/_/g, "/");
            const pay  = JSON.parse(Buffer.from(b64p + "==", "base64").toString()) as Record<string, unknown>;
            const jti  = (pay["jti"] as string | undefined) ?? "";
            // jti is the raw canary token hex (32 chars) — check directly against the cache
            const cache = client["canaryTokenCache"] as Set<string>;
            if (jti && cache.has(jti)) {
              client.track("http.canary.triggered", {
                ip, userId,
                meta: { endpoint: url, method, token: jti.slice(0, 16), source: "canary_jwt" },
              });
            }
          }
        } catch { /* not a valid JWT */ }
      }
    }

    // ── Enhanced honeypot interception ─────────────────────────────────────────
    // If this request matches a registered honeypot path, return realistic fake
    // content INSTEAD of forwarding to the customer's route handlers.
    // This is done BEFORE next() so the customer's routes are never involved.
    const urlPath = url.split("?")[0]?.toLowerCase() ?? url.toLowerCase();
    const isHoneypot = (client["honeypotPaths"] as Set<string>).size > 0 &&
      [...(client["honeypotPaths"] as Set<string>)].some((hp) =>
        urlPath === hp || urlPath.startsWith(hp + "/") || urlPath.startsWith(hp + ".")
      );

    if (isHoneypot) {
      const honeypotType = detectHoneypotType(url);
      const callbackBase = client.config.ingestUrl.replace(/\/v1\/events$/, "");
      const orgId        = "";

      // ── POST to admin portal: capture credential attempt ───────────────────
      // When an attacker fills in the fake login form and submits, we capture
      // what credentials they tried as threat intel. Username is stored in full
      // (useful to know which accounts are targeted); password is length-only.
      if (method === "POST" && honeypotType === "admin_portal") {
        const body_    = req["body"] as Record<string, unknown> | undefined;
        const username = String(
          body_?.["username"] ?? body_?.["email"] ?? body_?.["user"] ?? body_?.["login"] ?? ""
        );
        const password = String(
          body_?.["password"] ?? body_?.["pass"] ?? body_?.["pwd"] ?? body_?.["passwd"] ?? ""
        );

        if (username || password) {
          // Length-only hint — avoid storing any password material
          const passwordHint = password.length > 0
            ? `[len=${password.length}]`
            : "(empty)";

          client.track("http.honeypot.credential_attempt", {
            ip, userId,
            meta: {
              endpoint:     url,
              method,
              userAgent:    ua,
              honeypotType,
              username,
              passwordHint,
              // Hidden _token field — if this is the canary token we issued
              // in the GET response, we know this is the same attacker session
              formToken:    String(body_?.["_token"] ?? ""),
            },
          });
        }

        // Return "invalid credentials" response — lures further attempts
        const failed = makeAdminLoginFailed();
        sendFakeResponse(res, failed);
        return;
      }

      // ── GET or other method: serve the fake content ────────────────────────
      const canaryToken  = randomBytes(16).toString("hex");
      const fakeResponse = generateHoneypotResponse(honeypotType, canaryToken, callbackBase, orgId);

      client.track("http.honeypot.hit", {
        ip, userId,
        meta: {
          endpoint:     url,
          method,
          userAgent:    ua,
          honeypotType,
          canaryToken,
          responseType: "enhanced",
        },
      });

      sendFakeResponse(res, fakeResponse);
      return;
    }

    // ── Firewall rule evaluation ──
    const fwMatch = client.matchFirewallRule({ url, body: req["body"], headers: headersStr ?? {}, ip });
    if (fwMatch) {
      client.track("http.firewall." + fwMatch.rule.action, {
        ip, userId,
        meta: { url, method, ruleId: fwMatch.rule.id, attackType: fwMatch.rule.attackType },
      });
      const res_ = res as Record<string, unknown>;
      const setStatus = (code: number) => {
        if (typeof res_["status"] === "function") (res_["status"] as (c: number) => unknown)(code);
        else res_["statusCode"] = code;
      };
      const sendBody = (body: string) => {
        if (typeof res_["end"] === "function") (res_["end"] as (b: string) => void)(body);
      };
      const setHeader = (k: string, v: string) => {
        if (typeof res_["setHeader"] === "function") (res_["setHeader"] as (k: string, v: string) => void)(k, v);
      };
      const action = fwMatch.rule.action;
      if (action === "block" || action === "temporary_block") {
        setStatus(403); sendBody('{"error":"Blocked by firewall rule"}'); return;
      }
      if (action === "rate_limit") {
        setStatus(429); setHeader("Retry-After", "60"); sendBody('{"error":"Rate limit exceeded","retryAfter":60}'); return;
      }
      if (action === "redirect_honeypot") {
        const target = fwMatch.rule.redirectTarget ?? "/.env";
        setStatus(302); setHeader("Location", target); sendBody(""); return;
      }
      if (action === "challenge") {
        setStatus(403); sendBody('{"error":"Request challenge required"}'); return;
      }
      // tag | monitor | flag → allow through, already tracked above
    }

    // ── Detect path traversal before the request reaches the handler ──
    if (client.config.detect.pathTraversal && hasPathTraversal(url)) {
      client.track(EventName.PATH_TRAVERSAL, { ip, userId, meta: { url, method } });
    }

    // ── Detect XSS in body (only on POST/PUT/PATCH) ──
    if (client.config.detect.xss && ["POST", "PUT", "PATCH"].includes(method)) {
      if (scanForXss(req["body"])) {
        client.track(EventName.XSS_DETECTED, { ip, userId, meta: { url, method } });
      }
    }

    // ── Detect SSRF — scan URL-shaped parameter values ──
    // Only inspects fields whose names suggest they accept URLs (url, redirect,
    // webhook, src, etc.) to minimise false positives.
    if (client.config.detect.ssrf) {
      const query = (req["query"] as Record<string, string | string[] | undefined>) ?? {};
      const body  = (req["body"] as unknown) ?? {};
      const signal = scanForSsrf(body, query);
      if (signal) {
        client.track(EventName.SSRF_ATTEMPT, {
          ip, userId,
          meta: { url, method, ssrfPayload: signal.payload, ssrfField: signal.field, ssrfReason: signal.reason },
        });
      }
    }

    // ── Detect JWT header manipulation ──
    if (client.config.detect.jwtManipulation) {
      const reqHeaders = (headers ?? {}) as Record<string, string | string[] | undefined>;
      const reqBody    = (req["body"] as unknown) ?? {};
      const reqQuery   = (req["query"] as Record<string, string | string[] | undefined>) ?? {};
      const jwtResult  = scanRequestForJwtAttacks(reqHeaders, reqBody, reqQuery);
      if (jwtResult?.detected) {
        client.track(EventName.JWT_MANIPULATION, {
          ip, userId,
          meta: { url, method, jwtAttack: jwtResult.attack, jwtAlg: jwtResult.alg, jwtDetail: jwtResult.detail },
        });
      }
    }

    // ── Hook into response finish ──
    const onFinish = () => {
      // Re-read userId here — auth middleware has now run, so req.user is populated.
      // This is the fix for apps that mount Anomira before their auth middleware,
      // which is the standard setup order (block check needs to run first).
      // Fallback: if server-side auth didn't populate userId, use the browser SDK's
      // uid field — set via AnomaliraBrowser.identify({ userId }) on the frontend.
      const lateUserId = client.config.getUserId(req) || browserFp?.uid || "";

      // Warn once if userId is STILL missing even after the full request cycle.
      // This means neither auto-detection nor auth middleware populated it.
      if (!userIdWarnFired && userIdCheckCount < 20) {
        userIdCheckCount++;
        if (!lateUserId) userIdMissCount++;
        if (userIdCheckCount === 20 && userIdMissCount >= 18) {
          userIdWarnFired = true;
          console.warn(
            "[Anomira] WARNING: userId not captured on 90%+ of requests.\n" +
            "  EWS Evidence Package, geo-velocity, and account takeover detection\n" +
            "  silently stop working without it. The SDK tried 5 auto-detection tiers\n" +
            "  (Passport / express-jwt, req.auth, direct req.userId, session, JWT Bearer)\n" +
            "  — none matched your auth setup.\n\n" +
            "  Fix: pass a getUserId resolver that matches your auth middleware:\n" +
            "  new Anomira({ ..., getUserId: (req) => req.user?.id })"
          );
        }
      }

      const status    = (res["statusCode"] as number | undefined) ?? 0;
      const latencyMs = Date.now() - startMs;
      const getHeader = (res as Record<string, unknown>)["getHeader"];
      const bytes = typeof getHeader === "function"
        ? parseInt((getHeader as (h: string) => string | undefined).call(res, "content-length") ?? "0", 10) || 0
        : 0;

      // ── PII / sensitive-data detection ────────────────────────────────────
      // Runs after response is sent — zero latency impact on the client.
      // Layer 1: field name matching  (O(keys) lookup against pre-built Map)
      // Layer 2: value regex matching (only string values ≤ 200 chars)
      const rawBody = req["body"];
      const piiFields:     string[] = [];
      const piiPatterns:   string[] = [];
      const piiCatSet      = new Set<string>();

      if (rawBody != null && typeof rawBody === "object" && !Array.isArray(rawBody)) {
        const body = rawBody as Record<string, unknown>;
        for (const key of Object.keys(body)) {
          const cat = FIELD_CATEGORY_MAP.get(key.toLowerCase());
          if (cat) { piiFields.push(key.toLowerCase()); piiCatSet.add(cat); }
        }
        for (const val of Object.values(body)) {
          if (typeof val !== "string" || val.length > 200) continue;
          for (const { name, category, re } of VALUE_PATTERNS) {
            if (!piiPatterns.includes(name) && re.test(val)) {
              piiPatterns.push(name); piiCatSet.add(category);
            }
          }
        }
      }
      const piiCategories = piiCatSet.size > 0 ? [...piiCatSet] : undefined;

      client.track(EventName.REQUEST, {
        ip, userId: lateUserId,
        meta: {
          method, endpoint: url, status, latencyMs, userAgent: ua, bytes,
          ...(piiFields.length > 0     ? { piiFields }     : {}),
          ...(piiPatterns.length > 0   ? { piiPatterns }   : {}),
          ...(piiCategories            ? { piiCategories } : {}),
          _fp:    fingerprint.score,
          _fpSig: fingerprint.signals.join(","),
          ...(fingerprint.knownClient ? { _fpClient: fingerprint.knownClient } : {}),
          ...(browserFp ? {
            _bfp:   browserFp.fp,
            _bbot:  browserFp.bot,
            _bsigs: browserFp.sigs,
            ...(browserFp.pst !== undefined ? { _bpaste: browserFp.pst } : {}),
            ...(browserFp.ttf !== undefined && browserFp.ttf >= 0 ? { _bttf: browserFp.ttf } : {}),
            ...(browserFp.tts !== undefined && browserFp.tts >= 0 ? { _btts: browserFp.tts } : {}),
          } : {}),
          ...(h2settings ? {
            _h2Window:     h2settings.initialWindowSize,
            _h2HdrTable:   h2settings.headerTableSize,
            _h2Score:      h2settings.score,
            _h2Signals:    h2settings.signals.join(","),
          } : {}),
          ...(upstreamTls.ja3 ? { _ja3: upstreamTls.ja3 } : {}),
          ...(upstreamTls.ja4 ? { _ja4: upstreamTls.ja4 } : {}),
          ...(agentInfo.isAgent ? {
            agentDetected:   true,
            agentType:       agentInfo.agentType,
            agentName:       agentInfo.agentName,
            agentConfidence: agentInfo.confidence,
            mcpSessionId:    agentInfo.sessionId,
            isMcp:           agentInfo.isMcp,
            agentSignals:    agentInfo.signals.join(","),
          } : {}),
        },
      });

      if (agentInfo.isAgent) {
        client.track("http.agent_detected", {
          ip, userId: lateUserId,
          meta: {
            endpoint:        url,
            method,
            agentType:       agentInfo.agentType,
            agentName:       agentInfo.agentName,
            agentConfidence: agentInfo.confidence,
            mcpSessionId:    agentInfo.sessionId,
            isMcp:           agentInfo.isMcp,
            agentSignals:    agentInfo.signals.join(","),
            status,
            userAgent:       ua,
          },
        });
      }

      if (client.config.detect.rateAbuse && status === 429) {
        client.track(EventName.RATE_LIMIT, { ip, userId: lateUserId, meta: { url, method, statusCode: status } });
      }

      if (client.config.detect.bruteForce && status === 401) {
        if (/\/(login|signin|auth|token|session)/i.test(url)) {
          client.track(EventName.LOGIN_FAILED, { ip, userId: lateUserId, meta: { url, method, statusCode: status } });
        }
      }

      if (client.config.detect.scanDetection && status === 404) {
        const looksLikeScanner = !ua || /curl|wget|python|go-http|nuclei|sqlmap|nikto/i.test(ua);
        if (looksLikeScanner) {
          client.track(EventName.SCAN_DETECTED, { ip, userId: lateUserId, meta: { url, method, userAgent: ua } });
        }
      }

      cleanup();
    };

    const cleanup = () => {
      (res as unknown as { off: (e: string, fn: () => void) => void }).off?.("finish", onFinish);
    };

    (res as unknown as { on: (e: string, fn: () => void) => void }).on?.("finish", onFinish);

    // Run the downstream handler inside a context so console logs get endpoint tagged
    requestContext.run({ endpoint: url, method, ip }, next);
  };
}

function createFastifyPlugin(client: AnomiraClient) {
  let ipCheckCount = 0;
  let ipLoopCount  = 0;
  let ipWarnFired  = false;

  let userIdCheckCount = 0;
  let userIdMissCount  = 0;
  let userIdWarnFired  = false;

  return async function sentinelFastifyPlugin(
    fastify: {
      addHook: (
        event: string,
        fn: (req: Record<string, unknown>, reply: Record<string, unknown>) => void,
      ) => void;
    },
  ) {
    fastify.addHook("onRequest", (req, reply) => {
      const ip      = client.config.getIp(req);

      if (!ipWarnFired && ipCheckCount < 20) {
        ipCheckCount++;
        if (isLoopbackIp(ip)) ipLoopCount++;
        if (ipCheckCount === 20 && ipLoopCount >= 16) {
          ipWarnFired = true;
          console.warn(
            "[Anomira] WARNING: client IP not captured on 80%+ of requests.\n" +
            "  Your app is likely behind a reverse proxy (Nginx, Cloudflare, AWS ALB)\n" +
            "  that is not forwarding client IP headers. Alerts will have no IP attribution.\n\n" +
            "  Nginx fix:   proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n" +
            "               proxy_set_header X-Real-IP         $remote_addr;\n" +
            "  Fastify fix: Fastify({ trustProxy: true })\n" +
            "  Docs:        https://docs.anomira.io/sdk/ip-capture"
          );
        }
      }
      const url_    = (req["url"]    as string | undefined) ?? "/";
      const method_ = (req["method"] as string | undefined)?.toUpperCase() ?? "GET";
      const hdrs_   = (req as Record<string, unknown>)["headers"] as Record<string, string | undefined> | undefined;

      // ── Block check — synchronous, zero latency ──
      if (client.isBlocked(ip)) {
        const reason_ = client.blockReason(ip);
        client.reportBlockedHit(ip, { method: method_, url: url_, userAgent: hdrs_?.["user-agent"] ?? "" });

        if (reason_?.source === "community") {
          client.track("http.community_threat_blocked", {
            ip,
            meta: {
              endpoint:  url_,
              method:    method_,
              score:     reason_.score,
              topAttack: reason_.topAttack,
              source:    "anomira_network",
            },
          });
        }

        const rep = reply as Record<string, unknown>;
        if (typeof rep["code"] === "function") {
          const chained = (rep["code"] as (c: number) => Record<string, unknown>)(403);
          if (chained && typeof chained["send"] === "function") {
            (chained["send"] as (b: unknown) => void)({ error: "Forbidden" });
          }
        }
        return;
      }

      const url    = (req["url"] as string | undefined) ?? "/";
      const method = (req["method"] as string | undefined)?.toUpperCase() ?? "GET";
      const userId = client.config.getUserId(req);

      if (client.config.detect.pathTraversal && hasPathTraversal(url)) {
        client.track(EventName.PATH_TRAVERSAL, { ip, userId, meta: { url, method } });
      }
    });

    fastify.addHook("preHandler", (req, reply) => {
      const ip      = client.config.getIp(req);
      const url     = (req["url"] as string | undefined) ?? "/";
      const method  = (req["method"] as string | undefined)?.toUpperCase() ?? "GET";
      const userId  = client.config.getUserId(req);
      const headers = (req as Record<string, unknown>)["headers"] as Record<string, string | undefined> | undefined;

      // ── Firewall rule evaluation ──
      const fwMatch = client.matchFirewallRule({ url, body: (req as Record<string, unknown>)["body"], headers: headers ?? {}, ip });
      if (fwMatch) {
        client.track("http.firewall." + fwMatch.rule.action, {
          ip, userId,
          meta: { url, method, ruleId: fwMatch.rule.id, attackType: fwMatch.rule.attackType },
        });
        const rep = reply as Record<string, unknown>;
        const replyCode = (code: number) =>
          typeof rep["code"] === "function"
            ? (rep["code"] as (c: number) => Record<string, unknown>)(code)
            : rep;
        const replyHeader = (k: string, v: string) => {
          if (typeof rep["header"] === "function") (rep["header"] as (k: string, v: string) => unknown)(k, v);
        };
        const replySend = (chained: Record<string, unknown>, body: unknown) => {
          if (chained && typeof chained["send"] === "function") (chained["send"] as (b: unknown) => void)(body);
        };
        const action = fwMatch.rule.action;
        if (action === "block" || action === "temporary_block") {
          replySend(replyCode(403), { error: "Blocked by firewall rule" }); return;
        }
        if (action === "rate_limit") {
          replyHeader("Retry-After", "60");
          replySend(replyCode(429), { error: "Rate limit exceeded", retryAfter: 60 }); return;
        }
        if (action === "redirect_honeypot") {
          const target = fwMatch.rule.redirectTarget ?? "/.env";
          replyHeader("Location", target);
          replySend(replyCode(302), ""); return;
        }
        if (action === "challenge") {
          replySend(replyCode(403), { error: "Request challenge required" }); return;
        }
        // tag | monitor | flag → allow through, already tracked above
      }

      if (client.config.detect.xss && ["POST", "PUT", "PATCH"].includes(method)) {
        if (scanForXss((req as Record<string, unknown>)["body"])) {
          client.track(EventName.XSS_DETECTED, { ip, userId, meta: { url, method } });
        }
      }

      if (client.config.detect.ssrf) {
        const query  = ((req as Record<string, unknown>)["query"]  as Record<string, string | string[] | undefined>) ?? {};
        const body   = ((req as Record<string, unknown>)["body"])  as unknown ?? {};
        const signal = scanForSsrf(body, query);
        if (signal) {
          client.track(EventName.SSRF_ATTEMPT, {
            ip, userId,
            meta: { url, method, ssrfPayload: signal.payload, ssrfField: signal.field, ssrfReason: signal.reason },
          });
        }
      }

      if (client.config.detect.jwtManipulation) {
        const fHeaders = (req as Record<string, unknown>)["headers"] as Record<string, string | string[] | undefined> ?? {};
        const fBody    = ((req as Record<string, unknown>)["body"]) as unknown ?? {};
        const fQuery   = ((req as Record<string, unknown>)["query"]) as Record<string, string | string[] | undefined> ?? {};
        const jwtRes   = scanRequestForJwtAttacks(fHeaders, fBody, fQuery);
        if (jwtRes?.detected) {
          client.track(EventName.JWT_MANIPULATION, {
            ip, userId,
            meta: { url, method, jwtAttack: jwtRes.attack, jwtAlg: jwtRes.alg, jwtDetail: jwtRes.detail },
          });
        }
      }
    });

    fastify.addHook("onResponse", (req, reply) => {
      const ip      = client.config.getIp(req);
      const url     = (req["url"] as string | undefined) ?? "/";
      const method  = (req["method"] as string | undefined)?.toUpperCase() ?? "GET";
      // onResponse fires after all hooks — auth has run, req.user is populated.
      // userId fallback applied after browser FP is parsed below.
      const serverUserId = client.config.getUserId(req);
      const status  = (reply["statusCode"] as number | undefined) ?? 0;

      // Warn once if userId is still missing after the full request cycle.
      if (!userIdWarnFired && userIdCheckCount < 20) {
        userIdCheckCount++;
        if (!serverUserId) userIdMissCount++;
        if (userIdCheckCount === 20 && userIdMissCount >= 18) {
          userIdWarnFired = true;
          console.warn(
            "[Anomira] WARNING: userId not captured on 90%+ of requests.\n" +
            "  EWS Evidence Package, geo-velocity, and account takeover detection\n" +
            "  silently stop working without it. The SDK tried 5 auto-detection tiers\n" +
            "  (Passport / @fastify/jwt, req.auth, direct req.userId, session, JWT Bearer)\n" +
            "  — none matched your auth setup.\n\n" +
            "  Fix: pass a getUserId resolver that matches your auth middleware:\n" +
            "  new Anomira({ ..., getUserId: (req) => (req as any).user?.id })"
          );
        }
      }
      const headers     = (req as Record<string, unknown>)["headers"] as Record<string, string | string[] | undefined> | undefined;
      const ua          = (typeof headers?.["user-agent"] === "string" ? headers["user-agent"] : "") ?? "";
      const latencyMs   = (reply as Record<string, unknown>)["elapsedTime"] as number | undefined ?? 0;
      const agentInfo   = detectAgent(headers ?? {});
      const fingerprint = computeBrowserFingerprint(headers ?? {}, ua);
      const h2settings  = extractHttp2Settings(req as Record<string, unknown>);
      const upstreamTls = extractUpstreamTls(headers ?? {});

      // Browser SDK payload (Fastify) — cookie primary, header secondary
      const cookieHdrF   = headers?.["cookie"] as string | undefined;
      const cookieTokF   = cookieHdrF
        ? (cookieHdrF.split(";").map((c) => c.trim()).find((c) => c.startsWith("anomira_fp="))?.slice("anomira_fp=".length) ?? "")
        : "";
      const bfpRawF      = cookieTokF || (headers?.["x-anomira-fp"] as string | undefined) || "";

      let browserFpF: { fp: string; bot: number; sigs: string; uid?: string; pst?: boolean; ttf?: number; tts?: number } | null = null;
      if (bfpRawF) {
        try {
          const raw = JSON.parse(Buffer.from(bfpRawF, "base64").toString("utf8")) as Record<string, unknown>;
          if (typeof raw["v"] === "number" && typeof raw["fp"] === "string") {
            browserFpF = {
              fp:   raw["fp"]  as string,
              bot:  (raw["bot"] as number | undefined) ?? 0,
              sigs: ((raw["sigs"] as string[] | undefined) ?? []).join(","),
              uid:  typeof raw["uid"] === "string" && raw["uid"] ? raw["uid"] as string : undefined,
              pst:  (raw["frm"] as { pst?: boolean } | undefined)?.pst,
              ttf:  (raw["frm"] as { ttf?: number } | undefined)?.ttf,
              tts:  (raw["frm"] as { tts?: number } | undefined)?.tts,
            };
          }
        } catch { /* malformed — ignore */ }
      }

      // Apply browser SDK uid fallback now that browserFpF is parsed
      const userId = serverUserId || browserFpF?.uid || "";

      // Always emit HTTP access log entry for the Events dashboard.
      client.track(EventName.REQUEST, {
        ip, userId,
        meta: {
          method, endpoint: url, status, latencyMs: Math.round(latencyMs), userAgent: ua, bytes: 0,
          _fp:    fingerprint.score,
          _fpSig: fingerprint.signals.join(","),
          ...(fingerprint.knownClient ? { _fpClient: fingerprint.knownClient } : {}),
          ...(browserFpF ? {
            _bfp:   browserFpF.fp,
            _bbot:  browserFpF.bot,
            _bsigs: browserFpF.sigs,
            ...(browserFpF.pst !== undefined ? { _bpaste: browserFpF.pst } : {}),
            ...(browserFpF.ttf !== undefined && browserFpF.ttf >= 0 ? { _bttf: browserFpF.ttf } : {}),
            ...(browserFpF.tts !== undefined && browserFpF.tts >= 0 ? { _btts: browserFpF.tts } : {}),
          } : {}),
          ...(h2settings ? {
            _h2Window:  h2settings.initialWindowSize,
            _h2HdrTable: h2settings.headerTableSize,
            _h2Score:   h2settings.score,
            _h2Signals: h2settings.signals.join(","),
          } : {}),
          ...(upstreamTls.ja3 ? { _ja3: upstreamTls.ja3 } : {}),
          ...(upstreamTls.ja4 ? { _ja4: upstreamTls.ja4 } : {}),
          ...(agentInfo.isAgent ? {
            agentDetected:   true,
            agentType:       agentInfo.agentType,
            agentName:       agentInfo.agentName,
            agentConfidence: agentInfo.confidence,
            mcpSessionId:    agentInfo.sessionId,
            isMcp:           agentInfo.isMcp,
            agentSignals:    agentInfo.signals.join(","),
          } : {}),
        },
      });

      if (agentInfo.isAgent) {
        client.track("http.agent_detected", {
          ip, userId,
          meta: {
            endpoint:        url,
            method,
            agentType:       agentInfo.agentType,
            agentName:       agentInfo.agentName,
            agentConfidence: agentInfo.confidence,
            mcpSessionId:    agentInfo.sessionId,
            isMcp:           agentInfo.isMcp,
            agentSignals:    agentInfo.signals.join(","),
            status,
            userAgent:       ua,
          },
        });
      }

      if (client.config.detect.rateAbuse && status === 429) {
        client.track(EventName.RATE_LIMIT, { ip, userId, meta: { url, method, statusCode: status } });
      }

      if (client.config.detect.bruteForce && status === 401 && /\/(login|signin|auth|token)/i.test(url)) {
        client.track(EventName.LOGIN_FAILED, { ip, userId, meta: { url, method, statusCode: status } });
      }

      if (client.config.detect.scanDetection && status === 404) {
        if (!ua || /curl|wget|python|go-http|nuclei|sqlmap|nikto/i.test(ua)) {
          client.track(EventName.SCAN_DETECTED, { ip, userId, meta: { url, method, userAgent: ua } });
        }
      }

      if (client.config.detect.bruteForce && status === 200 && /\/(login|signin|auth|token)/i.test(url)) {
        if (userId) {
          void client.trackLogin({ ip, userId, meta: { url, method } });
        }
      }
    });
  };
}
