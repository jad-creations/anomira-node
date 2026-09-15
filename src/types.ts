// ─── SDK configuration ────────────────────────────────────────────────────────

export interface AnomiraConfig {
  /** SDK API key — get this from the Anomira dashboard */
  apiKey: string;

  /** Your app ID from the Anomira dashboard */
  appId: string;

  /**
   * Ingest endpoint URL.
   * @default "https://ingest.anomira.io/v1/events"
   */
  ingestUrl?: string;

  /**
   * Geo-lookup endpoint URL for client-side geo-velocity checks.
   * Should point to your Anomira ingest service geo endpoint.
   * If not provided, client-side geo-velocity is skipped (server-side still runs).
   * @example "https://ingest.anomira.io/v1/geo"
   */
  geoLookupUrl?: string;

  /**
   * Max events to buffer before forcing a flush.
   * @default 100
   */
  maxBatchSize?: number;

  /**
   * Max milliseconds to hold events before flushing.
   * @default 5000
   */
  flushIntervalMs?: number;

  /**
   * Max retry attempts on ingest failure.
   * @default 3
   */
  maxRetries?: number;

  /**
   * If true, log SDK activity to console (useful during integration).
   * @default false
   */
  debug?: boolean;

  /**
   * If true, automatically intercept console.log/info/warn/error/debug
   * and forward them to the Anomira Logs dashboard.
   * Existing console output is preserved — logs still print to your terminal.
   * @default false
   */
  captureConsole?: boolean;

  /**
   * Service name tag applied to all captured console logs.
   * @default "app"
   */
  service?: string;

  /**
   * Auto-detection features to enable in the middleware.
   * All default to true.
   */
  detect?: {
    /** Flag repeated login failures from the same IP as brute_force */
    bruteForce?: boolean;
    /** Flag 429 responses as rate_abuse */
    rateAbuse?: boolean;
    /** Flag path traversal patterns in the URL */
    pathTraversal?: boolean;
    /** Flag XSS patterns in request body */
    xss?: boolean;
    /** Flag suspicious scan patterns (many 404s) */
    scanDetection?: boolean;
    /** Detect impossible travel between login events */
    geoVelocity?: boolean;
    /** Detect SSRF payloads in request parameters (url, redirect, webhook, etc.) */
    ssrf?: boolean;
    /** Detect JWT header manipulation (alg:none, unknown algorithm, algorithm confusion, missing signature) */
    jwtManipulation?: boolean;
  };

  /**
   * Custom function to extract userId from the request.
   * Default: reads req.user?.id || req.user?.userId || req.user?.sub
   */
  getUserId?: (req: unknown) => string | undefined;

  /**
   * Custom function to extract the client IP from the request.
   * Default: reads X-Forwarded-For → X-Real-IP → socket.remoteAddress
   */
  getIp?: (req: unknown) => string;

  /**
   * Invisible security — automatic blocking from Anomira's community
   * threat intelligence network.
   *
   * When enabled (the default), the SDK periodically fetches high-confidence
   * attacker IPs from the Anomira network — IPs that have been seen attacking
   * multiple customers — and blocks them automatically, without any manual
   * decision required.
   *
   * This is the "invisible" part: your API is protected from known bad actors
   * the moment they appear in the network, before they even reach your handlers.
   *
   * Set `enabled: false` to disable auto-blocking and use threat data for
   * alerting only (the data is still fetched and logged).
   */
  autoBlock?: {
    /**
     * Whether to automatically block IPs from the community threat network.
     * @default true
     */
    enabled?: boolean;

    /**
     * Minimum community confidence score (0-100) to trigger an auto-block.
     * Only IPs above this threshold are blocked automatically.
     *
     * @default 85
     *
     * Guidance:
     *   85  (default) — confirmed malicious across multiple customers, very low false-positive risk
     *   70             — broader coverage, slightly higher false-positive risk
     *   95             — maximum precision, only the most confirmed threats
     *
     * Do not set below 60 — scores below that reflect limited data and carry
     * meaningful false-positive risk.
     */
    communityThreshold?: number;
  };
}

// ─── SDK event ────────────────────────────────────────────────────────────────

export interface SdkEvent {
  name: string;
  ts: number;
  ip: string;
  userId?: string;
  meta?: Record<string, unknown>;
}

// ─── Internal buffer event ────────────────────────────────────────────────────

export interface BufferedEvent extends SdkEvent {
  _retries: number;
}

// ─── Ingest request body ─────────────────────────────────────────────────────

export interface IngestPayload {
  appId: string;
  events: SdkEvent[];
}

// ─── Well-known event names ───────────────────────────────────────────────────

export const EventName = {
  // Auth
  LOGIN_SUCCESS: "auth.login.success",
  LOGIN_FAILED: "auth.login.failed",
  LOGOUT: "auth.logout",
  OTP_FAILED: "auth.otp.failed",
  OTP_SUCCESS: "auth.otp.success",
  BVN_LOOKUP: "auth.bvn.lookup",
  NIN_LOOKUP: "auth.nin.lookup", // NIN enumeration detection
  GEO_VELOCITY: "auth.login.geo_velocity",
  CREDENTIAL_STUFF: "auth.credential.stuffing",
  SIM_SWAP: "auth.sim_swap.suspected", // SIM swap fraud signal
  PHONE_AUTH: "auth.phone.verified", // Phone-based auth (OTP/2FA via phone)

  // HTTP layer (auto-detected by middleware)
  REQUEST: "http.request", // every request — feeds the Events dashboard
  RATE_LIMIT: "http.ratelimit.exceeded",
  XSS_DETECTED: "http.xss.detected",
  PATH_TRAVERSAL: "http.path.traversal",
  SSRF_ATTEMPT: "http.ssrf.attempt",
  JWT_MANIPULATION: "http.jwt.manipulation",
  SCAN_DETECTED: "http.scan.detected",
  IDOR_ATTEMPT: "user.idor.attempt",
  SQL_ERROR: "db.sql.error",

  // Firewall (emitted when a custom request filtering rule fires)
  FIREWALL_BLOCK: "http.firewall.block",
  FIREWALL_FLAG: "http.firewall.flag",
  FIREWALL_RATE_LIMIT: "http.firewall.rate_limit",
  FIREWALL_REDIRECT_HONEYPOT: "http.firewall.redirect_honeypot",
  FIREWALL_TAG: "http.firewall.tag",
  FIREWALL_MONITOR: "http.firewall.monitor",
  FIREWALL_CHALLENGE: "http.firewall.challenge",
  FIREWALL_TEMP_BLOCK: "http.firewall.temporary_block",
} as const;

export type EventNameValue = (typeof EventName)[keyof typeof EventName];

// ─── Firewall rule (synced from ingest, cached in SDK) ────────────────────────

export type FirewallField = "url" | "body" | "header" | "user_agent" | "ip";
export type FirewallOperator = "contains" | "equals" | "starts_with" | "ends_with" | "regex";
export type FirewallAction =
  | "block"
  | "flag"
  | "rate_limit"
  | "challenge"
  | "redirect_honeypot"
  | "tag"
  | "monitor"
  | "temporary_block";

// ─── Declared endpoint ────────────────────────────────────────────────────────

export interface EndpointDeclaration {
  /** HTTP method, e.g. "GET".  Use "*" to match any method. */
  method: string;
  /** Express-style path, e.g. "/api/users/:id" — colons are normalized automatically. */
  path: string;
  /** Whether this endpoint requires authentication.  Defaults to true. */
  auth?: boolean;
}

// ─── Firewall rule ────────────────────────────────────────────────────────────

export interface FirewallRule {
  id: string;
  field: FirewallField;
  headerName?: string | null;
  operator: FirewallOperator;
  value: string;
  action: FirewallAction;
  attackType: string;
  redirectTarget?: string | null;
  tempBlockMins?: number | null;
}
