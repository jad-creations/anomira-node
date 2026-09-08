/**
 * Behavioral Browser Fingerprinting
 *
 * Computes a 0-100 automation score from HTTP request headers.
 * Higher score = more likely to be a programmatic client (script, agent, bot).
 *
 * Three tiers of signals, all from confirmed primary sources:
 *
 *  Tier 1 — Definitive: User-Agent strings that are unambiguously automated.
 *    Sources: python-requests source (psf/requests utils.py), httpx test suite
 *    (encode/httpx tests/client/test_headers.py), undici issue #1305,
 *    curl documentation (everything.curl.dev), aiohttp docs, Go stdlib.
 *
 *  Tier 2 — Strong: Absence of browser-only headers.
 *    Sources: W3C Fetch Metadata spec (w3.org/TR/fetch-metadata/),
 *    MDN Sec-Fetch-Mode, undici issue #1305, SearXNG bot detection source.
 *
 *  Tier 3 — Corroborating: Incoherent header combinations.
 *    Source: undici issue #1305 (sends Sec-Fetch-Mode without Sec-Fetch-Site),
 *    MDN Sec-CH-UA (Chromium only — Firefox/Safari do not send it).
 */

export interface FingerprintResult {
  /** 0-100. ≥55 = likely automated. 100 = definitive known bot UA. */
  score:         number;
  /** Human-readable signals that contributed to the score. */
  signals:       string[];
  /** True when the User-Agent matches a confirmed automated client string. */
  isDefiniteBot: boolean;
  /** The specific known client name when isDefiniteBot is true, e.g. "python-requests". */
  knownClient:   string | null;
}

/**
 * HTTP/2 SETTINGS values extracted from the client's connection preface.
 * Populated only when the customer's Node.js app handles HTTP/2 directly
 * (no reverse proxy in between for TLS termination).
 *
 * Source for expected values:
 *   - Chrome 119+: initialWindowSize=6,291,456 (6 MB), headerTableSize=65,536
 *   - python-requests / httpx / curl: initialWindowSize=65,535 (HTTP/2 default)
 *   Reference: Akamai Black Hat EU 2017 whitepaper; scrapfly.io HTTP/2 guide
 */
export interface Http2SettingsResult {
  /** INITIAL_WINDOW_SIZE from client SETTINGS frame (bytes). */
  initialWindowSize: number;
  /** HEADER_TABLE_SIZE from client SETTINGS frame. */
  headerTableSize:   number;
  /** ENABLE_PUSH from client SETTINGS frame. */
  enablePush:        boolean;
  /**
   * Automation score contribution (0-20) derived from SETTINGS values.
   * Chrome/modern browsers use ~6 MB window; all Python/curl clients use ~65 KB.
   */
  score:    number;
  signals:  string[];
}

/**
 * JA3 or JA4 hash passed by an upstream proxy (customer's Nginx with the
 * ngx_ssl_fingerprint module, or a Cloudflare JA3 Worker).
 * The ingest includes this in event meta for dashboard display and future
 * mismatch-based scoring when a lookup database is available.
 */
export interface UpstreamTlsResult {
  ja3:  string | null;  // X-JA3-Hash header (HanadaLee / phuslu modules)
  ja4:  string | null;  // X-JA4 header
}

// ─── Tier 1: Confirmed known-automated User-Agent prefixes/patterns ────────────
//
// Each entry is [regex, display_name].
// Only patterns confirmed from primary sources (source code, official docs).
// Do NOT add speculative patterns.
const KNOWN_BOT_UA: [RegExp, string][] = [
  // Confirmed: psf/requests utils.py (default_headers)
  [/^python-requests\//i,          "python-requests"],
  // Confirmed: encode/httpx tests/client/test_headers.py
  [/^python-httpx\//i,             "python-httpx"],
  // Confirmed: aiohttp docs (format: "Python/3.x aiohttp/3.x.x")
  [/\baiohttp\//i,                 "aiohttp"],
  // Confirmed: nodejs/undici issue #1305
  [/^undici$/i,                    "undici"],
  // Confirmed: everything.curl.dev
  [/^curl\//i,                     "curl"],
  // Confirmed: GNU wget docs
  [/^Wget\//i,                     "wget"],
  // Confirmed: Go net/http DefaultClient (golang.org/pkg/net/http)
  [/^Go-http-client\//i,           "Go-http-client"],
  // Confirmed: Java HttpURLConnection default
  [/^Java\//i,                     "Java"],
  // Confirmed: Scrapy docs (scrapy.org)
  [/^Scrapy\//i,                   "Scrapy"],
  // Confirmed: OkHttp (square.github.io/okhttp)
  [/\bokhttp\//i,                  "okhttp"],
  // Confirmed: libwww-perl (metacpan.org/pod/LWP)
  [/^libwww-perl\//i,              "libwww-perl"],
  // Confirmed: node-fetch (github.com/node-fetch/node-fetch README)
  [/^node-fetch\//i,               "node-fetch"],
  // Confirmed: axios docs (axios-http.com/docs/config_defaults)
  [/^axios\//i,                    "axios"],
  // Confirmed: Ruby net/http default (ruby-doc.org)
  [/^Ruby$/i,                      "Ruby"],
];

// ─── Tier 1: axios-specific Accept header ─────────────────────────────────────
//
// Confirmed from axios documentation: axios sets
// `Accept: application/json, text/plain, */*` by default.
// NOTE: this is also sent by axios running as a frontend library inside a real
// browser (React, Vue, Angular apps). It is only a definitive bot signal when
// combined with a non-browser User-Agent. With a browser UA, treat it as a
// corroborating signal (score 15) rather than a definitive match.
const AXIOS_ACCEPT = "application/json, text/plain, */*";

// Returns true when the UA is clearly a real browser running on the user's OS.
// Presence of "Mozilla/5.0" combined with a known browser engine name is the
// standard browser UA format. Non-browser clients (server-side axios, curl, etc.)
// either have their own UA or send no UA at all.
function isBrowserUa(ua: string): boolean {
  return (
    /Mozilla\/5\.0/.test(ua) &&
    /(?:Chrome|Firefox|Safari|OPR|Edg(?:e|HTML)?|Trident)\/[\d.]+/.test(ua)
  );
}

// ─── Detection function ────────────────────────────────────────────────────────

/**
 * Compute a browser fingerprint score from a Node.js request's headers.
 *
 * @param headers  Node.js normalises incoming headers to lowercase — pass
 *                 `req.headers` directly.
 * @param ua       The User-Agent string (extracted separately for clarity).
 */
export function computeBrowserFingerprint(
  headers: Record<string, string | string[] | undefined>,
  ua: string,
): FingerprintResult {
  const signals:       string[] = [];
  let   score                   = 0;
  let   isDefiniteBot           = false;
  let   knownClient: string | null = null;

  // ── Tier 1a: Known automated User-Agent ──────────────────────────────────────
  for (const [pattern, name] of KNOWN_BOT_UA) {
    if (pattern.test(ua)) {
      isDefiniteBot = true;
      knownClient   = name;
      score         = 100;
      signals.push(`known_ua:${name}`);
      break;
    }
  }

  // ── Tier 1b: axios Accept header ─────────────────────────────────────────────
  // Definitive ONLY when the UA is not a real browser. If it is a browser UA,
  // this just means the web app uses axios as its frontend HTTP client — that
  // is completely normal (React/Vue/Angular apps all do this). Score it weakly.
  const accept = str(headers["accept"]);
  if (!isDefiniteBot && accept === AXIOS_ACCEPT) {
    if (!isBrowserUa(ua)) {
      isDefiniteBot = true;
      knownClient   = "axios";
      score         = 100;
      signals.push("known_accept:axios");
    } else {
      score += 15;
      signals.push("browser_axios_accept");
    }
  }

  // If already definitive, no need to score further
  if (isDefiniteBot) return { score, signals, isDefiniteBot, knownClient };

  // ── Tier 2: Absence of browser-mandatory headers ──────────────────────────────
  //
  // Sec-Fetch-Site and Sec-Fetch-Mode are sent on EVERY fetch()/XHR call by
  // Chrome (Chromium), Firefox (since 2023), and most modern browsers.
  // They are W3C "forbidden" headers — JavaScript cannot set or modify them.
  // Absence = 100% certainty the caller is not a standard browser fetch call.
  // Source: https://www.w3.org/TR/fetch-metadata/
  const hasSecFetchSite = "sec-fetch-site"  in headers;
  const hasSecFetchMode = "sec-fetch-mode"  in headers;

  if (!hasSecFetchSite && !hasSecFetchMode) {
    score   += 30;
    signals.push("missing_sec_fetch");
  }

  // Accept-Language: all browsers send this. python-requests, httpx, curl,
  // aiohttp, and Node.js undici do NOT send it by default.
  // Source: SearXNG bot detection; confirmed by examining default headers of
  // each library above.
  // Exception: undici sends `accept-language: *` — we handle that separately.
  const acceptLang = str(headers["accept-language"]);
  if (!acceptLang) {
    score   += 25;
    signals.push("missing_accept_language");
  }

  // Accept-Encoding: curl sends NO Accept-Encoding by default (unlike all others).
  // Its absence alone is a strong curl signal. Not a general "bot" signal,
  // but useful combined with other indicators.
  const acceptEnc = str(headers["accept-encoding"]);
  if (!acceptEnc) {
    score   += 10;
    signals.push("missing_accept_encoding");
  }

  // ── Tier 3: Incoherent header combinations ────────────────────────────────────
  //
  // Node.js undici (built-in fetch) sends `sec-fetch-mode: cors` but does NOT
  // send `sec-fetch-site` or `sec-fetch-dest`. Real browsers always send all
  // three together. This pattern is unique to undici.
  // Source: nodejs/undici GitHub issue #1305
  if (hasSecFetchMode && !hasSecFetchSite) {
    score   += 20;
    signals.push("undici_pattern:sec_fetch_mode_without_site");
    knownClient = "undici (Node.js fetch)";
  }

  // undici also sends `accept-language: *` (a bare wildcard) — not a valid
  // BCP 47 language tag, which browsers always send (e.g. "en-US,en;q=0.9").
  // Source: nodejs/undici issue #1305
  if (acceptLang === "*") {
    score   += 15;
    signals.push("undici_pattern:accept_language_wildcard");
  }

  // Sec-CH-UA is sent by Chromium browsers on ALL requests (including fetch())
  // without any server opt-in. If the UA claims to be Chrome but Sec-CH-UA
  // is absent, the Chrome UA is likely spoofed (or it's Firefox/Safari, which
  // never send Sec-CH-UA). Source: MDN Sec-CH-UA; Corbado blog.
  const claimsChrome  = /Chrome\//i.test(ua) && !/Chromium/i.test(ua);
  const hasSecChUa    = "sec-ch-ua" in headers;
  if (claimsChrome && !hasSecChUa) {
    score   += 10;
    signals.push("chrome_ua_without_sec_ch_ua");
  }

  // Cap at 100
  score = Math.min(100, score);

  return { score, signals, isDefiniteBot, knownClient };
}

// ─── HTTP/2 SETTINGS extraction ───────────────────────────────────────────────

/**
 * Extract HTTP/2 SETTINGS from the Node.js `http2.Http2Session` that handled
 * this request, if available. Works only when the customer's Node.js app is
 * the TLS endpoint (no reverse proxy terminating TLS before Node.js).
 *
 * The function is safe to call on any request — it returns null for HTTP/1.1
 * connections or when the session is not accessible.
 *
 * @param req  The raw Node.js IncomingMessage (Express: `req`, Fastify: `req.raw`)
 *
 * Reference values (Akamai Black Hat EU 2017 + scrapfly.io HTTP/2 guide):
 *   Chrome 119+ : initialWindowSize = 6,291,456 | headerTableSize = 65,536
 *   Firefox     : initialWindowSize = 65,535     | headerTableSize = 65,536
 *   python libs : initialWindowSize = 65,535     | headerTableSize = 4,096
 *   curl        : initialWindowSize = 65,535     | headerTableSize = 4,096
 */
export function extractHttp2Settings(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  req: Record<string, any>,
): Http2SettingsResult | null {
  // Access the http2.ServerHttp2Stream → http2.Http2Session → remoteSettings.
  // Express: req.stream (available when using http2.createServer)
  // Fastify: req.raw.stream (same path via req.raw which is the Node.js request)
  const stream = req["stream"] ?? req["raw"]?.["stream"];
  if (!stream) return null;

  const session = stream["session"];
  if (!session) return null;

  // remoteSettings is the Http2Settings object sent by the CLIENT in its
  // SETTINGS frame during the HTTP/2 connection preface.
  // Node.js docs: https://nodejs.org/api/http2.html#http2sessionremotesettings
  const remote = session["remoteSettings"] as {
    headerTableSize?:   number;
    enablePush?:        boolean;
    initialWindowSize?: number;
  } | undefined;

  if (!remote) return null;

  const initialWindowSize = remote.initialWindowSize ?? 65535;
  const headerTableSize   = remote.headerTableSize   ?? 4096;
  const enablePush        = remote.enablePush        ?? true;

  const signals: string[] = [];
  let   score              = 0;

  // The most discriminating signal: Chrome uses ~6 MB (6,291,456) while ALL
  // Python/curl HTTP/2 clients use the protocol default of 65,535 bytes.
  // Threshold of 131,072 (128 KB) gives a 50× margin above the default —
  // no realistic browser sends a value this low.
  // Source: Akamai Passive Fingerprinting of HTTP/2 Clients (Black Hat EU 2017)
  if (initialWindowSize <= 131_072) {
    score += 20;
    signals.push(`h2_window_${initialWindowSize}`);
  }

  // Chrome also uses a much larger HEADER_TABLE_SIZE (65,536 vs default 4,096).
  // Python libs leave this at the default.
  if (headerTableSize <= 4096 && initialWindowSize <= 131_072) {
    score += 5;
    signals.push("h2_header_table_default");
  }

  return { initialWindowSize, headerTableSize, enablePush, score, signals };
}

// ─── Upstream TLS fingerprint headers ─────────────────────────────────────────

/**
 * Read JA3/JA4 hashes injected by an upstream proxy that has TLS fingerprinting
 * enabled. Supports:
 *   - HanadaLee/ngx_ssl_fingerprint_module  → X-JA3-Hash, X-JA4
 *   - phuslu/nginx-ssl-fingerprint           → X-JA3-Hash, X-JA4
 *   - Custom Nginx configs                   → X-JA3, X-JA4 (alternate names)
 *
 * These values are included in event meta as `_ja3` / `_ja4` for:
 *   a) Display in the AI Agent Sessions dashboard
 *   b) Future mismatch-based scoring (UA claims Chrome but JA3 is python-requests)
 *
 * @param headers  Node.js lowercase-normalised header map
 */
export function extractUpstreamTls(
  headers: Record<string, string | string[] | undefined>,
): UpstreamTlsResult {
  // Try both common header name conventions
  const ja3 = str(headers["x-ja3-hash"]) || str(headers["x-ja3"]) || null;
  const ja4 = str(headers["x-ja4"])      || null;
  return { ja3: ja3 || null, ja4: ja4 || null };
}

// ─── Helper ────────────────────────────────────────────────────────────────────

function str(v: string | string[] | undefined): string {
  if (v === undefined) return "";
  return Array.isArray(v) ? (v[0] ?? "") : v;
}
