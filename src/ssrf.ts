/**
 * SSRF (Server-Side Request Forgery) detection
 * ─────────────────────────────────────────────
 * Scans incoming request parameters and body fields for URL-shaped values
 * that point to private/internal IP ranges, cloud metadata endpoints, or
 * dangerous non-HTTP schemes.
 *
 * Detection approach (research-informed):
 *   1. Only inspect fields whose NAMES suggest they accept URLs — reduces
 *      false positives dramatically. A field named "message" containing
 *      a URL is not an SSRF attempt; a field named "imageUrl" is suspicious.
 *
 *   2. Normalize obfuscated IP representations before checking:
 *      - Decimal: 2852039166  → 169.254.169.254
 *      - Hex:     0xa9fea9fe  → 169.254.169.254
 *      - Octal:   0251.0376... → 169.254.169.254
 *      - IPv6-mapped: ::ffff:a9fe:a9fe → 169.254.169.254
 *      This catches the most common WAF bypass techniques.
 *
 *   3. Cover all cloud metadata IPs — not just AWS:
 *      AWS:     169.254.169.254
 *      AWS ECS: 169.254.170.2
 *      GCP:     169.254.169.254 (same as AWS)
 *      Azure:   168.63.129.16
 *      Alibaba: 100.100.100.200
 *      Oracle:  192.0.0.192
 *
 *   4. Cover dangerous non-HTTP schemes: file://, gopher://, dict://,
 *      ftp://, sftp://, ldap://, netdoc://, jar://
 *
 * Sources:
 *   - https://highon.coffee/blog/ssrf-cheat-sheet/
 *   - https://medium.com/@cybersecplayground/ssrf-payloads-ipfuscation-guide-46e7ee9b2272
 *   - https://www.appsecure.security/blog/ssrf-cloud-environments
 */

// ─── Parameter names that typically accept URL inputs ────────────────────────
// Only fields with these names are scanned. This is intentional — broad body
// scanning creates too many false positives (e.g., a "description" field that
// happens to contain a URL is not an SSRF attempt).

const URL_PARAM_PATTERN =
  /^(url|uri|path|link|next|target|src|href|redirect|redirecturl|returnurl|successurl|callback|fetch|image|imageurl|avatar|photo|webhook|endpoint|to|host|domain|site|page|file|load|open|download|import|include|embed|source|proxy|destination|dest|resource|location|goto|return|referer|origin|remote|ping|pull)$/i;

// ─── Dangerous non-HTTP schemes ───────────────────────────────────────────────

const DANGEROUS_SCHEMES = new Set([
  "file",
  "gopher",
  "dict",
  "ftp",
  "sftp",
  "ldap",
  "ldaps",
  "netdoc",
  "jar",
  "mailto",
  "telnet",
  "tftp",
  "finger",
]);

// ─── IP normalization ─────────────────────────────────────────────────────────

/** Convert a 32-bit integer to dotted-decimal IP string. */
function intToIp(n: number): string {
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff].join(".");
}

/** Parse a single IP octet — supports decimal, hex (0x..), octal (0..) */
function parseOctet(s: string): number | null {
  s = s.trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return parseInt(s, 16);
  if (/^0[0-9]+$/.test(s)) return parseInt(s, 8); // leading zero = octal
  if (/^[0-9]+$/.test(s)) return parseInt(s, 10);
  return null;
}

/**
 * Normalize an IP hostname to standard dotted-decimal form.
 * Returns null if the hostname is not a parseable IP address.
 * Returns the normalized IP if it is.
 *
 * Handles:
 *   - Standard dotted decimal:   192.168.1.1
 *   - Hex integer:               0xc0a80101
 *   - Decimal integer:           3232235777
 *   - Octal dotted:              0300.0250.01.01
 *   - Mixed formats:             0xc0.168.0x01.1
 *   - IPv6 mapped:               ::ffff:c0a8:0101
 */
function normalizeIp(hostname: string): string | null {
  const h = hostname.trim().toLowerCase();

  // IPv6 mapped to IPv4: ::ffff:xxxx:xxxx or ::ffff:a.b.c.d
  const v6mapped =
    h.match(/^(?:::ffff:)([0-9a-f]{1,4}:[0-9a-f]{1,4})$/i) ??
    h.match(/^(?:0{0,4}:){5}ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (v6mapped?.[1]) {
    // ::ffff:a9fe:a9fe style — two hex groups
    const parts = v6mapped[1].split(":");
    if (parts.length === 2) {
      const hi = parseInt(parts[0]!, 16);
      const lo = parseInt(parts[1]!, 16);
      if (!isNaN(hi) && !isNaN(lo)) return intToIp((hi << 16) | lo);
    }
    // ::ffff:169.254.169.254 style — pass through to dotted parser below
    return normalizeIp(v6mapped[1]!);
  }

  // Pure IPv6 loopback
  if (h === "::1" || h === "0:0:0:0:0:0:0:1") return "127.0.0.1";

  // 32-bit hex integer: 0xa9fea9fe
  if (/^0x[0-9a-f]+$/i.test(h)) {
    const n = parseInt(h, 16);
    if (!isNaN(n) && n >= 0 && n <= 0xffffffff) return intToIp(n);
  }

  // 32-bit decimal integer: 2852039166
  if (/^\d+$/.test(h)) {
    const n = parseInt(h, 10);
    if (!isNaN(n) && n >= 0 && n <= 4294967295) return intToIp(n);
  }

  // Dotted notation (supports hex/octal/decimal per octet)
  const parts = h.split(".");
  if (parts.length >= 1 && parts.length <= 4) {
    const octets: number[] = [];
    for (const p of parts) {
      const v = parseOctet(p);
      if (v === null || v < 0 || v > 255) break;
      octets.push(v);
    }
    // Standard 4-octet
    if (octets.length === 4) return octets.join(".");
    // Short form: 127.1 → 127.0.0.1 (rare but valid)
    if (octets.length === 2) return `${octets[0]}.0.0.${octets[1]}`;
  }

  return null; // not a parseable IP — treat as hostname
}

// ─── Private IP range checker ─────────────────────────────────────────────────

/** Convert dotted IP to 32-bit integer for range comparisons. */
function ipToInt(ip: string): number {
  const parts = ip.split(".").map(Number);
  return ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0;
}

interface IpRange {
  start: number;
  end: number;
  label: string;
}

const PRIVATE_RANGES: IpRange[] = [
  { start: ipToInt("0.0.0.0"), end: ipToInt("0.255.255.255"), label: "unspecified" },
  { start: ipToInt("10.0.0.0"), end: ipToInt("10.255.255.255"), label: "private-10" },
  { start: ipToInt("100.64.0.0"), end: ipToInt("100.127.255.255"), label: "carrier-nat" },
  { start: ipToInt("127.0.0.0"), end: ipToInt("127.255.255.255"), label: "loopback" },
  { start: ipToInt("169.254.0.0"), end: ipToInt("169.254.255.255"), label: "link-local" }, // AWS/GCP metadata lives here
  { start: ipToInt("172.16.0.0"), end: ipToInt("172.31.255.255"), label: "private-172" },
  { start: ipToInt("192.0.0.0"), end: ipToInt("192.0.0.255"), label: "iana-special" }, // Oracle Cloud metadata
  { start: ipToInt("192.168.0.0"), end: ipToInt("192.168.255.255"), label: "private-192" },
  { start: ipToInt("198.18.0.0"), end: ipToInt("198.19.255.255"), label: "benchmark" },
  { start: ipToInt("240.0.0.0"), end: ipToInt("255.255.255.255"), label: "reserved" },
  // Specific cloud metadata endpoints not covered by ranges above
  { start: ipToInt("100.100.100.200"), end: ipToInt("100.100.100.200"), label: "alibaba-metadata" },
  { start: ipToInt("168.63.129.16"), end: ipToInt("168.63.129.16"), label: "azure-metadata" },
];

function isPrivateIp(ip: string): { private: boolean; label: string } {
  const n = ipToInt(ip);
  for (const range of PRIVATE_RANGES) {
    if (n >= range.start && n <= range.end) return { private: true, label: range.label };
  }
  return { private: false, label: "" };
}

// ─── Hostname aliases that always mean internal ───────────────────────────────

const INTERNAL_HOSTNAMES = new Set([
  "localhost",
  "local",
  "localdomain",
  "metadata",
  "metadata.google.internal",
  "169.254.169.254", // canonical — also caught by range check
  "instance-data", // AWS internal alias
]);

// ─── Main scanner ─────────────────────────────────────────────────────────────

export interface SsrfSignal {
  detected: boolean;
  payload: string; // the suspicious URL found
  field: string; // which parameter name triggered it
  reason: string; // "private-ip:loopback", "dangerous-scheme:gopher", etc.
}

function checkUrl(rawUrl: string, fieldName: string): SsrfSignal | null {
  // Must look like a URL (has :// or starts with //)
  if (!rawUrl.includes("://") && !rawUrl.startsWith("//")) return null;

  let parsed: URL;
  try {
    // Normalize: add scheme if missing
    const withScheme = rawUrl.startsWith("//") ? `https:${rawUrl}` : rawUrl;
    parsed = new URL(withScheme);
  } catch {
    return null; // unparseable — not a URL
  }

  const scheme = parsed.protocol.replace(":", "").toLowerCase();
  const hostname = parsed.hostname.toLowerCase().replace(/\[|\]/g, ""); // strip IPv6 brackets

  // 1. Dangerous scheme check
  if (DANGEROUS_SCHEMES.has(scheme)) {
    return {
      detected: true,
      payload: rawUrl,
      field: fieldName,
      reason: `dangerous-scheme:${scheme}`,
    };
  }

  // 2. Only proceed for http/https from here
  if (scheme !== "http" && scheme !== "https") return null;

  // 3. Known internal hostname aliases
  if (INTERNAL_HOSTNAMES.has(hostname)) {
    return {
      detected: true,
      payload: rawUrl,
      field: fieldName,
      reason: `internal-hostname:${hostname}`,
    };
  }

  // 4. Normalize IP (handles hex, octal, decimal, IPv6-mapped)
  const normalized = normalizeIp(hostname);
  if (normalized) {
    const { private: isPrivate, label } = isPrivateIp(normalized);
    if (isPrivate) {
      return { detected: true, payload: rawUrl, field: fieldName, reason: `private-ip:${label}` };
    }
  }

  return null;
}

/**
 * Scan request body and query parameters for SSRF payloads.
 * Returns the first suspicious signal found, or null if clean.
 */
export function scanForSsrf(
  body: unknown,
  query: Record<string, string | string[] | undefined>,
): SsrfSignal | null {
  const candidates: { name: string; value: string }[] = [];

  // Collect from query string
  for (const [key, val] of Object.entries(query)) {
    if (!URL_PARAM_PATTERN.test(key)) continue;
    const v = Array.isArray(val) ? val[0] : val;
    if (typeof v === "string" && v.length > 0) candidates.push({ name: key, value: v });
  }

  // Collect from body (flat keys + one level of nesting)
  if (body && typeof body === "object" && !Array.isArray(body)) {
    const flat = body as Record<string, unknown>;
    for (const [key, val] of Object.entries(flat)) {
      if (URL_PARAM_PATTERN.test(key) && typeof val === "string" && val.length > 0) {
        candidates.push({ name: key, value: val });
      }
      if (val && typeof val === "object" && !Array.isArray(val)) {
        for (const [nk, nv] of Object.entries(val as Record<string, unknown>)) {
          if (URL_PARAM_PATTERN.test(nk) && typeof nv === "string" && nv.length > 0) {
            candidates.push({ name: `${key}.${nk}`, value: nv });
          }
        }
      }
    }
  }

  for (const { name, value } of candidates) {
    const signal = checkUrl(value, name);
    if (signal) return signal;
  }

  return null;
}
