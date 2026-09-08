/**
 * JWT Header Manipulation Detection
 * ───────────────────────────────────
 * Detects the full class of JWT header tampering attacks, not just the classic
 * alg:none. Covers active CVEs in 2026 (Hono CVSS 8.2, HarbourJwt, CVE-2026-22817).
 *
 * All detections work by decoding the JWT header — which is unencrypted
 * base64url JSON — and inspecting the `alg` field before the token ever
 * reaches the application's verification logic.
 *
 * Attack classes detected:
 *
 * 1. alg:none — The server is told to skip signature verification entirely.
 *    Handled by modern libraries but still appears in legacy code, custom
 *    implementations, and newly-discovered library bugs.
 *
 * 2. Unknown/non-standard algorithm — Attacker supplies a made-up alg value
 *    ("zzz", "CUSTOM", empty string). Some libraries accept it and fall through
 *    to unsafe paths (CVE-2026-23993 pattern — HarbourJWT unknown alg bypass).
 *
 * 3. Algorithm confusion (RS256 → HS256) — The most dangerous active attack
 *    class. Server uses RS256 (asymmetric — public key available). Attacker
 *    changes header to HS256 (symmetric — uses public key as HMAC secret).
 *    Vulnerable library: reads alg from token, uses public key as secret,
 *    signature validates. Two active CVEs in January 2026 (Hono, HarbourJwt).
 *    Detection: flag the HS256 family when the token signature segment is
 *    unusually long (RSA public keys are 256+ bytes; normal HMAC sigs are 32-64).
 *
 * 4. Missing or empty signature — Token has fewer than 3 segments, or the
 *    third segment is empty. Indicates stripped signature (alg:none variant).
 *
 * Sources:
 *   - https://tools.pinusx.com/blog/jwt-algorithm-confusion-attack-cves-2026
 *   - https://pentesterlab.com/blog/cve-2026-23993-harbourjwt-unknown-alg-jwt-bypass
 *   - https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
 *   - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens
 */

// ─── Standard algorithms from RFC 7518 + RFC 8037 ────────────────────────────
// Any alg value outside this set is treated as suspicious.

const STANDARD_ALGORITHMS = new Set([
  // HMAC (symmetric)
  "HS256", "HS384", "HS512",
  // RSA PKCS#1 (asymmetric)
  "RS256", "RS384", "RS512",
  // ECDSA (asymmetric)
  "ES256", "ES384", "ES512",
  // RSA-PSS (asymmetric)
  "PS256", "PS384", "PS512",
  // Edwards-curve (RFC 8037)
  "EdDSA",
]);

// HMAC algorithms — symmetric, short signatures expected.
// When the signature segment is suspiciously long (>128 chars base64), it likely
// means an RSA public key was used as the HMAC secret (algorithm confusion attack).
const HMAC_ALGORITHMS = new Set(["HS256", "HS384", "HS512"]);

// Longest legitimate HMAC signature in base64url:
// HS512 produces 64 bytes → 86 base64url chars.
// RSA-2048 produces 256 bytes → 342 base64url chars.
// Threshold: anything over 128 chars with an HMAC algorithm is suspicious.
const MAX_HMAC_SIG_LENGTH = 128;

// ─── Base64url decoder (no external deps) ────────────────────────────────────

function decodeBase64Url(s: string): string {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad    = (4 - padded.length % 4) % 4;
  return Buffer.from(padded + "=".repeat(pad), "base64").toString("utf8");
}

// ─── Detection result ─────────────────────────────────────────────────────────

export type JwtAttackType =
  | "alg_none"           // alg field is "none" (case-insensitive)
  | "unknown_algorithm"  // alg value not in standard RFC 7518 set
  | "algorithm_confusion"// HS256 family with RSA-length signature (RS256→HS256 attack)
  | "missing_signature"; // fewer than 3 segments or empty third segment

export interface JwtDetectionResult {
  detected:  boolean;
  attack:    JwtAttackType | null;
  alg:       string | null;    // what the attacker claimed
  detail:    string;
}

// ─── Main detector ────────────────────────────────────────────────────────────

/**
 * Analyse a single JWT string for header manipulation attacks.
 * Returns a detection result — never throws.
 */
export function analyseJwt(token: string): JwtDetectionResult {
  const clean = token.trim();

  // ── Check 1: Segment count ─────────────────────────────────────────────────
  const parts = clean.split(".");

  if (parts.length < 3 || parts[2] === "") {
    return {
      detected: true,
      attack:   "missing_signature",
      alg:      null,
      detail:   `JWT has ${parts.length} segment(s) — signature is missing or empty.`,
    };
  }

  // ── Decode header ──────────────────────────────────────────────────────────
  let header: Record<string, unknown>;
  try {
    header = JSON.parse(decodeBase64Url(parts[0]!)) as Record<string, unknown>;
  } catch {
    return { detected: false, attack: null, alg: null, detail: "" };
  }

  const alg = typeof header["alg"] === "string" ? header["alg"] : null;

  if (!alg) {
    // Missing alg field — suspicious but ambiguous; skip
    return { detected: false, attack: null, alg: null, detail: "" };
  }

  // ── Check 2: alg:none (all case variants) ──────────────────────────────────
  // "none", "None", "NONE", "nOnE" — all indicate "skip signature verification"
  if (alg.toLowerCase() === "none") {
    return {
      detected: true,
      attack:   "alg_none",
      alg,
      detail:   `JWT header specifies alg="${alg}" — server told to skip signature verification.`,
    };
  }

  // ── Check 3: Non-standard algorithm ───────────────────────────────────────
  // Any alg value not in RFC 7518/8037 is suspicious. Libraries that accept
  // unknown values and fall through to unsafe code paths are the CVE-2026-23993
  // (HarbourJWT) pattern.
  if (!STANDARD_ALGORITHMS.has(alg)) {
    return {
      detected: true,
      attack:   "unknown_algorithm",
      alg,
      detail:   `JWT header specifies non-standard alg="${alg}" — not in RFC 7518 algorithm set.`,
    };
  }

  // ── Check 4: Algorithm confusion (RS256 → HS256) ──────────────────────────
  // In this attack the token claims a symmetric (HMAC) algorithm but is signed
  // with the server's RSA public key. The giveaway: the signature segment is
  // much longer than any legitimate HMAC output.
  if (HMAC_ALGORITHMS.has(alg) && parts[2]!.length > MAX_HMAC_SIG_LENGTH) {
    return {
      detected: true,
      attack:   "algorithm_confusion",
      alg,
      detail:   `JWT claims ${alg} (HMAC) but signature is ${parts[2]!.length} chars — characteristic of RSA key used as HMAC secret (algorithm confusion attack).`,
    };
  }

  return { detected: false, attack: null, alg, detail: "" };
}

/**
 * Extract and analyse all JWTs from an incoming request.
 * Checks the Authorization: Bearer header and common body/query fields.
 * Returns the first suspicious token found, or null if all look clean.
 */
export function scanRequestForJwtAttacks(
  headers: Record<string, string | string[] | undefined>,
  body:    unknown,
  query:   Record<string, string | string[] | undefined>,
): JwtDetectionResult | null {
  const candidates: string[] = [];

  // 1. Authorization: Bearer <token>
  const auth = headers["authorization"];
  const authStr = Array.isArray(auth) ? auth[0] : auth;
  if (typeof authStr === "string" && authStr.toLowerCase().startsWith("bearer ")) {
    candidates.push(authStr.slice(7).trim());
  }

  // 2. Common token body fields
  const TOKEN_FIELDS = new Set(["token", "jwt", "access_token", "accessToken", "id_token", "idToken", "refresh_token", "refreshToken"]);
  if (body && typeof body === "object" && !Array.isArray(body)) {
    for (const [key, val] of Object.entries(body as Record<string, unknown>)) {
      if (TOKEN_FIELDS.has(key) && typeof val === "string" && val.includes(".")) {
        candidates.push(val);
      }
    }
  }

  // 3. Common token query params
  for (const field of ["token", "jwt", "access_token"]) {
    const val = query[field];
    const str = Array.isArray(val) ? val[0] : val;
    if (typeof str === "string" && str.includes(".")) candidates.push(str);
  }

  for (const token of candidates) {
    const result = analyseJwt(token);
    if (result.detected) return result;
  }

  return null;
}
