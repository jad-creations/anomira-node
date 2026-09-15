/**
 * Lightweight XSS signal scanner for request bodies.
 * Scans string values only (not JSON keys) to avoid false positives on
 * property names like "onclick" or "javascript".
 */

const XSS_VALUE_RE =
  /<script[\s/>]|<\/script\s*>|javascript\s*:|vbscript\s*:|data\s*:\s*text\/html|on(?:click|error|load|mouse\w+|focus|blur|submit|input|change|keyup|keydown)\s*=/i;

/**
 * Returns true if any string value in the body looks like an XSS payload.
 */
export function scanForXss(body: unknown, depth = 0): boolean {
  if (body == null || depth > 6) return false;

  if (typeof body === "string") {
    return XSS_VALUE_RE.test(body);
  }

  if (Array.isArray(body)) {
    return body.some((item) => scanForXss(item, depth + 1));
  }

  if (typeof body === "object") {
    return Object.values(body as Record<string, unknown>).some((v) =>
      scanForXss(v, depth + 1),
    );
  }

  return false;
}
