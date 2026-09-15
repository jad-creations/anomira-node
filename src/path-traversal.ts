/**
 * Detect path-traversal sequences in a URL, including common encodings.
 */

const TRAVERSAL_RE = [
  /\.\.[\\/]/,           // ../ or ..\
  /\.\.%2f/i,            // ..%2f
  /\.\.%5c/i,            // ..%5c
  /%2e%2e[\\/]/i,       // %2e%2e/
  /%2e%2e%2f/i,          // %2e%2e%2f
  /%2e%2e%5c/i,          // %2e%2e%5c
  /\.%2e[\\/]/i,        // .%2e/
  /%2e\.[\\/]/i,        // %2e./
  /%252e%252e/i,         // double-encoded %2e%2e
];

function tryDecode(url: string): string {
  try {
    return decodeURIComponent(url);
  } catch {
    return url;
  }
}

/** Returns true if the URL contains a path-traversal pattern. */
export function hasPathTraversal(url: string): boolean {
  const candidates = [url, tryDecode(url), url.toLowerCase()];
  for (const candidate of candidates) {
    for (const re of TRAVERSAL_RE) {
      if (re.test(candidate)) return true;
    }
  }
  return false;
}
