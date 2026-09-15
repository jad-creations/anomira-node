import { describe, it, expect } from "vitest";
import { scanForLeaks, redactMessage } from "../sensitive.js";
import { generateHoneypotResponse } from "../honeypot-responses.js";
import { SDK_USER_AGENT, SDK_VERSION } from "../version.js";

describe("sensitive scan / redact", () => {
  it("detects AWS access keys", () => {
    const hits = scanForLeaks("key = AKIAIOSFODNN7EXAMPLE");
    expect(hits.some((h) => h.type === "aws_key")).toBe(true);
  });

  it("redacts AWS keys in excerpts", () => {
    const redacted = redactMessage("AKIAIOSFODNN7EXAMPLE leaked");
    expect(redacted).not.toContain("IOSFODNN7EXAMPLE");
    expect(redacted).toContain("AKIA");
  });
});

describe("honeypot admin portal", () => {
  it("HTML-escapes canary tokens in attributes", () => {
    const evil = '"><script>alert(1)</script>';
    const res = generateHoneypotResponse("admin_portal", evil, "https://ingest.example.com", "org");
    expect(res.body).not.toContain(evil);
    expect(res.body).toContain("&quot;");
    expect(res.body).toContain("&lt;script&gt;");
  });
});

describe("SDK version", () => {
  it("exposes a consistent user agent", () => {
    expect(SDK_VERSION).toMatch(/^\d+\.\d+\.\d+/);
    expect(SDK_USER_AGENT).toBe(`@anomira/node-sdk/${SDK_VERSION}`);
  });
});
