import { describe, it, expect } from "vitest";
import { scanForSsrf } from "../ssrf.js";

describe("scanForSsrf", () => {
  it("detects cloud metadata IP in url field", () => {
    const signal = scanForSsrf({ url: "http://169.254.169.254/latest/meta-data/" }, {});
    expect(signal?.detected).toBe(true);
    expect(signal?.reason).toMatch(/private-ip|internal-hostname/);
  });

  it("detects decimal-encoded metadata IP", () => {
    const signal = scanForSsrf({ redirect: "http://2852039166/" }, {});
    expect(signal?.detected).toBe(true);
  });

  it("detects dangerous schemes", () => {
    const signal = scanForSsrf({ webhook: "gopher://127.0.0.1:70/" }, {});
    expect(signal?.detected).toBe(true);
    expect(signal?.reason).toContain("dangerous-scheme:gopher");
  });

  it("detects nested URL fields one level deep", () => {
    const signal = scanForSsrf({ data: { imageUrl: "http://127.0.0.1/admin" } }, {});
    expect(signal?.detected).toBe(true);
    expect(signal?.field).toBe("data.imageUrl");
  });

  it("ignores URLs in non-URL-named fields", () => {
    const signal = scanForSsrf({ message: "see http://169.254.169.254" }, {});
    expect(signal).toBeNull();
  });

  it("scans query parameters", () => {
    const signal = scanForSsrf({}, { next: "http://localhost/steal" });
    expect(signal?.detected).toBe(true);
  });

  it("allows public HTTPS URLs", () => {
    const signal = scanForSsrf({ url: "https://cdn.example.com/img.png" }, {});
    expect(signal).toBeNull();
  });
});
