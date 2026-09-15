import { describe, it, expect } from "vitest";
import { hasPathTraversal } from "../path-traversal.js";
import { scanForXss } from "../xss-detect.js";

describe("hasPathTraversal", () => {
  it("detects plain ../", () => {
    expect(hasPathTraversal("/api/../../../etc/passwd")).toBe(true);
  });

  it("detects encoded variants", () => {
    expect(hasPathTraversal("/api/..%2Fsecret")).toBe(true);
    expect(hasPathTraversal("/api/%2e%2e/secret")).toBe(true);
    expect(hasPathTraversal("/api/%2e%2e%2fsecret")).toBe(true);
    expect(hasPathTraversal("/api/%252e%252e/secret")).toBe(true);
  });

  it("allows normal paths", () => {
    expect(hasPathTraversal("/api/users/profile")).toBe(false);
    expect(hasPathTraversal("/api/v1/orders?sort=created")).toBe(false);
  });
});

describe("scanForXss", () => {
  it("detects script tags in string values", () => {
    expect(scanForXss({ comment: "<script>alert(1)</script>" })).toBe(true);
  });

  it("detects javascript: URLs in values", () => {
    expect(scanForXss({ link: "javascript:alert(1)" })).toBe(true);
  });

  it("does not flag innocuous property names like onclick", () => {
    expect(scanForXss({ onclick: true, handler: "save" })).toBe(false);
  });

  it("scans nested values", () => {
    expect(scanForXss({ data: { bio: '<img onerror="x">' } })).toBe(true);
  });

  it("returns false for null/empty", () => {
    expect(scanForXss(null)).toBe(false);
    expect(scanForXss({})).toBe(false);
  });
});
