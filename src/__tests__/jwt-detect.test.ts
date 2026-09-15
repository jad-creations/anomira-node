import { describe, it, expect } from "vitest";
import { analyseJwt, looksLikeJwt, scanRequestForJwtAttacks } from "../jwt-detect.js";

function b64url(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

function makeJwt(header: Record<string, unknown>, payload: Record<string, unknown>, sig = "abc"): string {
  return `${b64url(header)}.${b64url(payload)}.${sig}`;
}

describe("looksLikeJwt", () => {
  it("returns false for opaque session tokens", () => {
    expect(looksLikeJwt("s:session.signature")).toBe(false);
    expect(looksLikeJwt("opaque-uuid-token")).toBe(false);
    expect(looksLikeJwt("abc123")).toBe(false);
  });

  it("returns true for real JWTs", () => {
    const token = makeJwt({ alg: "HS256", typ: "JWT" }, { sub: "user1" });
    expect(looksLikeJwt(token)).toBe(true);
  });
});

describe("analyseJwt", () => {
  it("does not flag opaque Bearer tokens as missing_signature", () => {
    expect(analyseJwt("s:opaque.session").detected).toBe(false);
    expect(analyseJwt("random-token-no-dots").detected).toBe(false);
  });

  it("detects alg:none", () => {
    const token = makeJwt({ alg: "none", typ: "JWT" }, { sub: "x" }, "");
    // empty sig → missing_signature takes precedence when 3rd segment empty;
    // use a non-empty placeholder so alg:none is checked after segment count
    const noneToken = `${b64url({ alg: "None" })}.${b64url({ sub: "x" })}.x`;
    const result = analyseJwt(noneToken);
    expect(result.detected).toBe(true);
    expect(result.attack).toBe("alg_none");
  });

  it("detects missing signature on JWT-shaped tokens", () => {
    const token = `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url({ sub: "x" })}.`;
    const result = analyseJwt(token);
    expect(result.detected).toBe(true);
    expect(result.attack).toBe("missing_signature");
  });

  it("detects unknown algorithm", () => {
    const token = makeJwt({ alg: "CUSTOM", typ: "JWT" }, { sub: "x" }, "sig");
    const result = analyseJwt(token);
    expect(result.detected).toBe(true);
    expect(result.attack).toBe("unknown_algorithm");
  });

  it("passes a normal HS256 token", () => {
    const token = makeJwt({ alg: "HS256", typ: "JWT" }, { sub: "x" }, "shortsig");
    expect(analyseJwt(token).detected).toBe(false);
  });

  it("detects algorithm confusion (HMAC + long sig)", () => {
    const longSig = "a".repeat(200);
    const token = makeJwt({ alg: "HS256", typ: "JWT" }, { sub: "x" }, longSig);
    const result = analyseJwt(token);
    expect(result.detected).toBe(true);
    expect(result.attack).toBe("algorithm_confusion");
  });
});

describe("scanRequestForJwtAttacks", () => {
  it("ignores opaque Authorization Bearer tokens", () => {
    const result = scanRequestForJwtAttacks(
      { authorization: "Bearer s:session.cookie.sig" },
      {},
      {},
    );
    expect(result).toBeNull();
  });

  it("flags alg:none in Authorization header", () => {
    const token = `${b64url({ alg: "none" })}.${b64url({ sub: "x" })}.x`;
    const result = scanRequestForJwtAttacks(
      { authorization: `Bearer ${token}` },
      {},
      {},
    );
    expect(result?.detected).toBe(true);
    expect(result?.attack).toBe("alg_none");
  });

  it("scans body token fields", () => {
    const token = `${b64url({ alg: "none" })}.${b64url({ sub: "x" })}.x`;
    const result = scanRequestForJwtAttacks({}, { access_token: token }, {});
    expect(result?.attack).toBe("alg_none");
  });
});
