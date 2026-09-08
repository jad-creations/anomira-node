import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { SentinelAPI, EventName } from "../index.js";

const BASE_CONFIG = {
  apiKey:          "sk_test",
  appId:           "app_test",
  ingestUrl:       "https://ingest.example.com/v1/events",
  flushIntervalMs: 60_000,
  maxBatchSize:    100,
  maxRetries:      1,
  debug:           false,
};

/** Minimal mock of Express req/res/next */
function makeReq(overrides: Record<string, unknown> = {}) {
  return {
    method:      "GET",
    originalUrl: "/api/resource",
    headers:     { "user-agent": "Mozilla/5.0", "x-forwarded-for": "5.5.5.5" },
    body:        {},
    socket:      { remoteAddress: "5.5.5.5" },
    user:        undefined as unknown,
    ...overrides,
  };
}

function makeRes(statusCode = 200) {
  const listeners: Map<string, (() => void)[]> = new Map();
  return {
    statusCode,
    on:  (event: string, fn: () => void) => { listeners.set(event, [...(listeners.get(event) ?? []), fn]); },
    off: (event: string, fn: () => void) => {
      const arr = listeners.get(event) ?? [];
      listeners.set(event, arr.filter((f) => f !== fn));
    },
    emit: (event: string) => { (listeners.get(event) ?? []).forEach((fn) => fn()); },
  };
}

describe("Express middleware", () => {
  let fetchSpy: ReturnType<typeof vi.fn>;
  let sentinel: SentinelAPI;
  let middleware: ReturnType<SentinelAPI["express"]>;

  beforeEach(() => {
    fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 202 });
    vi.stubGlobal("fetch", fetchSpy);
    sentinel = new SentinelAPI(BASE_CONFIG);
    middleware = sentinel.express();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("calls next() immediately", () => {
    const req  = makeReq();
    const res  = makeRes();
    const next = vi.fn();
    void middleware(req as never, res as never, next);
    expect(next).toHaveBeenCalledOnce();
  });

  it("tracks LOGIN_FAILED on 401 from auth endpoint", async () => {
    const req = makeReq({ method: "POST", originalUrl: "/api/auth/login" });
    const res = makeRes(401);
    void middleware(req as never, res as never, vi.fn());
    res.emit("finish");

    await sentinel.flush();
    const body = JSON.parse(fetchSpy.mock.calls[0]?.[1]?.body as string) as {
      events: Array<{ name: string }>;
    };
    expect(body.events.some((e) => e.name === EventName.LOGIN_FAILED)).toBe(true);
  });

  it("does NOT track LOGIN_FAILED on 401 from non-auth endpoint", async () => {
    const req = makeReq({ method: "GET", originalUrl: "/api/products" });
    const res = makeRes(401);
    void middleware(req as never, res as never, vi.fn());
    res.emit("finish");

    await sentinel.flush();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("tracks RATE_LIMIT on 429", async () => {
    const req = makeReq({ method: "GET", originalUrl: "/api/data" });
    const res = makeRes(429);
    void middleware(req as never, res as never, vi.fn());
    res.emit("finish");

    await sentinel.flush();
    const body = JSON.parse(fetchSpy.mock.calls[0]?.[1]?.body as string) as {
      events: Array<{ name: string }>;
    };
    expect(body.events.some((e) => e.name === EventName.RATE_LIMIT)).toBe(true);
  });

  it("tracks PATH_TRAVERSAL when URL contains ../", async () => {
    const req = makeReq({ originalUrl: "/api/files/../../../etc/passwd" });
    const res = makeRes(200);
    void middleware(req as never, res as never, vi.fn());
    res.emit("finish");

    await sentinel.flush();
    const body = JSON.parse(fetchSpy.mock.calls[0]?.[1]?.body as string) as {
      events: Array<{ name: string }>;
    };
    expect(body.events.some((e) => e.name === EventName.PATH_TRAVERSAL)).toBe(true);
  });

  it("tracks XSS_DETECTED when body contains <script>", async () => {
    const req = makeReq({
      method:      "POST",
      originalUrl: "/api/comments",
      body:        { comment: '<script>alert("xss")</script>' },
    });
    const res = makeRes(200);
    void middleware(req as never, res as never, vi.fn());
    res.emit("finish");

    await sentinel.flush();
    const body = JSON.parse(fetchSpy.mock.calls[0]?.[1]?.body as string) as {
      events: Array<{ name: string }>;
    };
    expect(body.events.some((e) => e.name === EventName.XSS_DETECTED)).toBe(true);
  });

  it("tracks SCAN_DETECTED on 404 with scanner user-agent", async () => {
    const req = makeReq({
      originalUrl: "/wp-admin/setup.php",
      headers: { "user-agent": "sqlmap/1.7", "x-forwarded-for": "6.6.6.6" },
    });
    const res = makeRes(404);
    void middleware(req as never, res as never, vi.fn());
    res.emit("finish");

    await sentinel.flush();
    const body = JSON.parse(fetchSpy.mock.calls[0]?.[1]?.body as string) as {
      events: Array<{ name: string; ip: string }>;
    };
    const scanEvent = body.events.find((e) => e.name === EventName.SCAN_DETECTED);
    expect(scanEvent).toBeDefined();
    expect(scanEvent?.ip).toBe("6.6.6.6");
  });

  it("does NOT track 404 with normal browser user-agent", async () => {
    const req = makeReq({
      originalUrl: "/missing-page",
      headers:     { "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "x-forwarded-for": "7.7.7.7" },
    });
    const res = makeRes(404);
    void middleware(req as never, res as never, vi.fn());
    res.emit("finish");

    await sentinel.flush();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("respects detect.bruteForce = false", async () => {
    const s = new SentinelAPI({ ...BASE_CONFIG, detect: { bruteForce: false } });
    const mw = s.express();
    const req = makeReq({ method: "POST", originalUrl: "/api/login" });
    const res = makeRes(401);
    void mw(req as never, res as never, vi.fn());
    res.emit("finish");

    await s.flush();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("extracts IP from X-Forwarded-For header", async () => {
    const req = makeReq({
      method: "POST",
      originalUrl: "/api/auth/login",
      headers: { "x-forwarded-for": "203.0.113.1, 10.0.0.1", "user-agent": "Mozilla/5.0" },
    });
    const res = makeRes(401);
    void middleware(req as never, res as never, vi.fn());
    res.emit("finish");

    await sentinel.flush();
    const body = JSON.parse(fetchSpy.mock.calls[0]?.[1]?.body as string) as {
      events: Array<{ ip: string }>;
    };
    expect(body.events[0]?.ip).toBe("203.0.113.1");
  });
});
