import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Anomira, EventName } from "../index.js";

const BASE_CONFIG = {
  apiKey: "sk_test",
  appId: "app_test",
  ingestUrl: "https://ingest.example.com/v1/events",
  flushIntervalMs: 60_000,
  maxBatchSize: 100,
  maxRetries: 1,
  debug: false,
};

/** Minimal mock of Express req/res/next */
function makeReq(overrides: Record<string, unknown> = {}) {
  return {
    method: "GET",
    originalUrl: "/api/resource",
    headers: { "user-agent": "Mozilla/5.0", "x-forwarded-for": "5.5.5.5" },
    body: {},
    socket: { remoteAddress: "5.5.5.5" },
    user: undefined as unknown,
    ...overrides,
  };
}

function makeRes(statusCode = 200) {
  const listeners: Map<string, (() => void)[]> = new Map();
  return {
    statusCode,
    on: (event: string, fn: () => void) => {
      listeners.set(event, [...(listeners.get(event) ?? []), fn]);
    },
    off: (event: string, fn: () => void) => {
      const arr = listeners.get(event) ?? [];
      listeners.set(
        event,
        arr.filter((f) => f !== fn),
      );
    },
    emit: (event: string) => {
      (listeners.get(event) ?? []).forEach((fn) => fn());
    },
  };
}

function ingestBodies(
  fetchSpy: ReturnType<typeof vi.fn>,
): Array<{ events: Array<{ name: string; ip?: string }> }> {
  return fetchSpy.mock.calls
    .filter(
      (c) =>
        typeof c[0] === "string" &&
        (c[0] as string).endsWith("/v1/events") &&
        c[1]?.method === "POST",
    )
    .map(
      (c) => JSON.parse(c[1]?.body as string) as { events: Array<{ name: string; ip?: string }> },
    );
}

function allEvents(fetchSpy: ReturnType<typeof vi.fn>) {
  return ingestBodies(fetchSpy).flatMap((b) => b.events);
}

describe("Express middleware", () => {
  let fetchSpy: ReturnType<typeof vi.fn>;
  let sentinel: InstanceType<typeof Anomira>;
  let middleware: ReturnType<InstanceType<typeof Anomira>["express"]>;

  beforeEach(() => {
    fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 202, json: async () => ({}) });
    vi.stubGlobal("fetch", fetchSpy);
    sentinel = new Anomira(BASE_CONFIG);
    middleware = sentinel.express();
  });

  afterEach(async () => {
    await sentinel.flush();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("calls next() immediately", () => {
    const req = makeReq();
    const res = makeRes();
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
    expect(allEvents(fetchSpy).some((e) => e.name === EventName.LOGIN_FAILED)).toBe(true);
  });

  it("does NOT track LOGIN_FAILED on 401 from non-auth endpoint", async () => {
    const req = makeReq({ method: "GET", originalUrl: "/api/products" });
    const res = makeRes(401);
    void middleware(req as never, res as never, vi.fn());
    res.emit("finish");

    await sentinel.flush();
    expect(allEvents(fetchSpy).some((e) => e.name === EventName.LOGIN_FAILED)).toBe(false);
  });

  it("tracks RATE_LIMIT on 429", async () => {
    const req = makeReq({ method: "GET", originalUrl: "/api/data" });
    const res = makeRes(429);
    void middleware(req as never, res as never, vi.fn());
    res.emit("finish");

    await sentinel.flush();
    expect(allEvents(fetchSpy).some((e) => e.name === EventName.RATE_LIMIT)).toBe(true);
  });

  it("tracks PATH_TRAVERSAL when URL contains ../", async () => {
    const req = makeReq({ originalUrl: "/api/files/../../../etc/passwd" });
    const res = makeRes(200);
    void middleware(req as never, res as never, vi.fn());
    res.emit("finish");

    await sentinel.flush();
    expect(allEvents(fetchSpy).some((e) => e.name === EventName.PATH_TRAVERSAL)).toBe(true);
  });

  it("tracks XSS_DETECTED when body contains <script>", async () => {
    const req = makeReq({
      method: "POST",
      originalUrl: "/api/comments",
      body: { comment: '<script>alert("xss")</script>' },
    });
    const res = makeRes(200);
    void middleware(req as never, res as never, vi.fn());
    res.emit("finish");

    await sentinel.flush();
    expect(allEvents(fetchSpy).some((e) => e.name === EventName.XSS_DETECTED)).toBe(true);
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
    const scanEvent = allEvents(fetchSpy).find((e) => e.name === EventName.SCAN_DETECTED);
    expect(scanEvent).toBeDefined();
    expect(scanEvent?.ip).toBe("6.6.6.6");
  });

  it("does NOT track SCAN_DETECTED on 404 with normal browser user-agent", async () => {
    const req = makeReq({
      originalUrl: "/missing-page",
      headers: {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "x-forwarded-for": "7.7.7.7",
      },
    });
    const res = makeRes(404);
    void middleware(req as never, res as never, vi.fn());
    res.emit("finish");

    await sentinel.flush();
    expect(allEvents(fetchSpy).some((e) => e.name === EventName.SCAN_DETECTED)).toBe(false);
  });

  it("respects detect.bruteForce = false", async () => {
    const s = new Anomira({ ...BASE_CONFIG, detect: { bruteForce: false } });
    const mw = s.express();
    const req = makeReq({ method: "POST", originalUrl: "/api/login" });
    const res = makeRes(401);
    void mw(req as never, res as never, vi.fn());
    res.emit("finish");

    await s.flush();
    expect(allEvents(fetchSpy).some((e) => e.name === EventName.LOGIN_FAILED)).toBe(false);
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
    const loginFailed = allEvents(fetchSpy).find((e) => e.name === EventName.LOGIN_FAILED);
    expect(loginFailed?.ip).toBe("203.0.113.1");
  });

  it("createExpressMiddleware matches client.express() behaviour", async () => {
    const { createExpressMiddleware } = await import("../middleware/express.js");
    const mw = createExpressMiddleware(sentinel);
    const req = makeReq({ originalUrl: "/api/files/../../../etc/passwd" });
    const res = makeRes(200);
    void mw(req as never, res as never, vi.fn());
    res.emit("finish");
    await sentinel.flush();
    expect(allEvents(fetchSpy).some((e) => e.name === EventName.PATH_TRAVERSAL)).toBe(true);
  });
});
