import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Anomira, EventName } from "../index.js";

const BASE_CONFIG = {
  apiKey:          "sk_test_key",
  appId:           "app_test_123",
  ingestUrl:       "https://ingest.example.com/v1/events",
  flushIntervalMs: 60_000,
  maxBatchSize:    100,
  maxRetries:      1,
  debug:           false,
};

describe("Anomira client", () => {
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 202, json: async () => ({}) });
    vi.stubGlobal("fetch", fetchSpy);
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("disables quietly when apiKey is missing", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const s = new Anomira({ apiKey: "", appId: "app" });
    s.track(EventName.LOGIN_FAILED, { ip: "1.2.3.4" });
    expect(warn).toHaveBeenCalled();
    expect(s.isBlocked("1.2.3.4")).toBe(false);
    warn.mockRestore();
  });

  it("disables quietly when appId is missing", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const s = new Anomira({ apiKey: "sk_x", appId: "" });
    s.track(EventName.LOGIN_FAILED, { ip: "1.2.3.4" });
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });

  it("applies default config values", async () => {
    const s = new Anomira({ apiKey: "sk_x", appId: "app_x" });
    expect(s.config.ingestUrl).toBe("https://ingest.anomira.io/v1/events");
    expect(s.config.maxBatchSize).toBe(100);
    expect(s.config.flushIntervalMs).toBe(5000);
    expect(s.config.maxRetries).toBe(3);
    expect(s.config.detect.bruteForce).toBe(true);
    expect(s.config.detect.geoVelocity).toBe(true);
    await s.flush();
  });

  it("track() buffers an event and flush() sends it", async () => {
    const sentinel = new Anomira(BASE_CONFIG);
    sentinel.track(EventName.LOGIN_FAILED, { ip: "1.2.3.4", userId: "user_1" });
    await sentinel.flush();

    const ingestCalls = fetchSpy.mock.calls.filter(
      (c) => typeof c[0] === "string" && (c[0] as string).endsWith("/v1/events") && c[1]?.method === "POST",
    );
    expect(ingestCalls.length).toBeGreaterThanOrEqual(1);
    const body = JSON.parse(ingestCalls[0]?.[1]?.body as string) as {
      appId: string;
      events: Array<{ name: string; ip: string; userId: string }>;
    };
    expect(body.appId).toBe("app_test_123");
    expect(body.events[0]?.name).toBe(EventName.LOGIN_FAILED);
    expect(body.events[0]?.ip).toBe("1.2.3.4");
    expect(body.events[0]?.userId).toBe("user_1");
  });

  it("track() attaches a millisecond timestamp", async () => {
    const before = Date.now();
    const sentinel = new Anomira(BASE_CONFIG);
    sentinel.track("custom.event", { ip: "1.1.1.1" });
    await sentinel.flush();

    const ingestCalls = fetchSpy.mock.calls.filter(
      (c) => typeof c[0] === "string" && (c[0] as string).endsWith("/v1/events") && c[1]?.method === "POST",
    );
    const body = JSON.parse(ingestCalls[0]?.[1]?.body as string) as {
      events: Array<{ ts: number }>;
    };
    expect(body.events[0]?.ts).toBeGreaterThanOrEqual(before);
    expect(body.events[0]?.ts).toBeLessThanOrEqual(Date.now());
  });

  it("track() with meta embeds it in the event", async () => {
    const sentinel = new Anomira(BASE_CONFIG);
    sentinel.track(EventName.OTP_FAILED, {
      ip:     "9.9.9.9",
      userId: "user_2",
      meta:   { endpoint: "/api/otp/verify", attempts: 3 },
    });
    await sentinel.flush();

    const ingestCalls = fetchSpy.mock.calls.filter(
      (c) => typeof c[0] === "string" && (c[0] as string).endsWith("/v1/events") && c[1]?.method === "POST",
    );
    const body = JSON.parse(ingestCalls[0]?.[1]?.body as string) as {
      events: Array<{ meta: { endpoint: string; attempts: number } }>;
    };
    expect(body.events[0]?.meta.endpoint).toBe("/api/otp/verify");
    expect(body.events[0]?.meta.attempts).toBe(3);
  });

  it("detect.geoVelocity = false disables geo check in trackLogin", async () => {
    const sentinel = new Anomira({
      ...BASE_CONFIG,
      detect: { geoVelocity: false },
    });
    await sentinel.trackLogin({ ip: "1.2.3.4", userId: "user_geo" });
    await sentinel.flush();

    const nonIngestCalls = fetchSpy.mock.calls.filter((c) => {
      const url = c[0] as string;
      return !url.includes("ingest.example.com");
    });
    expect(nonIngestCalls).toHaveLength(0);
  });

  it("flush() on empty buffer is a no-op for events", async () => {
    const sentinel = new Anomira(BASE_CONFIG);
    const before = fetchSpy.mock.calls.filter(
      (c) => typeof c[0] === "string" && (c[0] as string).endsWith("/v1/events") && c[1]?.method === "POST",
    ).length;
    await sentinel.flush();
    const after = fetchSpy.mock.calls.filter(
      (c) => typeof c[0] === "string" && (c[0] as string).endsWith("/v1/events") && c[1]?.method === "POST",
    ).length;
    expect(after).toBe(before);
  });

  it("multiple track() calls are batched in one flush", async () => {
    const sentinel = new Anomira(BASE_CONFIG);
    sentinel.track(EventName.LOGIN_FAILED, { ip: "1.1.1.1" });
    sentinel.track(EventName.OTP_FAILED,   { ip: "2.2.2.2" });
    sentinel.track(EventName.RATE_LIMIT,   { ip: "3.3.3.3" });
    await sentinel.flush();

    const ingestCalls = fetchSpy.mock.calls.filter(
      (c) => typeof c[0] === "string" && (c[0] as string).endsWith("/v1/events") && c[1]?.method === "POST",
    );
    expect(ingestCalls.length).toBeGreaterThanOrEqual(1);
    const body = JSON.parse(ingestCalls[0]?.[1]?.body as string) as {
      events: unknown[];
    };
    expect(body.events).toHaveLength(3);
  });

  it("createExpressMiddleware matches client.express()", async () => {
    const { createExpressMiddleware } = await import("../middleware/express.js");
    const sentinel = new Anomira(BASE_CONFIG);
    const a = sentinel.express();
    const b = createExpressMiddleware(sentinel);
    // Same underlying middleware factory — both are functions
    expect(typeof a).toBe("function");
    expect(typeof b).toBe("function");
    await sentinel.flush();
  });
});
