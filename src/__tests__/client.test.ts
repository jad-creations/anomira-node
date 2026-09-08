import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { SentinelAPI, EventName } from "../index.js";

const BASE_CONFIG = {
  apiKey:          "sk_test_key",
  appId:           "app_test_123",
  ingestUrl:       "https://ingest.example.com/v1/events",
  flushIntervalMs: 60_000,   // disable auto-flush in tests
  maxBatchSize:    100,
  maxRetries:      1,
  debug:           false,
};

describe("SentinelAPI client", () => {
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 202 });
    vi.stubGlobal("fetch", fetchSpy);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("throws if apiKey is missing", () => {
    expect(() => new SentinelAPI({ apiKey: "", appId: "app" })).toThrow("apiKey is required");
  });

  it("throws if appId is missing", () => {
    expect(() => new SentinelAPI({ apiKey: "sk_x", appId: "" })).toThrow("appId is required");
  });

  it("applies default config values", () => {
    const s = new SentinelAPI({ apiKey: "sk_x", appId: "app_x" });
    expect(s.config.ingestUrl).toBe("https://ingest.anomira.io/v1/events");
    expect(s.config.maxBatchSize).toBe(100);
    expect(s.config.flushIntervalMs).toBe(5000);
    expect(s.config.maxRetries).toBe(3);
    expect(s.config.detect.bruteForce).toBe(true);
    expect(s.config.detect.geoVelocity).toBe(true);
  });

  it("track() buffers an event and flush() sends it", async () => {
    const sentinel = new SentinelAPI(BASE_CONFIG);
    sentinel.track(EventName.LOGIN_FAILED, { ip: "1.2.3.4", userId: "user_1" });
    await sentinel.flush();

    expect(fetchSpy).toHaveBeenCalledOnce();
    const body = JSON.parse(fetchSpy.mock.calls[0]?.[1]?.body as string) as {
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
    const sentinel = new SentinelAPI(BASE_CONFIG);
    sentinel.track("custom.event", { ip: "1.1.1.1" });
    await sentinel.flush();

    const body = JSON.parse(fetchSpy.mock.calls[0]?.[1]?.body as string) as {
      events: Array<{ ts: number }>;
    };
    expect(body.events[0]?.ts).toBeGreaterThanOrEqual(before);
    expect(body.events[0]?.ts).toBeLessThanOrEqual(Date.now());
  });

  it("track() with meta embeds it in the event", async () => {
    const sentinel = new SentinelAPI(BASE_CONFIG);
    sentinel.track(EventName.OTP_FAILED, {
      ip:     "9.9.9.9",
      userId: "user_2",
      meta:   { endpoint: "/api/otp/verify", attempts: 3 },
    });
    await sentinel.flush();

    const body = JSON.parse(fetchSpy.mock.calls[0]?.[1]?.body as string) as {
      events: Array<{ meta: { endpoint: string; attempts: number } }>;
    };
    expect(body.events[0]?.meta.endpoint).toBe("/api/otp/verify");
    expect(body.events[0]?.meta.attempts).toBe(3);
  });

  it("detect.geoVelocity = false disables geo check in trackLogin", async () => {
    const sentinel = new SentinelAPI({
      ...BASE_CONFIG,
      detect: { geoVelocity: false },
    });
    // If geo-velocity is disabled, no extra fetch should happen for geo-lookup
    await sentinel.trackLogin({ ip: "1.2.3.4", userId: "user_geo" });
    await sentinel.flush();

    // Only the login success event flushed; no geo-lookup call
    const calls = fetchSpy.mock.calls;
    // All calls should be to ingest URL (geo check disabled, no ip-api.com call)
    const nonIngestCalls = calls.filter(
      (c) => !(c[0] as string).includes("ingest.example.com"),
    );
    expect(nonIngestCalls).toHaveLength(0);
  });

  it("flush() on empty buffer is a no-op", async () => {
    const sentinel = new SentinelAPI(BASE_CONFIG);
    await sentinel.flush();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("multiple track() calls are batched in one flush", async () => {
    const sentinel = new SentinelAPI(BASE_CONFIG);
    sentinel.track(EventName.LOGIN_FAILED, { ip: "1.1.1.1" });
    sentinel.track(EventName.OTP_FAILED,   { ip: "2.2.2.2" });
    sentinel.track(EventName.RATE_LIMIT,   { ip: "3.3.3.3" });
    await sentinel.flush();

    expect(fetchSpy).toHaveBeenCalledOnce();
    const body = JSON.parse(fetchSpy.mock.calls[0]?.[1]?.body as string) as {
      events: unknown[];
    };
    expect(body.events).toHaveLength(3);
  });
});
