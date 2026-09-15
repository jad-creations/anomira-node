import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { EventBuffer } from "../buffer.js";

const OPTS = {
  appId: "app_test",
  apiKey: "sk_test",
  ingestUrl: "https://ingest.example.com/v1/events",
  maxBatchSize: 5,
  flushIntervalMs: 60_000, // long — we flush manually in tests
  maxRetries: 1,
  debug: false,
};

describe("EventBuffer", () => {
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 202 });
    vi.stubGlobal("fetch", fetchSpy);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("flushes when batch size is reached", async () => {
    const buf = new EventBuffer(OPTS);

    for (let i = 0; i < 5; i++) {
      buf.push({ name: "test.event", ts: Date.now(), ip: "1.2.3.4" });
    }

    // Give the async flush a tick to complete
    await new Promise((r) => setTimeout(r, 50));

    expect(fetchSpy).toHaveBeenCalledOnce();
    const body = JSON.parse(fetchSpy.mock.calls[0]?.[1]?.body as string) as {
      appId: string;
      events: unknown[];
    };
    expect(body.appId).toBe("app_test");
    expect(body.events).toHaveLength(5);
  });

  it("sends Authorization header with API key", async () => {
    const buf = new EventBuffer(OPTS);
    buf.push({ name: "test.event", ts: Date.now(), ip: "1.2.3.4" });
    await buf.flush();

    const headers = fetchSpy.mock.calls[0]?.[1]?.headers as Record<string, string>;
    expect(headers?.["Authorization"]).toBe("Bearer sk_test");
  });

  it("does not throw on network failure (silent drop after max retries)", async () => {
    fetchSpy.mockRejectedValue(new Error("Network error"));
    const buf = new EventBuffer({ ...OPTS, maxRetries: 1 });
    buf.push({ name: "test.event", ts: Date.now(), ip: "1.2.3.4" });
    // Should not throw
    await expect(buf.flush()).resolves.toBeUndefined();
  });

  it("does not retry on 4xx response (non-retriable)", async () => {
    fetchSpy.mockResolvedValue({ ok: false, status: 401 });
    const buf = new EventBuffer({ ...OPTS, maxRetries: 3 });
    buf.push({ name: "test.event", ts: Date.now(), ip: "1.2.3.4" });
    await buf.flush();
    // Only called once — no retry for 4xx
    expect(fetchSpy).toHaveBeenCalledOnce();
  });

  it("retries on 5xx and eventually succeeds", async () => {
    fetchSpy
      .mockResolvedValueOnce({ ok: false, status: 500 })
      .mockResolvedValue({ ok: true, status: 202 });

    const buf = new EventBuffer({ ...OPTS, maxRetries: 3 });
    buf.push({ name: "test.event", ts: Date.now(), ip: "1.2.3.4" });
    await buf.flush();

    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it("manual flush sends pending events", async () => {
    const buf = new EventBuffer(OPTS);
    buf.push({ name: "test.event", ts: Date.now(), ip: "5.5.5.5" });
    buf.push({ name: "test.event", ts: Date.now(), ip: "5.5.5.5" });

    await buf.flush();
    expect(fetchSpy).toHaveBeenCalledOnce();
  });

  it("does not double-send on concurrent flush calls", async () => {
    fetchSpy.mockImplementation(
      () => new Promise((r) => setTimeout(() => r({ ok: true, status: 202 }), 50)),
    );

    const buf = new EventBuffer(OPTS);
    buf.push({ name: "test.event", ts: Date.now(), ip: "1.2.3.4" });

    // Fire two concurrent flushes
    await Promise.all([buf.flush(), buf.flush()]);
    expect(fetchSpy).toHaveBeenCalledOnce();
  });
});
