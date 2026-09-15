import type { SdkEvent, IngestPayload } from "./types.js";
import { SDK_USER_AGENT } from "./version.js";

interface BufferOptions {
  appId: string;
  apiKey: string;
  ingestUrl: string;
  maxBatchSize: number;
  flushIntervalMs: number;
  maxRetries: number;
  debug: boolean;
}

/**
 * EventBuffer — collects SDK events and flushes them in batches.
 *
 * Flush is triggered by whichever comes first:
 *   • Buffer reaches maxBatchSize events
 *   • flushIntervalMs timer fires
 *   • process exits (SIGTERM / SIGINT)
 *
 * On flush failure: exponential backoff up to maxRetries.
 * After maxRetries failures: events are dropped with a warning (never crash).
 */
export class EventBuffer {
  private queue: SdkEvent[] = [];
  private timer: ReturnType<typeof setInterval> | null = null;
  private flushing = false;
  private readonly opts: BufferOptions;

  constructor(opts: BufferOptions) {
    this.opts = opts;
    this.startTimer();
    this.registerShutdownHook();
  }

  // ─── Public API ────────────────────────────────────────────────────────────

  push(event: SdkEvent): void {
    this.queue.push(event);
    this.log(`[buffer] +1 event → ${this.queue.length} queued (${event.name})`);
    if (this.queue.length >= this.opts.maxBatchSize) {
      this.log("[buffer] batch size reached — flushing immediately");
      void this.flush();
    }
  }

  async flush(): Promise<void> {
    if (this.flushing || this.queue.length === 0) return;
    this.flushing = true;

    // Drain the queue atomically
    const batch = this.queue.splice(0, this.opts.maxBatchSize);
    this.log(`[buffer] flushing ${batch.length} events`);

    try {
      await this.sendWithRetry(batch);
    } catch (err) {
      // Last-resort: log and drop. Never propagate.
      this.warn(`[buffer] dropped ${batch.length} events after max retries:`, err);
    } finally {
      this.flushing = false;
    }
  }

  /** Call on graceful shutdown to flush remaining events synchronously. */
  async shutdown(): Promise<void> {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    await this.flush();
    this.log("[buffer] shutdown complete");
  }

  // ─── Internals ─────────────────────────────────────────────────────────────

  private startTimer(): void {
    this.timer = setInterval(() => {
      void this.flush();
    }, this.opts.flushIntervalMs);

    // Don't keep the Node process alive just for this timer
    if (this.timer.unref) this.timer.unref();
  }

  private registerShutdownHook(): void {
    // Increase the limit to avoid MaxListenersExceededWarning when many buffers
    // are instantiated in the same process (e.g. during tests).
    const current = process.getMaxListeners();
    process.setMaxListeners(current + 3);

    const handler = () => {
      void this.shutdown();
    };
    process.once("SIGTERM", handler);
    process.once("SIGINT", handler);
    process.once("beforeExit", handler);
  }

  private async sendWithRetry(events: SdkEvent[], attempt = 1): Promise<void> {
    const { appId, apiKey, ingestUrl, maxRetries } = this.opts;

    const payload: IngestPayload = { appId, events };

    try {
      const res = await fetch(ingestUrl, {
        method: "POST",
        redirect: "manual",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
          "User-Agent": SDK_USER_AGENT,
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(8_000),
      });

      if (res.ok) {
        this.log(`[buffer] ✅ sent ${events.length} events (attempt ${attempt})`);
        return;
      }

      if (res.status >= 300 && res.status < 400) {
        this.warn(
          `[buffer] ❌ Wrong ingest URL — got redirect to ${res.headers.get("location")}. Check SENTINEL_INGEST_URL.`,
        );
        return;
      }

      // 4xx errors are not retryable (bad API key, schema error)
      if (res.status === 401) {
        this.warn("[buffer] ❌ Invalid API key — check your SENTINEL_API_KEY environment variable");
        return;
      }
      if (res.status === 403) {
        this.warn("[buffer] ❌ App not found — check your SENTINEL_APP_ID environment variable");
        return;
      }
      if (res.status >= 400 && res.status < 500) {
        this.warn(`[buffer] ⚠️  ingest rejected ${res.status} — dropping batch`);
        return;
      }

      throw new Error(`Ingest HTTP ${res.status}`);
    } catch (err) {
      if (attempt >= maxRetries) throw err;

      const delayMs = Math.min(1000 * 2 ** (attempt - 1), 16_000); // 1s, 2s, 4s, …, 16s cap
      this.log(`[buffer] retry ${attempt}/${maxRetries} in ${delayMs}ms`);
      await sleep(delayMs);
      return this.sendWithRetry(events, attempt + 1);
    }
  }

  private log(...args: unknown[]): void {
    if (this.opts.debug) console.log("[Anomira]", ...args);
  }

  private warn(...args: unknown[]): void {
    console.warn("[Anomira]", ...args);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
