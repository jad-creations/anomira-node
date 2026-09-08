/**
 * Typed Express middleware — exported separately for projects that want
 * to import the middleware type explicitly.
 *
 * Most users will use `sentinel.express()` instead of importing this directly.
 */

import type { Request, Response, NextFunction } from "express";
import type { AnomiraClient } from "../client.js";
import { EventName } from "../types.js";

/**
 * Returns fully-typed Express middleware.
 *
 * ```ts
 * import express from "express";
 * import { Anomira } from "@sentinelapi/node-sdk";
 *
 * const app = express();
 * const sentinel = new Anomira({ apiKey: "...", appId: "..." });
 *
 * app.use(sentinel.express());          // auto-instrument all routes
 *
 * // Or import the typed version directly:
 * import { createExpressMiddleware } from "@sentinelapi/node-sdk/middleware/express";
 * app.use(createExpressMiddleware(sentinel));
 * ```
 */
export function createExpressMiddleware(client: AnomiraClient) {
  return function sentinelMiddleware(req: Request, res: Response, next: NextFunction): void {
    const ip     = client.config.getIp(req as unknown);
    const userId = client.config.getUserId(req as unknown);
    const { method, originalUrl: url } = req;

    // ── Block check — synchronous in-memory lookup, zero latency ──────────
    if (client.isBlocked(ip)) {
      client.reportBlockedHit(ip, { method, url, userAgent: req.headers["user-agent"] ?? "" });
      res.status(403).json({ error: "Forbidden" });
      return;
    }

    // ── Path traversal check (pre-handler) ────────────────────────────────
    if (client.config.detect.pathTraversal && (url.includes("../") || url.includes("..%2F"))) {
      client.track(EventName.PATH_TRAVERSAL, {
        ip, userId,
        meta: { url, method },
      });
    }

    // ── XSS body check (pre-handler) ──────────────────────────────────────
    if (client.config.detect.xss && ["POST", "PUT", "PATCH"].includes(method)) {
      try {
        const body = JSON.stringify(req.body as unknown);
        if (/<script|javascript:|on\w+=/i.test(body)) {
          client.track(EventName.XSS_DETECTED, {
            ip, userId,
            meta: { url, method },
          });
        }
      } catch {
        // body may not be parseable yet — ignore
      }
    }

    // ── Response metadata capture — size and field count (no body stored) ──
    // Override res.json to measure byte size and top-level field count, then
    // immediately forward the original body unchanged.  We never store content.
    const startTs = process.hrtime.bigint();
    let resSize       = 0;
    let resFieldCount = 0;

    const origJson = res.json.bind(res);
    (res as Response).json = function anomiraJson(body: unknown) {
      try {
        if (body !== null && typeof body === "object" && !Array.isArray(body)) {
          resFieldCount = Object.keys(body as Record<string, unknown>).length;
        }
        const serialised = JSON.stringify(body);
        resSize = Buffer.byteLength(serialised, "utf8");
      } catch { /* ignore serialisation errors */ }
      return origJson(body);
    };

    const origSend = res.send.bind(res);
    (res as Response).send = function anomiraSend(body?: unknown) {
      if (resSize === 0) {
        if (typeof body === "string")       resSize = Buffer.byteLength(body, "utf8");
        else if (Buffer.isBuffer(body))     resSize = body.length;
      }
      return origSend(body);
    };

    // ── Response-finish hook (post-handler) ───────────────────────────────
    const onFinish = () => {
      res.off("finish", onFinish);
      const { statusCode } = res;
      const resTimeMs = Math.round(Number(process.hrtime.bigint() - startTs) / 1_000_000);
      const resMeta   = { url, method, statusCode, resTimeMs, resSize, resFieldCount };

      if (client.config.detect.rateAbuse && statusCode === 429) {
        client.track(EventName.RATE_LIMIT, { ip, userId, meta: resMeta });
      }

      if (client.config.detect.bruteForce && statusCode === 401) {
        if (/\/(login|signin|auth|token|session)/i.test(url)) {
          client.track(EventName.LOGIN_FAILED, { ip, userId, meta: resMeta });
        }
      }

      if (client.config.detect.scanDetection && statusCode === 404) {
        const ua = req.headers["user-agent"] ?? "";
        if (!ua || /curl|wget|python|go-http|nuclei|sqlmap|nikto/i.test(ua)) {
          client.track(EventName.SCAN_DETECTED, {
            ip, userId,
            meta: { ...resMeta, userAgent: ua },
          });
        }
      }

      // Auto geo-velocity on successful login
      if (
        client.config.detect.geoVelocity &&
        statusCode === 200 &&
        /\/(login|signin|auth|token)/i.test(url) &&
        method === "POST"
      ) {
        const resolvedUserId = client.config.getUserId(req as unknown);
        if (resolvedUserId) {
          void client.trackLogin({ ip, userId: resolvedUserId, meta: resMeta });
        }
      }
    };

    res.on("finish", onFinish);
    next();
  };
}
