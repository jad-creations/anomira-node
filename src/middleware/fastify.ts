/**
 * Typed Fastify plugin — exported separately for projects that want
 * to import the plugin type explicitly.
 *
 * Most users will use `sentinel.fastify()` instead of importing this directly.
 */

import type { FastifyPluginAsync, FastifyRequest, FastifyReply } from "fastify";
import type { AnomiraClient } from "../client.js";
import { EventName } from "../types.js";

/**
 * Returns a Fastify plugin for auto-instrumentation.
 *
 * ```ts
 * import Fastify from "fastify";
 * import { Anomira } from "@sentinelapi/node-sdk";
 *
 * const app = Fastify();
 * const sentinel = new Anomira({ apiKey: "...", appId: "..." });
 *
 * await app.register(sentinel.fastify());
 * ```
 */
export function createFastifyPlugin(client: AnomiraClient): FastifyPluginAsync {
  return async function sentinelPlugin(fastify) {

    // ── onRequest: block check + path traversal ───────────────────────────
    fastify.addHook("onRequest", async (req: FastifyRequest, reply: FastifyReply) => {
      const ip     = client.config.getIp(req);
      const userId = client.config.getUserId(req);
      const url    = req.url;
      const method = req.method.toUpperCase();

      // ── Block check — synchronous in-memory lookup, zero latency ────────
      if (client.isBlocked(ip)) {
        client.reportBlockedHit(ip, { method, url, userAgent: req.headers["user-agent"] ?? "" });
        return reply.code(403).send({ error: "Forbidden" });
      }

      if (client.config.detect.pathTraversal && (url.includes("../") || url.includes("..%2F"))) {
        client.track(EventName.PATH_TRAVERSAL, { ip, userId, meta: { url, method } });
      }
    });

    // ── preHandler: XSS body check ────────────────────────────────────────
    fastify.addHook("preHandler", async (req: FastifyRequest, _reply: FastifyReply) => {
      const ip     = client.config.getIp(req);
      const userId = client.config.getUserId(req);
      const url    = req.url;
      const method = req.method.toUpperCase();

      if (client.config.detect.xss && ["POST", "PUT", "PATCH"].includes(method)) {
        try {
          const body = JSON.stringify(req.body);
          if (/<script|javascript:|on\w+=/i.test(body)) {
            client.track(EventName.XSS_DETECTED, { ip, userId, meta: { url, method } });
          }
        } catch { /* ignore */ }
      }
    });

    // ── onSend: capture response size + field count before body is flushed ──
    // We read payload metadata here — never stored, just measured.
    fastify.addHook("onSend", async (_req: FastifyRequest, _reply: FastifyReply, payload: unknown) => {
      try {
        if (typeof payload === "string") {
          (_req as FastifyRequest & { _anomiraResSize?: number; _anomiraResFields?: number })._anomiraResSize = Buffer.byteLength(payload, "utf8");
          try {
            const parsed = JSON.parse(payload);
            if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
              (_req as FastifyRequest & { _anomiraResFields?: number })._anomiraResFields = Object.keys(parsed as Record<string, unknown>).length;
            }
          } catch { /* not JSON */ }
        } else if (Buffer.isBuffer(payload)) {
          (_req as FastifyRequest & { _anomiraResSize?: number })._anomiraResSize = payload.length;
        }
      } catch { /* ignore */ }
      return payload;
    });

    // ── onResponse: status-code based detection ───────────────────────────
    fastify.addHook("onResponse", async (req: FastifyRequest, reply: FastifyReply) => {
      const ip         = client.config.getIp(req);
      const userId     = client.config.getUserId(req);
      const url        = req.url;
      const method     = req.method.toUpperCase();
      const statusCode = reply.statusCode;
      // reply.elapsedTime is Fastify's built-in elapsed time in ms (available since Fastify 4)
      const resTimeMs      = Math.round((reply as FastifyReply & { elapsedTime?: number }).elapsedTime ?? 0);
      const resSize        = (req as FastifyRequest & { _anomiraResSize?: number })._anomiraResSize        ?? 0;
      const resFieldCount  = (req as FastifyRequest & { _anomiraResFields?: number })._anomiraResFields    ?? 0;
      const resMeta        = { url, method, statusCode, resTimeMs, resSize, resFieldCount };

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
          client.track(EventName.SCAN_DETECTED, { ip, userId, meta: { ...resMeta, userAgent: ua } });
        }
      }

      // Auto geo-velocity on successful POST login
      if (
        client.config.detect.geoVelocity &&
        statusCode === 200 &&
        method === "POST" &&
        /\/(login|signin|auth|token)/i.test(url)
      ) {
        const resolvedUserId = client.config.getUserId(req);
        if (resolvedUserId) {
          void client.trackLogin({ ip, userId: resolvedUserId, meta: resMeta });
        }
      }
    });
  };
}
