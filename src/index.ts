/**
 * @anomira/node-sdk
 * ─────────────────
 * Drop-in API security monitoring for Node.js.
 * Zero runtime dependencies. Works with Express, Fastify, and any HTTP framework.
 *
 * Quick start:
 * ```ts
 * import { Anomira, EventName } from "@anomira/node-sdk";
 *
 * const anomira = new Anomira({
 *   apiKey: process.env.ANOMIRA_API_KEY!,
 *   appId:  process.env.ANOMIRA_APP_ID!,
 * });
 *
 * // Express
 * app.use(anomira.express());
 *
 * // Fastify
 * await app.register(anomira.fastify());
 *
 * // Manual tracking
 * anomira.track(EventName.OTP_FAILED, { ip: req.ip, userId: req.body.phone });
 * await anomira.trackLogin({ ip: req.ip, userId: user.id });
 * ```
 */

export { AnomiraClient as Anomira } from "./client.js";
// Backward-compat alias — remove in next major version
export { AnomiraClient } from "./client.js";
export { EventName } from "./types.js";
export type {
  AnomiraConfig,
  AnomiraConfig as SentinelConfig, // backward-compat alias
  SdkEvent,
  IngestPayload,
  EventNameValue,
  EndpointDeclaration,
} from "./types.js";
export { createExpressMiddleware } from "./middleware/express.js";
export { createFastifyPlugin } from "./middleware/fastify.js";

// Convenience: allow both named and default import
export { AnomiraClient as default } from "./client.js";
