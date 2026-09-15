/**
 * Typed Fastify plugin — exported separately for projects that want
 * to import the plugin type explicitly.
 *
 * Delegates to `client.fastify()` so there is a single implementation.
 */

import type { FastifyPluginAsync } from "fastify";
import type { AnomiraClient } from "../client.js";

/**
 * Returns a Fastify plugin for auto-instrumentation
 * (same behaviour as `client.fastify()`).
 *
 * ```ts
 * await app.register(createFastifyPlugin(anomira));
 * // equivalent:
 * await app.register(anomira.fastify());
 * ```
 */
export function createFastifyPlugin(client: AnomiraClient): FastifyPluginAsync {
  return client.fastify() as unknown as FastifyPluginAsync;
}
