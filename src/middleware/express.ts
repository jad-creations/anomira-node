/**
 * Typed Express middleware — exported separately for projects that want
 * to import the middleware type explicitly.
 *
 * Delegates to `client.express()` so there is a single implementation
 * (blocklist, honeypot, SSRF/JWT, fingerprints, PII, etc.).
 */

import type { Request, Response, NextFunction } from "express";
import type { AnomiraClient } from "../client.js";

/**
 * Returns fully-typed Express middleware (same behaviour as `client.express()`).
 *
 * ```ts
 * import { createExpressMiddleware } from "@anomira/node-sdk";
 * app.use(createExpressMiddleware(anomira));
 * // equivalent:
 * app.use(anomira.express());
 * ```
 */
export function createExpressMiddleware(client: AnomiraClient) {
  return client.express() as unknown as (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => void | Promise<void>;
}
