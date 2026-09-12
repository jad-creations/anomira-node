# @anomira/node-sdk

Drop-in API security monitoring for Node.js. Detect brute force, credential stuffing, account takeover, data scraping, path traversal, XSS, geo-velocity attacks, and more — in real time.

This repository is the **open-source Node.js SDK**. The Anomira dashboard, app
keys, and hosted ingest API are a separate product and are not in this repo.
Contributors can run tests and examples without an Anomira account.

[![npm version](https://img.shields.io/npm/v/@anomira/node-sdk)](https://www.npmjs.com/package/@anomira/node-sdk)
[![CI](https://github.com/jad-creations/anomira-node/actions/workflows/ci.yml/badge.svg)](https://github.com/jad-creations/anomira-node/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](https://nodejs.org)

## Install

```bash
npm install @anomira/node-sdk
# or
yarn add @anomira/node-sdk
# or
pnpm add @anomira/node-sdk
```

**Requirements:** Node.js 18+, ESM or CommonJS.

---

## Quick Start (5 minutes)

### 1. Set your environment variables

Copy these into your `.env` file if you use the hosted Anomira product. Get the
values from the dashboard under **Apps → Setup**. You do not need these to
contribute to this SDK — see [Examples](#examples).

```env
ANOMIRA_API_KEY=ak_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
ANOMIRA_APP_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

> **Never hardcode these values.** Use environment variables or a secrets manager. Run `npx @anomira/node-sdk scan .` to catch any leaks before you commit.

### 2. Add the middleware — pick your framework

---

## Express

The middleware goes **after** `express.json()` and **after your auth middleware** so it can read the authenticated user, and **before** your routes.

### How user identity is captured automatically

The SDK automatically extracts the authenticated user ID from the request — no configuration required. It tries the following sources in order:

| Priority | Source | Set by |
|---|---|---|
| 1 | `req.user.id` / `.sub` / `.userId` / `._id` / `.uid` | Passport.js, express-jwt v6, Firebase Admin, @fastify/jwt |
| 2 | `req.auth.sub` / `.id` / `.userId` | express-jwt v7+ |
| 3 | `req.userId` / `req.accountId` / `req.customerId` | Custom middleware |
| 4 | `req.session.userId` / `req.session.user.id` | express-session |
| 5 | JWT decode from `Authorization: Bearer ...` | **Automatic fallback — works even without explicit auth middleware** |

Tier 5 is the safety net: if your auth middleware hasn't set `req.user` yet, the SDK decodes the JWT token in the `Authorization` header itself (without verifying the signature — it only reads the `sub` / `id` claim). This means user tracking works even if middleware registration order is incorrect.

**The only requirement:** if you use a custom auth pattern not listed above, pass `getUserId`:

```ts
const anomira = new Anomira({
  apiKey:    process.env.ANOMIRA_API_KEY!,
  appId:     process.env.ANOMIRA_APP_ID!,
  getUserId: (req) => (req as any).myCustomField?.userId,
});
```

```ts
// app.ts (TypeScript)
import express from "express";
import { Anomira } from "@anomira/node-sdk";

const app = express();

const anomira = new Anomira({
  apiKey: process.env.ANOMIRA_API_KEY!,
  appId:  process.env.ANOMIRA_APP_ID!,
  service: "my-api",          // appears in the Logs dashboard
  captureConsole: true,        // forwards console.log/warn/error to Logs
});

app.use(express.json());
app.use(anomira.express());    // ← single line — instruments all routes

// Your routes
app.post("/api/auth/login", (req, res) => { /* ... */ });
app.get("/api/users/:id",   (req, res) => { /* ... */ });

// Always flush before shutdown
process.on("SIGTERM", async () => {
  await anomira.flush();
  process.exit(0);
});

app.listen(3000, () => console.log("API running on :3000"));
```

**CommonJS:**

```js
// app.js
const express = require("express");
const { Anomira } = require("@anomira/node-sdk");

const app = express();
const anomira = new Anomira({
  apiKey: process.env.ANOMIRA_API_KEY,
  appId:  process.env.ANOMIRA_APP_ID,
});

app.use(express.json());
app.use(anomira.express());
app.listen(3000);
```

---

## Fastify

```ts
// server.ts
import Fastify from "fastify";
import { Anomira } from "@anomira/node-sdk";

const app = Fastify({ logger: true });

const anomira = new Anomira({
  apiKey:  process.env.ANOMIRA_API_KEY!,
  appId:   process.env.ANOMIRA_APP_ID!,
  service: "my-api",
});

// Register BEFORE your route plugins
await app.register(anomira.fastify());

// Your routes
app.post("/api/auth/login", async (req, reply) => { /* ... */ });
app.get("/api/users/:id",   async (req, reply) => { /* ... */ });

process.on("SIGTERM", async () => {
  await anomira.flush();
  await app.close();
});

await app.listen({ port: 3000, host: "0.0.0.0" });
```

---

## What the middleware captures automatically

Once registered, the middleware records **every request** with zero additional code:

| Signal | Description |
|---|---|
| HTTP method, path, status | Full request log in **API Events** |
| Source IP + geolocation | Country, city, lat/lng |
| Latency | `latencyMs` per request |
| Brute force | Repeated failures on the same endpoint |
| Rate abuse | Unusually high request rate from one IP |
| Path traversal | `../`, `%2e%2e/`, null bytes in paths |
| XSS | Script tags and injection payloads in bodies |
| Scanner/bot probing | Systematic enumeration of endpoints |
| Geo-velocity | Impossible logins from two countries within minutes |

---

## Manual event tracking

Use these when the middleware can't infer the event on its own — e.g., application-level failures.

### Getting the real client IP

> **Important — do not use `req.ip` for the `ip` field.**
>
> Behind a reverse proxy (Nginx, AWS ALB, Cloudflare — which every production app uses), `req.ip` in Express without `trust proxy` configured returns `127.0.0.1` — the proxy's address, not the user's. This breaks geo-detection, IP blocking, and attack correlation.
>
> Always use `anomira.getClientIp(req)` instead. It reads `X-Forwarded-For`, `CF-Connecting-IP`, `X-Real-IP`, and other forwarded headers in the correct priority order automatically.

```ts
// ✅ Correct — works behind Nginx, Cloudflare, AWS ALB, any reverse proxy
const ip = anomira.getClientIp(req);

// ❌ Wrong behind a proxy — returns 127.0.0.1 unless trust proxy is configured
const ip = req.ip;
```

If you use `anomira.express()` or `anomira.fastify()` middleware and call `track()` **inside a request handler**, you can omit the `ip` field entirely — the SDK reads it from the active request context automatically.

```ts
// ✅ Also correct — IP is resolved from middleware context, no need to pass it
anomira.track("auth.otp.failed", { userId: req.body.phone });
```

### Examples

```ts
// Credential stuffing / failed login attempt
await anomira.trackLogin({
  ip:      anomira.getClientIp(req),
  userId:  req.body.email,     // email or user ID
  success: false,              // false = failed attempt
});

// Successful login (enables geo-velocity tracking)
await anomira.trackLogin({
  ip:      anomira.getClientIp(req),
  userId:  user.id,
  success: true,
});

// Failed OTP — otp_flood detection
anomira.track("auth.otp.failed", {
  ip:     anomira.getClientIp(req),
  userId: req.body.phone,
  meta:   { endpoint: "/api/verify-otp" },
});

// SIM swap detection — call after any phone-based auth
anomira.trackPhoneAuth({
  ip:     anomira.getClientIp(req),
  userId: user.id,
  phone:  user.phone,
});

// Account takeover signal — e.g., password changed from new IP
anomira.track("auth.account.takeover", {
  ip:     anomira.getClientIp(req),
  userId: user.id,
  meta:   { reason: "password_changed_new_ip" },
});

// Webhook replay — call when you detect a replayed webhook signature
anomira.track("webhook.replay.detected", {
  ip:   anomira.getClientIp(req),
  meta: { webhookId: req.headers["x-webhook-id"] },
});
```

---

## Structured logging

Replace `console.log` calls with `anomira.log` to push structured logs to the **Logs dashboard** with level, service name, and metadata.

```ts
anomira.log("info",  "User registered",    { userId: user.id, plan: "starter" });
anomira.log("warn",  "Slow DB query",       { queryMs: 1240, table: "transactions" });
anomira.log("error", "Payment failed",      { reason: err.message, amount: 500_00 });
anomira.log("debug", "Cache miss",          { key: cacheKey });
```

Or set `captureConsole: true` in the constructor to automatically forward all `console.*` calls — no code changes needed.

---

## Blocklist & firewall check

The SDK syncs your dashboard's blocked IPs and firewall rules every 60 seconds. Use these checks in a gateway middleware before your routes:

```ts
app.use((req, res, next) => {
  const ip = anomira.getClientIp(req);  // always use this, not req.ip

  // Check if IP is manually blocked in the dashboard
  if (anomira.isBlocked(ip)) {
    return res.status(403).json({ error: "Forbidden" });
  }

  // Check firewall rules (pattern-based: path, method, header, body)
  const match = anomira.matchFirewallRule({
    url:     req.originalUrl,
    method:  req.method,
    body:    req.body,
    headers: req.headers,
    ip,
  });

  if (match) {
    if (match.rule.action === "block") {
      return res.status(403).json({ error: "Request blocked", rule: match.rule.name });
    }
    // action === "flag" — let it through but the dashboard will flag it
  }

  next();
});
```

---

## Shadow endpoint detection

Register your known API routes once on startup. Anomira will flag any traffic to undeclared endpoints in the **API Surface** view — a leading indicator of probing and abuse.

```ts
// Call this once, after all your routes are defined
await anomira.declareEndpoints([
  { method: "POST", path: "/api/auth/login",       auth: false },
  { method: "POST", path: "/api/auth/register",    auth: false },
  { method: "POST", path: "/api/auth/forgot",      auth: false },
  { method: "GET",  path: "/api/users/:id",        auth: true  },
  { method: "PUT",  path: "/api/users/:id",        auth: true  },
  { method: "GET",  path: "/api/orders",           auth: true  },
  { method: "POST", path: "/api/orders",           auth: true  },
  { method: "GET",  path: "/api/health",           auth: false },
]);
```

Express-style `:param` segments (`/users/:id`) are normalized automatically to match real traffic. Call this after your routes are registered so all paths are included.

---

## Secret scanner CLI

Scan your codebase for leaked secrets, API keys, and PII before they reach production.

```bash
# One-off scan (no install needed)
npx @anomira/node-sdk scan ./src

# If the package is already installed
npx anomira scan ./src
```

**Options:**

```bash
npx @anomira/node-sdk scan ./src           # scan a directory
npx @anomira/node-sdk scan .               # scan entire project
npx @anomira/node-sdk scan ./src --strict  # entropy analysis (catches unknown secrets)
npx @anomira/node-sdk scan ./src --json    # machine-readable JSON for CI
npx @anomira/node-sdk scan ./src --quiet   # violations only, no header
```

**Detects:**

| Category | Examples |
|---|---|
| Cloud | AWS access keys, GCP service accounts, Azure connection strings |
| Source control | GitHub (`ghp_`), GitLab (`glpat-`), NPM (`npm_`) tokens |
| Payment | Stripe (`sk_live_`), Paystack secret keys |
| Communication | Slack (`xoxb-`), Twilio, SendGrid |
| Database | Connection strings with embedded passwords |
| Auth | JWT tokens, bearer tokens, generic API keys |
| PII | BVN/NIN (11-digit), card PANs, Nigerian phone numbers |
| Unknown | High-entropy strings on secret-like variable names (`--strict`) |

Add to CI/CD — exits `1` if violations are found:

```json
{
  "scripts": {
    "scan": "anomira scan ./src --json"
  }
}
```

---

## Graceful shutdown

Always flush the event buffer before your process exits. Unflushed events may be lost on a hard kill.

```ts
process.on("SIGTERM", async () => {
  await anomira.flush();
  process.exit(0);
});

// For Fastify with lifecycle hooks:
app.addHook("onClose", async () => {
  await anomira.flush();
});
```

---

## Environment variables reference

| Variable | Required | Description |
|---|---|---|
| `ANOMIRA_API_KEY` | ✅ | Your API key — from dashboard under **Apps → Setup** |
| `ANOMIRA_APP_ID` | ✅ | Your app ID — from dashboard under **Apps → Setup** |

---

## Configuration reference

| Option | Type | Default | Description |
|---|---|---|---|
| `apiKey` | `string` | — | API key (required) |
| `appId` | `string` | — | App ID (required) |
| `debug` | `boolean` | `false` | Log SDK activity to console |
| `service` | `string` | `"app"` | Service name tag on all log entries |
| `captureConsole` | `boolean` | `false` | Forward `console.*` to Logs dashboard |
| `detect.bruteForce` | `boolean` | `true` | Brute force detection on auth endpoints |
| `detect.rateAbuse` | `boolean` | `true` | High-rate abuse from single IP |
| `detect.pathTraversal` | `boolean` | `true` | Path traversal payloads in URLs |
| `detect.xss` | `boolean` | `true` | XSS payloads in request bodies |
| `detect.scanDetection` | `boolean` | `true` | Endpoint scanner / bot probing |
| `detect.geoVelocity` | `boolean` | `true` | Impossible travel between logins |

---

## Troubleshooting

**No events showing in the dashboard?**
1. Set `debug: true` in the constructor — the SDK will log every event it sends to the console.
2. Check that `ANOMIRA_API_KEY` and `ANOMIRA_APP_ID` are set in your process environment (`console.log(process.env.ANOMIRA_API_KEY)`).
3. Confirm the middleware is registered **before** your routes and **after** body parsers.
4. Make sure you're not blocking outbound HTTPS traffic to `api.anomira.io`.

**TypeScript errors on IP extraction?**
Use `anomira.getClientIp(req)` — it handles all proxy headers and TypeScript types correctly. Do not use `req.ip` or `req.socket.remoteAddress` directly in production; both return the proxy address behind Nginx.

**`flush()` taking too long on shutdown?**
The flush waits for in-flight HTTP requests to complete. If your process needs to exit fast, you can add a timeout:
```ts
await Promise.race([
  anomira.flush(),
  new Promise((resolve) => setTimeout(resolve, 3000)),
]);
```

---

## Examples

This repository is the **Node.js SDK only**. The Anomira dashboard and hosted
ingest API are not open source, so contributors cannot create API keys.

The apps in [`examples/`](examples/) start a local mock ingest. You do not need
an Anomira account:

```bash
npm install
npm run build
cd examples/express   # or examples/fastify
npm install
npm start
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, tests, and pull request
guidelines. Please read the [Code of Conduct](CODE_OF_CONDUCT.md) before
participating.

## Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Do not open a
public issue for security reports.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE)
