/**
 * Shared example setup.
 *
 * This repository is the Node SDK only. The Anomira dashboard and ingest
 * service are not open source, so contributors cannot create API keys.
 * Examples therefore talk to a local mock ingest unless ANOMIRA_INGEST_URL
 * is set to a hosted endpoint.
 */
import fs from "node:fs";
import http from "node:http";
import path from "node:path";

export const LOCAL_INGEST_HOST = "127.0.0.1";
export const LOCAL_INGEST_PORT = 8787;
export const LOCAL_INGEST_URL = `http://${LOCAL_INGEST_HOST}:${LOCAL_INGEST_PORT}/v1/events`;

export function loadEnvFile(filePath = path.resolve(".env")) {
  if (!fs.existsSync(filePath)) return;
  for (const line of fs.readFileSync(filePath, "utf8").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim();
    if (process.env[key] === undefined) process.env[key] = value;
  }
}

export function exampleConfig(service) {
  const hosted = Boolean(process.env.ANOMIRA_INGEST_URL);
  return {
    apiKey: process.env.ANOMIRA_API_KEY || "ak_local_dev",
    appId: process.env.ANOMIRA_APP_ID || "local-dev-app",
    ingestUrl: process.env.ANOMIRA_INGEST_URL || LOCAL_INGEST_URL,
    service,
    debug: true,
    hosted,
  };
}

const JSON_GET = {
  "/v1/ping": { ok: true, mock: true },
  "/v1/blocked-ips/sync": { ips: [], allowedIps: [] },
  "/v1/community-threats/sync": { threats: [] },
  "/v1/honeypots/sync": { paths: [] },
  "/v1/canary-tokens/sync": { tokens: [] },
  "/v1/firewall-rules/sync": { rules: [] },
};

function pathname(url) {
  return new URL(url, "http://127.0.0.1").pathname;
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  if (chunks.length === 0) return undefined;
  const raw = Buffer.concat(chunks).toString("utf8");
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

function listen(server, port, host) {
  return new Promise((resolve, reject) => {
    const attempt = (left) => {
      const onError = (err) => {
        if (err && err.code === "EADDRINUSE" && left > 0) {
          setTimeout(() => attempt(left - 1), 200);
          return;
        }
        reject(err);
      };
      server.once("error", onError);
      server.listen(port, host, () => {
        server.removeListener("error", onError);
        resolve();
      });
    };
    attempt(10);
  });
}

/**
 * @param {{ port?: number, host?: string }} [options]
 */
export async function startMockIngest(options = {}) {
  const port = options.port ?? LOCAL_INGEST_PORT;
  const host = options.host ?? LOCAL_INGEST_HOST;
  const url = `http://${host}:${port}/v1/events`;

  const server = http.createServer(async (req, res) => {
    const route = pathname(req.url ?? "/");
    const method = (req.method ?? "GET").toUpperCase();

    if (method === "GET" && JSON_GET[route]) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(JSON_GET[route]));
      return;
    }

    const body = await readBody(req);

    if (method === "POST" && route === "/v1/events") {
      const events = body?.events ?? [];
      console.log(`[mock-ingest] ${events.length} event(s)`);
      for (const event of events) {
        console.log(`  ${event.name}  ip=${event.ip ?? "-"}  user=${event.userId ?? "-"}`);
      }
      res.writeHead(202, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    if (
      method === "POST" &&
      (route === "/v1/logs" || route === "/v1/declare-endpoints" || route === "/v1/blocked-hit")
    ) {
      res.writeHead(202, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not found", route, method }));
  });

  try {
    await listen(server, port, host);
  } catch (err) {
    if (err && err.code === "EADDRINUSE") {
      throw new Error(
        `Mock ingest port ${port} is already in use. Stop the other example, then try again.`,
      );
    }
    throw err;
  }

  console.log(`[mock-ingest] listening on ${url}`);
  console.log("[mock-ingest] local stand-in only — the Anomira cloud is not part of this repo");

  return {
    url,
    close: () =>
      new Promise((done) => {
        server.close(() => done());
      }),
  };
}

export async function ensureLocalIngest() {
  if (process.env.ANOMIRA_INGEST_URL) return { close: async () => {} };
  return startMockIngest();
}
