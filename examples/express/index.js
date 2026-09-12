import { Anomira } from "@anomira/node-sdk";
import express from "express";
import { ensureLocalIngest, exampleConfig, loadEnvFile } from "../setup.js";

loadEnvFile();
const ingest = await ensureLocalIngest();
const config = exampleConfig("express-example");

const app = express();
const anomira = new Anomira(config);

app.use(express.json());
app.use(anomira.express());

app.get("/api/health", (_req, res) => {
  res.json({ ok: true });
});

app.post("/api/auth/login", (req, res) => {
  const email = req.body?.email;
  if (!email) {
    return res.status(401).json({ error: "invalid credentials" });
  }

  anomira.trackLogin({
    ip: anomira.getClientIp(req),
    userId: email,
    success: true,
  });

  res.json({ ok: true, userId: email });
});

async function shutdown() {
  await anomira.flush();
  await ingest.close();
  process.exit(0);
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

app.listen(3000, () => {
  console.log("Express example listening on http://localhost:3000");
  if (!config.hosted) {
    console.log("Sending events to local mock ingest (no Anomira account required).");
  }
});
