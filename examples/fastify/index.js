import { Anomira } from "@anomira/node-sdk";
import Fastify from "fastify";
import { ensureLocalIngest, exampleConfig, loadEnvFile } from "../setup.js";

loadEnvFile();
const ingest = await ensureLocalIngest();
const config = exampleConfig("fastify-example");

const app = Fastify({ logger: true });
const anomira = new Anomira(config);

await app.register(anomira.fastify());

app.get("/api/health", async () => ({ ok: true }));

app.post("/api/auth/login", async (req, reply) => {
  const email = req.body?.email;
  if (!email) {
    return reply.code(401).send({ error: "invalid credentials" });
  }

  anomira.trackLogin({
    ip: anomira.getClientIp(req),
    userId: email,
    success: true,
  });

  return { ok: true, userId: email };
});

app.addHook("onClose", async () => {
  await anomira.flush();
  await ingest.close();
});

process.on("SIGTERM", async () => {
  await app.close();
});
process.on("SIGINT", async () => {
  await app.close();
  process.exit(0);
});

await app.listen({ port: 3000, host: "0.0.0.0" });
if (!config.hosted) {
  app.log.info("Sending events to local mock ingest (no Anomira account required).");
}
