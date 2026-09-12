# Fastify example

Minimal Fastify app with `@anomira/node-sdk`.

No Anomira account is required. `npm start` stands up a local mock ingest and
prints captured events to the terminal.

```bash
# from the repository root
npm install
npm run build

cd examples/fastify
npm install
npm start
```

Then:

```bash
curl http://localhost:3000/api/health
curl -X POST http://localhost:3000/api/auth/login -H 'content-type: application/json' -d '{"email":"demo@example.com"}'
```

See [`../README.md`](../README.md) for the hosted-ingest override (operators of
the closed-source Anomira product only).
