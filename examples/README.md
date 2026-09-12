# Examples

This repository is **only the Node.js SDK**. The Anomira dashboard, API keys,
and hosted ingest service are **not open source**. Contributors and maintainers
of this repo cannot create `ANOMIRA_API_KEY` / `ANOMIRA_APP_ID` values.

The examples therefore start a **local mock ingest** on
`http://127.0.0.1:8787`. You can see events printed in the terminal. Nothing
is sent to Anomira cloud.

## Run (no account required)

From the repository root:

```bash
npm install
npm run build
cd examples/express   # or examples/fastify
npm install
npm start
```

Then:

```bash
curl http://localhost:3000/api/health
curl -X POST http://localhost:3000/api/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"demo@example.com"}'
```

You should see `[mock-ingest]` lines for `http.request` and `auth.login.success`.

## Optional: hosted Anomira (not available to OSS contributors)

If you operate the closed-source Anomira product, you can point an example at
the real ingest service:

```env
ANOMIRA_API_KEY=ak_live_...
ANOMIRA_APP_ID=your-app-id
ANOMIRA_INGEST_URL=https://ingest.anomira.io/v1/events
```

Leave `ANOMIRA_INGEST_URL` unset to keep using the local mock.
