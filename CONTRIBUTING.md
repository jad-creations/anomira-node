# Contributing to @anomira/node-sdk

Thanks for helping improve the Anomira Node.js SDK. This document is the
shortest path from clone to a reviewable pull request, and the playbook
maintainers use to verify and ship work.

## Code of conduct

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
Report unacceptable behavior to [sdk@anomira.io](mailto:sdk@anomira.io).

## Security issues

Do not open a public issue or pull request for a vulnerability. Follow
[SECURITY.md](SECURITY.md) instead.

## Prerequisites

- Node.js 18 or later (CI tests on Node 22 and 24)
- npm 9 or later

## Local setup

```bash
git clone https://github.com/jad-creations/anomira-node.git
cd anomira-node
npm install
```

Tests and examples do **not** need Anomira credentials. This repository is the
SDK only; the Anomira dashboard is not open source, so contributors cannot
create API keys. The example apps start a local mock ingest automatically.

## Checks to run before you open a PR

```bash
npm run typecheck
npm test
npm run lint
npm run build
```

These four commands are what CI runs and what the pull request template asks
for. They are enough to merge SDK changes. You do not need the Anomira
dashboard.

To try middleware against a real Express or Fastify app after a build:

```bash
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

Watch the terminal for `[mock-ingest]` lines (`http.request`,
`auth.login.success`). That terminal output is the local stand-in for a
landing page. Use `npm test` / `npm run test:watch` for detector behavior.

See [examples/README.md](examples/README.md) for the hosted-ingest override
(operators of the closed-source Anomira product only).

## How to know a change works

This package emits events over HTTP. It does not render a UI. “Working” means
the SDK built the right payload and sent it to the right URL.

| What you changed                             | Required check                                                                 | What success looks like                          |
| -------------------------------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------ |
| Detector, client, buffer, Express middleware | `npm test` (add or update a case in `src/__tests__/`)                          | The new assertion passes                         |
| Fastify plugin or real HTTP wiring           | Build, then run `examples/fastify` or `examples/express` and `curl` the routes | `[mock-ingest]` prints the expected event names  |
| CLI scanner (`src/cli.ts`)                   | `npm run build` then `node dist/cli.cjs scan ./src`                            | Exit code and output match the intended behavior |
| Types or public API                          | `npm run typecheck` plus README / changelog                                    | Callers can use the new export                   |
| Dashboard charts, Logs view, API Surface     | Out of scope for this repo                                                     | Do not block an SDK PR on this                   |

**In scope for every PR:** tests, typecheck, lint, and build.

**Optional smoke:** the example apps. CI does not start them, so run them
locally when you touch middleware wiring or ingest.

**Out of scope:** whether events appear in the Anomira dashboard. Only someone
who operates the hosted product can confirm that, by setting
`ANOMIRA_INGEST_URL`. OSS contributors and SDK maintainers should not wait on
that.

If the test or `[mock-ingest]` line is correct, the SDK did its job.

## Project layout

| Path              | What it is                                                          |
| ----------------- | ------------------------------------------------------------------- |
| `src/index.ts`    | Public exports. Anything not exported from here is internal         |
| `src/client.ts`   | `AnomiraClient` — track, flush, sync, logs, middleware factories    |
| `src/buffer.ts`   | Event batching and retries                                          |
| `src/types.ts`    | `AnomiraConfig`, `EventName`, payload types                         |
| `src/middleware/` | Express and Fastify adapters                                        |
| `src/cli.ts`      | `anomira` secret-scanner CLI                                        |
| `src/__tests__/`  | Vitest suites (see coverage notes below)                            |
| `examples/`       | Express/Fastify demos plus a local mock ingest (no Anomira account) |
| `dist/`           | Build output (do not edit or commit)                                |

Detector helpers live next to the client (`geo-velocity.ts`, `ssrf.ts`,
`jwt-detect.ts`, and similar). Follow those modules when you add a new
signal: define the event name in `src/types.ts`, emit it from middleware or
the client, and add a Vitest case.

### What tests cover today

| Suite                                      | Covers                                                                                                  | Does not cover        |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------- | --------------------- |
| `src/__tests__/client.test.ts`             | Config, `track()`, `flush()` payloads                                                                   | Dashboard delivery    |
| `src/__tests__/buffer.test.ts`             | Batch size, flush, retries                                                                              | —                     |
| `src/__tests__/middleware-express.test.ts` | Express middleware with mocked `req`/`res` (login failure, rate limit, path traversal, XSS, scanner UA) | A real Express server |
| `src/__tests__/geo-velocity.test.ts`       | Impossible-travel math with mocked geo lookups                                                          | Live geolocation      |

There is **no Fastify test suite** and **no CLI test suite**. CI runs Vitest
only; it does not boot `examples/`. If you change Fastify or the CLI, add
tests where you can and smoke the example or `node dist/cli.cjs` locally.

## Pull requests

1. Open an issue first for larger changes so we can agree on the approach.
2. Create a branch from `main`.
3. Keep the change focused. Prefer small PRs over mixed refactors.
4. Add or update tests in `src/__tests__/` for behavior changes.
5. Update `README.md` and `CHANGELOG.md` (`[Unreleased]`) when the public API or
   user-facing behavior changes.
6. Never commit secrets, API keys, `.env` files, or `dist/`.
7. Fill in the pull request template.

### Commit messages

Use a short imperative subject, for example:

- `Add Fastify onClose flush example`
- `Fix geo-velocity skip when geoLookupUrl is unset`
- `Document trusted npm publishing`

## Coding notes

- TypeScript, ESM source, compiled to ESM and CommonJS via `tsup`.
- `express` and `fastify` are optional peer dependencies — keep them out of the
  published SDK runtime bundle.
- Prefer existing patterns in `src/client.ts` and the middleware adapters over
  new abstractions.
- Public exports live in `src/index.ts`. Treat anything not exported from there
  as internal.

## Maintainers

SDK maintainers own this repository: review, merge, and release
`@anomira/node-sdk`. They do **not** need the Anomira dashboard to do that
work.

Product operators (people who run the closed-source ingest and UI) may
optionally point `examples/` at hosted ingest. That check is extra. It is not
required to merge or publish the SDK.

### Review bar

Before merging:

- The four PR checks are green on CI (Node 22 and 24).
- Behavior changes include tests, or a Fastify/CLI smoke is described in the PR
  when tests do not exist yet.
- No dashboard access is required to approve.

`CODEOWNERS` routes review to `@jad-creations`. Prefer that path for merges
to `main`.

### Release process

1. On `main`, move `[Unreleased]` notes in `CHANGELOG.md` into a new
   `## [X.Y.Z] - YYYY-MM-DD` section. Follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
   and [SemVer](https://semver.org/spec/v2.0.0.html) (`MAJOR` for breaking
   public API, `MINOR` for compatible additions, `PATCH` for fixes).
2. Set `"version"` in `package.json` to the same `X.Y.Z`.
3. Merge that commit to `main`.
4. Tag `vX.Y.Z` on the merge commit (`git tag vX.Y.Z && git push origin vX.Y.Z`).
   The [release workflow](.github/workflows/release.yml) runs typecheck, tests,
   build, and `npm publish --provenance --access public`.
5. Confirm the [npm package](https://www.npmjs.com/package/@anomira/node-sdk)
   shows the new version.

Do not publish from a laptop. The tag (or a manual `workflow_dispatch` on the
release workflow) is the publish path.

Configure [npm trusted publishing](https://docs.npmjs.com/trusted-publishers)
for this GitHub repository before the first automated publish. The workflow
needs `id-token: write` (already set).

If a publish fails, fix the problem and cut a **new** patch version. Do not
move or reuse a tag that already exists on the remote.

## Questions

Open a GitHub issue or email [sdk@anomira.io](mailto:sdk@anomira.io).
